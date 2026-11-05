# RB-004 — Ransomware Detection & Response

![Severity](https://img.shields.io/badge/Severity-CRITICAL-red?style=flat)
![Category](https://img.shields.io/badge/Category-Incident_Response-blueviolet?style=flat)
![Service](https://img.shields.io/badge/AWS-EC2_·_EBS_·_VPC_·_S3-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF RS.RP-1, RS.CO-2, RC.RP-1 · ISO 27001 A.16.1 · GDPR Art 33

---

## Overview

Ransomware or wiper malware detected on an AWS workload. Ransomware in cloud environments often targets both EC2 EBS volumes (encrypting data at the OS level) and S3 buckets (deleting or overwriting objects after exfiltration — "double extortion").

**This is a P1 incident. CISO must be notified within 15 minutes of declaration.**

---

## Detection Signals

```
GuardDuty:    Execution:EC2/MaliciousFile
GuardDuty:    CryptoCurrency:EC2/BitcoinTool.B  (ransomware C2 comms pattern)
GuardDuty:    Behavior:EC2/NetworkPortUnusual
GuardDuty:    UnauthorizedAccess:EC2/SSHBruteForce (common precursor)
CloudWatch:   High CPU (encryption process), unusual disk I/O
SIEM alert:   Mass file rename events (e.g., .locked, .encrypted extensions)
VPC Flow:     Large outbound transfer to unknown external IP (exfiltration)
```

---

## STOP — Before Anything Else

Do not restart, terminate, or patch affected instances before completing Phase 1. Forensic evidence is lost on termination.

---

## Phase 1 — Immediate Isolation (T+0 to T+10 min)

### 1.1 Identify affected instances

```bash
# Instances with anomalous GuardDuty findings
aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --finding-criteria '{"Criterion":{"type":{"Eq":["Execution:EC2/MaliciousFile"]}}}' \
  --query 'FindingIds'

# Describe the finding to get instance ID
aws guardduty get-findings \
  --detector-id $DETECTOR_ID \
  --finding-ids $FINDING_ID \
  --query 'Findings[0].Resource.InstanceDetails.{ID:InstanceId,IP:NetworkInterfaces[0].PrivateIpAddress}'
```

### 1.2 Move instance to quarantine security group

```bash
# Quarantine SG rules:
# Inbound:  ONLY from forensic workstation IP on port 22/3389
# Outbound: DENY ALL

QUARANTINE_SG=<quarantine-sg-id>
INSTANCE_ID=<affected-instance-id>

# Store current SGs for reference
aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].SecurityGroups'

# Apply quarantine SG (replaces all existing SGs)
aws ec2 modify-instance-attribute \
  --instance-id $INSTANCE_ID \
  --groups $QUARANTINE_SG
```

### 1.3 Snapshot all EBS volumes BEFORE any remediation

```bash
# Get all volume IDs attached to the instance
VOLUMES=$(aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[].Ebs.VolumeId' \
  --output text)

# Snapshot each volume with forensic tags
for VOL in $VOLUMES; do
  aws ec2 create-snapshot \
    --volume-id $VOL \
    --description "FORENSIC-RANSOMWARE-$(date +%Y%m%d-%H%M)-$INSTANCE_ID" \
    --tag-specifications "ResourceType=snapshot,Tags=[
      {Key=Purpose,Value=ForensicEvidence},
      {Key=IncidentId,Value=<TICKET_ID>},
      {Key=DoNotDelete,Value=true}
    ]"
  echo "Snapshot created for $VOL"
done
```

---

## Phase 2 — Evidence Collection (T+10 to T+30 min)

### 2.1 Export CloudTrail logs for the incident window

```bash
aws cloudtrail lookup-events \
  --start-time <INCIDENT_START_ISO> \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=$INSTANCE_ID \
  --output json > cloudtrail-$INSTANCE_ID-$(date +%Y%m%d).json
```

### 2.2 Check VPC Flow Logs for exfiltration

```bash
# Query in Athena (replace with your VPC flow log Athena table)
# Run this in the AWS Athena console or via CLI

cat << 'EOF'
SELECT
  srcaddr,
  dstaddr,
  dstport,
  SUM(bytes) AS total_bytes,
  COUNT(*) AS connection_count
FROM vpc_flow_logs
WHERE srcaddr = '<INSTANCE_PRIVATE_IP>'
  AND action = 'ACCEPT'
  AND start > CAST('<INCIDENT_START_UNIX_EPOCH>' AS bigint)
GROUP BY srcaddr, dstaddr, dstport
ORDER BY total_bytes DESC
LIMIT 20;
EOF
```

Large outbound transfers (>1GB) to unknown external IPs confirm double-extortion exfiltration. **Engage legal and comms immediately if confirmed.**

### 2.3 Check S3 for ransomware impact

```bash
# Look for mass delete or overwrite events on S3
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
  --start-time <INCIDENT_START_ISO> \
  --query 'Events[].{Time:EventTime,Bucket:Resources[0].ResourceName,Key:Resources[1].ResourceName}'
```

If S3 versioning and MFA delete were enabled, objects can be recovered. If not, data may be permanently lost.

---

## Phase 3 — Eradication

### 3.1 Terminate compromised instance (after forensic snapshots confirmed)

```bash
# Confirm snapshots are complete first
aws ec2 describe-snapshots \
  --filters Name=tag:IncidentId,Values=<TICKET_ID> \
  --query 'Snapshots[].{ID:SnapshotId,State:State,Progress:Progress}'

# Once all snapshots show State=completed:
aws ec2 terminate-instances --instance-ids $INSTANCE_ID
```

### 3.2 Scan remaining instances for lateral movement

```bash
# Launch AWS Inspector scan on all instances in the same subnet
aws inspector2 create-filter \
  --name "ransomware-investigation-$(date +%Y%m%d)" \
  --filter-criteria '{"ec2InstanceSubnetId":[{"comparison":"EQUALS","value":"<SUBNET_ID>"}]}'
```

### 3.3 Reset all credentials that touched the affected instance

- IAM roles attached to the instance → revoke active sessions
- Any API keys used from the instance (found in CloudTrail)
- Database passwords accessible from the instance
- Any Secrets Manager secrets the instance role could read

---

## Phase 4 — Recovery

### 4.1 Build from golden AMI (preferred over restoring from snapshot)

```bash
# Launch replacement from pre-approved, hardened AMI
aws ec2 run-instances \
  --image-id <GOLDEN_AMI_ID> \
  --instance-type <TYPE> \
  --subnet-id <CLEAN_SUBNET_ID> \
  --security-group-ids <CORRECT_SGS> \
  --iam-instance-profile Name=<CORRECT_PROFILE> \
  --metadata-options HttpTokens=required \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=<NAME>}]'
```

> Always prefer rebuilding from a golden AMI over restoring a snapshot. Snapshots may contain the malware or backdoor.

### 4.2 Restore data from pre-incident backups

```bash
# Check AWS Backup for recovery points before the incident
aws backup list-recovery-points-by-resource \
  --resource-arn arn:aws:ec2:<REGION>:<ACCOUNT>:volume/$VOL \
  --query 'RecoveryPoints[?CreationDate<=`<INCIDENT_START_ISO>`].{ID:RecoveryPointArn,Date:CreationDate}'
```

---

## Phase 5 — Post-Incident

### P1 notifications timeline

| Time | Action |
|------|--------|
| T+0 | Incident declared, on-call paged |
| T+15 min | CISO notified |
| T+1h | Legal notified if data exfiltration confirmed |
| T+4h | Board notified (P1 requirement) |
| T+24h | Draft regulatory notification if personal/regulated data affected |
| T+72h | GDPR notification to supervisory authority (if applicable) |
| T+7d | Full post-incident report published |

### Prevention controls

| Control | AWS Service | Configuration |
|---------|------------|---------------|
| S3 Object Lock | S3 | COMPLIANCE mode on backups — ransomware cannot delete |
| Versioning on S3 | S3 | Enable on all sensitive buckets |
| Backups in separate account | AWS Backup | Cross-account vault with no delete permissions for workload account |
| IMDSv2 only | EC2 | `HttpTokens=required` on all instances — blocks credential theft via SSRF |
| Systems Manager | SSM | Replace SSH with SSM Session Manager — no inbound ports required |
| GuardDuty Malware Protection | GuardDuty | Enable EBS scanning — detects malware before execution |

---

## Related Runbooks

- [RB-001 — IAM Privilege Escalation](./RB-001-iam-privilege-escalation.md) — common ransomware follow-on
- [RB-002 — S3 Data Exposure](./RB-002-s3-data-exposure.md) — if S3 was targeted

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: CRITICAL*
