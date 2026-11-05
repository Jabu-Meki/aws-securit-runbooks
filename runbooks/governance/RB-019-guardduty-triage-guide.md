# RB-019 — GuardDuty Finding-Type Triage Guide

![Category](https://img.shields.io/badge/Category-Governance-blue?style=flat)
![Service](https://img.shields.io/badge/AWS-GuardDuty_·_Security_Hub_·_EventBridge-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF DE.AE-5, DE.CM-4 · CIS Controls 8.11 · SOC 2 CC7.2 · PCI-DSS Req 10.7

---

## Overview

GuardDuty generates findings across seven threat categories. This runbook provides a triage decision matrix for every major finding type — helping you quickly classify severity, determine the blast radius, and route to the correct response runbook. Use this as the first stop when a GuardDuty alert fires.

---

## GuardDuty Threat Categories

```
Backdoor         — C2 communication, DDoS participation
Behaviour        — Anomalous resource usage patterns
CryptoCurrency   — Mining pool communication
Discovery        — Enumeration / reconnaissance
Execution        — Malicious code running on a resource
Exfiltration     — Data leaving the environment
Impact           — Destructive actions (deletion, ransom)
InitialAccess    — First foothold obtained
Pentest          — Penetration testing tool signatures
Policy           — Configuration changed to weaken security
PrivilegeEsc     — Permissions escalation
Recon            — Port scanning, probing
Stealth          — Covering tracks, disabling logging
Trojan           — Malware detected
UnauthorizedAccess — Credentials used from unexpected source
```

---

## Triage Decision Matrix

### CRITICAL — Respond immediately (P1)

| Finding Type | What It Means | First Action | Runbook |
|-------------|--------------|-------------|---------|
| `PrivilegeEscalation:IAMUser/AdministrativePermissions` | IAM user attached admin policy to themselves | Disable access key, attach DenyAll policy | [RB-001](../incident-response/RB-001-iam-privilege-escalation.md) |
| `PrivilegeEscalation:IAMUser/RolesCreatedWithAdminAccessPermissions` | New admin role created | Check CloudTrail for CreateRole events | [RB-001](../incident-response/RB-001-iam-privilege-escalation.md) |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | EC2 role creds used from non-AWS IP | Revoke session, check IMDSv2 | [RB-011](../incident-response/RB-011-ec2-metadata-ssrf.md) |
| `Policy:IAMUser/RootCredentialUsage` | Root account used | Confirm legitimate use within 10 min | [RB-012](../incident-response/RB-012-root-account-usage.md) |
| `Execution:EC2/MaliciousFile` | Malware file detected on EC2 EBS | Snapshot + quarantine instance | [RB-004](../incident-response/RB-004-ransomware-response.md) |
| `Impact:EC2/WinRMBruteForce` | Active RDP/WinRM brute force | Check SG rules, isolate if compromised | [RB-005](../misconfigurations/RB-005-security-group-open-internet.md) |
| `Exfiltration:S3/MaliciousIPCaller` | S3 accessed from malicious IP | Check bucket policy, pull access logs | [RB-002](../incident-response/RB-002-s3-data-exposure.md) |
| `Discovery:S3/MaliciousIPCaller` | S3 enumeration from malicious IP | Restrict bucket policy, check public access | [RB-002](../incident-response/RB-002-s3-data-exposure.md) |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | CloudTrail was disabled | Re-enable immediately, treat as P1 | [RB-007](../misconfigurations/RB-007-cloudtrail-logging-gap.md) |
| `Impact:S3/ObjectDelete` | Mass S3 object deletion | Check versioning, assess data loss | [RB-002](../incident-response/RB-002-s3-data-exposure.md) |
| `Execution:EKS/ExecInKubeDNSPod` | Shell exec into kube-dns pod | Isolate node, check for container escape | [RB-015](../misconfigurations/RB-015-eks-misconfiguration.md) |

---

### HIGH — Respond within 4 hours (P2)

| Finding Type | What It Means | First Action | Runbook |
|-------------|--------------|-------------|---------|
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | Instance communicating with mining pool | Isolate instance, check cost spike | [RB-013](../incident-response/RB-013-cryptomining-detection.md) |
| `CryptoCurrency:EC2/BitcoinTool.B` | Mining pool IP connection | Isolate instance, snapshot EBS | [RB-013](../incident-response/RB-013-cryptomining-detection.md) |
| `UnauthorizedAccess:EC2/SSHBruteForce` | SSH brute-force against EC2 | Check SG — is port 22 open to 0.0.0.0/0? | [RB-005](../misconfigurations/RB-005-security-group-open-internet.md) |
| `UnauthorizedAccess:EC2/RDPBruteForce` | RDP brute-force against EC2 | Check SG — is port 3389 open to internet? | [RB-005](../misconfigurations/RB-005-security-group-open-internet.md) |
| `Backdoor:EC2/C&CActivity.B!DNS` | EC2 querying known C2 domains | Isolate instance, check for malware | [RB-004](../incident-response/RB-004-ransomware-response.md) |
| `Trojan:EC2/BlackholeTraffic!DNS` | EC2 resolving sinkholed domains | Possible malware — isolate and investigate | [RB-004](../incident-response/RB-004-ransomware-response.md) |
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | Console login from unusual country/IP | Confirm identity with user immediately | [RB-001](../incident-response/RB-001-iam-privilege-escalation.md) |
| `Policy:S3/BucketBlockPublicAccessDisabled` | Block Public Access turned off | Re-enable immediately, check objects | [RB-002](../incident-response/RB-002-s3-data-exposure.md) |
| `PrivilegeEscalation:Kubernetes/PrivilegedContainer` | Privileged container deployed | Check who deployed, review RBAC | [RB-015](../misconfigurations/RB-015-eks-misconfiguration.md) |
| `CredentialAccess:Kubernetes/MaliciousIPCaller` | K8s API call from malicious IP | Check API server access + restrict CIDR | [RB-015](../misconfigurations/RB-015-eks-misconfiguration.md) |
| `Recon:EC2/PortProbeUnprotectedPort` | Port scanning detected against EC2 | Check SG rules, review exposure | [RB-005](../misconfigurations/RB-005-security-group-open-internet.md) |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` | EC2 creds used from different AWS account | Check IMDSv2, check assumed-role chain | [RB-011](../incident-response/RB-011-ec2-metadata-ssrf.md) |

---

### MEDIUM — Triage within 24 hours (P3)

| Finding Type | What It Means | First Action |
|-------------|--------------|-------------|
| `Discovery:S3/BucketEnumeration` | S3 ListBuckets called from unusual location | Confirm identity, check bucket policies |
| `Discovery:IAMUser/AnomalousBehavior` | Unusual IAM enumeration pattern | Review user's recent CloudTrail activity |
| `Recon:IAMUser/UserPermissions` | IAM permission enumeration | Check if this is a legitimate audit/script |
| `Behavior:EC2/TrafficVolumeUnusual` | Unusually high network traffic | Check workload type — may be legitimate |
| `Policy:IAMUser/S3BlockPublicAccessDisabled` | IAM user turned off block public access | Confirm with user, re-enable if unauthorised |
| `InitialAccess:IAMUser/AnomalousBehavior` | First-time API call from new location | Verify with user — may be travel or new machine |
| `Execution:Lambda/SuspiciousCodeExecution` | Lambda executing unusual code | Check function URL auth type, review invocations |
| `Pentest:IAMUser/KaliLinux` | Kali Linux user agent in API calls | Confirm with penetration test team — may be scheduled |
| `Pentest:EC2/KaliLinux` | Kali Linux activity on EC2 | Confirm pen test scope — quarantine if unplanned |

---

### LOW / INFO — Review in next sprint

| Finding Type | What It Means | Action |
|-------------|--------------|--------|
| `Discovery:S3/TorIPCaller` | S3 access from Tor exit node | Review if any data was accessed; add IP block |
| `UnauthorizedAccess:IAMUser/TorIPCaller` | API call from Tor exit node | Likely credential testing — disable key if suspicious |
| `Recon:EC2/PortProbeEMRUnprotectedPort` | EMR port probe detected | Check EMR cluster security group |
| `Policy:IAMUser/NoPasswordPolicy` | No account password policy set | Set password policy — see CIS 1.8 |

---

## GuardDuty Operational Commands

### Pull all active HIGH/CRITICAL findings

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "severity": {"Gte": 7},
      "service.archived": {"Eq": ["false"]}
    }
  }' \
  --sort-criteria '{"AttributeName":"severity","OrderBy":"DESC"}' \
  --query 'FindingIds' --output text | tr '\t' '\n' | while read FID; do
    aws guardduty get-findings \
      --detector-id $DETECTOR_ID \
      --finding-ids $FID \
      --query 'Findings[0].{Sev:Severity,Type:Type,Resource:Resource.ResourceType,Time:CreatedAt}' \
      --output table
  done
```

### Archive confirmed false positives

```bash
aws guardduty archive-findings \
  --detector-id $DETECTOR_ID \
  --finding-ids $FINDING_ID
```

### Create suppression rule (for known safe patterns)

```bash
# Example: suppress SSH brute-force findings from your own penetration test IPs
aws guardduty create-filter \
  --detector-id $DETECTOR_ID \
  --name "Suppress-PenTest-SSH-BruteForce" \
  --action ARCHIVE \
  --finding-criteria '{
    "Criterion": {
      "type": {"Eq": ["UnauthorizedAccess:EC2/SSHBruteForce"]},
      "service.action.networkConnectionAction.remoteIpDetails.ipAddressV4": {
        "Eq": ["<PENTEST_FIRM_IP>"]
      }
    }
  }'
```

### Export findings to S3 for SIEM/long-term retention

```bash
aws guardduty create-publishing-destination \
  --detector-id $DETECTOR_ID \
  --destination-type S3 \
  --destination-properties DestinationArn=arn:aws:s3:::<SIEM-BUCKET>/guardduty/,KmsKeyArn=<KMS_KEY_ARN>
```

---

## GuardDuty Coverage — Enable All Protection Plans

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Enable all protection plans
aws guardduty update-detector \
  --detector-id $DETECTOR_ID \
  --features '[
    {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"},
    {"Name": "EKS_AUDIT_LOGS", "Status": "ENABLED"},
    {"Name": "EBS_MALWARE_PROTECTION", "Status": "ENABLED"},
    {"Name": "RDS_LOGIN_EVENTS", "Status": "ENABLED"},
    {"Name": "EKS_RUNTIME_MONITORING", "Status": "ENABLED"},
    {"Name": "LAMBDA_NETWORK_LOGS", "Status": "ENABLED"}
  ]'
```

| Protection Plan | Detects |
|----------------|---------|
| S3 Data Events | S3 access from malicious IPs, unusual data access patterns |
| EKS Audit Logs | Kubernetes API anomalies, privilege escalation |
| EBS Malware Protection | Malware in EC2 EBS volumes (scans on snapshot) |
| RDS Login Events | Brute-force, credential stuffing against RDS |
| EKS Runtime Monitoring | Container runtime anomalies, process execution |
| Lambda Network Logs | Lambda function network anomalies |

---

## Governance Notes

- GuardDuty findings are the primary evidence for SOC 2 CC7.2 (monitoring for anomalous activity) — export and retain for the full audit period
- **PCI-DSS Req 10.7:** Systems and processes must detect and prevent anomalous behaviour — GuardDuty is a key technical control satisfying this requirement
- Enable GuardDuty in ALL regions, even unused ones — attackers deliberately target regions where logging is absent
- Set up multi-account GuardDuty with a delegated admin (Security account) so findings from all member accounts are centralised

---

## Related Runbooks

All incident response runbooks — this is the entry point that routes to them.

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Reference: GuardDuty Finding Types documentation*
