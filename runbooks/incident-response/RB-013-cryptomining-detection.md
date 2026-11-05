# RB-013 — Cryptomining / Unauthorised Compute Usage

![Severity](https://img.shields.io/badge/Severity-HIGH-orange?style=flat)
![Category](https://img.shields.io/badge/Category-Incident_Response-blueviolet?style=flat)
![Service](https://img.shields.io/badge/AWS-EC2_·_GuardDuty_·_CloudTrail_·_Cost_Explorer-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF DE.CM-4 · CIS Controls 10.1 · MITRE ATT&CK T1496

---

## Overview

Cryptomining malware is deployed on AWS compute resources — EC2, ECS, Lambda, or EKS — using your compute for an attacker's financial gain. Often the first indicator is an unexpected AWS bill spike before any security alert fires. Also a common indicator of initial access — cryptomining is frequently deployed alongside persistence mechanisms.

**AWS will not waive charges for unauthorised cryptomining — contain fast.**

---

## Detection Signals

```
GuardDuty:   CryptoCurrency:EC2/BitcoinTool.B!DNS
GuardDuty:   CryptoCurrency:EC2/BitcoinTool.B
GuardDuty:   Execution:EC2/MaliciousFile
GuardDuty:   Backdoor:EC2/C&CActivity.B!DNS
CloudWatch:  CPU utilisation > 90% sustained (unusual for workload type)
Cost Alert:  AWS Budgets alert — compute spend 3x above baseline
EC2:         Instance type suddenly changed to compute-optimised (c5, c6i, hpc6a)
```

---

## Phase 1 — Detection & Scope

### 1.1 Identify affected instances via GuardDuty

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Get all cryptomining findings
aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "type": {
        "Eq": ["CryptoCurrency:EC2/BitcoinTool.B!DNS", "CryptoCurrency:EC2/BitcoinTool.B"]
      }
    }
  }' \
  --query 'FindingIds' --output text | tr '\t' '\n' | while read FID; do
    aws guardduty get-findings \
      --detector-id $DETECTOR_ID \
      --finding-ids $FID \
      --query 'Findings[0].{
        Instance:Resource.InstanceDetails.InstanceId,
        InstanceType:Resource.InstanceDetails.InstanceType,
        Domain:Service.Action.DnsRequestAction.Domain,
        Count:Service.Count
      }'
  done
```

### 1.2 Check for unexpected high-CPU instances

```bash
# Find instances with sustained high CPU (last 24h)
aws cloudwatch get-metric-statistics \
  --namespace AWS/EC2 \
  --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=<INSTANCE_ID> \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 3600 \
  --statistics Average \
  --query 'Datapoints[?Average>`80`].{Time:Timestamp,CPU:Average}' \
  --output table
```

### 1.3 Check for unexpected instance launches (attacker spinning up compute)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].{
    Time:EventTime,
    Who:Username,
    IP:CloudTrailEvent
  }' | python3 -c "
import sys, json
events = json.load(sys.stdin)
for e in events:
    raw = json.loads(e.get('IP', '{}'))
    params = raw.get('requestParameters', {})
    instance_type = params.get('instanceType', 'unknown')
    count = params.get('maxCount', '?')
    print(f\"{e['Time']} | {e['Who']} | type={instance_type} | count={count}\")
"
```

Look for: compute-optimised types (c5, c6, hpc), large instance counts, launches by unfamiliar principals.

### 1.4 Financial impact assessment

```bash
# Check cost spike in Cost Explorer
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '-7 days' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity DAILY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  --query 'ResultsByTime[].{Date:TimePeriod.Start,Groups:Groups}' \
  --output table
```

---

## Phase 2 — Containment

### 2.1 Isolate mining instances immediately

```bash
# Quarantine SG — no outbound (blocks mining pool communication)
for INSTANCE_ID in <INSTANCE_1> <INSTANCE_2>; do
  aws ec2 modify-instance-attribute \
    --instance-id $INSTANCE_ID \
    --groups <QUARANTINE_SG_ID>
  echo "Quarantined: $INSTANCE_ID"
done
```

### 2.2 Snapshot before termination (forensic evidence)

```bash
INSTANCE_ID=<affected-instance>

VOLUMES=$(aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[].Ebs.VolumeId' \
  --output text)

for VOL in $VOLUMES; do
  aws ec2 create-snapshot \
    --volume-id $VOL \
    --description "FORENSIC-CRYPTOMINING-$(date +%Y%m%d)-$INSTANCE_ID" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=Purpose,Value=ForensicEvidence},{Key=Incident,Value=<TICKET>}]"
done
```

### 2.3 If attacker launched their own instances — terminate them

```bash
# Terminate instances launched by compromised credential
aws ec2 describe-instances \
  --filters "Name=tag:aws:cloudtrail:arn,Values=arn:aws:sts::<ACCOUNT>:assumed-role/<COMPROMISED_ROLE>/*" \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text | xargs aws ec2 terminate-instances --instance-ids
```

### 2.4 Revoke the compromised credential

```bash
# If EC2 instance role was used to spin up mining instances
aws iam put-role-policy \
  --role-name <COMPROMISED_ROLE> \
  --policy-name EMERGENCY-DenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect":"Deny","Action":"*","Resource":"*"}]
  }'
```

---

## Phase 3 — Eradication

### 3.1 Identify the initial access vector

Common cryptomining entry points in AWS:

| Vector | How to check |
|--------|-------------|
| Exposed SSH (port 22 open) | Check SG rules + CloudTrail for successful SSH sessions |
| Exposed Docker daemon (port 2375) | Check SG for 0.0.0.0/0 on port 2375 |
| Web app RCE | ALB logs for suspicious requests, CVE scan |
| Compromised IAM key | CloudTrail `RunInstances` from unexpected IP |
| Malicious container image | ECR scan results; image provenance |
| Lambda misconfiguration | Lambda invocation logs |

### 3.2 Block known mining pool domains at DNS level

```bash
# Route 53 Resolver DNS Firewall — block mining pools
aws route53resolver create-firewall-rule-group \
  --name CryptominingBlocklist \
  --creator-request-id $(uuidgen)

# Add known mining pool domains
aws route53resolver create-firewall-rule \
  --firewall-rule-group-id <GROUP_ID> \
  --firewall-domain-list-id <DOMAIN_LIST_ID> \
  --priority 100 \
  --action BLOCK \
  --block-response NXDOMAIN \
  --name "Block mining pools"
```

Common mining pool domains to block: `pool.minergate.com`, `xmrpool.eu`, `moneroocean.stream`, `nanopool.org`, `2miners.com`

### 3.3 Set up AWS Budgets alert for future cost anomalies

```bash
aws budgets create-budget \
  --account-id $ACCOUNT_ID \
  --budget '{
    "BudgetName": "UnexpectedComputeSpike",
    "BudgetLimit": {"Amount": "500", "Unit": "USD"},
    "TimeUnit": "MONTHLY",
    "BudgetType": "COST",
    "CostFilters": {"Service": ["Amazon Elastic Compute Cloud - Compute"]}
  }' \
  --notifications-with-subscribers '[{
    "Notification": {
      "NotificationType": "ACTUAL",
      "ComparisonOperator": "GREATER_THAN",
      "Threshold": 150,
      "ThresholdType": "PERCENTAGE"
    },
    "Subscribers": [{"SubscriptionType": "EMAIL","Address": "<security-team@company.com>"}]
  }]'
```

---

## Governance Notes

- Cryptomining is often a secondary payload — treat as evidence of initial access and investigate fully
- AWS Cost Anomaly Detection (free service) should be enabled in all accounts — it often detects mining before GuardDuty
- **Financial liability:** AWS charges for compute regardless of whether it was authorised. Escalate to finance immediately with estimated impact
- Tag all instances with `Owner` and `Environment` — untagged instances are often the ones abused

---

## Related Runbooks

- [RB-001 — IAM Privilege Escalation](./RB-001-iam-privilege-escalation.md) — common attack chain
- [RB-011 — EC2 Metadata SSRF](./RB-011-ec2-metadata-ssrf.md) — common initial access vector
- [RB-005 — Security Group Open to Internet](../misconfigurations/RB-005-security-group-open-internet.md)

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: HIGH*
