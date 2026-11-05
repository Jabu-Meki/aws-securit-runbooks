# RB-018 — Cost Anomaly as a Security Signal

![Severity](https://img.shields.io/badge/Severity-HIGH-orange?style=flat)
![Category](https://img.shields.io/badge/Category-Governance-blue?style=flat)
![Service](https://img.shields.io/badge/AWS-Cost_Explorer_·_Budgets_·_CloudTrail_·_GuardDuty-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF DE.AE-1 · CIS Controls 13.1 · ISO 27001 A.16.1.2

---

## Overview

An unexpected spike in AWS costs is often the first indicator of a security incident — before GuardDuty fires, before the SIEM alerts, before anyone notices. Cryptomining, data exfiltration, attacker-launched infrastructure, and compromised credentials driving API calls all generate cost anomalies.

This runbook treats cost spikes as security events, not just billing issues.

---

## Security Incidents That Generate Cost Signals

| Incident Type | Cost Signal | Typical Spike |
|---------------|-------------|--------------|
| Cryptomining | EC2 compute | 5–50x baseline |
| Data exfiltration | S3 data transfer out | 10–1000x baseline |
| Attacker-launched EC2 | EC2, EBS | New spend in unused region |
| Credential abuse | Any service | Spend in unexpected region |
| Lambda abuse (public URL) | Lambda invocations | 100x+ invocations |
| DynamoDB scan attack | DynamoDB read | Large read unit spike |
| Secrets Manager enumeration | Secrets Manager API | GetSecretValue call spike |

---

## Phase 1 — Cost Anomaly Detection Setup (Preventive)

### 1.1 Enable AWS Cost Anomaly Detection

```bash
# Create a monitor for all services
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "AllServicesMonitor",
    "MonitorType": "DIMENSIONAL",
    "MonitorDimension": "SERVICE"
  }'

# Create a monitor per account (for multi-account environments)
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "LinkedAccountMonitor",
    "MonitorType": "DIMENSIONAL",
    "MonitorDimension": "LINKED_ACCOUNT"
  }'

# Create alert subscription — notify security team
aws ce create-anomaly-subscription \
  --anomaly-subscription '{
    "MonitorArnList": ["<MONITOR_ARN>"],
    "Subscribers": [{
      "Address": "<SECURITY_TEAM_EMAIL>",
      "Type": "EMAIL"
    }, {
      "Address": "<SNS_TOPIC_ARN>",
      "Type": "SNS"
    }],
    "Threshold": 100,
    "Frequency": "IMMEDIATE",
    "SubscriptionName": "SecurityCostAlert"
  }'
```

### 1.2 Set AWS Budgets with security alert thresholds

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Budget: alert at 150% of previous month spend
aws budgets create-budget \
  --account-id $ACCOUNT_ID \
  --budget '{
    "BudgetName": "SecuritySpendAlert-EC2",
    "BudgetType": "COST",
    "TimeUnit": "MONTHLY",
    "BudgetLimit": {"Amount": "<BASELINE_EC2_MONTHLY_COST>", "Unit": "USD"},
    "CostFilters": {"Service": ["Amazon Elastic Compute Cloud - Compute"]}
  }' \
  --notifications-with-subscribers '[{
    "Notification": {
      "NotificationType": "ACTUAL",
      "ComparisonOperator": "GREATER_THAN",
      "Threshold": 150,
      "ThresholdType": "PERCENTAGE"
    },
    "Subscribers": [{"SubscriptionType": "SNS", "Address": "<SECURITY_SNS_ARN>"}]
  }]'
```

---

## Phase 2 — Cost Spike Investigation

### 2.1 Identify the anomalous service and time window

```bash
# Get daily spend by service for the last 14 days
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '-14 days' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity DAILY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  --query 'ResultsByTime[].{
    Date:TimePeriod.Start,
    Services:Groups[].{
      Service:Keys[0],
      Cost:Metrics.BlendedCost.Amount
    }
  }' | python3 -c "
import sys, json
data = json.load(sys.stdin)
for day in data:
    for svc in day['Services']:
        cost = float(svc['Cost'])
        if cost > 10:  # Filter noise — adjust threshold
            print(f\"{day['Date']} | {svc['Service']:50} | \${cost:.2f}\")
" | sort -k5 -t'$' -rn | head -30
```

### 2.2 Drill into the anomalous service

```bash
# Example: EC2 compute spike — find instance types and regions
aws ce get-cost-and-usage \
  --time-period Start=<ANOMALY_START_DATE>,End=<ANOMALY_END_DATE> \
  --granularity DAILY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=INSTANCE_TYPE \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Elastic Compute Cloud - Compute"]}}' \
  --query 'ResultsByTime[].Groups[].{Type:Keys[0],Cost:Metrics.BlendedCost.Amount}' \
  --output table

# Find regions with unexpected spend
aws ce get-cost-and-usage \
  --time-period Start=<ANOMALY_START_DATE>,End=<ANOMALY_END_DATE> \
  --granularity DAILY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=REGION \
  --output table
```

Unexpected compute-optimised instance types (c5, hpc) or spend in regions you don't operate in = strong security signal.

### 2.3 Correlate with CloudTrail events at the spike time

```bash
# Who launched instances during the cost spike window?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --start-time <SPIKE_START_ISO> \
  --end-time <SPIKE_END_ISO> \
  --query 'Events[].{
    Time:EventTime,
    Who:Username,
    IP:CloudTrailEvent
  }' | python3 -c "
import sys, json
events = json.load(sys.stdin)
for e in events:
    raw = json.loads(e.get('IP','{}'))
    it = raw.get('requestParameters',{}).get('instanceType','?')
    ip = raw.get('sourceIPAddress','?')
    print(f\"{e['Time']} | {e['Who']} | {it} | from {ip}\")
"
```

### 2.4 Check for S3 data transfer anomaly (exfiltration indicator)

```bash
# Data transfer out spike
aws ce get-cost-and-usage \
  --time-period Start=<ANOMALY_START_DATE>,End=<ANOMALY_END_DATE> \
  --granularity DAILY \
  --metrics UsageQuantity \
  --group-by Type=DIMENSION,Key=USAGE_TYPE \
  --filter '{
    "And": [
      {"Dimensions": {"Key":"SERVICE","Values":["Amazon Simple Storage Service"]}},
      {"Dimensions": {"Key":"USAGE_TYPE_GROUP","Values":["S3: Data Transfer - Internet (Out)"]}}
    ]
  }' \
  --query 'ResultsByTime[].{Date:TimePeriod.Start,GB:Groups[0].Metrics.UsageQuantity.Amount}'
```

Unexpected GBs transferred out of S3 = potential data exfiltration. Cross-reference with Macie findings.

---

## Phase 3 — Security Response

### 3.1 EC2 compute spike → possible cryptomining

Escalate to [RB-013 — Cryptomining Detection](../incident-response/RB-013-cryptomining-detection.md)

Key actions:
```bash
# Find and terminate unexpected instances immediately
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[?!Tags].{ID:InstanceId,Type:InstanceType,Launch:LaunchTime}'
```

Untagged instances running expensive types in unexpected regions are highly suspicious.

### 3.2 S3 transfer spike → possible exfiltration

Escalate to [RB-002 — S3 Data Exposure](../incident-response/RB-002-s3-data-exposure.md)

```bash
# Check S3 server access logs for bulk GET requests
# Identify which bucket, which requester, which objects
```

### 3.3 Unexpected region spend → shadow infrastructure

```bash
# Find all resources in an unexpected region
aws ec2 describe-instances --region <UNEXPECTED_REGION>
aws s3api list-buckets --query 'Buckets[?contains(Name, `<UNEXPECTED_REGION>`)]'
aws lambda list-functions --region <UNEXPECTED_REGION>
```

Shadow infrastructure in unused regions is often an attacker's persistence mechanism — they deploy in regions where your monitoring is thin.

---

## Phase 4 — Governance & Financial Controls

### Request credit from AWS (if applicable)

AWS will not automatically waive charges for compromised accounts, but will consider credit requests with evidence of:
- Active security incident
- Prompt containment action
- GuardDuty findings showing unauthorised activity

Contact AWS Support → Billing case → Request credit with incident evidence.

### Implement tagging enforcement to enable cost attribution

```bash
# SCP: deny launching EC2 without required tags
# Required tags: Environment, Owner, CostCentre, Application
aws organizations create-policy \
  --type SERVICE_CONTROL_POLICY \
  --name RequireEC2Tags \
  --content file://require-ec2-tags-scp.json
```

Untagged resources that appear in cost reports are immediately suspicious — you can't attribute the cost and can't confirm the owner.

---

## Monthly Security Cost Review Checklist

- [ ] Cost Anomaly Detection alerts reviewed and actioned
- [ ] AWS Budgets — no alerts in past 30 days (or all investigated)
- [ ] Spend in all regions verified against known workloads
- [ ] No compute-optimised instance types outside of approved use cases
- [ ] S3 data transfer out within expected range
- [ ] No new services appearing in cost breakdown without corresponding project
- [ ] Cost allocation tags coverage > 95%

---

## Related Runbooks

- [RB-013 — Cryptomining Detection](../incident-response/RB-013-cryptomining-detection.md)
- [RB-002 — S3 Data Exposure](../incident-response/RB-002-s3-data-exposure.md)
- [RB-001 — IAM Privilege Escalation](../incident-response/RB-001-iam-privilege-escalation.md)

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: HIGH*
