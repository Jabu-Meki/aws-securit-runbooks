# RB-009 — SOC 2 Type II Evidence Collection

![Severity](https://img.shields.io/badge/Category-Governance-blue?style=flat)
![Framework](https://img.shields.io/badge/Framework-SOC_2_Type_II-2ea44f?style=flat)
![Service](https://img.shields.io/badge/AWS-IAM_·_CloudTrail_·_GuardDuty_·_Config-FF9900?style=flat&logo=amazonaws&logoColor=black)

---

## Overview

Evidence collection guide for SOC 2 Type II audits, mapped to AWS services. SOC 2 evaluates controls across five Trust Services Criteria (TSC): Security, Availability, Confidentiality, Processing Integrity, and Privacy.

This runbook focuses on the Security (CC) criteria — the most commonly scoped. Adapt for Availability (A) and Confidentiality (C) as needed.

**Audit period:** typically 6 or 12 months. Evidence must cover the entire audit period, not just the snapshot date.

---

## Evidence Collection by TSC

### CC6 — Logical and Physical Access Controls

#### CC6.1 — Logical access security measures

**What auditors want to see:** Users can only access systems they're authorised for, using authenticated sessions. MFA is enforced.

```bash
# Evidence 1: IAM Credential Report (run monthly, save each version)
aws iam generate-credential-report
aws iam get-credential-report \
  --query Content --output text | base64 -d \
  > evidence/cc6.1-credential-report-$(date +%Y%m%d).csv

# Evidence 2: Config rule compliance — MFA enforced
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name mfa-enabled-for-iam-console-access \
  --compliance-types NON_COMPLIANT \
  --query 'EvaluationResults[].{Resource:EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,Time:ResultRecordedTime}' \
  > evidence/cc6.1-mfa-noncompliant-$(date +%Y%m%d).json

# Evidence 3: SCP or IAM policy enforcing MFA (document once)
aws organizations describe-policy \
  --policy-id <MFA_SCP_ID> \
  --query 'Policy.Content' --output text | python3 -m json.tool \
  > evidence/cc6.1-mfa-scp.json
```

#### CC6.2 — New access provisioning

**What auditors want to see:** Users are granted access through a defined process, with approvals.

Collect:
- Joiner tickets showing access request → approval → provisioning workflow
- Sample of new IAM user creation events from CloudTrail

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time <AUDIT_PERIOD_START> \
  --end-time <AUDIT_PERIOD_END> \
  --query 'Events[].{Time:EventTime,NewUser:CloudTrailEvent}' \
  > evidence/cc6.2-user-provisioning-$(date +%Y%m%d).json
```

Auditor will sample 5–10 of these and ask for the corresponding approval ticket.

#### CC6.3 — Access reviews

**What auditors want to see:** Access is reviewed periodically and removed when no longer needed.

```bash
# IAM Access Advisor — shows last access time for each service per user
aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::<ACCOUNT>:user/<USER>

# After a few seconds:
aws iam get-service-last-accessed-details \
  --job-id <JOB_ID> \
  --query 'ServicesLastAccessed[?LastAuthenticated==null || LastAuthenticated<=`<90_DAYS_AGO>`].{Service:ServiceName,LastUsed:LastAuthenticated}' \
  > evidence/cc6.3-unused-access-$(date +%Y%m%d).json
```

Also export: access review completion records from your ITSM or HR system showing who reviewed, when, and the outcome.

#### CC6.6 — Network access controls

**What auditors want to see:** Firewall rules restrict access to only necessary traffic.

```bash
# Evidence: Security groups — no 0.0.0.0/0 on sensitive ports
aws ec2 describe-security-groups \
  --query 'SecurityGroups[].{ID:GroupId,Name:GroupName,Rules:IpPermissions}' \
  > evidence/cc6.6-security-groups-$(date +%Y%m%d).json

# Config rule compliance — restricted SSH
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name restricted-ssh \
  --query 'EvaluationResults[?ComplianceType==`NON_COMPLIANT`]' \
  > evidence/cc6.6-restricted-ssh-$(date +%Y%m%d).json
```

---

### CC7 — System Operations & Monitoring

#### CC7.1 — Infrastructure vulnerability scanning

```bash
# AWS Inspector findings summary
aws inspector2 list-findings \
  --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}]}' \
  --query 'findings[].{Title:title,Severity:severity,Resource:resources[0].id,Fixed:fixAvailable}' \
  > evidence/cc7.1-inspector-findings-$(date +%Y%m%d).json
```

#### CC7.2 — Monitoring for anomalous activity

**What auditors want to see:** Alerts exist and are actioned when triggered.

```bash
# GuardDuty findings during audit period — shows monitoring is active
aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {
        "Gte": <AUDIT_START_EPOCH_MS>,
        "Lte": <AUDIT_END_EPOCH_MS>
      }
    }
  }' \
  --query 'FindingIds' \
  > evidence/cc7.2-guardduty-finding-ids-$(date +%Y%m%d).json

# CloudWatch alarms — show monitoring is configured
aws cloudwatch describe-alarms \
  --query 'MetricAlarms[].{Name:AlarmName,State:StateValue,Metric:MetricName,Action:AlarmActions}' \
  > evidence/cc7.2-cloudwatch-alarms-$(date +%Y%m%d).json
```

#### CC7.3 — Incident response

Auditors will want to see documented evidence of incidents handled during the audit period. For each P1/P2 incident:
- Incident timeline document
- Containment and remediation evidence
- Post-incident review

Keep incident reports in a dedicated evidence folder. Even a low-incident period is evidence — it shows your monitoring is working and generating accurate results.

---

### CC8 — Change Management

#### CC8.1 — Change management process

**What auditors want to see:** Infrastructure changes go through an approved process.

```bash
# CloudTrail — all significant infrastructure changes during audit period
aws cloudtrail lookup-events \
  --start-time <AUDIT_PERIOD_START> \
  --end-time <AUDIT_PERIOD_END> \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  > evidence/cc8.1-ec2-launches-$(date +%Y%m%d).json
```

Also collect: pull request approvals for IaC (Terraform/CloudFormation) changes, deployment pipeline logs, and change management tickets.

---

## Evidence Folder Structure

```
soc2-audit-<YEAR>/
├── cc6-logical-access/
│   ├── cc6.1-credential-reports/          # Monthly exports
│   ├── cc6.2-provisioning-samples/        # 10 samples + approval tickets
│   ├── cc6.3-access-reviews/              # Quarterly review records
│   └── cc6.6-network-controls/
├── cc7-monitoring/
│   ├── cc7.1-vulnerability-scans/
│   ├── cc7.2-alert-configuration/
│   └── cc7.3-incident-records/
├── cc8-change-management/
│   └── cc8.1-change-records/
└── population-lists/                      # Auditor requests populations first
    ├── all-iam-users.csv
    ├── all-ec2-instances.csv
    └── all-s3-buckets.csv
```

---

## Audit Preparation Timeline

| Weeks before audit | Action |
|-------------------|--------|
| 12 weeks | Confirm scope and audit period with auditor |
| 8 weeks | Run internal readiness assessment — identify gaps |
| 6 weeks | Begin collecting evidence; remediate open findings |
| 4 weeks | Compile population lists for all in-scope systems |
| 2 weeks | Complete evidence folder; conduct internal walkthrough |
| 1 week | Resolve any last-minute issues; brief control owners |
| Audit starts | Provide population lists; respond to sample requests within 48h |

---

## Common Audit Findings (and how to avoid them)

| Finding | Prevention |
|---------|-----------|
| Users with no MFA | AWS Config rule + SCP enforcement |
| Access not reviewed quarterly | Calendar reminder + ITSM workflow |
| Terminated employees retain access | HR–IAM integration or deprovisioning checklist |
| No documented incident response | This runbook library + documented PIRs |
| CloudTrail gaps | Config rule + CloudWatch alarm ([RB-007](../misconfigurations/RB-007-cloudtrail-logging-gap.md)) |
| Security group exceptions without justification | Exception register + CSPM triage process |

---

## Accounting Background Note

SOC 2 evidence collection has direct parallels to financial audit preparation:

- **Population → sample** mirrors audit sampling methodology
- **Control testing** mirrors substantive testing and test of controls
- **Management assertions** in SOC 2 = assertions in financial statements
- **Control owner walkthroughs** = inquiry procedures in financial audit

Your accounting background is a genuine advantage here — you understand what auditors need, how to organise evidence packages, and how to communicate control effectiveness.

---

## Related Runbooks

- [RB-006 — MFA Not Enforced](../misconfigurations/RB-006-mfa-not-enforced.md) — CC6.1 remediation
- [RB-007 — CloudTrail Logging Gap](../misconfigurations/RB-007-cloudtrail-logging-gap.md) — CC7.2 remediation
- [RB-008 — CSPM Alert Triage](./RB-008-cspm-alert-triage.md) — ongoing posture management

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Framework: SOC 2 Type II*
