# RB-008 — CSPM Alert Triage (AWS Security Hub)

![Severity](https://img.shields.io/badge/Severity-MEDIUM-yellow?style=flat)
![Category](https://img.shields.io/badge/Category-Governance-blue?style=flat)
![Service](https://img.shields.io/badge/AWS-Security_Hub_·_Config_·_GuardDuty-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF DE.CM-8, ID.RA-1 · CIS Controls 4.1 · ISO 27001 A.18.2

---

## Overview

Standard triage workflow for Cloud Security Posture Management alerts from AWS Security Hub. Covers classification, prioritisation, exception management, and tracking. Run this workflow daily (or on alert trigger for CRITICAL/HIGH findings).

---

## Security Hub Finding Lifecycle

```
NEW → NOTIFIED → SUPPRESSED
              ↓
           RESOLVED
```

All findings start as `NEW`. Your job is to move them to `RESOLVED` (remediated) or `SUPPRESSED` (accepted exception with business justification).

---

## Phase 1 — Pull & Prioritise Active Findings

### 1.1 Get all active HIGH and CRITICAL findings

```bash
aws securityhub get-findings \
  --filters '{
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    "SeverityLabel": [
      {"Value": "CRITICAL", "Comparison": "EQUALS"},
      {"Value": "HIGH", "Comparison": "EQUALS"}
    ]
  }' \
  --query 'Findings[].{
    Title:Title,
    Severity:Severity.Label,
    Resource:Resources[0].Id,
    Account:AwsAccountId,
    Created:CreatedAt
  }' \
  --output table
```

### 1.2 Prioritise using the triage matrix

Score each finding across these factors:

| Factor | 3 — High | 2 — Medium | 1 — Low |
|--------|----------|------------|---------|
| Severity | CRITICAL | HIGH | MEDIUM |
| Asset criticality | Production | Staging | Dev |
| Internet-facing | Yes | Internal, no egress | Isolated |
| Data sensitivity | PII / PCI / regulated | Business-sensitive | Public |
| Active exploitation | Confirmed | Suspected | No evidence |

**Triage score = sum of factors.** Score ≥ 12: treat as P1. Score 8–11: P2. Score < 8: scheduled remediation.

---

## Phase 2 — Classify Each Finding

For each active finding, apply one of these dispositions:

### Option A: True positive — remediate

Assign to the relevant team and track:

```bash
aws securityhub batch-update-findings \
  --finding-identifiers '[{"Id": "<FINDING_ARN>", "ProductArn": "<PRODUCT_ARN>"}]' \
  --workflow '{"Status": "NOTIFIED"}' \
  --note '{"Text": "Assigned to: <TEAM> | Ticket: <JIRA_ID> | Due: <DATE>", "UpdatedBy": "<YOUR_NAME>"}'
```

### Option B: False positive — suppress with justification

```bash
aws securityhub batch-update-findings \
  --finding-identifiers '[{"Id": "<FINDING_ARN>", "ProductArn": "<PRODUCT_ARN>"}]' \
  --workflow '{"Status": "SUPPRESSED"}' \
  --note '{"Text": "False positive: <REASON>. Reviewed by: <NAME>. Ticket: <ID>", "UpdatedBy": "<YOUR_NAME>"}'
```

### Option C: Accepted risk / exception

Use only with documented approval. Must include:
- Business justification
- Compensating control (if any)
- Exception expiry date (max 90 days — requires re-review)
- Manager approval in the note

```bash
aws securityhub batch-update-findings \
  --finding-identifiers '[{"Id": "<FINDING_ARN>", "ProductArn": "<PRODUCT_ARN>"}]' \
  --workflow '{"Status": "SUPPRESSED"}' \
  --note '{"Text": "Exception accepted. Justification: <REASON>. Compensating control: <CONTROL>. Approved by: <MANAGER>. Expires: <DATE>. Ticket: <ID>", "UpdatedBy": "<YOUR_NAME>"}'
```

---

## Phase 3 — Bulk Operations for Common Findings

### Suppress test/dev accounts from production triage view

```bash
# Create a suppression filter for dev accounts
aws securityhub create-automation-rule \
  --rule-name "SuppressDevAccountFindings" \
  --rule-order 1 \
  --criteria '{
    "AwsAccountId": [
      {"Value": "<DEV_ACCOUNT_ID>", "Comparison": "EQUALS"}
    ],
    "SeverityLabel": [
      {"Value": "LOW", "Comparison": "EQUALS"},
      {"Value": "MEDIUM", "Comparison": "EQUALS"}
    ]
  }' \
  --actions '[{"Type": "FINDING_FIELDS_UPDATE", "FindingFieldsUpdate": {"Workflow": {"Status": "SUPPRESSED"}, "Note": {"Text": "Auto-suppressed: dev account", "UpdatedBy": "AutomationRule"}}}]'
```

### Mark a finding resolved after remediation

```bash
aws securityhub batch-update-findings \
  --finding-identifiers '[{"Id": "<FINDING_ARN>", "ProductArn": "<PRODUCT_ARN>"}]' \
  --workflow '{"Status": "RESOLVED"}' \
  --note '{"Text": "Remediated. Config rule now COMPLIANT. Evidence in ticket: <ID>", "UpdatedBy": "<YOUR_NAME>"}'
```

---

## Phase 4 — Weekly Posture Review

### 4.1 Generate a posture summary

```bash
# Count by severity
aws securityhub get-findings \
  --filters '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}],"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}]}' \
  --query 'Findings[].Severity.Label' \
  --output text | sort | uniq -c | sort -rn

# Findings older than 30 days (overdue)
aws securityhub get-findings \
  --filters '{
    "RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}],
    "WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],
    "CreatedAt":[{"DateRange":{"Value":30,"Unit":"DAYS"},"Comparison":"LTE"}]
  }' \
  --query 'length(Findings)'
```

### 4.2 Track Security Hub score trend

The overall security score is visible in the Security Hub console. Target thresholds:

| Score | Status |
|-------|--------|
| > 80% | Target state |
| 60–80% | Acceptable, improving |
| 40–60% | Needs programme investment |
| < 40% | Immediate escalation to CISO |

---

## Exception Management Policy

All suppressed findings must be logged in the exception register with:

| Field | Required |
|-------|---------|
| Finding ID | Yes |
| Severity | Yes |
| Business justification | Yes |
| Compensating control | Yes (if available) |
| Approved by | Yes (manager or CISO for CRITICAL) |
| Expiry date | Yes (max 90 days) |
| Ticket reference | Yes |

Exceptions older than 90 days with no renewal → auto-escalate to engineering team lead.

---

## Related Runbooks

- [RB-007 — CloudTrail Logging Gap](../misconfigurations/RB-007-cloudtrail-logging-gap.md)
- [RB-009 — SOC 2 Evidence Collection](./RB-009-soc2-evidence-collection.md)

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: MEDIUM*
