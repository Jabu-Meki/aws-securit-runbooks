# RB-001 — IAM Privilege Escalation Response

![Severity](https://img.shields.io/badge/Severity-CRITICAL-red?style=flat)
![Category](https://img.shields.io/badge/Category-Incident_Response-blueviolet?style=flat)
![Service](https://img.shields.io/badge/AWS-IAM_·_CloudTrail_·_GuardDuty-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF PR.AC-4, PR.AC-6 · CIS Controls 5.4, 6.2 · SOC 2 CC6.1 · ISO 27001 A.9.2

---

## Overview

Triggered when an IAM principal (user or role) gains permissions beyond their authorised scope. Common paths include misconfigured trust policies, `sts:AssumeRole` chain abuse, inline policy injection, or compromised long-lived access keys.

**Impact if uncontained:** full account takeover, lateral movement across accounts, data exfiltration, persistent backdoor access.

---

## Prerequisites

- AWS CLI configured with a break-glass read-only role
- CloudTrail enabled in all regions (see [RB-007](../misconfigurations/RB-007-cloudtrail-logging-gap.md))
- GuardDuty enabled in the affected account
- Incident ticket created before any remediation steps

---

## Detection Signals

GuardDuty finding types that trigger this runbook:

```
PrivilegeEscalation:IAMUser/AdministrativePermissions
PrivilegeEscalation:IAMUser/RolesCreatedWithAdminAccessPermissions
UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
Policy:IAMUser/RootCredentialUsage
```

Manual detection via AWS Config rule:
```
iam-no-inline-policy-check
iam-policy-no-statements-with-admin-access
```

---

## Phase 1 — Detection & Triage

> **Goal:** Confirm true positive and establish blast radius before touching anything.

### 1.1 Pull the GuardDuty finding

```bash
aws guardduty get-findings \
  --detector-id $DETECTOR_ID \
  --finding-ids $FINDING_ID \
  --query 'Findings[0].{Title:Title,Severity:Severity,Principal:Service.Action.AwsApiCallAction.RemoteIpDetails}'
```

### 1.2 Get all CloudTrail events for the principal (last 24h)

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<PRINCIPAL> \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].{Time:EventTime,Event:EventName,Source:EventSource}' \
  --output table
```

Key events to look for:

| Event | Significance |
|-------|-------------|
| `CreatePolicy` | New managed policy created |
| `AttachRolePolicy` | Managed policy attached to role |
| `PutUserPolicy` | Inline policy added to user |
| `AssumeRole` | Role assumption — check target role |
| `CreateLoginProfile` | Console access enabled on an API-only user |
| `UpdateAssumeRolePolicy` | Trust policy modified |
| `AddUserToGroup` | User added to a group (check group perms) |

### 1.3 Document current policy state before remediation

```bash
# Attached managed policies
aws iam list-attached-user-policies --user-name <USER>

# Inline policies
aws iam list-user-policies --user-name <USER>

# Group memberships
aws iam list-groups-for-user --user-name <USER>
```

> ⚠️ **Do not proceed to containment until you have documented the current state.** Screenshots or JSON exports saved to your incident ticket.

---

## Phase 2 — Containment

> **Goal:** Stop the attack without destroying forensic evidence.

### 2.1 Disable the access key (do not delete yet)

```bash
aws iam update-access-key \
  --access-key-id <KEY_ID> \
  --status Inactive \
  --user-name <USER>
```

### 2.2 Attach an emergency deny-all policy

This is faster than revoking individual policies and overrides all existing allows:

```bash
# Create the deny-all policy (one-time setup — save this as a permanent break-glass resource)
aws iam create-policy \
  --policy-name EMERGENCY-DenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

# Attach to the affected user
aws iam attach-user-policy \
  --user-name <USER> \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/EMERGENCY-DenyAll
```

### 2.3 Revoke all active console sessions

```bash
# Force re-authentication on all active sessions
aws iam create-policy \
  --policy-name RevokeOldSessions-<USER>-$(date +%s) \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        }
      }
    }]
  }'
```

### 2.4 Check for backdoor IAM entities created during the attack

```bash
# Users created after the incident start time
aws iam list-users \
  --query "Users[?CreateDate>='<INCIDENT_START_ISO>'].{User:UserName,Created:CreateDate}"

# Roles with suspicious trust policies (look for unknown account IDs)
aws iam list-roles \
  --query 'Roles[].{Role:RoleName,Trust:AssumeRolePolicyDocument}' \
  | python3 -c "import sys,json; roles=json.load(sys.stdin); [print(r['Role'], r['Trust']) for r in roles]"
```

---

## Phase 3 — Eradication

> **Goal:** Remove all attacker-created resources and restore least-privilege.

### 3.1 Remove unauthorised policy attachments

```bash
aws iam detach-user-policy \
  --user-name <USER> \
  --policy-arn <UNAUTHORISED_POLICY_ARN>
```

### 3.2 Delete backdoor users

```bash
# Must delete keys and login profile before deleting user
aws iam delete-access-key --user-name <BACKDOOR_USER> --access-key-id <KEY_ID>
aws iam delete-login-profile --user-name <BACKDOOR_USER>
aws iam delete-user --user-name <BACKDOOR_USER>
```

### 3.3 Delete backdoor roles

```bash
# Detach all policies first
aws iam detach-role-policy --role-name <BACKDOOR_ROLE> --policy-arn <ARN>
aws iam delete-role --role-name <BACKDOOR_ROLE>
```

### 3.4 Rotate legitimate credentials

```bash
# Create new access key
aws iam create-access-key --user-name <USER>

# Deliver via secure channel (not email). Then:
aws iam delete-access-key --user-name <USER> --access-key-id <OLD_KEY_ID>
```

---

## Phase 4 — Recovery

- Remove the emergency deny-all policy
- Re-attach only the minimum required policies (re-validate with access advisor)
- Enable MFA if not already present
- Create a CloudWatch alarm for future anomalous `AssumeRole` activity:

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "UnusualAssumeRoleActivity" \
  --metric-name "ErrorCount" \
  --namespace "CloudTrailMetrics" \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions <SNS_TOPIC_ARN>
```

---

## Phase 5 — Post-Incident

### Required documentation

- [ ] Timeline of events (T+0 to containment)
- [ ] Root cause (how did the escalation occur?)
- [ ] Blast radius (what did the attacker access?)
- [ ] Indicators of Compromise (IOCs) — IPs, user agents, patterns
- [ ] Evidence package saved to immutable S3 (CloudTrail exports, screenshots)
- [ ] Control gaps identified
- [ ] Remediation tasks added to backlog with owners and due dates

### Governance notes

- **NIST CSF PR.AC-4:** Verify least-privilege policies are in place post-incident
- **SOC 2 CC6.3:** Document the access review that should have caught this
- **CIS 5.4:** Confirm IAM Access Analyzer is enabled and alerting correctly
- CISO notification required for all P1 incidents within 1 hour of declaration
- If attacker accessed another AWS account via role assumption: notify that account's owner

---

## Related Runbooks

- [RB-003 — Exposed API Keys](./RB-003-exposed-api-keys.md) — often the initial access vector
- [RB-007 — CloudTrail Logging Gap](../misconfigurations/RB-007-cloudtrail-logging-gap.md) — confirms audit trail integrity
- [RB-006 — MFA Not Enforced](../misconfigurations/RB-006-mfa-not-enforced.md) — common contributing factor

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: CRITICAL*
