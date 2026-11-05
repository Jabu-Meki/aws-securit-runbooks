# RB-006 — MFA Not Enforced on Root / Privileged Accounts

![Severity](https://img.shields.io/badge/Severity-HIGH-orange?style=flat)
![Category](https://img.shields.io/badge/Category-Misconfiguration-yellow?style=flat)
![Service](https://img.shields.io/badge/AWS-IAM_·_Organizations-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** CIS Controls v8 — 6.3, 6.4, 6.5 · PCI-DSS v4 Req 8.4 · SOC 2 CC6.1 · NIST CSF PR.AC-7 · ISO 27001 A.9.4.2

---

## Overview

The root account or one or more IAM admin users do not have MFA enabled. MFA is a baseline control required by every major compliance framework. Its absence is typically a critical finding in any cloud security assessment.

This runbook covers both remediation and the evidence package required for audit purposes.

---

## Detection Signals

```
AWS Config rule:  root-account-mfa-enabled          (checks root MFA)
AWS Config rule:  mfa-enabled-for-iam-console-access (checks all IAM users)
Security Hub:     [IAM.6] Hardware MFA should be enabled for the root user
Security Hub:     [IAM.19] MFA should be enabled for all IAM users
Trusted Advisor:  MFA on Root Account (red check)
```

---

## Phase 1 — Identify Scope

### 1.1 Generate and review the IAM Credential Report

```bash
# Request report generation (takes up to 4 hours to update, usually seconds)
aws iam generate-credential-report

# Download and decode
aws iam get-credential-report \
  --query 'Content' \
  --output text | base64 -d > credential-report-$(date +%Y%m%d).csv

# Quick check: users without MFA who have console access
awk -F',' '$4=="true" && $8=="false" {print $1, "NO MFA, has console access"}' \
  credential-report-$(date +%Y%m%d).csv
```

Columns of interest:
- `user` — IAM username (`<root_account>` is the first row)
- `password_enabled` — true = can log in to console
- `mfa_active` — false = MFA not enrolled
- `access_key_1_active` — active long-lived key

### 1.2 Check root account MFA specifically

```bash
aws iam get-account-summary \
  --query 'SummaryMap.AccountMFAEnabled'
```

`0` = root MFA is disabled. This must be remediated immediately.

### 1.3 List all IAM users without MFA who have console access

```bash
aws iam list-users --query 'Users[].UserName' --output text | \
  tr '\t' '\n' | while read USER; do
    MFA=$(aws iam list-mfa-devices --user-name "$USER" --query 'MFADevices' --output text)
    LOGIN=$(aws iam get-login-profile --user-name "$USER" 2>/dev/null && echo "has_console")
    if [ -z "$MFA" ] && [ -n "$LOGIN" ]; then
      echo "NO MFA: $USER"
    fi
  done
```

---

## Phase 2 — Remediation

### 2.1 Enable MFA on the root account

Root MFA must be configured manually via the AWS console — it cannot be done via CLI (the CLI itself requires authentication, creating a bootstrapping problem).

Steps:
1. Sign in to the AWS console as root
2. Go to **IAM → My Security Credentials**
3. Under **Multi-factor authentication (MFA)**, click **Assign MFA device**
4. Choose hardware MFA token for root (virtual MFA is acceptable for non-production)
5. Test MFA before logging out

> For production/regulated environments: use a hardware MFA device (YubiKey or AWS-supported hardware token) for root, not a virtual authenticator app.

### 2.2 Enforce MFA for all IAM console users via SCP

This SCP denies all actions unless MFA is present, while allowing users to enrol their own MFA device:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptMFAManagement",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

Apply this SCP to all OUs in AWS Organizations except the management account (apply separately there).

### 2.3 Create a per-user IAM policy that enforces MFA (account-level alternative to SCP)

```bash
cat > require-mfa-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowManageMFAOnly",
      "Effect": "Allow",
      "Action": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices"
      ],
      "Resource": "arn:aws:iam::*:user/${aws:username}"
    },
    {
      "Sid": "DenyWithoutMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
EOF

aws iam put-user-policy \
  --user-name <USER> \
  --policy-name RequireMFA \
  --policy-document file://require-mfa-policy.json
```

### 2.4 Enable AWS Config rule for continuous monitoring

```bash
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "mfa-enabled-for-iam-console-access",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
    }
  }'

aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "root-account-mfa-enabled",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "ROOT_ACCOUNT_MFA_ENABLED"
    }
  }'
```

---

## Phase 3 — Evidence for Audit

### SOC 2 CC6.1 evidence package

Required evidence for "Logical Access Uses Multi-Factor Authentication":

```bash
# 1. Credential report showing mfa_active=true for all console users
aws iam get-credential-report --query Content --output text | base64 -d \
  > soc2-evidence-mfa-report-$(date +%Y%m%d).csv

# 2. Screenshot of AWS Config rule compliance status
aws configservice describe-compliance-by-config-rule \
  --config-rule-names mfa-enabled-for-iam-console-access \
  --query 'ComplianceByConfigRules[0].Compliance'

# 3. SCP document confirming MFA enforcement
aws organizations list-policies --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[?Name==`EnforceMFA`].Id' --output text | \
  xargs aws organizations describe-policy --policy-id \
  --query 'Policy.Content' --output text | python3 -m json.tool
```

### PCI-DSS Req 8.4 evidence

- Credential report showing MFA enabled for all users accessing the CDE
- SCP or IAM policy document demonstrating technical enforcement
- Auditor walkthrough: demonstrate MFA prompt when logging in without session token

---

## Governance Notes

- **CIS Control 6.5:** Require MFA for all administrative access — both for console and CLI (enforce via `aws:MultiFactorAuthPresent` condition on privileged actions)
- Root account should only be used for tasks that specifically require it (billing, account closure, support tier changes). All other work via IAM users or roles.
- Prefer IAM Identity Center (SSO) over individual IAM users — centralised MFA enforcement, shorter session tokens, better audit trail
- Set a CloudWatch alarm for root account console sign-ins:

```bash
# CloudWatch metric filter on CloudTrail logs
aws logs put-metric-filter \
  --log-group-name CloudTrail/DefaultLogGroup \
  --filter-name RootAccountLogin \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations metricName=RootAccountLoginCount,metricNamespace=CloudTrailMetrics,metricValue=1
```

---

## Related Runbooks

- [RB-001 — IAM Privilege Escalation](../incident-response/RB-001-iam-privilege-escalation.md)
- [RB-009 — SOC 2 Evidence Collection](../governance/RB-009-soc2-evidence-collection.md)

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: HIGH*
