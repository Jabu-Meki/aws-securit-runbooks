# RB-017 — Cross-Account Role Trust Policy Misconfiguration

![Severity](https://img.shields.io/badge/Severity-CRITICAL-red?style=flat)
![Category](https://img.shields.io/badge/Category-Misconfiguration-yellow?style=flat)
![Service](https://img.shields.io/badge/AWS-IAM_·_Organizations_·_CloudTrail_·_Access_Analyzer-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF PR.AC-4 · CIS Controls 6.8 · ISO 27001 A.9.1.2

---

## Overview

IAM role trust policies define who can assume a role. Misconfigurations — trusting the wrong account, using wildcards, or omitting the `ExternalId` condition for third-party access — can allow any principal in a trusted account (or any account entirely) to assume the role. This is a "confused deputy" class of vulnerability.

**A trust policy that trusts an entire AWS account (`arn:aws:iam::ACCOUNT:root`) grants assume-role access to every IAM principal in that account — not just the root user.**

---

## Detection Signals

```
IAM Access Analyzer: Cross-account access finding — role accessible from external account
CloudTrail:          AssumeRole calls from unexpected accounts or principals
Security Hub:        [IAM.21] IAM customer managed policies should not allow wildcard actions
IAM Access Analyzer: PUBLIC access finding on IAM role (trusts *)
```

---

## Common Vulnerable Patterns

### Pattern 1 — Trusting an entire external account (no ExternalId)

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::VENDOR_ACCOUNT_ID:root"
  },
  "Action": "sts:AssumeRole"
}
```

Risk: any IAM user or role in the vendor account can assume this role — including if the vendor is compromised.

**Fix:** Add `ExternalId` condition:

```json
{
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "unique-secret-string-agreed-with-vendor"
    }
  }
}
```

### Pattern 2 — Wildcard principal (trusts any AWS account)

```json
{
  "Principal": {"AWS": "*"},
  "Action": "sts:AssumeRole"
}
```

Risk: literally anyone on AWS can assume this role. Equivalent to making it public.

### Pattern 3 — Overly broad service principal

```json
{
  "Principal": {"Service": "ec2.amazonaws.com"}
}
```

This is usually fine, but watch for: `lambda.amazonaws.com` on a role with admin permissions — any Lambda function in the account can assume it.

### Pattern 4 — Trusting wrong account ID (typo)

A single digit typo in an account ID could trust a completely unrelated account. Always verify account IDs against your AWS Organizations account list.

---

## Phase 1 — Discovery

### 1.1 Find all roles with cross-account trust

```bash
# List all roles and their trust policies
aws iam list-roles \
  --query 'Roles[].{
    Role:RoleName,
    Trust:AssumeRolePolicyDocument
  }' \
  --output json | python3 -c "
import sys, json
roles = json.load(sys.stdin)
MY_ACCOUNT = '<YOUR_ACCOUNT_ID>'
for role in roles:
    trust = role['Trust']
    for stmt in trust.get('Statement', []):
        principal = stmt.get('Principal', {})
        aws_principals = principal if isinstance(principal, str) else principal.get('AWS', [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        for p in aws_principals:
            if p == '*':
                print(f'PUBLIC TRUST: {role[\"Role\"]} -> *')
            elif MY_ACCOUNT not in p and 'amazonaws.com' not in p:
                ext_id = stmt.get('Condition', {}).get('StringEquals', {}).get('sts:ExternalId')
                print(f'CROSS-ACCOUNT: {role[\"Role\"]} -> {p} | ExternalId: {ext_id or \"MISSING\"}')
"
```

### 1.2 Use IAM Access Analyzer

```bash
# Create an analyser for the account/organisation
aws accessanalyzer create-analyzer \
  --analyzer-name AccountAccessAnalyzer \
  --type ACCOUNT

# List cross-account findings
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:<REGION>:<ACCOUNT>:analyzer/AccountAccessAnalyzer \
  --filter '{"resourceType":{"eq":["AWS::IAM::Role"]},"isPublic":{"eq":["true"]}}' \
  --query 'findings[].{
    Resource:resource,
    Principal:principal,
    IsPublic:isPublic,
    Status:status
  }' \
  --output table
```

### 1.3 Check CloudTrail for unexpected AssumeRole calls

```bash
# Find AssumeRole calls from external account IDs
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].CloudTrailEvent' \
  --output text | python3 -c "
import sys, json
MY_ACCOUNT = '<YOUR_ACCOUNT_ID>'
for line in sys.stdin:
    try:
        event = json.loads(line)
        source_account = event.get('userIdentity', {}).get('accountId', '')
        role_arn = event.get('requestParameters', {}).get('roleArn', '')
        if source_account and source_account != MY_ACCOUNT:
            print(f\"External assume-role: {source_account} -> {role_arn} from {event.get('sourceIPAddress')}\")
    except:
        pass
"
```

---

## Phase 2 — Remediation

### 2.1 Add ExternalId for third-party vendor roles

```bash
ROLE_NAME=<vendor-role>

# Get current trust policy
aws iam get-role \
  --role-name $ROLE_NAME \
  --query 'Role.AssumeRolePolicyDocument' \
  --output json > current-trust.json

# Edit current-trust.json to add ExternalId condition, then:
aws iam update-assume-role-policy \
  --role-name $ROLE_NAME \
  --policy-document file://updated-trust.json
```

Updated trust policy with ExternalId:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::<VENDOR_ACCOUNT>:root"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "<GENERATE_A_UUID_HERE>"
      }
    }
  }]
}
```

Share the ExternalId with the vendor via a secure channel. Rotate it if the vendor relationship ends.

### 2.2 Restrict overly broad trust to specific principals

```bash
# Instead of trusting the entire account:
# "AWS": "arn:aws:iam::VENDOR_ACCOUNT:root"

# Restrict to specific roles/users:
# "AWS": "arn:aws:iam::VENDOR_ACCOUNT:role/VendorSpecificRole"
```

### 2.3 Remove wildcard trust immediately

```bash
# Any role trusting * must be immediately patched or deleted
# First confirm the role is not in use:
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --query 'Events[?Resources[?ResourceName==`<ROLE_ARN>`]].{Time:EventTime,Who:Username}'

# If not in legitimate use — delete the role
aws iam delete-role --role-name <ROLE_WITH_WILDCARD_TRUST>
```

---

## Phase 3 — Preventive Controls

### 3.1 SCP to prevent wildcard trust policies

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyWildcardTrustPolicies",
    "Effect": "Deny",
    "Action": [
      "iam:CreateRole",
      "iam:UpdateAssumeRolePolicy"
    ],
    "Resource": "*",
    "Condition": {
      "StringLike": {
        "iam:PolicyDocument": "*\"Principal\":{\"AWS\":\"*\"*"
      }
    }
  }]
}
```

### 3.2 Enable IAM Access Analyzer continuously

```bash
# Organisation-level analyser (sees all accounts)
aws accessanalyzer create-analyzer \
  --analyzer-name OrgAccessAnalyzer \
  --type ORGANIZATION \
  --region us-east-1  # Must be in us-east-1 for org analyser
```

Configure EventBridge rule to alert on new Access Analyzer findings:

```bash
aws events put-rule \
  --name AccessAnalyzerNewFinding \
  --event-pattern '{
    "source": ["aws.access-analyzer"],
    "detail-type": ["Access Analyzer Finding"]
  }' \
  --state ENABLED

aws events put-targets \
  --rule AccessAnalyzerNewFinding \
  --targets '[{"Id":"SecurityTeamAlert","Arn":"<SNS_TOPIC_ARN>"}]'
```

---

## Governance Notes

- Every cross-account trust relationship must be documented in your asset inventory with: trusting account, trusted account, trusted principal, ExternalId (if applicable), business justification, review date
- Third-party vendor access must require ExternalId — no exceptions. Without ExternalId, the vendor's account security becomes your security
- **ISO 27001 A.9.1.2:** Access to networks and network services — cross-account access is a network boundary crossing and requires the same justification and approval as firewall exceptions
- Review all cross-account trust relationships quarterly via IAM Access Analyzer

---

## Related Runbooks

- [RB-001 — IAM Privilege Escalation](../incident-response/RB-001-iam-privilege-escalation.md)
- [RB-008 — CSPM Alert Triage](../governance/RB-008-cspm-alert-triage.md)

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: CRITICAL*
