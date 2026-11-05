# RB-020 — AWS Organizations SCP Governance

![Category](https://img.shields.io/badge/Category-Governance-blue?style=flat)
![Service](https://img.shields.io/badge/AWS-Organizations_·_IAM_·_CloudTrail-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF GV.PO-1, PR.AC-4 · CIS Controls 4.1 · ISO 27001 A.9.1.1 · SOC 2 CC6.1

---

## Overview

Service Control Policies (SCPs) are the most powerful preventive control in AWS. They apply at the AWS Organizations level and create guardrails that cannot be overridden by any IAM policy — including the root account — in member accounts. Correctly designed SCPs make entire classes of misconfiguration impossible rather than merely detectable.

This runbook covers SCP design, the essential baseline SCP set, governance processes, and how to test SCPs safely before deployment.

---

## SCP Fundamentals

### How SCPs work

SCPs do not grant permissions — they define the maximum permissions any principal in a member account can have. The effective permission is the intersection of the SCP and the IAM policy:

```
Effective Permission = SCP allows AND IAM allows (AND no explicit deny anywhere)
```

Key implications:
- An SCP `Deny` overrides any IAM `Allow` — including `AdministratorAccess`
- Root account in member accounts is also constrained by SCPs
- SCPs apply to all principals in the account: IAM users, roles, federated users
- SCPs do NOT apply to the management (root) account — apply separately
- AWS service-linked roles are also constrained by SCPs

### SCP attachment points

```
Root (applies to all OUs and accounts)
├── Security OU
│   └── Security tooling account (GuardDuty admin, etc.)
├── Workloads OU
│   ├── Production OU
│   │   ├── prod-account-1
│   │   └── prod-account-2
│   └── Non-Production OU
│       ├── staging-account
│       └── dev-account
├── Sandbox OU
│   └── sandbox-account (looser SCPs — learning environment)
└── Suspended OU
    └── suspended-account (deny all)
```

Apply restrictive SCPs at the Root or Workloads OU level. Grant slightly more permission at lower levels only when justified.

---

## Essential SCP Baseline

### SCP-001 — Deny leaving the organisation

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyLeaveOrg",
    "Effect": "Deny",
    "Action": "organizations:LeaveOrganization",
    "Resource": "*"
  }]
}
```

**Why:** Prevents an attacker or rogue admin from removing an account from your organisation, stripping all SCPs instantly.

---

### SCP-002 — Protect security services (GuardDuty, CloudTrail, Security Hub, Config)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDisableGuardDuty",
      "Effect": "Deny",
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:StopMonitoringMembers",
        "guardduty:UpdateDetector"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyDisableCloudTrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyDisableConfig",
      "Effect": "Deny",
      "Action": [
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:StopConfigurationRecorder"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyDisableSecurityHub",
      "Effect": "Deny",
      "Action": [
        "securityhub:DisableSecurityHub",
        "securityhub:DeleteMembers",
        "securityhub:DisassociateMembers"
      ],
      "Resource": "*"
    }
  ]
}
```

**Why:** Your detection and audit stack cannot be switched off by anyone in a member account — including account admins. This is the most important SCP after DenyLeaveOrg.

**Exceptions:** Security tooling account may need to update these services. Use a condition to exempt the security team role:

```json
"Condition": {
  "StringNotLike": {
    "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityAdminRole"
  }
}
```

---

### SCP-003 — Enforce IMDSv2 on EC2

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "RequireIMDSv2",
    "Effect": "Deny",
    "Action": "ec2:RunInstances",
    "Resource": "arn:aws:ec2:*:*:instance/*",
    "Condition": {
      "StringNotEquals": {
        "ec2:MetadataHttpTokens": "required"
      }
    }
  }]
}
```

**Why:** Prevents SSRF credential theft (see [RB-011](../incident-response/RB-011-ec2-metadata-ssrf.md)). Makes an entire attack class impossible rather than detectable.

---

### SCP-004 — Deny public S3 buckets

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicS3",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketAcl",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutAccountPublicAccessBlock"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": [
            "public-read",
            "public-read-write",
            "authenticated-read"
          ]
        }
      }
    },
    {
      "Sid": "DenyDisableBlockPublicAccess",
      "Effect": "Deny",
      "Action": "s3:PutBucketPublicAccessBlock",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "public-read"
        }
      }
    }
  ]
}
```

---

### SCP-005 — Restrict to approved regions only

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyNonApprovedRegions",
    "Effect": "Deny",
    "NotAction": [
      "iam:*",
      "organizations:*",
      "support:*",
      "sts:*",
      "cloudfront:*",
      "route53:*",
      "route53domains:*",
      "waf:*",
      "budgets:*",
      "ce:*",
      "health:*",
      "globalaccelerator:*"
    ],
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:RequestedRegion": [
          "eu-west-1",
          "eu-west-2",
          "us-east-1"
        ]
      }
    }
  }]
}
```

**Why:** Constrains the attack surface to regions you actually monitor and operate in. Attackers routinely deploy in unused regions where logging coverage is thin.

**Note:** `NotAction` approach whitelists global services (IAM, Route53, etc.) that don't have regional endpoints.

---

### SCP-006 — Enforce MFA for sensitive actions

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyHighRiskActionsWithoutMFA",
    "Effect": "Deny",
    "Action": [
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:AttachUserPolicy",
      "iam:DetachUserPolicy",
      "iam:CreateUser",
      "iam:DeleteUser",
      "iam:CreateRole",
      "ec2:TerminateInstances",
      "rds:DeleteDBInstance",
      "s3:DeleteBucket"
    ],
    "Resource": "*",
    "Condition": {
      "BoolIfExists": {
        "aws:MultiFactorAuthPresent": "false"
      }
    }
  }]
}
```

---

### SCP-007 — Deny root account actions

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyRootActions",
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringLike": {
        "aws:PrincipalArn": "arn:aws:iam::*:root"
      }
    }
  }]
}
```

**Important caveat:** This SCP does NOT apply to the management account, and root retains the ability to perform root-only tasks regardless of SCPs. This SCP primarily documents intent and adds a layer of resistance.

---

### SCP-008 — Deny unapproved instance types (FinOps / security)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyLargeInstancesWithoutTag",
    "Effect": "Deny",
    "Action": "ec2:RunInstances",
    "Resource": "arn:aws:ec2:*:*:instance/*",
    "Condition": {
      "StringLike": {
        "ec2:InstanceType": [
          "p4d.*",
          "p3.*",
          "p2.*",
          "hpc6a.*",
          "hpc6id.*"
        ]
      }
    }
  }]
}
```

**Why:** GPU and HPC instance types are the primary compute used for cryptomining. Blocking them unless explicitly needed eliminates the cost of a mining attack.

---

## SCP Testing Process

**Never deploy an SCP to production without testing.** A badly written SCP can lock everyone out of an account.

### Safe testing workflow

```bash
# Step 1: Apply to a single TEST account in Sandbox OU first
aws organizations attach-policy \
  --policy-id $POLICY_ID \
  --target-id <SANDBOX_ACCOUNT_ID>

# Step 2: Test the blocked action from the sandbox account
# (should be denied)
aws s3api put-bucket-acl --bucket test-bucket --acl public-read 2>&1
# Expected: AccessDenied

# Step 3: Test a permitted action
# (should succeed)
aws s3 ls 2>&1
# Expected: lists buckets normally

# Step 4: Only after sandbox validation, apply to production OU
aws organizations attach-policy \
  --policy-id $POLICY_ID \
  --target-id <PROD_OU_ID>
```

### IAM policy simulator for SCPs

```bash
# Simulate the effect of your SCP without deploying it
aws iam simulate-custom-policy \
  --policy-input-list file://scp-to-test.json \
  --action-names "s3:PutBucketAcl" "ec2:RunInstances" "cloudtrail:StopLogging" \
  --resource-arns "*" \
  --query 'EvaluationResults[].{Action:EvalActionName,Decision:EvalDecision}'
```

---

## SCP Governance Process

### Change management

1. SCP change request raised as a ticket with: business justification, affected OUs/accounts, testing plan, rollback procedure
2. Security Lead reviews — no SCPs deployed without security team sign-off
3. Tested in Sandbox OU for minimum 48 hours
4. Change approval from CISO or delegated authority for production deployment
5. Post-deployment monitoring: watch CloudTrail for unexpected `AccessDenied` errors for 24 hours

### Quarterly SCP review

```bash
# List all SCPs and their attachments
aws organizations list-policies \
  --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[].{Name:Name,Id:Id,Description:Description}'

# List accounts each SCP is attached to
aws organizations list-targets-for-policy \
  --policy-id $POLICY_ID \
  --query 'Targets[].{Type:Type,Name:Name,Id:TargetId}'
```

Review questions:
- Are there SCPs no longer attached to anything? (zombie policies — clean up)
- Have any SCPs been modified without a change record?
- Are there accounts that should have a restrictive SCP but don't?
- Are exception conditions still valid?

---

## Evidence for Auditors

SCPs are powerful evidence that controls are technically enforced, not just policy-based.

```bash
# Export all SCP content for audit evidence
aws organizations list-policies \
  --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[].Id' --output text | tr '\t' '\n' | while read PID; do
    aws organizations describe-policy \
      --policy-id $PID \
      --query '{Name:Policy.PolicySummary.Name,Content:Policy.Content}' \
      > "evidence/governance/scp-$(date +%Y%m%d)-$PID.json"
  done
```

Frame for SOC 2 CC6.1: "Access controls are technically enforced via AWS Organizations SCPs that prevent any principal in member accounts from disabling monitoring, creating public S3 buckets, or launching EC2 instances without IMDSv2."

This is stronger evidence than a policy document alone.

---

## Related Runbooks

- [RB-001 — IAM Privilege Escalation](../incident-response/RB-001-iam-privilege-escalation.md) — SCPs as preventive control
- [RB-006 — MFA Not Enforced](../misconfigurations/RB-006-mfa-not-enforced.md) — SCP-006 implementation
- [RB-009 — SOC 2 Evidence Collection](./RB-009-soc2-evidence-collection.md) — SCP as CC6.1 evidence

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Framework: NIST GV.PO-1 · ISO 27001 A.9.1.1*
