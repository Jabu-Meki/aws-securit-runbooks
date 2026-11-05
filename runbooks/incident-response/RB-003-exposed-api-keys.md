# RB-003 — Exposed API Keys Response

![Severity](https://img.shields.io/badge/Severity-HIGH-orange?style=flat)
![Category](https://img.shields.io/badge/Category-Incident_Response-blueviolet?style=flat)
![Service](https://img.shields.io/badge/AWS-IAM_·_Secrets_Manager_·_CloudTrail-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF PR.DS-2 · CIS Controls 14.8 · ISO 27001 A.9.4.3

---

## Overview

AWS access keys or secrets committed to a public repository, hardcoded in source code, printed in application logs, or found by a secret scanning tool. Treat as fully compromised from the moment of exposure — assume the key has been harvested even if no malicious usage is visible yet.

Common sources: GitHub public repos, Docker image layers, CI/CD logs, Slack messages, S3 bucket objects, Lambda environment variables.

---

## Detection Signals

```
GitHub Advanced Security:  Secret scanning alert — AWS Access Key
GitGuardian / TruffleHog: AWS credentials detected in commit
AWS Health:                Potentially exposed AWS Access Key
GuardDuty:                 UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
Internal alert:            New AWS API calls from unexpected region/IP
```

---

## Phase 1 — Identify & Scope

### 1.1 Confirm the key is live

```bash
# Test if the key is still active (use from isolated environment)
AWS_ACCESS_KEY_ID=<EXPOSED_KEY> \
AWS_SECRET_ACCESS_KEY=<EXPOSED_SECRET> \
aws sts get-caller-identity
```

If this returns an identity: the key is active. Proceed immediately.

### 1.2 Determine what the key can do

```bash
# Check attached policies
aws iam list-attached-user-policies --user-name <USER>
aws iam list-user-policies --user-name <USER>
aws iam list-groups-for-user --user-name <USER>

# Simulate what the key can access (quick scope check)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<ACCOUNT>:user/<USER> \
  --action-names "s3:GetObject" "ec2:DescribeInstances" "rds:DescribeDBInstances" \
  --query 'EvaluationResults[].{Action:EvalActionName,Decision:EvalDecision}'
```

### 1.3 Establish the exposure window

```bash
# When was the key created?
aws iam list-access-keys --user-name <USER>

# When was it first committed (GitHub)?
# gh api /repos/<ORG>/<REPO>/commits --jq '.[].commit | select(.message | contains("<KEY_FRAGMENT>"))'

# Pull all CloudTrail usage for the key
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<KEY_ID> \
  --query 'Events[].{Time:EventTime,Event:EventName,IP:CloudTrailEvent}' \
  --output table
```

Look for: unusual regions, data access (`GetObject`, `DescribeInstances`), new resource creation, IAM changes.

---

## Phase 2 — Containment (Rotate First, Then Revoke)

> ⚠️ **Create the replacement key before disabling the old one** to avoid service disruption.

### 2.1 Create a replacement key

```bash
aws iam create-access-key --user-name <USER>
# Save the new AccessKeyId and SecretAccessKey securely
```

### 2.2 Update all consumers of the old key

Check these locations in order:

```bash
# 1. AWS Secrets Manager
aws secretsmanager put-secret-value \
  --secret-id <SECRET_NAME> \
  --secret-string '{"access_key":"<NEW_KEY>","secret_key":"<NEW_SECRET>"}'

# 2. SSM Parameter Store
aws ssm put-parameter \
  --name /prod/app/aws-access-key \
  --value <NEW_KEY> \
  --type SecureString \
  --overwrite

# 3. Lambda environment variables
aws lambda update-function-configuration \
  --function-name <FUNCTION_NAME> \
  --environment Variables='{AWS_ACCESS_KEY_ID=<NEW_KEY>,AWS_SECRET_ACCESS_KEY=<NEW_SECRET>}'

# 4. ECS task definitions — update and redeploy
# 5. CodeBuild / CodePipeline — update environment variables
# 6. GitHub Actions secrets — update via GitHub UI or CLI
# 7. Any third-party SaaS integrations
```

### 2.3 Disable the exposed key

```bash
aws iam update-access-key \
  --access-key-id <EXPOSED_KEY_ID> \
  --status Inactive \
  --user-name <USER>
```

Verify services are working with the new key, then:

### 2.4 Delete the exposed key

```bash
aws iam delete-access-key \
  --access-key-id <EXPOSED_KEY_ID> \
  --user-name <USER>
```

---

## Phase 3 — Remove from Source

### 3.1 Remove from git history

> ⚠️ Removing from current code is not enough — the key exists in git history and is still accessible via `git log`.

```bash
# Install BFG Repo Cleaner (faster than git filter-branch)
# https://rtyley.github.io/bfg-repo-cleaner/

# Create a file listing the secret to scrub
echo '<EXPOSED_KEY_ID>' > secrets-to-remove.txt
echo '<EXPOSED_SECRET>' >> secrets-to-remove.txt

# Run BFG
java -jar bfg.jar --replace-text secrets-to-remove.txt <REPO>

# Clean up refs and force push
cd <REPO>
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push --force --all
git push --force --tags
```

> Even after BFG, treat the exposed key as permanently compromised. Rotation is mandatory regardless of source removal success.

### 3.2 Revoke any GitHub/GitLab OAuth tokens if the repo itself was compromised

---

## Phase 4 — Eradication & Hardening

### Migrate away from long-lived keys

Long-lived IAM access keys are the root cause. The secure alternative is role-based authentication:

| Compute Type | Secure Alternative |
|-------------|-------------------|
| EC2 instances | IAM Instance Profile (no keys needed) |
| Lambda functions | Lambda Execution Role |
| ECS tasks | Task Role (IRSA equivalent) |
| GitHub Actions | OIDC federation → assume role |
| On-premises | IAM Roles Anywhere with PKI certificates |
| Third-party SaaS | Per-service IAM roles with minimal permissions |

### Implement pre-commit secret scanning

```bash
# Install detect-secrets
pip install detect-secrets

# Initialise baseline (excludes known non-secrets)
detect-secrets scan > .secrets.baseline

# Add pre-commit hook
cat >> .pre-commit-config.yaml << 'EOF'
- repo: https://github.com/Yelp/detect-secrets
  rev: v1.4.0
  hooks:
  - id: detect-secrets
    args: ['--baseline', '.secrets.baseline']
EOF

pre-commit install
```

---

## Phase 5 — Post-Incident

### Governance notes

- **CIS 14.8:** Implement automated detection of secrets in code repositories
- **ISO 27001 A.9.4.3:** Password management system — extend to API keys
- All access keys must have a maximum 90-day rotation policy enforced via AWS Config rule `access-keys-rotated`
- Add the compromised key ID to your IOC feed and SIEM watchlist

### Questions to answer in the PIR

1. How long was the key exposed before detection?
2. Was any malicious activity observed during the exposure window?
3. What data or infrastructure could the key have accessed?
4. Why was a long-lived key used instead of a role-based approach?
5. What prevented the pre-commit hook from catching this?

---

## Related Runbooks

- [RB-001 — IAM Privilege Escalation](./RB-001-iam-privilege-escalation.md) — if the key had admin permissions
- [RB-006 — MFA Not Enforced](../misconfigurations/RB-006-mfa-not-enforced.md)

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: HIGH*
