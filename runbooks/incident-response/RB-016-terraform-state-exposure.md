# RB-016 — Terraform State File Exposure

![Severity](https://img.shields.io/badge/Severity-CRITICAL-red?style=flat)
![Category](https://img.shields.io/badge/Category-Incident_Response-blueviolet?style=flat)
![Service](https://img.shields.io/badge/AWS-S3_·_IAM_·_KMS_·_CloudTrail-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF PR.DS-5 · CIS Controls 3.3 · ISO 27001 A.9.4.3

---

## Overview

Terraform state files (`terraform.tfstate`) contain a full inventory of your infrastructure — including plaintext values of sensitive outputs, database passwords, IAM access keys, TLS private keys, and any `sensitive = true` variable that was ever output. A publicly accessible or improperly secured state file is equivalent to handing an attacker a complete map of your environment plus the keys to much of it.

**State files are frequently committed to Git repositories by mistake. Treat any exposure as a credential compromise event.**

---

## What's in a State File (Examples)

```json
{
  "resources": [{
    "type": "aws_db_instance",
    "instances": [{
      "attributes": {
        "password": "SuperSecretDBPassword123!",   ← PLAINTEXT
        "endpoint": "prod-db.xxxx.rds.amazonaws.com",
        "username": "admin"
      }
    }]
  }, {
    "type": "aws_iam_access_key",
    "instances": [{
      "attributes": {
        "id": "AKIAIOSFODNN7EXAMPLE",              ← ACCESS KEY ID
        "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  ← SECRET KEY
      }
    }]
  }]
}
```

---

## Detection Signals

```
CloudTrail:  GetObject on S3 state bucket from unexpected IP or principal
S3 Access Logs: requests to .tfstate files from external IPs
GitHub:      Secret scanning alert — state file committed to repo
AWS Config:  s3-bucket-public-read-prohibited NON_COMPLIANT on state bucket
Git history: terraform.tfstate present in any commit (even if deleted)
```

---

## Phase 1 — Confirm Exposure and Scope

### 1.1 Check if state bucket is publicly accessible

```bash
STATE_BUCKET=<your-terraform-state-bucket>

aws s3api get-public-access-block --bucket $STATE_BUCKET
aws s3api get-bucket-policy --bucket $STATE_BUCKET | python3 -m json.tool
aws s3api get-bucket-acl --bucket $STATE_BUCKET
```

### 1.2 Check S3 access logs for unauthorised access

```bash
# Download state bucket access logs
aws s3 sync s3://<LOG-BUCKET>/logs/$STATE_BUCKET/ ./state-access-logs/

# Find GetObject requests for .tfstate files from non-expected IPs
grep "REST.GET.OBJECT.*\.tfstate" ./state-access-logs/*.log | \
  awk '{print $1, $4, $8, $12}' | \
  grep -v "<YOUR_CIDR_PREFIX>"
```

### 1.3 Extract all sensitive values from the state file

```bash
# Download the state file
aws s3 cp s3://$STATE_BUCKET/terraform.tfstate ./tfstate-incident-$(date +%Y%m%d).json

# Extract passwords
cat tfstate-incident-*.json | python3 -c "
import sys, json

def extract_sensitive(obj, path=''):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if any(kw in k.lower() for kw in ['password','secret','key','token','private','credential']):
                print(f'SENSITIVE [{path}.{k}]: {str(v)[:80]}')
            extract_sensitive(v, f'{path}.{k}')
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            extract_sensitive(v, f'{path}[{i}]')

data = json.load(sys.stdin)
extract_sensitive(data)
"
```

Every value returned must be treated as compromised and rotated.

### 1.4 If exposed via Git — determine reach

```bash
# Check if tfstate was ever committed
git log --all --full-history -- "**/*.tfstate" "**/*.tfstate.backup"

# Find the commit that added it
git log --diff-filter=A -- "*.tfstate"

# Check if repo is/was public
gh repo view --json isPrivate,createdAt,pushedAt
```

Even private repos should be treated as compromised if any team member's GitHub account was compromised, or if the repo was ever public even briefly.

---

## Phase 2 — Containment

### 2.1 Block access to the state bucket immediately

```bash
# Enable Block Public Access
aws s3api put-public-access-block \
  --bucket $STATE_BUCKET \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,\
    BlockPublicPolicy=true,RestrictPublicBuckets=true

# Remove any public bucket policy
aws s3api delete-bucket-policy --bucket $STATE_BUCKET
```

### 2.2 Rotate every credential found in the state file

Work through this systematically — do not skip any:

```bash
# For each IAM access key found:
aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name <USER>
aws iam create-access-key --user-name <USER>  # Create replacement first
aws iam delete-access-key --access-key-id <KEY_ID> --user-name <USER>

# For each RDS password found:
aws rds modify-db-instance \
  --db-instance-identifier <DB_INSTANCE> \
  --master-user-password <NEW_RANDOM_PASSWORD> \
  --apply-immediately

# For each Secrets Manager secret referenced:
aws secretsmanager rotate-secret --secret-id <SECRET_ARN>

# For any TLS private keys found:
# Revoke the certificate via your CA
# Issue a new certificate
# Update all services using the old cert
```

---

## Phase 3 — Eradication

### 3.1 Remove state file from Git history

```bash
# Install BFG Repo Cleaner
java -jar bfg.jar --delete-files "*.tfstate" <REPO_DIR>

git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push origin --force --all
git push origin --force --tags
```

### 3.2 Secure the state backend properly

**Properly secured S3 backend configuration:**

```hcl
# backend.tf
terraform {
  backend "s3" {
    bucket         = "my-terraform-state-<account-id>"
    key            = "production/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true                    # SSE-KMS encryption
    kms_key_id     = "arn:aws:kms:..."      # CMK for state encryption
    dynamodb_table = "terraform-state-lock"  # Prevents concurrent modifications
    
    # Access controlled via IAM — no bucket policy public access
  }
}
```

### 3.3 Add .tfstate to .gitignore

```bash
cat >> .gitignore << 'EOF'
# Terraform state — NEVER commit
*.tfstate
*.tfstate.*
.terraform/
.terraform.lock.hcl
terraform.tfvars      # May contain sensitive variable values
*.auto.tfvars
EOF

git add .gitignore
git commit -m "security: exclude terraform state and sensitive files from git"
```

### 3.4 Implement state bucket hardening

```bash
# Enable versioning (allows recovery from accidental state corruption)
aws s3api put-bucket-versioning \
  --bucket $STATE_BUCKET \
  --versioning-configuration Status=Enabled

# Enable encryption with CMK
aws s3api put-bucket-encryption \
  --bucket $STATE_BUCKET \
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms","KMSMasterKeyID": "<CMK_ARN>"},"BucketKeyEnabled": true}]
  }'

# Enable Object Lock on future state buckets
# (existing buckets cannot have Object Lock added retroactively)

# Restrict access — only Terraform execution role
aws s3api put-bucket-policy \
  --bucket $STATE_BUCKET \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": ["arn:aws:s3:::'"$STATE_BUCKET"'","arn:aws:s3:::'"$STATE_BUCKET"'/*"],
        "Condition": {
          "StringNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::<ACCOUNT>:role/TerraformExecutionRole",
              "arn:aws:iam::<ACCOUNT>:role/TerraformReadRole"
            ]
          }
        }
      }
    ]
  }'
```

---

## Prevention: Sensitive Values in State

Terraform state will always contain resource attributes. Minimise sensitive data:

| Instead of... | Do this... |
|---------------|-----------|
| Output RDS password | Store password in Secrets Manager; output only the secret ARN |
| Output IAM access key | Use IRSA/instance profiles instead of IAM users |
| Output TLS private key | Use ACM — private key never leaves AWS |
| Reference sensitive tfvars | Use Secrets Manager data source at plan time |

```hcl
# Retrieve secret at plan time — value still in state but at least not in tfvars/outputs
data "aws_secretsmanager_secret_version" "db_pass" {
  secret_id = "prod/db/password"
}

resource "aws_db_instance" "main" {
  password = data.aws_secretsmanager_secret_version.db_pass.secret_string
}
```

---

## Governance Notes

- Terraform state is a sensitive asset — classify it at the same level as the most sensitive data it references
- **ISO 27001 A.9.4.3:** Password management systems must protect secrets — Terraform state containing plaintext passwords is a direct A.9.4.3 finding
- All state buckets must be included in your data asset inventory and access review scope
- CI/CD pipelines that run Terraform must use short-lived OIDC roles — not static IAM access keys

---

## Related Runbooks

- [RB-003 — Exposed API Keys](./RB-003-exposed-api-keys.md) — IAM keys found in state
- [RB-002 — S3 Data Exposure](./RB-002-s3-data-exposure.md) — state bucket public access

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: CRITICAL*
