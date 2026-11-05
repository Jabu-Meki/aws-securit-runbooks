# RB-002 — S3 Bucket Data Exposure Response

![Severity](https://img.shields.io/badge/Severity-CRITICAL-red?style=flat)
![Category](https://img.shields.io/badge/Category-Incident_Response-blueviolet?style=flat)
![Service](https://img.shields.io/badge/AWS-S3_·_Macie_·_CloudTrail-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** PCI-DSS v4 Req 3 · NIST CSF PR.DS-1, PR.DS-5 · CIS Controls 3.3, 13.6 · GDPR Art 33

---

## Overview

An S3 bucket is publicly accessible due to a misconfigured bucket policy, ACL, or disabled Block Public Access setting. This runbook covers both accidental misconfiguration and deliberate exfiltration scenarios.

**If personal data or PCI cardholder data may be exposed: GDPR 72-hour notification clock starts at the moment you become aware. Engage legal immediately.**

---

## Detection Signals

```
AWS Config rule:  s3-bucket-public-read-prohibited (NON_COMPLIANT)
AWS Config rule:  s3-bucket-public-write-prohibited (NON_COMPLIANT)
Security Hub:     [S3.2] S3 buckets should prohibit public read access
Security Hub:     [S3.3] S3 buckets should prohibit public write access
GuardDuty:        Discovery:S3/MaliciousIPCaller
GuardDuty:        Policy:S3/BucketBlockPublicAccessDisabled
```

---

## Phase 1 — Detection & Assessment

### 1.1 Confirm public access and scope

```bash
BUCKET=<your-bucket-name>

# Check all four Block Public Access settings
aws s3api get-public-access-block --bucket $BUCKET

# Check bucket ACL
aws s3api get-bucket-acl --bucket $BUCKET

# Check bucket policy
aws s3api get-bucket-policy --bucket $BUCKET | python3 -m json.tool

# Check if bucket is actually publicly listable
aws s3 ls s3://$BUCKET --no-sign-request 2>&1 | head -5
```

### 1.2 Classify the data

```bash
# Start a Macie classification job on the bucket
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "incident-$(date +%Y%m%d)-$BUCKET" \
  --s3-job-definition "{
    \"bucketDefinitions\": [{
      \"accountId\": \"$(aws sts get-caller-identity --query Account --output text)\",
      \"buckets\": [\"$BUCKET\"]
    }]
  }"
```

Macie will flag: credit card numbers (PAN), national ID numbers, passport numbers, AWS credentials, and other sensitive data types. Results in 15–30 minutes.

### 1.3 Check server access logs for exfiltration evidence

```bash
# Download access logs (if enabled)
aws s3 sync s3://<LOG-BUCKET>/logs/$BUCKET/ ./incident-logs/

# Identify large GET requests from unknown IPs
awk '{print $1, $8, $12, $13}' ./incident-logs/* \
  | grep "REST.GET" \
  | sort -k3 -rn \
  | head -30
```

Fields: date, operation, bytes-sent, requester-IP. Look for:
- High byte counts (potential bulk exfiltration)
- Requests from unexpected geolocations
- Requests to objects containing sensitive data patterns

---

## Phase 2 — Containment

> ⚠️ Do these steps in order. Step 2.1 is the fastest containment action available.

### 2.1 Enable Block Public Access (immediate)

```bash
aws s3api put-public-access-block \
  --bucket $BUCKET \
  --public-access-block-configuration \
    BlockPublicAcls=true,\
    IgnorePublicAcls=true,\
    BlockPublicPolicy=true,\
    RestrictPublicBuckets=true
```

Takes effect immediately. Verify:

```bash
aws s3api get-public-access-block --bucket $BUCKET
```

### 2.2 Remove public ACL

```bash
aws s3api put-bucket-acl --bucket $BUCKET --acl private
```

### 2.3 Remove or restrict permissive bucket policy

```bash
# Option A: Delete the policy entirely (if no policy is needed)
aws s3api delete-bucket-policy --bucket $BUCKET

# Option B: Replace with least-privilege policy
# Edit least-privilege-policy.json first, then:
aws s3api put-bucket-policy \
  --bucket $BUCKET \
  --policy file://least-privilege-policy.json
```

### 2.4 Preserve evidence before any object deletion

```bash
# Export full object inventory
aws s3api list-objects-v2 \
  --bucket $BUCKET \
  --query 'Contents[].{Key:Key,Size:Size,Modified:LastModified}' \
  --output json > incident-object-inventory-$(date +%Y%m%d).json

# Save current policy state (already pulled in 1.1 — confirm it's saved)
```

---

## Phase 3 — Data Impact Assessment

### 3.1 Review Macie results

```bash
# List all classification jobs
aws macie2 list-classification-jobs \
  --filter-criteria '{"includes":{"simpleCriterion":[{"comparator":"EQ","key":"name","values":["incident-'"$(date +%Y%m%d)"'"]}]}}'

# Get findings from the job
aws macie2 list-findings \
  --finding-criteria '{"criterion":{"classificationDetails.jobId":{"eq":["<JOB_ID>"]}}}' \
  --query 'findingIds'
```

### 3.2 Determine exposure window

```bash
# When was Block Public Access last changed?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPublicAccessBlock \
  --query 'Events[?Resources[?ResourceName==`'$BUCKET'`]].{Time:EventTime,Who:Username}'

# When was the bucket policy changed?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy \
  --query 'Events[?Resources[?ResourceName==`'$BUCKET'`]].{Time:EventTime,Who:Username}'
```

---

## Phase 4 — Eradication & Hardening

```bash
# Enable versioning (enables recovery + audit trail of object changes)
aws s3api put-bucket-versioning \
  --bucket $BUCKET \
  --versioning-configuration Status=Enabled

# Enable server-side encryption if not already on
aws s3api put-bucket-encryption \
  --bucket $BUCKET \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Enable S3 Object Lock on new buckets containing sensitive data
# (must be set at bucket creation — cannot be added retroactively)
```

---

## Phase 5 — Post-Incident & Regulatory

### GDPR checklist (if personal data was exposed)

- [ ] Determine if exposure constitutes a "personal data breach" under Art 4(12)
- [ ] Notify Data Protection Officer (DPO) immediately
- [ ] 72-hour clock: notify supervisory authority (ICO in UK, relevant DPA in EU)
- [ ] Assess risk to data subjects — determine if individuals must be notified (Art 34)
- [ ] Document: nature of breach, categories of data, approximate number of subjects, likely consequences, measures taken

### PCI-DSS checklist (if cardholder data was exposed)

- [ ] Notify Qualified Security Assessor (QSA) if in active assessment
- [ ] Report to card brands per their incident notification requirements
- [ ] Conduct forensic investigation to determine if PAN data was accessed

### Evidence package

Save the following to an immutable S3 location (Object Lock, COMPLIANCE mode):

- [ ] CloudTrail logs covering the exposure window
- [ ] S3 server access logs
- [ ] Macie classification report
- [ ] Object inventory export
- [ ] Timeline of containment actions with timestamps
- [ ] Screenshots of remediated configuration

---

## Prevention

| Control | Implementation |
|---------|---------------|
| Block Public Access at Org level | SCP denying `s3:PutBucketPublicAccessBlock` with `false` values |
| Continuous Macie scanning | Enable Macie at account level, not per-job |
| AWS Config rule | `s3-bucket-public-read-prohibited` in all regions |
| Bucket notifications | S3 Event Notifications → SNS on `PutBucketPolicy` changes |
| Access points | Use S3 Access Points instead of bucket policies for granular access |

---

## Related Runbooks

- [RB-009 — SOC 2 Evidence Collection](../governance/RB-009-soc2-evidence-collection.md)
- [RB-010 — PCI-DSS Scope Violation](../governance/RB-010-pci-scope-violation.md)
- [RB-007 — CloudTrail Logging Gap](../misconfigurations/RB-007-cloudtrail-logging-gap.md)

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: CRITICAL*
