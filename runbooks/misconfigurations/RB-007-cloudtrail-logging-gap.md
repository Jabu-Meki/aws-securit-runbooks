# RB-007 — CloudTrail / Audit Logging Gap

![Severity](https://img.shields.io/badge/Severity-MEDIUM-yellow?style=flat)
![Category](https://img.shields.io/badge/Category-Misconfiguration-yellow?style=flat)
![Service](https://img.shields.io/badge/AWS-CloudTrail_·_S3_·_CloudWatch-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** CIS Controls v8 — 8.2, 8.5, 8.7 · NIST CSF DE.CM-3, DE.AE-3 · SOC 2 CC7.2 · PCI-DSS v4 Req 10

---

## Overview

CloudTrail is disabled in one or more regions, the log delivery S3 bucket has been modified, log file integrity validation is off, or there is a gap in log delivery. Without continuous CloudTrail logging, forensic investigation of any incident becomes severely limited or impossible.

**Treat any logging gap as HIGH severity if it overlaps with another security incident.**

---

## Detection Signals

```
AWS Config rule:  cloud-trail-enabled
AWS Config rule:  cloud-trail-log-file-validation-enabled
AWS Config rule:  cloudtrail-s3-dataevents-enabled
Security Hub:     [CloudTrail.1] CloudTrail should be enabled and configured with log validation
Security Hub:     [CloudTrail.2] CloudTrail should have encryption at rest enabled
CloudWatch alarm: CloudTrail configuration changes
```

---

## Phase 1 — Assessment

### 1.1 Verify CloudTrail status across all regions

```bash
# Check all trails and their status
aws cloudtrail describe-trails \
  --include-shadow-trails \
  --query 'trailList[].{
    Name:Name,
    Region:HomeRegion,
    MultiRegion:IsMultiRegionTrail,
    LogValidation:LogFileValidationEnabled,
    S3Bucket:S3BucketName
  }' \
  --output table

# Check if each trail is actually logging
aws cloudtrail get-trail-status \
  --name <TRAIL_NAME> \
  --query '{
    IsLogging:IsLogging,
    LastDelivery:LatestDeliveryTime,
    LastDeliveryError:LatestDeliveryError,
    LastNotification:LatestNotificationTime
  }'
```

`IsLogging: false` or `LatestDeliveryError` present = active gap.

### 1.2 Check for regions without coverage

```bash
# Multi-region trail covers all regions. Verify it's set.
aws cloudtrail describe-trails \
  --query 'trailList[?IsMultiRegionTrail==`true`].Name'

# If no multi-region trail, check each region individually
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  STATUS=$(aws cloudtrail describe-trails \
    --region $REGION \
    --query 'trailList[0].TrailARN' \
    --output text 2>/dev/null)
  echo "$REGION: ${STATUS:-NO TRAIL}"
done
```

### 1.3 Verify log delivery bucket integrity

```bash
BUCKET=<cloudtrail-log-bucket>

# Check bucket policy hasn't been modified to allow deletions
aws s3api get-bucket-policy --bucket $BUCKET | python3 -m json.tool

# Check if Object Lock is enabled (prevents log tampering)
aws s3api get-object-lock-configuration --bucket $BUCKET

# Confirm bucket is not public
aws s3api get-public-access-block --bucket $BUCKET

# Check if MFA delete is enabled
aws s3api get-bucket-versioning --bucket $BUCKET
```

### 1.4 Determine the gap window

```bash
# When did logging stop?
aws cloudtrail get-trail-status \
  --name <TRAIL_NAME> \
  --query '{
    StoppedAt:StopLoggingTime,
    StartedAt:StartLoggingTime,
    LastDelivery:LatestDeliveryTime
  }'

# Who stopped it? (check CloudTrail management events from the management trail)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --query 'Events[].{Time:EventTime,Who:Username,Trail:Resources[0].ResourceName}'
```

---

## Phase 2 — Remediation

### 2.1 Re-enable logging immediately

```bash
aws cloudtrail start-logging --name <TRAIL_NAME>

# Confirm
aws cloudtrail get-trail-status \
  --name <TRAIL_NAME> \
  --query 'IsLogging'
```

### 2.2 Create a multi-region trail if none exists

```bash
# Create a secure log bucket first
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
LOG_BUCKET="cloudtrail-logs-$ACCOUNT_ID-$(date +%Y%m%d)"

aws s3 mb s3://$LOG_BUCKET

# Apply a secure bucket policy (only CloudTrail can write, no public access)
cat > cloudtrail-bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::$LOG_BUCKET"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::$LOG_BUCKET/AWSLogs/$ACCOUNT_ID/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
      }
    },
    {
      "Sid": "DenyNonTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::$LOG_BUCKET",
        "arn:aws:s3:::$LOG_BUCKET/*"
      ],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}
EOF

aws s3api put-bucket-policy --bucket $LOG_BUCKET --policy file://cloudtrail-bucket-policy.json

# Enable versioning on the log bucket
aws s3api put-bucket-versioning \
  --bucket $LOG_BUCKET \
  --versioning-configuration Status=Enabled

# Block public access
aws s3api put-public-access-block \
  --bucket $LOG_BUCKET \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Create the trail
aws cloudtrail create-trail \
  --name org-audit-trail \
  --s3-bucket-name $LOG_BUCKET \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --include-global-service-events

# Start logging
aws cloudtrail start-logging --name org-audit-trail
```

### 2.3 Enable S3 data events (required for PCI and high-sensitivity environments)

```bash
aws cloudtrail put-event-selectors \
  --trail-name org-audit-trail \
  --event-selectors '[
    {
      "ReadWriteType": "All",
      "IncludeManagementEvents": true,
      "DataResources": [
        {
          "Type": "AWS::S3::Object",
          "Values": ["arn:aws:s3:::sensitive-bucket-name/"]
        },
        {
          "Type": "AWS::Lambda::Function",
          "Values": ["arn:aws:lambda"]
        }
      ]
    }
  ]'
```

### 2.4 Set a CloudWatch alarm for future CloudTrail disruptions

```bash
# Metric filter for CloudTrail changes
aws logs put-metric-filter \
  --log-group-name CloudTrail/DefaultLogGroup \
  --filter-name CloudTrailChanges \
  --filter-pattern '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }' \
  --metric-transformations \
    metricName=CloudTrailEventCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name CloudTrailConfigurationChanges \
  --metric-name CloudTrailEventCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions <SNS_TOPIC_ARN>
```

---

## Phase 3 — Hardening

### Protect the log bucket with Object Lock (COMPLIANCE mode)

> ⚠️ Object Lock must be enabled at bucket creation — it cannot be added retroactively.

For new log buckets:
```bash
aws s3api create-bucket \
  --bucket $LOG_BUCKET \
  --object-lock-enabled-for-bucket

aws s3api put-object-lock-configuration \
  --bucket $LOG_BUCKET \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 365
      }
    }
  }'
```

With COMPLIANCE mode enabled, no user (including root) can delete log files within the retention period.

---

## CIS Benchmark Controls — CloudTrail

| CIS Control | AWS Config Rule | Required |
|-------------|----------------|----------|
| 3.1 — CloudTrail enabled all regions | `cloud-trail-enabled` | Yes |
| 3.2 — CloudTrail log file validation | `cloud-trail-log-file-validation-enabled` | Yes |
| 3.3 — CloudTrail S3 bucket not public | `cloudtrail-bucket-not-publicly-accessible` | Yes |
| 3.4 — CloudTrail CloudWatch integration | `cloud-trail-cloud-watch-logs-enabled` | Yes |
| 3.5 — Config enabled all regions | `config-enabled-in-all-regions` | Yes |
| 3.7 — Alarm for CloudTrail changes | CloudWatch alarm | Yes |

---

## Related Runbooks

- [RB-001 — IAM Privilege Escalation](../incident-response/RB-001-iam-privilege-escalation.md) — heavily reliant on CloudTrail
- [RB-008 — CSPM Alert Triage](../governance/RB-008-cspm-alert-triage.md)

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: MEDIUM*
