# RB-011 — EC2 Metadata SSRF / IMDSv1 Credential Theft

![Severity](https://img.shields.io/badge/Severity-CRITICAL-red?style=flat)
![Category](https://img.shields.io/badge/Category-Incident_Response-blueviolet?style=flat)
![Service](https://img.shields.io/badge/AWS-EC2_·_IAM_·_CloudTrail_·_GuardDuty-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF PR.PT-3 · CIS Controls 4.6 · MITRE ATT&CK T1552.005

---

## Overview

Server-Side Request Forgery (SSRF) targeting the EC2 Instance Metadata Service (IMDS) at `http://169.254.169.254` allows an attacker to steal the IAM role credentials attached to the instance. With IMDSv1 enabled, a single HTTP request from a vulnerable web application is enough. The stolen credentials work from any IP address until they expire (up to 6 hours).

**This is one of the most common cloud attack techniques in the wild. Capital One breach (2019) used exactly this method.**

---

## Detection Signals

```
GuardDuty:   UnauthorizedAccess:EC2/MetaDataDNSRebind
GuardDuty:   UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS
GuardDuty:   UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
CloudTrail:  API calls from expected role ARN but unexpected source IP
CloudTrail:  API calls from instance ARN originating from non-AWS IP range
WAF:         Requests to internal IP 169.254.169.254 in request URL/body
```

The clearest signal: CloudTrail shows `arn:aws:sts::<ACCOUNT>:assumed-role/<ROLE>/<INSTANCE-ID>` making API calls from an IP address that is not in AWS IP ranges.

---

## Attack Path (for context)

```
1. Attacker finds SSRF vulnerability in web app on EC2
2. Crafts request: GET http://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. App fetches the URL server-side — returns role name
4. Second request: GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE-NAME>
5. Returns: AccessKeyId, SecretAccessKey, Token (valid ~6 hours)
6. Attacker uses credentials from their own machine to call AWS APIs
```

IMDSv2 breaks this attack by requiring a PUT request with a session token first — SSRF is typically GET-only.

---

## Phase 1 — Detection & Confirmation

### 1.1 Identify the source instance and role

```bash
# Find CloudTrail events where instance credentials used from external IP
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity \
  --query 'Events[?contains(CloudTrailEvent, `InstanceCredentialExfiltration`)].{
    Time:EventTime,
    User:Username,
    IP:CloudTrailEvent
  }'

# Check GuardDuty finding for instance ID and source IP
aws guardduty get-findings \
  --detector-id $DETECTOR_ID \
  --finding-ids $FINDING_ID \
  --query 'Findings[0].{
    InstanceId:Resource.InstanceDetails.InstanceId,
    Role:Resource.InstanceDetails.IamInstanceProfile.Arn,
    ExternalIP:Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4,
    Country:Service.Action.NetworkConnectionAction.RemoteIpDetails.Country.CountryName
  }'
```

### 1.2 Confirm IMDSv1 is enabled on the instance

```bash
INSTANCE_ID=<affected-instance-id>

aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].MetadataOptions'
```

`HttpTokens: optional` = IMDSv1 allowed (vulnerable). `HttpTokens: required` = IMDSv2 only (protected).

### 1.3 Pull all API calls made with the stolen credential

```bash
# Get the role session name (instance ID is used as session name)
ROLE_NAME=<role-name>
INSTANCE_ID=<instance-id>

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=$ROLE_NAME \
  --start-time <ESTIMATED_THEFT_TIME_ISO> \
  --query 'Events[].{
    Time:EventTime,
    Event:EventName,
    Region:CloudTrailEvent,
    IP:CloudTrailEvent
  }' | python3 -c "
import sys, json
events = json.load(sys.stdin)
for e in events:
    raw = json.loads(e.get('Region','{}'))
    src_ip = raw.get('sourceIPAddress','unknown')
    print(f\"{e['Time']} | {e['Event']} | {src_ip}\")
"
```

---

## Phase 2 — Containment

### 2.1 Revoke the stolen session credentials immediately

```bash
# Attach an inline deny policy to the role — invalidates ALL existing sessions
aws iam put-role-policy \
  --role-name $ROLE_NAME \
  --policy-name EMERGENCY-RevokeAllSessions \
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

This invalidates all credentials issued before the current timestamp. The instance itself will automatically get new credentials on next metadata call.

### 2.2 Enable IMDSv2 on the affected instance immediately

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id $INSTANCE_ID \
  --http-tokens required \
  --http-endpoint enabled \
  --http-put-response-hop-limit 1
```

Hop limit of 1 means containers inside the instance cannot reach IMDS — prevents container escape scenarios.

### 2.3 Isolate instance if exploitation confirmed

```bash
# Move to quarantine security group
aws ec2 modify-instance-attribute \
  --instance-id $INSTANCE_ID \
  --groups <QUARANTINE_SG_ID>
```

---

## Phase 3 — Eradication

### 3.1 Patch the SSRF vulnerability

Identify the vulnerable code path from the web server access logs:

```bash
# Download and scan ALB/web server access logs
aws s3 sync s3://<ALB-LOG-BUCKET>/ ./alb-logs/
grep "169.254.169.254" ./alb-logs/*.log
```

The request containing `169.254.169.254` in the URL, referrer, or POST body is the SSRF trigger.

### 3.2 Enforce IMDSv2 across ALL instances in the account

```bash
# Enforce on all running instances
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text | tr '\t' '\n' | while read ID; do
    aws ec2 modify-instance-metadata-options \
      --instance-id $ID \
      --http-tokens required \
      --http-endpoint enabled
    echo "IMDSv2 enforced: $ID"
  done
```

### 3.3 SCP to prevent IMDSv1 on new instances

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

### 3.4 AWS Config rule for continuous enforcement

```bash
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "ec2-imdsv2-check",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "EC2_IMDSV2_CHECK"
    }
  }'
```

---

## Phase 4 — Post-Incident

### Evidence to collect

- [ ] GuardDuty finding export (JSON)
- [ ] CloudTrail events showing external IP using instance credentials
- [ ] ALB access logs showing the SSRF request
- [ ] Before/after `describe-instance-metadata-options` output
- [ ] Code commit showing SSRF vulnerability remediation
- [ ] IMDSv2 compliance evidence (Config rule output)

### Governance notes

- **MITRE ATT&CK T1552.005:** Unsecured Credentials — Cloud Instance Metadata APIs
- **CIS 4.6:** Use dedicated administrative accounts — instance roles should have minimal permissions; even if stolen, blast radius is limited
- Review IAM role permissions on all EC2 instances — follow least-privilege; a stolen role with read-only permissions is far less damaging than admin

---

## Related Runbooks

- [RB-001 — IAM Privilege Escalation](./RB-001-iam-privilege-escalation.md) — if stolen role had broad permissions
- [RB-003 — Exposed API Keys](./RB-003-exposed-api-keys.md) — credential compromise response

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: CRITICAL*
