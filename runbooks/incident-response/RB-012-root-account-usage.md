# RB-012 — Root Account Usage Detected

![Severity](https://img.shields.io/badge/Severity-CRITICAL-red?style=flat)
![Category](https://img.shields.io/badge/Category-Incident_Response-blueviolet?style=flat)
![Service](https://img.shields.io/badge/AWS-IAM_·_CloudTrail_·_Organizations-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** CIS Controls 5.4 · NIST CSF PR.AC-4 · PCI-DSS v4 Req 7.2 · SOC 2 CC6.3

---

## Overview

The AWS root account has unlimited permissions and cannot be restricted by IAM policies or SCPs. Any use of root — outside of a small set of root-only tasks — is a major security signal. Either a legitimate admin is bypassing controls, or an attacker has compromised the root credentials.

**Treat every root account login as a potential P1 until confirmed otherwise.**

---

## Tasks That Legitimately Require Root

| Task | Notes |
|------|-------|
| Activate IAM Identity Center for the first time | One-time setup |
| Change AWS support plan | Billing operation |
| Close the AWS account | Destructive — needs hardware MFA confirmation |
| Restore IAM admin access when locked out | Break-glass only |
| Enable MFA on root for the first time | Bootstrap operation |
| Transfer Route 53 domain to another registrar | Domain operation |
| Create GovCloud account | One-time |

**Everything else can and should be done via IAM roles.**

---

## Detection Signals

```
CloudTrail:   userIdentity.type = "Root" in any management event
GuardDuty:    Policy:IAMUser/RootCredentialUsage
Security Hub: [IAM.7] Password policies for IAM users should have strong configurations
CloudWatch:   RootAccountLogin metric filter alert (CIS Benchmark 3.3)
```

### CIS Benchmark CloudWatch alarm (must be pre-configured)

```bash
# Metric filter for root activity
aws logs put-metric-filter \
  --log-group-name CloudTrail/DefaultLogGroup \
  --filter-name RootAccountActivity \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations \
    metricName=RootAccountActivityCount,\
    metricNamespace=CloudTrailMetrics,\
    metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name RootAccountActivity \
  --metric-name RootAccountActivityCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 60 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions <SNS_TOPIC_ARN> \
  --alarm-description "CRITICAL: Root account activity detected"
```

---

## Phase 1 — Triage (within 10 minutes)

### 1.1 Get the exact CloudTrail event

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --start-time $(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[].{
    Time:EventTime,
    Event:EventName,
    Source:EventSource,
    IP:CloudTrailEvent
  }' | python3 -c "
import sys, json
events = json.load(sys.stdin)
for e in events:
    raw = json.loads(e.get('IP','{}'))
    print(f\"Time: {e['Time']}\")
    print(f\"Event: {e['Event']}\")
    print(f\"Source: {e['Source']}\")
    print(f\"IP: {raw.get('sourceIPAddress','?')}\")
    print(f\"UA: {raw.get('userAgent','?')}\")
    print('---')
"
```

### 1.2 Evaluate legitimacy

Ask these questions immediately:

| Question | Legitimate | Suspicious |
|----------|-----------|-----------|
| Is this a known root-only task? | Yes — from the list above | No — could be done via IAM |
| Does the source IP match corporate VPN or known location? | Yes | Unknown IP, Tor, VPN service, foreign country |
| Was there a change request / ticket for this? | Yes, with approval | No record |
| Did a senior engineer confirm they did this? | Yes, within minutes | No one claims it |
| Was MFA used? (check `additionalEventData.MFAUsed`) | true | false — **critical red flag** |

### 1.3 Check if MFA was used

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --query 'Events[0].CloudTrailEvent' \
  --output text | python3 -c "
import sys, json
event = json.load(sys.stdin)
mfa = event.get('additionalEventData', {}).get('MFAUsed', 'NOT_PRESENT')
print(f'MFA used: {mfa}')
print(f'Source IP: {event.get(\"sourceIPAddress\")}')
print(f'User agent: {event.get(\"userAgent\")}')
"
```

`MFAUsed: No` during a console login = either MFA is not configured (fix immediately — see [RB-006](../misconfigurations/RB-006-mfa-not-enforced.md)) or an attacker bypassed it via API (access keys).

---

## Phase 2 — If Unauthorised: Containment

### 2.1 Change root password immediately

This must be done via console. Have a trusted senior engineer:
1. Sign in to console (use hardware MFA)
2. Go to IAM → My Security Credentials → Password
3. Generate a cryptographically random 32+ character password
4. Store in corporate password manager / secrets vault — not email

### 2.2 Check for and delete root access keys

Root should **never** have access keys. If any exist, they are malicious:

```bash
# Check via CLI (requires current credentials)
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
# 0 = no root keys (correct). 1 = root has active keys (CRITICAL).
```

If root access keys exist:
1. Go to IAM console → Security Credentials (as root)
2. Delete all access keys — do not deactivate, delete
3. Document the key IDs for IOC tracking

### 2.3 Review all actions taken during the root session

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --start-time <SESSION_START_ISO> \
  --end-time <SESSION_END_ISO> \
  --query 'Events[].{Time:EventTime,Event:EventName,Region:CloudTrailEvent}'
```

High-risk events to look for: `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `PutBucketPolicy`, `ModifyDBInstance`, `DeleteTrail`, `StopLogging`.

### 2.4 If account takeover confirmed — notify AWS

If you believe the account is fully compromised:
- Call AWS Support immediately (escalate to Security team)
- AWS can place a temporary lock on the account while you regain control
- Number: +1-206-266-4064 (AWS Security)

---

## Phase 3 — Hardening

### Lock down root after confirmed legitimate use

After any legitimate root action, verify:

```bash
# Confirm MFA is still active
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'
# Must be 1

# Confirm no access keys exist
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
# Must be 0
```

### Implement break-glass procedure for future root access

Document a formal procedure:
1. Root password and MFA device stored in physical safe / hardware vault
2. Access requires two-person authorisation (4-eyes principle)
3. All root sessions must have an open change request ticket
4. Post-session review within 24 hours
5. CloudWatch alarm notifies CISO within 60 seconds of any root activity

---

## Governance Notes

- **CIS 5.4:** Restrict administrator privileges to dedicated administrator accounts — root is the ultimate admin and must be locked away
- **PCI-DSS Req 7.2:** All system components are protected from unrestricted access — root access without MFA and a ticket is a direct Req 7.2 finding
- **SOC 2 CC6.3:** Access is removed when no longer needed — root access keys are never needed; their existence alone is a finding
- Document every legitimate root access in an access log with: date, operator, task performed, ticket reference, MFA confirmation

---

## Related Runbooks

- [RB-001 — IAM Privilege Escalation](./RB-001-iam-privilege-escalation.md)
- [RB-006 — MFA Not Enforced](../misconfigurations/RB-006-mfa-not-enforced.md)

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: CRITICAL*
