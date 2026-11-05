# RB-010 — PCI-DSS Scope Violation Response

![Severity](https://img.shields.io/badge/Severity-HIGH-orange?style=flat)
![Category](https://img.shields.io/badge/Category-Governance-blue?style=flat)
![Service](https://img.shields.io/badge/AWS-Macie_·_VPC_·_CloudTrail-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** PCI-DSS v4.0 — Req 1.3, 3.2, 4.2, 11.4 · NIST CSF ID.AM-3, PR.DS-5

---

## Overview

A system not intended to be in-scope for PCI-DSS has come into contact with cardholder data (CHD), expanding the compliance scope unexpectedly. Scope creep is one of the most common and costly PCI findings.

**Notify your Qualified Security Assessor (QSA) within 24 hours if this occurs during an active audit engagement.**

---

## What is Cardholder Data?

| Data Element | In Scope | Storage Permitted |
|-------------|----------|------------------|
| Primary Account Number (PAN) | Always | Only if encrypted |
| Cardholder Name | If stored with PAN | Yes |
| Service Code | If stored with PAN | Yes |
| Expiration Date | If stored with PAN | Yes |
| Full Track Data | Always | Never |
| CAV2 / CVV / CVV2 | Always | Never |
| PIN / PIN Block | Always | Never |

**The most important rule:** the full card number (PAN) defines PCI scope. If a system can see an unmasked PAN, it is in scope.

---

## Phase 1 — Detection & Confirmation

### 1.1 Confirm cardholder data is present using Macie

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Scan the affected resource
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "pci-scope-check-$(date +%Y%m%d)" \
  --managed-data-identifier-selector '{"types":["SensitiveData:Financial"]}' \
  --s3-job-definition "{
    \"bucketDefinitions\": [{
      \"accountId\": \"$ACCOUNT_ID\",
      \"buckets\": [\"<BUCKET_NAME>\"]
    }]
  }"
```

Macie will identify PANs and other financial data. For EC2 databases, use Amazon Inspector or a manual scan with a PAN-detection regex:

```bash
# PAN detection pattern (Luhn-valid 13-19 digit sequences)
grep -rE '\b[3-6][0-9]{12,18}\b' /path/to/data --include="*.csv" --include="*.log" --include="*.txt"
```

### 1.2 Map how CHD reached the out-of-scope system

```bash
# Network path — VPC Flow Logs (run in Athena)
cat << 'EOF'
SELECT
  srcaddr,
  dstaddr,
  srcport,
  dstport,
  action,
  SUM(bytes) AS bytes,
  COUNT(*) AS connections
FROM vpc_flow_logs
WHERE (srcaddr = '<CDE_IP>' OR dstaddr = '<OOS_SYSTEM_IP>')
  AND start > CAST('<INCIDENT_START_EPOCH>' AS bigint)
GROUP BY srcaddr, dstaddr, srcport, dstport, action
ORDER BY bytes DESC;
EOF

# Application-level path — CloudTrail API calls between systems
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<OOS_RESOURCE> \
  --start-time <DISCOVERY_DATE_ISO> \
  --query 'Events[].{Time:EventTime,Event:EventName,Source:EventSource}'
```

Common causes of unintended scope expansion:
- Logging pipelines routing CDE logs to out-of-scope SIEM
- Shared S3 buckets accessed by CDE and non-CDE workloads
- Database replicas or ETL pipelines without proper masking
- Developer copying production data to dev environment
- API responses including full PANs instead of masked values

---

## Phase 2 — Containment

### 2.1 Isolate the out-of-scope system

```bash
# Move to isolated security group (no CDE inbound/outbound)
aws ec2 modify-instance-attribute \
  --instance-id <OOS_INSTANCE_ID> \
  --groups <ISOLATED_SG_ID>

# Block the S3 bucket from CDE account (if S3 scope creep)
aws s3api put-bucket-policy \
  --bucket <SHARED_BUCKET> \
  --policy file://deny-cde-access-policy.json
```

### 2.2 Purge or quarantine the cardholder data

```bash
# If CHD is in S3 — quarantine specific objects
aws s3 mv s3://<BUCKET>/<PATH_TO_CHD>/ s3://<QUARANTINE_BUCKET>/<PATH>/ --recursive

# If in a database — work with DBA to purge and vacuum
# If in logs — apply log rotation and overwrite

# Confirm Macie no longer finds PAN after purge
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --name "pci-purge-verify-$(date +%Y%m%d)" \
  --s3-job-definition "{\"bucketDefinitions\":[{\"accountId\":\"$ACCOUNT_ID\",\"buckets\":[\"<BUCKET>\"]}]}"
```

---

## Phase 3 — Scope Assessment

### Determine whether the out-of-scope system is now in-scope

Once a system has touched CHD, it is technically in scope for PCI-DSS. You have two options:

**Option A — Bring into scope:**
- Apply all relevant PCI-DSS controls to the system
- Update the network data flow diagram
- Inform QSA of scope change
- Higher cost but simpler if the system must continue to access CHD

**Option B — Descope (preferred):**
- Purge all CHD from the system (confirmed by Macie)
- Close the network path that allowed CHD to reach the system
- Implement tokenisation or masking at the CDE boundary
- Document the descoping and have QSA confirm
- Lower long-term cost

---

## Phase 4 — Network Segmentation Remediation

PCI-DSS Req 1.3 requires network controls that prevent unauthorised traffic between the CDE and out-of-scope systems. 

### Implement CDE network boundary controls

```bash
# Create dedicated CDE security group with strict egress
aws ec2 create-security-group \
  --group-name CDE-Boundary-SG \
  --description "PCI CDE boundary — only authorised CDE traffic" \
  --vpc-id <VPC_ID>

# Allow only known CDE-to-CDE communication
aws ec2 authorize-security-group-ingress \
  --group-id <CDE_SG_ID> \
  --protocol tcp \
  --port 443 \
  --source-group <AUTHORISED_CDE_SG_ID>

# Explicitly deny all other inbound
# (AWS SGs are deny-by-default — simply don't add unauthorised rules)
```

### Implement tokenisation at the CDE boundary

Rather than passing PANs to out-of-scope systems, return a token:

- AWS Payment Cryptography provides PCI-validated tokenisation
- All downstream systems receive the token, not the PAN
- Only the CDE can detokenise — out-of-scope systems never see PAN

---

## Phase 5 — Documentation & QSA Notification

### Required documentation

- [ ] Root cause analysis: how did CHD reach the out-of-scope system?
- [ ] Data flow diagram updated to reflect actual data flows
- [ ] Evidence of purge: Macie report showing no PAN detected post-remediation
- [ ] Network segmentation changes implemented and tested
- [ ] Penetration test of the new segmentation (required by PCI Req 11.4 if scoping changed significantly)
- [ ] Exception or scope change form submitted to QSA

### Notify QSA if

- The scope change affects an active assessment
- CHD was in an out-of-scope system for > 30 days
- The number of in-scope systems increased by > 20%
- Card brand notification may be required

---

## PCI-DSS Scoping Quick Reference

| System Type | In Scope? |
|-------------|---------|
| Stores, processes, or transmits CHD | Always |
| Connected to CDE network (no segmentation) | Yes |
| Provides security services to CDE (IAM, logging, monitoring) | Yes |
| Connected to CDE but with verified network segmentation | No |
| Has no connectivity path to CDE | No |
| SaaS payment processor (Stripe, Braintree) | Reduces scope — SAQ A eligible |

---

## Related Runbooks

- [RB-002 — S3 Data Exposure](../incident-response/RB-002-s3-data-exposure.md) — CHD exposed via S3
- [RB-005 — Security Group Open to Internet](../misconfigurations/RB-005-security-group-open-internet.md) — segmentation failure
- [RB-009 — SOC 2 Evidence Collection](./RB-009-soc2-evidence-collection.md)

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Framework: PCI-DSS v4.0*
