# AWS Defence-in-Depth Architecture

A reference architecture for layered security controls across an AWS environment. Each layer provides independent protection — an attacker who bypasses one layer still faces the next.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 0 — PERIMETER                                                │
│  Route 53 (DNS)  ·  AWS Shield (DDoS)  ·  WAF (Layer 7 filtering)  │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│  LAYER 1 — NETWORK                                                  │
│  VPC  ·  Subnets (Public / Private / Isolated)                      │
│  Security Groups  ·  NACLs  ·  VPC Flow Logs                        │
│  Transit Gateway  ·  VPN / Direct Connect                           │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│  LAYER 2 — IDENTITY                                                 │
│  IAM (users, roles, policies)  ·  AWS Organizations + SCPs          │
│  IAM Identity Center (SSO)  ·  MFA enforcement  ·  Permissions Bdry │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│  LAYER 3 — COMPUTE                                                  │
│  EC2 (IMDSv2, hardened AMIs)  ·  ECS / EKS (task roles)            │
│  Lambda (execution roles)  ·  Systems Manager (no open SSH)         │
│  AWS Inspector (vulnerability scanning)  ·  GuardDuty Malware Prot. │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│  LAYER 4 — DATA                                                     │
│  S3 (Block Public Access, Object Lock, Versioning)                  │
│  KMS (envelope encryption)  ·  Macie (PII discovery)               │
│  RDS encryption  ·  Secrets Manager (auto-rotation)                │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│  LAYER 5 — DETECTION & RESPONSE                                     │
│  CloudTrail  ·  AWS Config  ·  Security Hub  ·  GuardDuty           │
│  CloudWatch Alarms  ·  EventBridge  ·  SNS / PagerDuty             │
│  AWS Audit Manager  ·  Detective (investigation)                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Layer Detail

### Layer 0 — Perimeter

| Service | Purpose | Key Config |
|---------|---------|-----------|
| AWS Shield Standard | DDoS protection (free, automatic) | Enabled by default for CloudFront, Route 53, ELBs |
| AWS Shield Advanced | Enhanced DDoS + 24/7 DRT access | Opt-in, ~$3k/month — required for PCI-regulated internet-facing workloads |
| AWS WAF | Layer 7 web application filtering | Managed rule groups: Core Rule Set, Known Bad Inputs, SQL injection, XSS |
| Route 53 | DNS with DNSSEC support | Enable DNSSEC signing for public hosted zones |
| CloudFront | CDN + edge TLS termination | Minimum TLS 1.2, HSTS headers |

### Layer 1 — Network

**Subnet design — three-tier:**

```
Public subnet (10.0.1.0/24)   — ALB, NAT Gateway only. No application servers.
Private subnet (10.0.2.0/24)  — EC2, ECS, Lambda. Egress via NAT.
Isolated subnet (10.0.3.0/24) — RDS, ElastiCache. No internet egress at all.
```

**Security Group rules — least privilege:**
- Inbound: only from the specific SG or CIDR that needs access
- Outbound: restrict to required ports (not 0.0.0.0/0 by default)
- No rules combining `0.0.0.0/0` source with sensitive ports (22, 3389, DB ports)

**NACLs:** stateless, subnet-level. Use as a secondary control — security groups are the primary control.

### Layer 2 — Identity

**Key principles:**

- **Least privilege:** every IAM principal has only the permissions needed for its function
- **No long-lived keys:** use roles and instance profiles instead of IAM user access keys
- **SCP guardrails:** SCPs at the OU level prevent any account from disabling security controls
- **Separation of duties:** separate roles for read, write, admin, and break-glass access
- **MFA everywhere:** enforced via SCP on the organisation, not voluntary

**Critical SCPs to implement:**

```
DenyLeavingOrganisation       — prevents accounts escaping governance
DenyDisablingGuardDuty        — keeps threat detection running
DenyDisablingCloudTrail       — protects audit trail
DenyRootAccountUsage          — except for break-glass (hardware MFA required)
DenyPublicS3Buckets           — prevents accidental data exposure
RequireIMDSv2                 — prevents SSRF credential theft on EC2
RestrictRegions               — limits activity to approved regions only
```

### Layer 3 — Compute

**EC2 hardening checklist:**

- [ ] Launch from approved golden AMI (CIS-hardened baseline)
- [ ] IMDSv2 enforced (`HttpTokens=required`) — prevents SSRF attacks from stealing instance credentials
- [ ] No direct SSH — use SSM Session Manager
- [ ] Instance profile attached (role-based auth, no access keys)
- [ ] EBS volumes encrypted with KMS
- [ ] AWS Inspector enabled for continuous CVE scanning
- [ ] GuardDuty Malware Protection enabled for EBS scanning

### Layer 4 — Data

**S3 security baseline:**

- [ ] Block Public Access enabled at account level (Organisation-wide SCP)
- [ ] Default encryption: SSE-KMS
- [ ] Versioning enabled on sensitive buckets
- [ ] Object Lock (COMPLIANCE mode) on audit log buckets
- [ ] S3 Access Logging enabled → centralised log bucket
- [ ] Macie enabled continuously for PII/PAN discovery
- [ ] Bucket policies: deny non-TLS access (`aws:SecureTransport: false`)

**KMS key policy principle:** key administrators ≠ key users. No single identity should be able to both manage and use the same KMS key.

### Layer 5 — Detection & Response

**Minimum viable monitoring stack:**

| Service | What it detects | Where findings go |
|---------|----------------|-------------------|
| GuardDuty | Threat intelligence, behavioural anomalies, malware | Security Hub |
| AWS Config | Configuration drift, policy violations | Security Hub |
| CloudTrail | All API calls — who did what, when, from where | S3 + CloudWatch Logs |
| Security Hub | Aggregates findings from all security services | SIEM / PagerDuty |
| Macie | PII and sensitive data exposure in S3 | Security Hub |
| Inspector | CVEs in EC2, Lambda, container images | Security Hub |
| Access Analyzer | Overly permissive IAM policies and resource policies | Security Hub |

---

## Threat Modelling — This Architecture vs Common Attacks

| Attack Technique | Mitigating Layer | AWS Control |
|----------------|-----------------|-------------|
| Credential stuffing / password spray | Layer 2 | MFA enforcement, Cognito advanced security |
| API key theft from code repo | Layer 2, 5 | Secrets Manager, GitHub secret scanning, GuardDuty |
| SSRF → EC2 metadata credential theft | Layer 3 | IMDSv2 (`HttpTokens=required`) |
| Public S3 bucket | Layer 4 | Block Public Access SCP, Config rule |
| Privilege escalation via IAM | Layer 2, 5 | SCPs, IAM Access Analyzer, GuardDuty |
| Data exfiltration | Layer 1, 4, 5 | VPC flow logs, Macie, GuardDuty |
| Ransomware | Layer 3, 4, 5 | GuardDuty Malware Protection, S3 Object Lock |
| Insider threat | Layer 2, 5 | CloudTrail, least-privilege, access reviews |
| Supply chain (malicious AMI/package) | Layer 3, 5 | Inspector, approved AMI catalogue |
| DDoS | Layer 0 | Shield, WAF, CloudFront |

---

## Related Runbooks

- [RB-001 — IAM Privilege Escalation](../runbooks/incident-response/RB-001-iam-privilege-escalation.md) — Layer 2 failure
- [RB-002 — S3 Data Exposure](../runbooks/incident-response/RB-002-s3-data-exposure.md) — Layer 4 failure
- [RB-005 — Security Group Open to Internet](../runbooks/misconfigurations/RB-005-security-group-open-internet.md) — Layer 1 failure

---

*Last reviewed: Q1 2025 · Reference architecture for AWS commercial environments*
