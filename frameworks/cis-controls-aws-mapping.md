# CIS Controls v8 — AWS Implementation Guide

The CIS Controls are 18 prioritised security actions. They're implementation-focused — each control maps directly to a concrete thing you can configure. This makes them popular for cloud environments where "how" matters as much as "what."

---

## Implementation Groups

CIS v8 organises controls into three Implementation Groups (IGs) based on organisational risk profile:

| IG | Target | Controls |
|----|--------|----------|
| **IG1** | Small organisations, limited IT resources | Subset of all 18 controls — basic hygiene |
| **IG2** | Mid-size, moderate risk, some IT staff | IG1 + additional controls |
| **IG3** | Large/high-risk, dedicated security team | All 18 controls, full implementation |

> For study planning, compare the controls in each group with the risk profile and resources of the organisation being assessed.

---

## All 18 Controls — AWS Implementation

### CIS 1 — Inventory and Control of Enterprise Assets

**What:** Know every asset in your environment.

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 1.1 Establish and maintain asset inventory | 1 | AWS Config — resource inventory. Resource Groups for logical grouping. |
| 1.2 Address unauthorised assets | 1 | AWS Config rule: `ec2-instance-no-public-ip` for unexpected instances |
| 1.3 Utilise DHCP logging | 1 | VPC DHCP options sets; VPC Flow Logs capture IP assignments |
| 1.4 Use dynamic host config | 1 | AWS-managed DHCP within VPC |
| 1.5 Use a passive asset discovery tool | 2 | Amazon Inspector — continuous asset discovery |

**Key AWS Config rules:**
```
required-tags              — enforce tagging for asset tracking
ec2-instance-managed-by-ssm — all EC2 registered in Systems Manager
```

---

### CIS 2 — Inventory and Control of Software Assets

**What:** Know what software runs in your environment.

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 2.1 Establish software inventory | 1 | Systems Manager Inventory — installed software per instance |
| 2.2 Ensure authorised software | 1 | Approved AMI catalogue; Systems Manager State Manager |
| 2.3 Address unauthorised software | 1 | AWS Config + Lambda auto-remediation for non-compliant instances |
| 2.5 Allow list authorised software | 2 | Systems Manager Application Manager |
| 2.6 Address unapproved software libraries | 2 | Inspector SBOM (Software Bill of Materials) for Lambda and containers |
| 2.7 Allow list authorised scripts | 2 | Systems Manager Run Command — only approved documents |

---

### CIS 3 — Data Protection

**What:** Protect data through classification, encryption, and access controls.

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 3.1 Establish data management process | 1 | Data classification policy + S3 bucket tagging by sensitivity |
| 3.2 Inventory sensitive data | 1 | Amazon Macie — automatic PII/PAN discovery in S3 |
| 3.3 Configure data access controls | 1 | S3 bucket policies + Block Public Access; IAM least-privilege |
| 3.5 Encrypt data at rest | 1 | KMS + SSE on S3, EBS, RDS; Config rule: `s3-bucket-server-side-encryption-enabled` |
| 3.6 Encrypt data in transit | 1 | `aws:SecureTransport` deny condition; ACM TLS certificates; ALB HTTPS only |
| 3.7 Establish backup process | 1 | AWS Backup — centralised policy; cross-account vault |
| 3.9 Encrypt backups | 1 | AWS Backup encryption with KMS |
| 3.10 Encrypt sensitive data in transit | 2 | TLS 1.2+ minimum; CloudFront security policy |
| 3.11 Encrypt sensitive data at rest | 2 | KMS CMKs for regulated data; key rotation enabled |
| 3.12 Segment data processing | 2 | Multi-account architecture; VPC segmentation per data class |
| 3.13 Deploy data loss prevention | 2 | Macie continuous monitoring; S3 Access Points with data perimeter |
| 3.14 Log sensitive data access | 3 | CloudTrail S3 data events; Macie findings |

**Key AWS Config rules:**
```
s3-bucket-server-side-encryption-enabled
s3-bucket-public-read-prohibited
s3-bucket-public-write-prohibited
encrypted-volumes
rds-storage-encrypted
```

---

### CIS 4 — Secure Configuration of Enterprise Assets and Software

**What:** Establish and maintain secure configurations.

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 4.1 Establish secure configuration process | 1 | AWS Config rules; CIS Benchmark AMIs; Terraform modules |
| 4.2 Establish secure configuration process for network | 1 | Security groups; NACLs; no default VPC in use |
| 4.6 Securely manage enterprise assets | 1 | Systems Manager Session Manager (replaces SSH); no open port 22 |
| 4.7 Manage default accounts | 1 | Disable/rename default accounts; enforce IAM users via SSO |
| 4.8 Uninstall or disable unnecessary services | 1 | Golden AMI with minimal packages; Systems Manager inventory checks |
| 4.12 Separate enterprise workspaces | 2 | Multi-account strategy (separate prod/dev/security accounts) |

**Key Config rules:**
```
ec2-imdsv2-check               — IMDSv2 required (prevents SSRF)
no-unrestricted-ssh            — port 22 not open to 0.0.0.0/0
vpc-default-security-group-closed — default SG has no rules
ec2-instance-no-public-ip      — EC2 in private subnets only
```

---

### CIS 5 — Account Management

**What:** Use processes and tools to manage credentials for all accounts.

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 5.1 Establish account inventory | 1 | IAM credential report; AWS Organizations account list |
| 5.2 Use unique passwords | 1 | IAM password policy (min length 14, complexity, no reuse) |
| 5.3 Disable dormant accounts | 1 | IAM Access Advisor — disable users inactive >90 days |
| 5.4 Restrict admin privileges | 1 | Separate admin role from day-to-day role; SCP limiting admin policy attachment |
| 5.5 Establish access revoking process | 1 | IAM deny policy on termination; SailPoint/Okta provisioning integration |
| 5.6 Centralise account management | 2 | IAM Identity Center — single place to manage all accounts |

```bash
# Find dormant IAM users (no activity in 90 days)
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d \
  | awk -F',' '$5=="true" && $11!="N/A" && $11<="'$(date -d '-90 days' +%Y-%m-%d)'" {print $1, $11}'
```

---

### CIS 6 — Access Control Management

**What:** Use processes and tools to manage and maintain accounts and access.

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 6.1 Establish access-granting process | 1 | ITSM-integrated provisioning; documented role request workflow |
| 6.2 Establish access-revoking process | 1 | HR–IAM integration; same-day revocation on termination |
| 6.3 Require MFA for admin access | 1 | SCP: deny all if `aws:MultiFactorAuthPresent = false` |
| 6.4 Require MFA for remote access | 1 | IAM Identity Center MFA; VPN MFA requirement |
| 6.5 Require MFA for all users | 2 | IAM policy requiring MFA for console; SCP enforcement |
| 6.6 Establish unique accounts | 2 | No shared accounts; every human has individual IAM Identity Center user |
| 6.7 Centralise access control | 2 | IAM Identity Center; cross-account roles (no direct IAM users per account) |
| 6.8 Define and maintain role-based access | 3 | Permission sets in IAM Identity Center; RBAC defined in policy documents |

---

### CIS 7 — Continuous Vulnerability Management

**What:** Continuously identify, prioritise, and remediate vulnerabilities.

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 7.1 Establish vulnerability management process | 1 | Amazon Inspector — continuous CVE scanning |
| 7.2 Establish vulnerability remediation process | 1 | Inspector → Security Hub → Jira automation via EventBridge |
| 7.3 Perform automated OS patch management | 1 | Systems Manager Patch Manager — automatic patching on schedule |
| 7.4 Perform automated app patch management | 1 | ECR image scanning; Lambda layer updates |
| 7.5 Perform automated vulnerability scans | 2 | Inspector — always-on, not periodic |
| 7.6 Perform privileged account vulnerability scans | 2 | IAM Access Analyzer; Prowler for IAM misconfiguration scanning |
| 7.7 Remediate detected vulnerabilities | 2 | Systems Manager Automation — auto-remediation runbooks |

---

### CIS 8 — Audit Log Management

**What:** Collect, alert, review, and retain audit logs.

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 8.1 Establish audit log management process | 1 | CloudTrail policy; log retention standards |
| 8.2 Collect audit logs | 1 | CloudTrail (all regions); VPC Flow Logs; CloudWatch Logs |
| 8.3 Ensure log storage | 1 | S3 with Object Lock; 1-year minimum retention |
| 8.5 Collect detailed audit logs | 2 | CloudTrail data events (S3, Lambda); GuardDuty |
| 8.6 Collect DNS query audit logs | 2 | Route 53 Resolver query logging |
| 8.7 Collect URL request audit logs | 2 | WAF logs; ALB access logs; CloudFront logs |
| 8.10 Retain audit logs | 2 | S3 lifecycle policy: 1 year hot, 6 years Glacier |
| 8.11 Conduct audit log reviews | 3 | Security Hub; Amazon Detective; SIEM integration |
| 8.12 Collect service logs | 3 | All AWS service logging enabled: RDS, EKS, API Gateway |

---

### CIS 9 — Email and Web Browser Protections

Less applicable to AWS infrastructure (applies to endpoint security). For cloud context:
- Protect email-originated phishing paths to cloud credentials
- WAF for web application protection
- CloudFront with AWS Managed Rules for web browsers

---

### CIS 10 — Malware Defenses

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 10.1 Deploy anti-malware software | 1 | GuardDuty Malware Protection (EC2 + EBS scanning) |
| 10.2 Configure automatic anti-malware updates | 1 | GuardDuty uses AWS-managed threat intel (auto-updated) |
| 10.5 Enable anti-exploitation features | 2 | IMDSv2; Systems Manager; no unapproved packages |
| 10.7 Use DNS filtering | 3 | Route 53 Resolver DNS Firewall — block malicious domains |

---

### CIS 11 — Data Recovery

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 11.1 Establish data recovery process | 1 | AWS Backup policy; RTO/RPO documented |
| 11.2 Perform automated backups | 1 | AWS Backup — automatic daily backups; 35-day RDS automated |
| 11.3 Protect recovery data | 1 | Cross-account backup vault; Object Lock on backup bucket |
| 11.4 Establish isolated instances | 2 | Separate backup account; no delete permissions in workload account |
| 11.5 Test data recovery | 2 | Annual DR test; GameDays; documented test results |

---

### CIS 12 — Network Infrastructure Management

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 12.1 Ensure network infrastructure up to date | 1 | AWS-managed network infrastructure (responsibility model) |
| 12.2 Establish and maintain network architecture | 1 | VPC design; three-tier subnet; documented network diagram |
| 12.3 Securely manage network infrastructure | 1 | No console access for routing; IaC for all network changes |
| 12.6 Use secure network management tools | 2 | SSM Session Manager; no bastion hosts with open SSH |
| 12.7 Centralise network authentication | 2 | IAM + VPC endpoints (no public internet for AWS APIs) |
| 12.8 Establish network segmentation | 3 | Multi-account; Transit Gateway; Security Groups as micro-segmentation |

---

### CIS 13 — Network Monitoring and Defense

| Sub-control | IG | AWS Implementation |
|-------------|----|--------------------|
| 13.1 Centralise security event alerting | 1 | Security Hub — aggregation point for all findings |
| 13.2 Deploy host-based IDS | 2 | GuardDuty — DNS queries, API behaviour, network anomalies |
| 13.3 Deploy network-based IDS | 2 | Network Firewall; GuardDuty VPC flow analysis |
| 13.4 Perform traffic filtering | 2 | WAF; NACLs; Security Groups |
| 13.6 Collect network traffic flow logs | 2 | VPC Flow Logs on all VPCs; Transit Gateway flow logs |
| 13.7 Deploy host-based IPS | 3 | GuardDuty automated response via EventBridge + Lambda |
| 13.8 Deploy web application firewall | 3 | AWS WAF with managed rule groups |

---

### CIS 14–18 (Summary)

| Control | Topic | Primary AWS Service |
|---------|-------|-------------------|
| 14 — Security Awareness | Training programme | AWS Security Hub Security Score as team KPI |
| 15 — Service Provider Management | Third-party risk | AWS Marketplace; Vendor Assessment; shared responsibility |
| 16 — Application Security | Secure SDLC | CodeGuru Security; Inspector for Lambda; WAF |
| 17 — Incident Response | IR programme | GuardDuty + EventBridge + this runbook library |
| 18 — Penetration Testing | Adversarial testing | AWS allows pen testing (notify AWS first); use Prowler for baseline |

---

## CIS AWS Foundations Benchmark

Separate from CIS Controls — the **CIS AWS Foundations Benchmark** is a specific configuration checklist for AWS accounts. Current version: 3.0.

Key areas:
- IAM — password policy, MFA, unused credentials, root account
- Storage — S3 Block Public Access, bucket logging
- Logging — CloudTrail, Config, VPC Flow Logs
- Monitoring — CloudWatch alarms for 14 specific events
- Networking — default VPC, security groups, routing

AWS Security Hub has a built-in CIS AWS Foundations Benchmark standard — enable it and you get automated checking against all Benchmark requirements.

```bash
# Enable CIS AWS Foundations Benchmark in Security Hub
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    StandardsArn=arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0
```

---

*Last reviewed: Q1 2025 · Framework: CIS Controls v8 (2021) + CIS AWS Foundations Benchmark v3.0*
