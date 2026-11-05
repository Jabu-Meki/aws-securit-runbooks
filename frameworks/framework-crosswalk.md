# Framework Crosswalk — AWS Security Controls

Maps common AWS security controls to the major compliance frameworks simultaneously. Use this when you need to demonstrate how a single control satisfies multiple framework requirements.

---

## How to Use This Document

Each row is an AWS control or security practice. The columns show which specific requirement within each framework it satisfies. A single well-implemented control often satisfies 4–6 requirements across frameworks — this is the efficiency argument for controls-based programmes.

---

## Identity & Access Management

| AWS Control | NIST CSF 2.0 | CIS v8 | SOC 2 | PCI-DSS v4 | ISO 27001 |
|------------|-------------|--------|-------|-----------|----------|
| MFA for all console users | PR.AC-7 | 6.3, 6.5 | CC6.1 | Req 8.4 | A.9.4.2 |
| MFA for root account | PR.AC-7 | 1.5 | CC6.1 | Req 8.4.1 | A.9.4.2 |
| No root account access keys | PR.AC-1 | 1.4 | CC6.2 | Req 7.2 | A.9.2.3 |
| IAM least-privilege policies | PR.AC-4 | 5.4, 6.8 | CC6.3 | Req 7.2 | A.9.2.3 |
| Quarterly access reviews | ID.GV-1 | 6.2 | CC6.3 | Req 7.3 | A.9.2.5 |
| No unused IAM credentials (90 days) | PR.AC-1 | 5.3 | CC6.2 | Req 8.3 | A.9.2.6 |
| SCPs enforcing guardrails | PR.AC-4 | 4.1 | CC6.1 | Req 7.2 | A.9.1.2 |
| IAM Access Analyzer | ID.RA-1 | 3.3 | CC7.1 | Req 11.3 | A.18.2.1 |
| IAM roles for EC2 (no keys) | PR.DS-2 | 5.1 | CC6.1 | Req 8.6 | A.9.4.3 |

---

## Logging & Monitoring

| AWS Control | NIST CSF 2.0 | CIS v8 | SOC 2 | PCI-DSS v4 | ISO 27001 |
|------------|-------------|--------|-------|-----------|----------|
| CloudTrail multi-region trail | DE.AE-3 | 8.2 | CC7.2 | Req 10.2 | A.12.4.1 |
| CloudTrail log integrity validation | DE.AE-3 | 8.7 | CC7.2 | Req 10.5 | A.12.4.2 |
| CloudTrail S3 Object Lock | PR.DS-1 | 8.3 | CC7.2 | Req 10.5 | A.12.4.2 |
| VPC Flow Logs enabled | DE.CM-1 | 8.2 | CC7.2 | Req 10.2 | A.12.4.1 |
| CloudWatch Alarms for security events | DE.CM-8 | 8.11 | CC7.2 | Req 10.6 | A.16.1.2 |
| GuardDuty enabled in all regions | DE.CM-4 | 8.11 | CC7.2 | Req 10.7 | A.16.1.4 |
| Security Hub aggregating all findings | DE.AE-5 | 4.1 | CC7.2 | Req 10.7 | A.12.6.1 |
| Log retention ≥ 1 year | DE.AE-3 | 8.10 | CC7.2 | Req 10.7 | A.12.4.1 |
| AWS Config enabled all regions | DE.CM-8 | 1.1 | CC7.1 | Req 2.2 | A.18.2.2 |

---

## Network Security

| AWS Control | NIST CSF 2.0 | CIS v8 | SOC 2 | PCI-DSS v4 | ISO 27001 |
|------------|-------------|--------|-------|-----------|----------|
| No 0.0.0.0/0 on sensitive ports | PR.AC-5 | 12.2 | CC6.6 | Req 1.3 | A.13.1.1 |
| Three-tier subnet architecture | PR.AC-5 | 12.3 | CC6.6 | Req 1.3 | A.13.1.3 |
| WAF for internet-facing apps | PR.PT-4 | 13.8 | CC6.6 | Req 6.4 | A.13.1.1 |
| NACLs as secondary network control | PR.AC-5 | 12.2 | CC6.6 | Req 1.3 | A.13.1.1 |
| TLS 1.2+ enforced (no 1.0/1.1) | PR.DS-2 | 3.10 | CC6.7 | Req 4.2.1 | A.14.1.2 |
| VPC endpoints for AWS services | PR.AC-5 | 12.6 | CC6.6 | Req 1.3 | A.13.1.3 |

---

## Data Protection

| AWS Control | NIST CSF 2.0 | CIS v8 | SOC 2 | PCI-DSS v4 | ISO 27001 |
|------------|-------------|--------|-------|-----------|----------|
| S3 Block Public Access (account) | PR.DS-5 | 3.3 | CC6.1 | Req 3.4 | A.8.2.3 |
| S3 default encryption (SSE-KMS) | PR.DS-1 | 3.11 | CC6.7 | Req 3.5 | A.10.1.1 |
| EBS encryption at rest | PR.DS-1 | 3.11 | CC6.7 | Req 3.5 | A.10.1.1 |
| RDS encryption at rest | PR.DS-1 | 3.11 | CC6.7 | Req 3.5 | A.10.1.1 |
| KMS key rotation enabled | PR.DS-1 | 3.11 | CC6.7 | Req 3.7 | A.10.1.2 |
| Secrets Manager (no hardcoded creds) | PR.DS-2 | 5.1 | CC6.1 | Req 8.3 | A.9.4.3 |
| Secrets Manager auto-rotation (90d) | PR.DS-2 | 5.2 | CC6.2 | Req 8.3 | A.9.4.3 |
| Macie for PII discovery | ID.AM-5 | 3.2 | CC6.1 | Req 9.5 | A.8.2.1 |
| S3 Object Lock on log buckets | PR.DS-1 | 8.3 | CC7.2 | Req 10.5 | A.12.4.2 |

---

## Vulnerability & Configuration Management

| AWS Control | NIST CSF 2.0 | CIS v8 | SOC 2 | PCI-DSS v4 | ISO 27001 |
|------------|-------------|--------|-------|-----------|----------|
| AWS Inspector (CVE scanning) | ID.RA-1 | 7.1, 7.7 | CC7.1 | Req 11.3 | A.12.6.1 |
| Systems Manager Patch Manager | PR.MA-1 | 7.3 | CC7.1 | Req 6.3 | A.12.6.1 |
| Hardened golden AMIs | PR.IP-1 | 2.5 | CC7.1 | Req 2.2 | A.14.2.1 |
| IMDSv2 enforced (EC2) | PR.PT-3 | 4.1 | CC6.6 | Req 6.3 | A.9.4.1 |
| SSM Session Manager (no SSH) | PR.AC-3 | 4.1 | CC6.1 | Req 8.6 | A.6.2.2 |
| AWS Config rules continuous | DE.CM-8 | 1.1 | CC7.1 | Req 2.2 | A.18.2.2 |

---

## Incident Response

| AWS Control | NIST CSF 2.0 | CIS v8 | SOC 2 | PCI-DSS v4 | ISO 27001 |
|------------|-------------|--------|-------|-----------|----------|
| Documented IR runbooks | RS.RP-1 | 17.1 | CC7.3 | Req 12.10 | A.16.1.5 |
| GuardDuty + EventBridge alerts | RS.CO-2 | 17.3 | CC7.3 | Req 12.10 | A.16.1.2 |
| IR exercises conducted annually | RS.IM-1 | 17.7 | CC7.3 | Req 12.10 | A.16.1.1 |
| Forensic capabilities (snapshots) | RS.AN-3 | 17.6 | CC7.4 | Req 12.10 | A.16.1.7 |
| Post-incident reviews (PIRs) | RS.IM-2 | 17.8 | CC7.4 | Req 12.10 | A.16.1.6 |

---

---

*Last reviewed: Q1 2025 · Covers: NIST CSF 2.0, CIS Controls v8, SOC 2 Type II (CC), PCI-DSS v4.0, ISO 27001:2022*
