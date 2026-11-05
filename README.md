# AWS Cloud Security Runbook Library

![AWS](https://img.shields.io/badge/AWS-FF9900?style=flat&logo=amazonaws&logoColor=black)
![Runbooks](https://img.shields.io/badge/Runbooks-18-blueviolet?style=flat)
![NIST CSF](https://img.shields.io/badge/NIST_CSF-2.0-1a6faf?style=flat)
![CIS](https://img.shields.io/badge/CIS_Controls-v8-e75480?style=flat)
![SOC2](https://img.shields.io/badge/SOC_2-Type_II-2ea44f?style=flat)
![PCI](https://img.shields.io/badge/PCI--DSS-v4.0-00457c?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Last Updated](https://img.shields.io/badge/Updated-Q1_2025-blue?style=flat)

A student project documenting AWS security runbooks, incident response procedures, governance frameworks, and evidence collection examples. It is a learning resource and a practical reference for exploring cloud security operations.

---

## Purpose

- Cloud security analysts and engineers working in AWS environments
- GRC / governance professionals managing AWS compliance programmes
- Anyone studying for AWS Security Specialty, SAA-C03, or CCP certifications

---

## Repository Structure

```
aws-cloud-security-runbooks/
├── README.md
├── SETUP.md                           ← How to publish the project on GitHub
│
├── runbooks/
│   ├── incident-response/             ← 8 runbooks: detect, contain, eradicate, recover
│   ├── misconfigurations/             ← 6 runbooks: find it, fix it, prevent recurrence
│   └── governance/                    ← 4 runbooks: audit, evidence, compliance
│
├── diagrams/
│   ├── aws-defence-in-depth.md
│   ├── zero-trust-architecture.md
│   └── shared-responsibility-model.md
│
├── frameworks/
│   ├── nist-csf-aws-mapping.md
│   ├── cis-controls-aws-mapping.md
│   └── framework-crosswalk.md
│
├── evidence/
│   ├── README.md                      ← Evidence standards, retention, naming convention
│   ├── incident-response/             ← 8 per-runbook evidence folders
│   ├── misconfigurations/             ← 6 per-runbook evidence folders
│   ├── governance/                    ← 3 per-runbook evidence folders
│   └── templates/
│       ├── incident-evidence-package.md
│       ├── sample-guardduty-finding.json
│       ├── sample-cloudtrail-event.json
│       ├── sample-credential-report.csv
│       └── sample-config-compliance.json
│
└── templates/
    ├── incident-report-template.md
    └── new-runbook-template.md
```

---

## Runbook Index

### Incident Response

| ID | Runbook | Severity | Key AWS Services | Frameworks |
|----|---------|----------|-----------------|------------|
| [RB-001](./runbooks/incident-response/RB-001-iam-privilege-escalation.md) | IAM Privilege Escalation | 🔴 Critical | IAM, CloudTrail, GuardDuty | NIST PR.AC-4 · CIS 5.4 · SOC2 CC6.1 |
| [RB-002](./runbooks/incident-response/RB-002-s3-data-exposure.md) | S3 Bucket Data Exposure | 🔴 Critical | S3, Macie, CloudTrail | PCI Req 3 · NIST PR.DS-5 · GDPR Art 33 |
| [RB-003](./runbooks/incident-response/RB-003-exposed-api-keys.md) | Exposed API Keys | 🟠 High | IAM, Secrets Manager | CIS 14.8 · NIST PR.DS-2 |
| [RB-004](./runbooks/incident-response/RB-004-ransomware-response.md) | Ransomware Response | 🔴 Critical | EC2, EBS, VPC, S3 | NIST RS.RP-1 · ISO 27001 A.16.1 |
| [RB-011](./runbooks/incident-response/RB-011-ec2-metadata-ssrf.md) | EC2 Metadata SSRF (IMDSv1) | 🔴 Critical | EC2, IAM, GuardDuty | NIST PR.PT-3 · CIS 4.6 · MITRE T1552.005 |
| [RB-012](./runbooks/incident-response/RB-012-root-account-usage.md) | Root Account Usage Detected | 🔴 Critical | IAM, CloudTrail, Organizations | CIS 5.4 · PCI Req 7.2 · SOC2 CC6.3 |
| [RB-013](./runbooks/incident-response/RB-013-cryptomining-detection.md) | Cryptomining Detection | 🟠 High | EC2, GuardDuty, Cost Explorer | NIST DE.CM-4 · CIS 10.1 · MITRE T1496 |
| [RB-016](./runbooks/incident-response/RB-016-terraform-state-exposure.md) | Terraform State File Exposure | 🔴 Critical | S3, IAM, KMS | NIST PR.DS-5 · CIS 3.3 · ISO 27001 A.9.4.3 |

### Misconfigurations

| ID | Runbook | Severity | Key AWS Services | Frameworks |
|----|---------|----------|-----------------|------------|
| [RB-005](./runbooks/misconfigurations/RB-005-security-group-open-internet.md) | Security Group Open to Internet | 🟠 High | EC2, VPC | CIS 12.2 · PCI Req 1.3 · SOC2 CC6.6 |
| [RB-006](./runbooks/misconfigurations/RB-006-mfa-not-enforced.md) | MFA Not Enforced | 🟠 High | IAM, Organizations | CIS 6.3 · PCI Req 8.4 · SOC2 CC6.1 |
| [RB-007](./runbooks/misconfigurations/RB-007-cloudtrail-logging-gap.md) | CloudTrail Logging Gap | 🟡 Medium | CloudTrail, S3, CloudWatch | CIS 8.2 · SOC2 CC7.2 · PCI Req 10 |
| [RB-014](./runbooks/misconfigurations/RB-014-lambda-misconfiguration.md) | Lambda Function URL Exposure | 🟠 High | Lambda, IAM, Secrets Manager | NIST PR.AC-3 · CIS 4.1 |
| [RB-015](./runbooks/misconfigurations/RB-015-eks-misconfiguration.md) | EKS Public Endpoint / Container Security | 🟠 High | EKS, EC2, ECR | NIST PR.AC-5 · CIS EKS Benchmark |
| [RB-017](./runbooks/misconfigurations/RB-017-cross-account-role-misconfiguration.md) | Cross-Account Role Trust Misconfiguration | 🔴 Critical | IAM, Access Analyzer, Organizations | NIST PR.AC-4 · CIS 6.8 · ISO 27001 A.9.1.2 |

### Governance

| ID | Runbook | Category | Key AWS Services | Frameworks |
|----|---------|----------|-----------------|------------|
| [RB-008](./runbooks/governance/RB-008-cspm-alert-triage.md) | CSPM Alert Triage | Posture | Security Hub, Config | NIST DE.CM-8 · CIS 4.1 |
| [RB-009](./runbooks/governance/RB-009-soc2-evidence-collection.md) | SOC 2 Evidence Collection | Audit | IAM, CloudTrail, GuardDuty | SOC 2 CC6, CC7, CC8 |
| [RB-010](./runbooks/governance/RB-010-pci-scope-violation.md) | PCI-DSS Scope Violation | Compliance | Macie, VPC, CloudTrail | PCI-DSS v4.0 |
| [RB-018](./runbooks/governance/RB-018-cost-anomaly-security-signal.md) | Cost Anomaly as Security Signal | Detection | Cost Explorer, Budgets, CloudTrail | NIST DE.AE-1 · CIS 13.1 |

---

## Evidence Library

Each runbook has a corresponding folder in `evidence/` for storing incident artifacts. The library follows audit-grade evidence standards:

- **Naming convention:** `YYYY-MM-DD_INC-XXXX_<description>.<ext>`
- **Integrity:** SHA-256 hashes recorded per artifact
- **Retention:** Incident records 3 years · SOC 2 2 years · PCI 1 year minimum
- **Immutability:** Production evidence in S3 with Object Lock (COMPLIANCE mode)

### Evidence Templates

| Template | Used For |
|----------|---------|
| `sample-guardduty-finding.json` | GuardDuty finding — SOC 2 CC7.2, PCI Req 10.7 |
| `sample-cloudtrail-event.json` | CloudTrail sequence — SOC 2 CC7.2, PCI Req 10.2 |
| `sample-credential-report.csv` | IAM credential report — SOC 2 CC6.1, PCI Req 8.4 |
| `sample-config-compliance.json` | AWS Config output — SOC 2 CC7.1, CIS Benchmark |
| `incident-evidence-package.md` | Full evidence package with chain of custody |

---

## Severity Reference

| Level | Label | Contain Within | Notify |
|-------|-------|---------------|--------|
| 🔴 | Critical | 1 hour | CISO within 15 min |
| 🟠 | High | 4 hours | Security Lead within 30 min |
| 🟡 | Medium | 24 hours | Security team next business day |
| 🔵 | Low | 7 days | Tracked in backlog |
| ℹ️ | Info | Next sprint | Scheduled |

---

## Frameworks Covered

| Framework | Version | Coverage |
|-----------|---------|----------|
| NIST CSF | 2.0 (Feb 2024) | All 6 functions — GV, ID, PR, DE, RS, RC |
| CIS Controls | v8 | All 18 controls, Implementation Groups 1–3 |
| CIS AWS Foundations Benchmark | 3.0 | Account-level baseline configuration |
| SOC 2 Type II | 2017 TSC | CC6, CC7, CC8 |
| PCI-DSS | v4.0 | Requirements 1, 3, 4, 7, 8, 10, 11, 12 |
| ISO 27001 | 2022 | Annex A controls referenced per runbook |
| MITRE ATT&CK | v14 | Technique IDs in relevant runbooks |

---

## Suggested Next Runbooks

| ID | Topic |
|----|-------|
| RB-019 | GuardDuty full finding-type triage guide |
| RB-020 | AWS Organizations SCP governance |
| RB-021 | VPC endpoint misconfiguration and data exfiltration |
| RB-022 | KMS key deletion / accidental rotation response |
| RB-023 | ECR image with critical CVEs — supply chain |
| RB-024 | ISO 27001 evidence collection |

---

## Background

Built while studying cloud security after working in financial audit and accounting. The governance and compliance sections apply that experience to evidence collection, control-to-framework mapping, and audit trail practices.

The evidence library structure is directly modelled on financial audit evidence preparation: population → sample → evidence → management assertion. The same logic applies to SOC 2 and PCI-DSS.

---

## Stats

**18 runbooks** · **23 evidence files** · **3 architecture docs** · **3 framework mappings** · **405 KB**

---

*Maintained by Jabulani Meki (https://github.com/Jabu-Meki) · MIT License · Last reviewed Q4 2026*
