# Evidence Library

This folder contains evidence packages for security incidents and compliance audits. Each subfolder maps to a runbook or compliance framework and holds the artifacts an auditor, CISO, or regulator would request.

---

## Structure

```
evidence/
├── README.md                          ← This file
│
├── incident-response/                 ← Post-incident evidence packages
│   ├── RB-001-iam-privilege-escalation/
│   ├── RB-002-s3-data-exposure/
│   ├── RB-003-exposed-api-keys/
│   ├── RB-004-ransomware-response/
│   ├── RB-011-ec2-metadata-ssrf/
│   ├── RB-012-root-account-usage/
│   ├── RB-013-cryptomining/
│   └── RB-016-terraform-state-exposure/
│
├── misconfigurations/                 ← Remediation evidence
│   ├── RB-005-security-group/
│   ├── RB-006-mfa/
│   ├── RB-007-cloudtrail/
│   ├── RB-014-lambda/
│   ├── RB-015-eks/
│   └── RB-017-cross-account-role/
│
├── governance/                        ← Audit and compliance evidence
│   ├── RB-008-cspm/
│   ├── RB-009-soc2/
│   └── RB-010-pci/
│
└── templates/                         ← Blank evidence package templates
    ├── incident-evidence-package.md
    ├── sample-guardduty-finding.json
    ├── sample-cloudtrail-event.json
    ├── sample-credential-report.csv
    └── sample-config-compliance.json
```

---

## Evidence Standards

### Naming Convention

All evidence files must follow this naming pattern:

```
YYYY-MM-DD_<INCIDENT-OR-TICKET-ID>_<description>.<ext>
```

Examples:
```
2025-01-15_INC-2025-001_guardduty-finding.json
2025-01-15_INC-2025-001_cloudtrail-export.json
2025-01-15_INC-2025-001_iam-credential-report.csv
2025-01-15_INC-2025-001_containment-screenshot.png
2025-01-15_INC-2025-001_remediation-screenshot.png
```

### What to Collect for Every Incident

| Evidence Item | Format | Mandatory |
|-------------|--------|-----------|
| GuardDuty finding (raw JSON) | .json | Yes |
| CloudTrail events (incident window) | .json | Yes |
| Incident timeline | .md | Yes |
| Containment actions with timestamps | .md | Yes |
| Before/after configuration state | .json or .png | Yes |
| Remediation evidence | .json or .png | Yes |
| Post-incident review | .md | Yes (within 72h) |

### What to Collect for Compliance Audits

| Evidence Item | Framework | Frequency |
|-------------|-----------|----------|
| IAM credential report | SOC 2 CC6.1, PCI Req 8.4 | Monthly |
| MFA compliance Config rule status | SOC 2 CC6.1, CIS 6.3 | Monthly |
| CloudTrail status | SOC 2 CC7.2, CIS 8.2 | Monthly |
| GuardDuty findings summary | SOC 2 CC7.2 | Monthly |
| Security Hub compliance score | All frameworks | Monthly |
| Access review completion records | SOC 2 CC6.3 | Quarterly |
| Incident register | SOC 2 CC7.3 | Ongoing |
| Vulnerability scan results | SOC 2 CC7.1, PCI Req 11.3 | Monthly |

---

## Retention Policy

| Evidence Type | Minimum Retention | Rationale |
|-------------|------------------|-----------|
| Security incident records | 3 years | Legal and regulatory |
| SOC 2 audit evidence | 2 years | Auditor bridge letter requirement |
| PCI-DSS evidence | 1 year (minimum) | PCI DSS Req 10.7 |
| GDPR breach records | 3 years (UK/EU) | GDPR Art 33 |
| CloudTrail logs (raw) | 1 year hot + 6 years cold | CIS 8.10, PCI Req 10.7 |
| Access reviews | 2 years | SOC 2 CC6.3 |

---

## Evidence Integrity

All evidence must be stored in an immutable location. In production:

- **CloudTrail logs:** S3 with Object Lock (COMPLIANCE mode), log integrity validation enabled
- **Incident evidence packages:** Uploaded to a separate evidence S3 bucket with Object Lock before the incident is closed
- **Screenshots:** Hash the file (SHA-256) and record the hash in the incident report

```bash
# Generate SHA-256 hash for a screenshot before storing
sha256sum 2025-01-15_INC-2025-001_remediation-screenshot.png
# Record output in the incident report under "Evidence hashes"
```

---

*Student project evidence examples. Apply your organisation's approved retention and handling requirements to real evidence.*
