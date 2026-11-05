# Evidence Package — [INCIDENT-ID or AUDIT-PERIOD]

> Copy this file into the relevant evidence subfolder and complete every section. An incomplete evidence package cannot support an audit finding or incident closure.

---

## Package Header

| Field | Value |
|-------|-------|
| Package ID | EVP-YYYY-NNN |
| Related Incident / Audit | INC-YYYY-NNN or SOC2-YYYY-QN |
| Runbook Used | RB-NNN — [Title] |
| Evidence Collector | Name |
| Collection Date | YYYY-MM-DD |
| Review Date | YYYY-MM-DD |
| Reviewer | Name |
| Retention Expiry | YYYY-MM-DD (see retention policy) |
| Storage Location | s3://evidence-bucket/[path] |

---

## Evidence Index

List every file in this package with its hash for integrity verification.

| Filename | Type | SHA-256 Hash | Collected At |
|----------|------|-------------|-------------|
| YYYY-MM-DD_INC-XXX_guardduty-finding.json | GuardDuty finding | `sha256:...` | HH:MM UTC |
| YYYY-MM-DD_INC-XXX_cloudtrail-export.json | CloudTrail events | `sha256:...` | HH:MM UTC |
| YYYY-MM-DD_INC-XXX_before-config.json | Pre-remediation config | `sha256:...` | HH:MM UTC |
| YYYY-MM-DD_INC-XXX_after-config.json | Post-remediation config | `sha256:...` | HH:MM UTC |
| YYYY-MM-DD_INC-XXX_timeline.md | Incident timeline | `sha256:...` | HH:MM UTC |

Generate hash: `sha256sum <filename>`

---

## Evidence Descriptions

### 1. Detection Evidence

**File:** `YYYY-MM-DD_INC-XXX_guardduty-finding.json`

_Describe what this file shows and its significance._

```bash
# Command used to collect:
aws guardduty get-findings --detector-id $DID --finding-ids $FID > YYYY-MM-DD_INC-XXX_guardduty-finding.json
```

**Key fields:**
- Finding type: 
- Severity: 
- Affected resource: 
- Source IP: 
- First seen: 
- Last seen: 

---

### 2. Scope Evidence

**File:** `YYYY-MM-DD_INC-XXX_cloudtrail-export.json`

_Describe what API calls were made, by whom, and from where._

```bash
# Command used to collect:
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USER> \
  --start-time <ISO_START> \
  --end-time <ISO_END> > YYYY-MM-DD_INC-XXX_cloudtrail-export.json
```

**Key events in this file:**
- 
- 

---

### 3. Pre-Remediation State

**File:** `YYYY-MM-DD_INC-XXX_before-config.json`

_Document the misconfigured/compromised state before any changes._

```bash
# Command used to collect:
# <insert command>
```

---

### 4. Containment Evidence

**File:** `YYYY-MM-DD_INC-XXX_containment-actions.md`

_Document every containment action with timestamp and executor._

| Time (UTC) | Action | Executed By | Command/Reference |
|-----------|--------|------------|------------------|
| | | | |

---

### 5. Post-Remediation State

**File:** `YYYY-MM-DD_INC-XXX_after-config.json`

_Confirm remediation was successful._

```bash
# Command used to verify:
# <insert command>
```

**Result confirms:**
- [ ] Configuration is now correct
- [ ] No further anomalous activity observed
- [ ] Monitoring enhanced for re-detection

---

### 6. Screenshots

List any screenshots taken (name, what it shows, why it was captured):

| Filename | Content | Captured At |
|----------|---------|------------|
| | | |

---

## Auditor Notes

_Any additional context an auditor would need to understand this evidence package without reading the full incident report._

---

## Framework Mapping

| Evidence Item | NIST CSF | CIS Control | SOC 2 | PCI-DSS |
|-------------|---------|------------|-------|---------|
| GuardDuty finding | DE.AE-5 | 8.11 | CC7.2 | Req 10.7 |
| CloudTrail export | DE.AE-3 | 8.2 | CC7.2 | Req 10.2 |
| Remediation evidence | RS.MI-2 | 7.2 | CC7.4 | Req 11.5 |

---

## Chain of Custody

| Transfer | From | To | Method | Date | Authorised By |
|---------|------|-----|--------|------|--------------|
| Initial collection | Responder workstation | Evidence S3 bucket | aws s3 cp | | |
| Auditor access | Evidence S3 bucket | Auditor portal | Pre-signed URL | | |

---

*Evidence package template v1.0 · Follows NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response*
