# Incident Report — [INCIDENT-ID]

> Copy this template for every declared security incident. Save completed reports in your evidence store.

---

## Header

| Field | Value |
|-------|-------|
| Incident ID | INC-YYYY-NNN |
| Title | Brief description |
| Severity | P1 / P2 / P3 / P4 |
| Status | Open / Contained / Resolved / Closed |
| Declared by | Name |
| Declared at | YYYY-MM-DD HH:MM UTC |
| Resolved at | YYYY-MM-DD HH:MM UTC |
| Total duration | HH hours MM minutes |
| Runbook used | RB-NNN — [Title] |
| Ticket | JIRA-XXXX |

---

## Executive Summary

_2–3 sentences. What happened, what was the impact, what was done._

---

## Timeline

| Time (UTC) | Action | Who |
|-----------|--------|-----|
| HH:MM | Alert received from [GuardDuty / SIEM / user report] | |
| HH:MM | Initial triage started | |
| HH:MM | Incident declared | |
| HH:MM | CISO notified | |
| HH:MM | Containment complete | |
| HH:MM | Eradication complete | |
| HH:MM | Recovery complete | |
| HH:MM | Incident resolved | |

---

## Detection

**Source:** GuardDuty / Security Hub / SIEM / User report / Other

**Finding type:** _(e.g., PrivilegeEscalation:IAMUser/AdministrativePermissions)_

**Time from event to detection:** _(minutes / hours)_

---

## Root Cause

_What was the underlying cause? Be specific. "Misconfigured IAM policy" is not enough — describe which policy, how it was misconfigured, and why the misconfiguration occurred._

---

## Impact Assessment

**Systems affected:**

| System | Impact | Duration |
|--------|--------|---------|
| | | |

**Data affected:**

- Personal data involved: Yes / No
- PCI cardholder data involved: Yes / No
- Regulatory notification required: Yes / No / TBD

**Business impact:**

- Service disruption: Yes / No — Duration: 
- Financial impact: Estimated / Confirmed: 
- Reputational impact: Low / Medium / High

---

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP address | | |
| IAM Access Key ID | | |
| User agent | | |
| S3 bucket/path | | |

---

## Actions Taken

### Containment

- [ ] Action taken — timestamp — who

### Eradication

- [ ] Action taken — timestamp — who

### Recovery

- [ ] Action taken — timestamp — who

---

## Evidence Collected

| Evidence item | Location | Collected by | Time |
|-------------|---------|-------------|------|
| CloudTrail export | s3://evidence-bucket/INC-YYYY-NNN/ | | |
| GuardDuty finding export | | | |
| VPC flow logs | | | |
| IAM credential report | | | |
| Screenshots | | | |

---

## Control Gaps Identified

_What controls, if in place, would have prevented or limited this incident?_

| Gap | Recommended Control | Priority | Owner | Due Date |
|-----|-------------------|---------|-------|---------|
| | | | | |

---

## Lessons Learned

_Honest assessment. What went well? What could be improved?_

**What went well:**

**What could be improved:**

**What was unclear during the response:**

---

## Follow-up Actions

| Action | Owner | Due Date | Status |
|--------|-------|---------|--------|
| | | | |

---

## Approvals

| Role | Name | Date |
|------|------|------|
| Incident Commander | | |
| Cloud Security Lead | | |
| CISO | | |

---

_Template version: 1.0 · Based on NIST SP 800-61r2 incident handling framework_
