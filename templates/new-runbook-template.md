# RB-NNN — [Runbook Title]

![Severity](https://img.shields.io/badge/Severity-CRITICAL|HIGH|MEDIUM|LOW-red|orange|yellow|blue?style=flat)
![Category](https://img.shields.io/badge/Category-Incident_Response|Misconfiguration|Governance-blueviolet|yellow|blue?style=flat)
![Service](https://img.shields.io/badge/AWS-Service1_·_Service2-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF XX.XX · CIS Controls X.X · SOC 2 CCX.X · PCI-DSS Req X

---

## Overview

_1–2 paragraphs describing what this runbook covers. Include: what triggers it, what the risk is, and what the impact looks like if not contained._

---

## Prerequisites

- _What access is needed to run this runbook?_
- _What tools or services must be enabled?_
- _What documentation should exist before starting?_

---

## Detection Signals

```
AWS Config rule:  <rule-name>
Security Hub:     [SERVICE.N] Description
GuardDuty:        FindingType:Service/Description
```

---

## Phase 1 — Detection & Triage

> **Goal:** _State the goal of this phase in one sentence._

### 1.1 Step title

_Description of what this step does and why._

```bash
# Command with inline comments
aws service command \
  --parameter value \
  --query 'Output.Field'
```

> ⚠️ _Note any important warnings, sequencing requirements, or gotchas._

### 1.2 Step title

_Description._

```bash
aws service command
```

---

## Phase 2 — Containment

> **Goal:** Stop the attack or exposure without destroying evidence.

### 2.1 Step title

```bash
aws service command
```

### 2.2 Step title

```bash
aws service command
```

---

## Phase 3 — Eradication

> **Goal:** Remove the root cause and all attacker-controlled resources.

### 3.1 Step title

```bash
aws service command
```

---

## Phase 4 — Recovery

_Describe recovery actions. Include validation steps to confirm the system is back to a known-good state._

```bash
aws service command
```

---

## Phase 5 — Post-Incident

### Required documentation

- [ ] Timeline of events
- [ ] Root cause analysis
- [ ] Blast radius / data impact assessment
- [ ] Evidence package saved to immutable storage
- [ ] Control gaps identified
- [ ] Remediation backlog items created

### Governance notes

- **Framework X, Control Y:** _How this incident relates to the framework requirement_
- Escalation requirements: _When to notify CISO, legal, regulators_
- Evidence retention: _How long to keep the incident evidence package_

---

## Prevention

| Control | Implementation | Priority |
|---------|---------------|----------|
| | | High / Medium / Low |

---

## Related Runbooks

- `RB-NNN-title.md` (replace with related runbook paths)

---

_Last reviewed: YYYY-MM · Maintainer: Student project · Severity: [SEVERITY]_
