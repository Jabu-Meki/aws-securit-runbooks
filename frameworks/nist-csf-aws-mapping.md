# NIST CSF 2.0 — AWS Service Mapping

Maps NIST Cybersecurity Framework 2.0 functions and categories to AWS services and native controls. Use it to explore gap assessments and security programme planning.

---

## NIST CSF 2.0 Functions

NIST CSF 2.0 (released 2024) added a sixth function — **Govern** — to the original five.

```
GOVERN  →  IDENTIFY  →  PROTECT  →  DETECT  →  RESPOND  →  RECOVER
  GV          ID           PR         DE          RS          RC
```

---

## GV — Govern

The newest function. Establishes cybersecurity risk management strategy, expectations, and policy.

| Category | Subcategory | AWS Mapping |
|---------|-------------|-------------|
| GV.OC — Organisational Context | GV.OC-1: Mission, stakeholders | AWS Security Hub — security posture dashboard |
| GV.RM — Risk Management | GV.RM-1: Risk strategy established | AWS Audit Manager — risk framework mapping |
| GV.RM — Risk Management | GV.RM-2: Risk appetite defined | AWS Config rules — enforce risk thresholds |
| GV.SC — Supply Chain | GV.SC-3: Third-party cyber risk | AWS Marketplace seller vetting; Inspector for third-party images |
| GV.PO — Policy | GV.PO-1: Policy established | AWS Organizations SCPs — policy-as-code |
| GV.RR — Roles & Responsibilities | GV.RR-2: Roles assigned | IAM roles with clear naming and tagging conventions |

---

## ID — Identify

Understanding your assets, risks, and exposure.

| Category | Subcategory | AWS Mapping |
|---------|-------------|-------------|
| ID.AM — Asset Management | ID.AM-1: Physical assets inventoried | AWS Config — resource inventory across all accounts/regions |
| ID.AM — Asset Management | ID.AM-2: Software assets inventoried | Systems Manager Inventory, Inspector SBOM |
| ID.AM — Asset Management | ID.AM-3: Network maps maintained | VPC topology in AWS Console; Network Manager |
| ID.AM — Asset Management | ID.AM-5: Resources prioritised by criticality | Resource tagging strategy (Environment, DataClass, CriticalityTier) |
| ID.AM — Asset Management | ID.AM-8: Systems use logged | CloudTrail; Config configuration history |
| ID.RA — Risk Assessment | ID.RA-1: Vulnerabilities identified | Amazon Inspector (CVEs for EC2, Lambda, containers) |
| ID.RA — Risk Assessment | ID.RA-2: Threat intelligence received | AWS Security Hub (integrates threat intel feeds); GuardDuty threat intel |
| ID.RA — Risk Assessment | ID.RA-3: Internal and external threats identified | GuardDuty; Security Hub findings |
| ID.RA — Risk Assessment | ID.RA-6: Risk response prioritised | Security Hub severity scoring; custom CSPM scoring |
| ID.IM — Improvement | ID.IM-1: Improvements identified | Security Hub recommendations; Trusted Advisor |

---

## PR — Protect

Safeguards to limit impact of cybersecurity events.

### PR.AA — Identity Management, Authentication, and Access Control

| Subcategory | AWS Mapping | Implementation |
|-------------|-------------|---------------|
| PR.AA-1: Identities and credentials managed | IAM Identity Center | Centralised identity with SSO; no local IAM users |
| PR.AA-2: Identities proofed | IAM Identity Center + IdP (Okta/Entra) | Identity federation with strong authentication at IdP |
| PR.AA-3: Users authenticated | IAM + MFA enforcement | SCP: deny all actions if `aws:MultiFactorAuthPresent = false` |
| PR.AA-4: Identity assertions protected | STS short-lived tokens | Roles vs long-lived keys; max 12h session duration |
| PR.AA-5: Access permissions managed | IAM least-privilege | IAM Access Analyzer; quarterly access reviews |
| PR.AA-6: Physical access managed | AWS physical security | In-scope for AWS's responsibility (see shared responsibility model) |

### PR.AT — Awareness and Training

| Subcategory | AWS Mapping |
|-------------|-------------|
| PR.AT-1: Personnel trained | AWS Security Hub Security Score as team KPI; internal runbook training |
| PR.AT-2: Privileged users trained | Documented runbooks (this library); tabletop exercises |

### PR.DS — Data Security

| Subcategory | AWS Mapping | Implementation |
|-------------|-------------|---------------|
| PR.DS-1: Data at rest protected | KMS, S3 SSE, EBS encryption, RDS encryption | Default encryption on all storage; CMKs for regulated data |
| PR.DS-2: Data in transit protected | TLS, ACM | `aws:SecureTransport` deny condition; ACM for certificate management |
| PR.DS-10: Data integrity ensured | S3 Object Lock, CloudTrail log validation | COMPLIANCE mode Object Lock on audit data |
| PR.DS-11: Backups managed | AWS Backup, S3 versioning | Cross-account backup vault; 35-day RDS automated backups |

### PR.IR — Incident Response Preparation *(see RS function)*

### PR.PS — Platform Security

| Subcategory | AWS Mapping | Implementation |
|-------------|-------------|---------------|
| PR.PS-1: Config managed as code | CloudFormation, Terraform, CDK | IaC in version control; no manual console changes in prod |
| PR.PS-2: Software maintained | Systems Manager Patch Manager | Automated patching on maintenance windows; Inspector for CVEs |
| PR.PS-3: Hardware maintained | AWS responsibility | Managed under shared responsibility model |
| PR.PS-4: Logs collected | CloudTrail, VPC Flow Logs, CloudWatch | Multi-region trail; flow logs on all VPCs |
| PR.PS-5: Software installation controlled | Systems Manager, approved AMI catalogue | Only approved AMIs via SCP; SSM for software installation |

### PR.IR — Technology Infrastructure Resilience

| Subcategory | AWS Mapping |
|-------------|-------------|
| PR.IR-1: Networks protected | Security groups, NACLs, WAF, Shield |
| PR.IR-2: Environment isolated | Multi-account strategy; VPC segmentation; PrivateLink |
| PR.IR-3: Mechanisms tested | Chaos engineering; Game Days; DR tests |
| PR.IR-4: Adequate resources ensured | Auto Scaling; Reserved Capacity; Multi-AZ |

---

## DE — Detect

Timely discovery of cybersecurity events.

| Category | Subcategory | AWS Mapping | Config |
|---------|-------------|-------------|--------|
| DE.AE — Adverse Events Analysis | DE.AE-2: Events correlated | Security Hub; Amazon Detective | Aggregate all findings into Security Hub |
| DE.AE — Adverse Events Analysis | DE.AE-3: Data collected | CloudTrail, VPC Flow Logs, CloudWatch | Centralise all logs; retain 1+ year |
| DE.AE — Adverse Events Analysis | DE.AE-4: Impact estimated | Security Hub severity; GuardDuty finding details | Severity thresholds → PagerDuty escalation |
| DE.AE — Adverse Events Analysis | DE.AE-5: Incidents declared | GuardDuty → EventBridge → SNS → PagerDuty | Automated alerting on HIGH/CRITICAL |
| DE.AE — Adverse Events Analysis | DE.AE-6: Information shared | Security Hub cross-account aggregation | Delegated admin account for multi-account |
| DE.CM — Continuous Monitoring | DE.CM-1: Networks monitored | VPC Flow Logs, GuardDuty | Flow logs on all VPCs; GuardDuty in all regions |
| DE.CM — Continuous Monitoring | DE.CM-3: Personnel activity monitored | CloudTrail; IAM Access Analyzer | User and role activity tracked per API call |
| DE.CM — Continuous Monitoring | DE.CM-6: External services monitored | GuardDuty (DNS queries, API calls to C2) | Threat intelligence feeds active |
| DE.CM — Continuous Monitoring | DE.CM-9: Vulnerability scans performed | Amazon Inspector | Continuous scanning — not periodic |

---

## RS — Respond

Taking action on detected incidents.

| Category | Subcategory | AWS Mapping |
|---------|-------------|-------------|
| RS.MA — Incident Management | RS.MA-1: Incidents investigated | Amazon Detective (automated investigation graph) |
| RS.MA — Incident Management | RS.MA-2: Incidents reported | Security Hub → SNS → PagerDuty/Slack |
| RS.MA — Incident Management | RS.MA-3: Incidents categorised | Security Hub severity labels; runbook severity matrix |
| RS.MA — Incident Management | RS.MA-5: Incidents closed | Security Hub workflow status → RESOLVED |
| RS.AN — Incident Analysis | RS.AN-3: Forensics performed | CloudTrail export; EBS snapshots; VPC flow log analysis |
| RS.AN — Incident Analysis | RS.AN-6: Actions catalogued | Incident report template; CloudTrail immutable record |
| RS.CO — Incident Communication | RS.CO-2: Personnel notified | SNS → email/PagerDuty; defined escalation path |
| RS.CO — Incident Communication | RS.CO-3: Information shared | AWS Security Hub cross-account; ISAC participation |
| RS.MI — Incident Mitigation | RS.MI-1: Incidents contained | IAM deny policies; SG quarantine; GuardDuty block list |
| RS.MI — Incident Mitigation | RS.MI-2: Incidents eradicated | IAM key deletion; EC2 termination; Config remediation |

---

## RC — Recover

Restoring capabilities after an incident.

| Category | Subcategory | AWS Mapping |
|---------|-------------|-------------|
| RC.RP — Incident Recovery Plan | RC.RP-1: Recovery executed | AWS Backup restore; RDS point-in-time recovery |
| RC.RP — Incident Recovery Plan | RC.RP-3: Security measures restored | Reapply SCPs, security groups from IaC |
| RC.RP — Incident Recovery Plan | RC.RP-6: Incidents documented | Post-incident review; incident report template |
| RC.CO — Incident Recovery Communication | RC.CO-3: Recovery communicated | Status page; stakeholder update cadence |

---

## NIST CSF Maturity Self-Assessment

Use this to assess your current state and identify gaps. Rate each function 1–4:

| Score | Level | Description |
|-------|-------|-------------|
| 1 | Partial | Ad hoc, reactive. No formal process. |
| 2 | Risk-Informed | Risk awareness exists but inconsistently applied. |
| 3 | Repeatable | Formally approved processes, consistently applied. |
| 4 | Adaptive | Adaptive, continuously improving, lessons learned fed back. |

**Suggested learning target:** Work toward Level 3 across GV, ID, and PR, and Levels 2–3 across DE and RS.

---

## Further Reading

- [NIST CSF 2.0 full text](https://www.nist.gov/cyberframework)
- [AWS NIST CSF mapping on AWS Artifact](https://aws.amazon.com/compliance/nist/)
- [Framework crosswalk — multi-framework view](./framework-crosswalk.md)

---

*Last reviewed: Q1 2025 · Framework: NIST Cybersecurity Framework 2.0 (Feb 2024)*
