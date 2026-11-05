# AWS Shared Responsibility Model

Understanding where AWS's responsibility ends and the customer's begins is foundational to security decisions in the cloud.

---

## The Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                     CUSTOMER RESPONSIBILITY                         │
│                    "Security IN the Cloud"                          │
│                                                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│  │   YOUR DATA     │  │  YOUR PLATFORM  │  │  YOUR IDENTITY  │    │
│  │                 │  │                 │  │                 │    │
│  │ Classification  │  │ OS patching     │  │ IAM policies    │    │
│  │ Encryption      │  │ App security    │  │ MFA             │    │
│  │ Access controls │  │ Runtime config  │  │ Access reviews  │    │
│  │ Backup policy   │  │ Network config  │  │ Least privilege │    │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  YOUR COMPLIANCE                                            │   │
│  │  Evidence collection · Audit management · Policy adherence  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘

════════════════════ SHARED RESPONSIBILITY BOUNDARY ═════════════════

┌─────────────────────────────────────────────────────────────────────┐
│                       AWS RESPONSIBILITY                            │
│                    "Security OF the Cloud"                          │
│                                                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │
│  │   COMPUTE       │  │    STORAGE      │  │   NETWORKING    │    │
│  │                 │  │                 │  │                 │    │
│  │ Hypervisor      │  │ S3 durability   │  │ Global network  │    │
│  │ Host OS         │  │ EBS replication │  │ Edge locations  │    │
│  │ Hardware        │  │ Hardware        │  │ Undersea cables │    │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  GLOBAL INFRASTRUCTURE                                      │   │
│  │  Data centres · Physical security · Power · Cooling         │   │
│  │  Region redundancy · Availability Zone design               │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Responsibility by Service Type

The boundary shifts depending on which AWS service you use. More managed = more AWS responsibility = less operational burden on you, but you still own identity, data, and compliance.

### IaaS — EC2 (most customer responsibility)

```
AWS responsible for:          Customer responsible for:
├── Physical hardware          ├── Guest OS (patching, hardening)
├── Hypervisor                 ├── Application code and config
├── Host OS                    ├── Security groups and NACLs
├── Physical network           ├── IAM roles and policies
└── Availability Zones         ├── Data encryption
                               ├── EBS volume encryption
                               └── AMI selection and hardening
```

### PaaS — RDS (shared responsibility)

```
AWS responsible for:          Customer responsible for:
├── Database engine patching   ├── Database user accounts
├── Hardware / host OS         ├── Network access (security groups)
├── Automated backups          ├── Encryption at rest (opt-in)
├── Multi-AZ failover          ├── Encryption in transit (TLS)
└── Storage durability         └── What data you store and who accesses it
```

### SaaS — S3 (least customer responsibility for infrastructure)

```
AWS responsible for:          Customer responsible for:
├── Storage durability (11 9s) ├── Bucket policies and ACLs
├── Hardware                   ├── Block Public Access settings
├── Replication                ├── Encryption settings
└── Availability               ├── Object lifecycle policies
                               ├── Access logging
                               └── Data classification
```

### Managed services — Lambda, DynamoDB, ECS Fargate

```
AWS responsible for:          Customer responsible for:
├── Runtime patching           ├── Execution role permissions
├── Scaling infrastructure     ├── Application code security
├── Availability               ├── Environment variable secrets
└── Host isolation             └── Data in/out of the function
```

---

## The Compliance Responsibility — Often Misunderstood

A critical point: **AWS holds certifications (SOC 2, ISO 27001, PCI-DSS), but you must independently achieve your own compliance.**

AWS's certifications prove that the infrastructure layer meets those standards. They do NOT:
- Cover your application running on EC2
- Cover your IAM configuration
- Cover your data classification practices
- Substitute for your own audit evidence

What you get from AWS to support your compliance:
- **AWS Artifact** — downloadable compliance reports (SOC 2 report, ISO certificate, PCI AOC)
- **Shared responsibility documentation** — defines what AWS covers in each certification
- **AWS Config** — continuous evidence of your configuration state
- **CloudTrail** — audit log of all API calls (your evidence, not AWS's)
- **AWS Audit Manager** — automated evidence collection mapped to frameworks

---

## Responsibility Mapping by Framework

### PCI-DSS — Who does what?

| Requirement | AWS Handles | Customer Handles |
|-------------|------------|-----------------|
| Req 1 — Firewall | Physical network isolation | Security groups, NACLs, WAF rules |
| Req 2 — No defaults | Hardware defaults | OS hardening, application defaults |
| Req 3 — Protect CHD | Physical storage security | Encryption at rest, key management |
| Req 4 — Encrypt transit | Network infrastructure | TLS configuration, certificate management |
| Req 6 — Secure systems | Managed service patching | EC2 OS patching, code security |
| Req 7 — Access control | Physical access | IAM policies, least privilege |
| Req 8 — Authentication | N/A | IAM users, MFA, access keys |
| Req 10 — Logging | Physical access logs | CloudTrail, application logs |
| Req 11 — Testing | N/A | Penetration testing, vulnerability scanning |
| Req 12 — Policy | N/A | Security programme, incident response |

### SOC 2 — Shared responsibility

| TSC | AWS Evidence Available | Customer Evidence Required |
|-----|----------------------|--------------------------|
| CC6.1 — Logical access | AWS physical access controls | IAM policies, MFA, access reviews |
| CC6.6 — Network controls | AWS network infrastructure | Security groups, WAF, VPC design |
| CC7.1 — Vulnerability scanning | AWS platform patching | Inspector, EC2 OS patching |
| CC7.2 — Monitoring | AWS infrastructure monitoring | CloudTrail, GuardDuty, SIEM |
| A1.2 — Availability | AWS SLAs, multi-AZ | Application architecture, backups |

---

## Common Misconceptions

**"AWS is ISO 27001 certified so we are too."**
No. AWS's ISO certificate covers the infrastructure layer. You need your own certificate for your application and data handling practices.

**"AWS manages security groups so that's AWS's responsibility."**
No. AWS provides the security group feature; configuring the rules is your responsibility. An open 0.0.0.0/0 rule is your misconfiguration, not AWS's.

**"AWS encrypts our data."**
Partially. AWS encrypts data in transit on its network backbone and offers encryption at rest features (SSE-S3, SSE-KMS). But enabling encryption on your S3 buckets, RDS instances, and EBS volumes — and managing the KMS keys — is your responsibility.

**"If AWS has a SOC 2 report, we don't need our own."**
No. AWS's SOC 2 report covers CC controls related to the infrastructure. Your auditor will require evidence for how your team manages IAM, monitors systems, responds to incidents, and reviews access.

---

---

*Last reviewed: Q1 2025 · Reference: AWS Shared Responsibility Model (aws.amazon.com/compliance/shared-responsibility-model)*
