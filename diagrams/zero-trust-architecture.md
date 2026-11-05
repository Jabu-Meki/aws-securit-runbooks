# Zero Trust Architecture on AWS

Zero Trust is a security model built on the principle "never trust, always verify." Unlike traditional perimeter-based security (trust everything inside the network), Zero Trust assumes the network is already compromised and requires continuous verification of every access request regardless of source.

This document describes how to implement Zero Trust principles on AWS.

---

## Core Principles

| Principle | Traditional Perimeter | Zero Trust |
|-----------|----------------------|-----------|
| Default stance | Trust inside the network | Distrust everything, verify explicitly |
| Identity | Network location = identity | Identity verified per-request |
| Access | Broad access once authenticated | Least-privilege, per-resource access |
| Monitoring | Perimeter ingress/egress | All traffic, all sessions, continuously |
| Failure mode | Lateral movement possible | Blast radius contained per identity |

---

## Architecture Flow

```
┌────────────────────────────────────────────────────────────────────┐
│  STEP 1 — WHO ARE YOU?                                             │
│                                                                    │
│  User / Device / Workload                                          │
│       │                                                            │
│       ▼                                                            │
│  Identity Provider (IdP)                                           │
│  AWS IAM Identity Center · Okta · Entra ID                        │
│       │                                                            │
│  ┌────┴────────────────────────────────┐                           │
│  │  Verify:                           │                           │
│  │  ✓ Identity (username + password)  │                           │
│  │  ✓ MFA (TOTP / hardware / push)    │                           │
│  │  ✓ Device health (MDM compliance)  │                           │
│  │  ✓ Location (expected country/IP)  │                           │
│  └────────────────────────────────────┘                           │
└────────────────────────────┬───────────────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────────────┐
│  STEP 2 — WHAT CAN YOU DO?                                         │
│                                                                    │
│  Policy Engine                                                     │
│  AWS IAM · SCPs · Resource Policies                               │
│       │                                                            │
│  ┌────┴───────────────────────────────────────┐                   │
│  │  Evaluate:                                 │                   │
│  │  ✓ IAM permissions (what actions allowed?) │                   │
│  │  ✓ Resource policy (does resource allow?)  │                   │
│  │  ✓ SCP (does org policy permit?)           │                   │
│  │  ✓ Session conditions (MFA present?)       │                   │
│  │  ✓ Time/IP conditions if configured        │                   │
│  └────────────────────────────────────────────┘                   │
└────────────────────────────┬───────────────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────────────┐
│  STEP 3 — ACCESS GRANTED (SCOPED)                                  │
│                                                                    │
│  Short-lived credential issued (STS AssumeRole → 1h session)      │
│  Access to specific resource only                                  │
│  All actions logged to CloudTrail                                  │
│                                                                    │
│  Resource (EC2 / S3 / RDS / API Gateway / etc.)                   │
│  ├── Micro-segmented (only reachable from authorised sources)      │
│  ├── Encrypted in transit (TLS 1.2+) and at rest (KMS)            │
│  └── Monitored (VPC flow logs, GuardDuty, CloudWatch)             │
└────────────────────────────┬───────────────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────────────┐
│  STEP 4 — CONTINUOUS VERIFICATION                                  │
│                                                                    │
│  All access events → CloudTrail → SIEM                            │
│  Anomaly detection → GuardDuty                                     │
│  Credential validity re-checked per API call                       │
│  Session revoked if anomaly detected                               │
└────────────────────────────────────────────────────────────────────┘
```

---

## AWS Services That Enable Zero Trust

### Identity Layer

**AWS IAM Identity Center (SSO)**
- Central identity store or federation to Okta/Entra ID
- Single sign-on with short-lived credentials (no long-lived keys)
- MFA enforced at the IdP level
- Permission sets applied per account — not broad org-wide access

**IAM Roles + STS**
- No permanent credentials — all access via `AssumeRole` with time-limited tokens (default 1h, max 12h)
- Role chaining limited to necessary account boundaries
- `aws:MultiFactorAuthPresent` condition on sensitive actions

**IAM Conditions for Zero Trust policies:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::sensitive-bucket/*",
    "Condition": {
      "Bool": {
        "aws:MultiFactorAuthPresent": "true",
        "aws:SecureTransport": "true"
      },
      "StringEquals": {
        "aws:RequestedRegion": "eu-west-1"
      },
      "IpAddress": {
        "aws:SourceIp": ["10.0.0.0/8", "192.168.1.0/24"]
      },
      "DateGreaterThan": {
        "aws:CurrentTime": "2024-01-01T00:00:00Z"
      }
    }
  }]
}
```

---

### Network Layer — Software-Defined Perimeter

Traditional VPNs grant broad network access once connected. Zero Trust alternatives on AWS:

**AWS Verified Access**
- Application-level access without VPN
- Evaluates identity and device posture per request
- Integrates with IAM Identity Center and third-party IdPs
- Logs every access decision to CloudWatch / S3

```bash
# Create a Verified Access trust provider (IAM Identity Center)
aws ec2 create-verified-access-trust-provider \
  --trust-provider-type user \
  --user-trust-provider-type iam-identity-center \
  --policy-reference-name idc \
  --description "Zero Trust — IAM Identity Center provider"
```

**VPC Lattice (service-to-service Zero Trust)**
- Service-to-service authentication at the application layer
- Each service proves its identity via IAM before connecting
- No implicit trust based on VPC membership

**PrivateLink + VPC Endpoints**
- Access AWS services without traversing the internet
- Network access to specific service only — not broad VPC routing

---

### Workload Identity (No Human, No Keys)

For workload-to-workload authentication — the most common source of long-lived key exposure:

| Compute | Zero Trust Approach | How |
|---------|-------------------|-----|
| EC2 | IAM Instance Profile | Role attached to instance — STS auto-renews |
| Lambda | Execution Role | Role specified at function creation |
| ECS | Task Role | Per-task IAM role via task definition |
| EKS | IRSA | Service Account → IAM Role via OIDC |
| GitHub Actions | OIDC Federation | GitHub IdP → STS AssumeRoleWithWebIdentity |
| On-premises | IAM Roles Anywhere | PKI certificate → STS session |

**OIDC federation for GitHub Actions (eliminates static AWS keys in CI/CD):**

```bash
# Create the OIDC provider for GitHub
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list <GITHUB_THUMBPRINT>

# Create role trusted by the GitHub OIDC provider
cat > github-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT>:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:<ORG>/<REPO>:*"
      }
    }
  }]
}
EOF

aws iam create-role \
  --role-name GitHubActionsDeployRole \
  --assume-role-policy-document file://github-trust-policy.json
```

In your GitHub Actions workflow:
```yaml
permissions:
  id-token: write
  contents: read

steps:
  - name: Configure AWS credentials
    uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::<ACCOUNT>:role/GitHubActionsDeployRole
      aws-region: eu-west-1
```

No AWS secrets stored in GitHub. No rotation needed. Automatically scoped to the specific repo.

---

## Zero Trust Maturity Model

| Stage | Description | AWS Controls |
|-------|-------------|-------------|
| **1 — Traditional** | Perimeter firewall, VPN, trusted internal network | Security groups, VPN |
| **2 — Identity-aware** | MFA, SSO, identity-based policies | IAM Identity Center, MFA SCPs |
| **3 — Zero Trust foundations** | No long-lived keys, least-privilege, logging everywhere | Roles everywhere, CloudTrail, GuardDuty |
| **4 — Adaptive** | Device posture, risk-based access, continuous re-verification | Verified Access, conditional policies |
| **5 — Optimised** | Automated response, workload identity, service mesh | VPC Lattice, IRSA, automated IR |

Use the stages to assess an environment's current maturity and identify practical next steps. Progress depends on business risk, technical constraints, and available resources.

---

*Last reviewed: Q1 2025 · Reference: NIST SP 800-207 Zero Trust Architecture*
