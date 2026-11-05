# RB-005 — Security Group Open to Internet (0.0.0.0/0)

![Severity](https://img.shields.io/badge/Severity-HIGH-orange?style=flat)
![Category](https://img.shields.io/badge/Category-Misconfiguration-yellow?style=flat)
![Service](https://img.shields.io/badge/AWS-EC2_·_VPC-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** CIS Controls v8 — 12.2 · PCI-DSS v4 Req 1.3 · NIST CSF PR.AC-5 · SOC 2 CC6.6

---

## Overview

A security group allows unrestricted inbound access from `0.0.0.0/0` (all IPv4) or `::/0` (all IPv6) on a sensitive port. This exposes workloads directly to the internet and is a frequent cause of unauthorised access incidents.

**Highest-risk ports:**

| Port | Protocol | Risk |
|------|----------|------|
| 22 | SSH | Remote code execution, brute force |
| 3389 | RDP | Remote desktop, ransomware entry vector |
| 3306 | MySQL | Direct database access |
| 5432 | PostgreSQL | Direct database access |
| 27017 | MongoDB | Often unauthenticated by default |
| 6379 | Redis | Unauthenticated access, data theft |
| 9200 | Elasticsearch | Data exfiltration, ransom |
| 0 | All traffic | Full exposure |

---

## Detection Signals

```
AWS Config rule:  restricted-ssh            (checks port 22)
AWS Config rule:  restricted-common-ports   (checks ports 20,21,3306,3389,4333)
Security Hub:     [EC2.19] Security groups should not allow unrestricted access to high-risk ports
Security Hub:     [EC2.18] Security groups should not allow unrestricted access to port 3389
GuardDuty:        Recon:EC2/PortProbeUnprotectedPort
```

---

## Phase 1 — Discovery & Impact Assessment

### 1.1 Find all security groups with open-to-internet rules

```bash
# IPv4 — all ports
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{
    ID:GroupId,
    Name:GroupName,
    VPC:VpcId,
    Rules:IpPermissions
  }' \
  --output table

# IPv6
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?Ipv6Ranges[?CidrIpv6==`::/0`]]].{
    ID:GroupId,Name:GroupName
  }' \
  --output table
```

### 1.2 Identify which instances use each exposed security group

```bash
SG_ID=<security-group-id>

aws ec2 describe-instances \
  --filters "Name=instance.group-id,Values=$SG_ID" \
  --query 'Reservations[].Instances[].{
    ID:InstanceId,
    State:State.Name,
    PublicIP:PublicIpAddress,
    PrivateIP:PrivateIpAddress,
    Name:Tags[?Key==`Name`].Value|[0]
  }' \
  --output table
```

### 1.3 Assess risk level

| Factor | Higher Risk | Lower Risk |
|--------|------------|------------|
| Instance has public IP | Yes | No (private subnet) |
| Port exposed | 22, 3389, DB ports | Ephemeral ports only |
| Instance is internet-facing | Yes | Internal service |
| Data sensitivity | Production, PCI, PII | Dev/sandbox |

---

## Phase 2 — Containment

### 2.1 Remove the offending rule

```bash
# SSH (port 22) open to all
aws ec2 revoke-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# RDP (port 3389) open to all
aws ec2 revoke-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 3389 \
  --cidr 0.0.0.0/0

# All traffic open
aws ec2 revoke-security-group-ingress \
  --group-id $SG_ID \
  --protocol -1 \
  --cidr 0.0.0.0/0
```

### 2.2 Replace with least-privilege rule

**Option A — Restrict to corporate VPN CIDR:**
```bash
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr <CORPORATE_VPN_CIDR>
```

**Option B — Restrict to bastion host security group (preferred):**
```bash
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --source-group <BASTION_SG_ID>
```

**Option C — Remove SSH entirely and use SSM Session Manager (best practice):**
```bash
# No inbound rules needed — SSM uses outbound HTTPS
# Ensure instance has AmazonSSMManagedInstanceCore policy attached
# Connect with:
aws ssm start-session --target $INSTANCE_ID
```

---

## Phase 3 — Eradication & Prevention

### 3.1 SCP to prevent recurrence at the Organisation level

Create a Service Control Policy that blocks creating or modifying security group rules to allow `0.0.0.0/0` on sensitive ports:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOpenSSH",
      "Effect": "Deny",
      "Action": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:cidr": "0.0.0.0/0"
        },
        "NumericEquals": {
          "ec2:FromPort": 22,
          "ec2:ToPort": 22
        }
      }
    }
  ]
}
```

Apply to all OUs except the security tooling account.

### 3.2 Enable AWS Config rule for continuous monitoring

```bash
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "restricted-ssh",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "INCOMING_SSH_DISABLED"
    },
    "Scope": {
      "ComplianceResourceTypes": ["AWS::EC2::SecurityGroup"]
    }
  }'
```

### 3.3 Check for VPC flow log evidence of exploitation attempts

```bash
# Were there successful inbound connections to the exposed port before containment?
# Run in Athena against your VPC flow logs table:
cat << 'EOF'
SELECT
  srcaddr,
  dstport,
  action,
  COUNT(*) AS connection_count,
  SUM(bytes) AS bytes_transferred
FROM vpc_flow_logs
WHERE dstaddr = '<INSTANCE_PRIVATE_IP>'
  AND dstport = 22
  AND start > CAST('<EXPOSURE_START_EPOCH>' AS bigint)
GROUP BY srcaddr, dstport, action
ORDER BY connection_count DESC;
EOF
```

`ACCEPT` connections from external IPs = potential exploitation. Escalate to incident response.

---

## Governance Notes

- **PCI-DSS Req 1.3:** Network access controls must restrict inbound and outbound traffic to only what is necessary for the cardholder data environment. Open-to-internet rules are an immediate finding.
- **CIS Control 12.2:** Manage all traffic flowing over the network — includes maintaining firewall rules with documented business justification.
- **SOC 2 CC6.6:** Logical access security measures are implemented to protect against threats from sources outside its system boundaries — open SGs are direct evidence of control failure.
- All exceptions to this rule require documented business justification, manager approval, and a compensating control (e.g., WAF in front of the exposed service).

---

## Related Runbooks

- [RB-006 — MFA Not Enforced](./RB-006-mfa-not-enforced.md)
- [RB-007 — CloudTrail Logging Gap](./RB-007-cloudtrail-logging-gap.md)

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: HIGH*
