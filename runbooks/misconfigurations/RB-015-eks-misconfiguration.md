# RB-015 — EKS Public API Endpoint / Container Security Misconfiguration

![Severity](https://img.shields.io/badge/Severity-HIGH-orange?style=flat)
![Category](https://img.shields.io/badge/Category-Misconfiguration-yellow?style=flat)
![Service](https://img.shields.io/badge/AWS-EKS_·_EC2_·_IAM_·_ECR-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF PR.AC-5 · CIS EKS Benchmark · MITRE ATT&CK T1610 (Deploy Container)

---

## Overview

Amazon EKS (Elastic Kubernetes Service) misconfigurations can expose the Kubernetes API, enable anonymous authentication, grant overly permissive RBAC access, permit privileged containers, or deploy ECR images with critical CVEs.

---

## Detection Signals

```
Security Hub:    [EKS.1] EKS cluster endpoints should not be publicly accessible
Security Hub:    [EKS.2] EKS clusters should run a supported Kubernetes version
GuardDuty:       Impact:EKS/SuccessfulAnonymousAccess
GuardDuty:       CredentialAccess:Kubernetes/MaliciousIPCaller
GuardDuty:       Execution:Kubernetes/ExecInKubeDNSPod
AWS Config:      eks-endpoint-no-public-access
CloudTrail:      Kubernetes audit log — anonymous API calls
```

---

## Phase 1 — Discovery & Assessment

### 1.1 Check EKS endpoint access configuration

```bash
CLUSTER_NAME=<your-cluster>

aws eks describe-cluster \
  --name $CLUSTER_NAME \
  --query 'cluster.resourcesVpcConfig.{
    EndpointPublicAccess:endpointPublicAccess,
    EndpointPrivateAccess:endpointPrivateAccess,
    PublicAccessCidrs:publicAccessCidrs
  }'
```

`endpointPublicAccess: true` + `publicAccessCidrs: ["0.0.0.0/0"]` = API server reachable from anywhere. Immediate risk.

### 1.2 Check for anonymous authentication

```bash
# Check if system:anonymous has any RBAC bindings
kubectl get clusterrolebindings -o json | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data['items']:
    subjects = item.get('spec', {}).get('subjects', [])
    for s in subjects:
        if s.get('name') in ['system:anonymous', 'system:unauthenticated']:
            print(f'ANONYMOUS BINDING: {item[\"metadata\"][\"name\"]} -> {item[\"roleRef\"][\"name\"]}')
"
```

### 1.3 Find privileged containers

```bash
# Pods running as privileged
kubectl get pods --all-namespaces -o json | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data['items']:
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    for c in item['spec'].get('containers', []):
        sc = c.get('securityContext', {})
        if sc.get('privileged') or sc.get('runAsRoot') or sc.get('runAsUser') == 0:
            print(f'PRIVILEGED: {ns}/{name} ({c[\"name\"]})')
"

# Containers running as root
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{range .spec.containers[*]}{.securityContext.runAsUser}{"\n"}{end}{end}' | grep -E '\t0$|\tNone'
```

### 1.4 Check ECR images for critical CVEs

```bash
# Get scan results for all images in a repo
aws ecr describe-image-scan-findings \
  --repository-name <REPO_NAME> \
  --image-id imageTag=latest \
  --query 'imageScanFindings.findingSeverityCounts'

# List all critical vulnerabilities
aws ecr describe-image-scan-findings \
  --repository-name <REPO_NAME> \
  --image-id imageTag=latest \
  --query 'imageScanFindings.findings[?severity==`CRITICAL`].{CVE:name,Package:attributes[?key==`package name`].value|[0],Fix:attributes[?key==`fixed with`].value|[0]}' \
  --output table
```

### 1.5 Check IAM Roles for Service Accounts (IRSA) vs node-level permissions

```bash
# Pods inheriting EC2 node role (broad permissions, bad)
# vs pods using dedicated service account role (least-privilege, good)

kubectl get serviceaccounts --all-namespaces -o json | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for sa in data['items']:
    ns = sa['metadata']['namespace']
    name = sa['metadata']['name']
    annotations = sa['metadata'].get('annotations', {})
    role = annotations.get('eks.amazonaws.com/role-arn', None)
    if role:
        print(f'IRSA configured: {ns}/{name} -> {role}')
    elif name != 'default':
        print(f'No IRSA: {ns}/{name} (inherits node role)')
"
```

---

## Phase 2 — Containment

### 2.1 Restrict public endpoint access immediately

```bash
# Option A: Add corporate IP allowlist (maintains some public access)
aws eks update-cluster-config \
  --name $CLUSTER_NAME \
  --resources-vpc-config \
    endpointPublicAccess=true,\
    publicAccessCidrs="<CORP_IP>/32,<VPN_CIDR>" \
    endpointPrivateAccess=true

# Option B: Disable public endpoint entirely (most secure)
aws eks update-cluster-config \
  --name $CLUSTER_NAME \
  --resources-vpc-config \
    endpointPublicAccess=false,\
    endpointPrivateAccess=true
```

After disabling public access, `kubectl` must be run from within the VPC (via bastion, VPN, or AWS CloudShell in the VPC).

### 2.2 Remove anonymous authentication bindings

```bash
kubectl delete clusterrolebinding <ANONYMOUS_BINDING_NAME>
```

### 2.3 Remove pod security exceptions

```bash
# Identify pods with privileged security context
# Coordinate with app team before removing — may break workloads
kubectl patch deployment <DEPLOYMENT_NAME> \
  --patch '{"spec":{"template":{"spec":{"containers":[{"name":"<CONTAINER>","securityContext":{"privileged":false,"runAsNonRoot":true,"runAsUser":1000}}]}}}}'
```

---

## Phase 3 — Hardening

### 3.1 Enable EKS control plane logging

```bash
aws eks update-cluster-config \
  --name $CLUSTER_NAME \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
```

Audit logs capture every `kubectl` command. Critical for forensics.

### 3.2 Implement Pod Security Standards

```bash
# Enforce restricted PSS (Pod Security Standards) on all namespaces
kubectl label namespace <NAMESPACE> \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
```

The `restricted` profile blocks: privileged containers, host network/PID/IPC, all capabilities except allowed list, root users.

### 3.3 Enable ECR image scanning on push

```bash
aws ecr put-image-scanning-configuration \
  --repository-name <REPO_NAME> \
  --image-scanning-configuration scanOnPush=true

# Enable enhanced scanning (Inspector integration — CVEs + OS packages)
aws ecr put-registry-scanning-configuration \
  --scan-type ENHANCED \
  --rules '[{
    "repositoryFilters": [{"filter": "*", "filterType": "WILDCARD"}],
    "scanFrequency": "CONTINUOUS_SCAN"
  }]'
```

### 3.4 Enforce IRSA for all workloads

All pods should use dedicated service account roles, not the EC2 node instance profile:

```bash
# Attach OIDC provider to cluster (one-time setup)
OIDC_URL=$(aws eks describe-cluster --name $CLUSTER_NAME \
  --query 'cluster.identity.oidc.issuer' --output text)

aws iam create-open-id-connect-provider \
  --url $OIDC_URL \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list <OIDC_THUMBPRINT>
```

---

## EKS Security Baseline Checklist

- [ ] API endpoint: private-only or public with IP allowlist
- [ ] Kubernetes version: within 3 minor versions of latest
- [ ] Node groups: latest AMI applied (Managed Node Group auto-update)
- [ ] Control plane logging: all log types enabled
- [ ] RBAC: no anonymous bindings; no `cluster-admin` for non-admin users
- [ ] Pod Security Standards: `restricted` on all production namespaces
- [ ] IRSA: all pods use service account roles (not node instance profile)
- [ ] Network policies: default-deny ingress/egress per namespace
- [ ] ECR: enhanced scanning enabled; no critical CVEs in deployed images
- [ ] Secrets: no Kubernetes secrets with plaintext credentials (use Secrets Manager CSI driver)
- [ ] GuardDuty EKS Protection: enabled

---

## Related Runbooks

- [RB-001 — IAM Privilege Escalation](../incident-response/RB-001-iam-privilege-escalation.md) — container escape often leads here
- [RB-011 — EC2 Metadata SSRF](../incident-response/RB-011-ec2-metadata-ssrf.md) — IMDS accessible from pods without IMDSv2

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: HIGH*
