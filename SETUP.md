# SETUP.md — Pushing This Library to GitHub

Step-by-step instructions for publishing this student project on GitHub.

---

## Prerequisites

- Git installed locally
- GitHub account
- GitHub CLI (`gh`) — optional but faster

---

## Option A — GitHub CLI (recommended)

```bash
# 1. Unzip the downloaded file
unzip aws-cloud-security-runbooks.zip
cd aws-cloud-security-runbooks

# 2. Initialise git and create the repo in one command
git init
git add .
git commit -m "feat: initial AWS cloud security runbook library

20 runbooks covering incident response, misconfigurations, and governance.
Framework mappings for NIST CSF 2.0, CIS Controls v8, SOC 2, PCI-DSS.
Architecture diagrams: defence-in-depth, zero trust, shared responsibility."

# 3. Create the GitHub repo and push
gh repo create aws-cloud-security-runbooks \
  --public \
  --description "AWS-specific security runbooks, incident response procedures, and governance framework mappings" \
  --source=. \
  --push

# 4. Add topics so it appears in GitHub search
gh repo edit --add-topic aws,cloud-security,security-runbooks,incident-response,soc2,pci-dss,nist-csf,iam,devsecops,governance
```

---

## Option B — Manual GitHub UI + Git

```bash
# 1. Create repo on github.com
# Go to github.com → New Repository
# Name: aws-cloud-security-runbooks
# Description: AWS-specific security runbooks, incident response procedures, and governance framework mappings
# Visibility: Public
# Do NOT initialise with README (you have your own)

# 2. Unzip, init, and push
unzip aws-cloud-security-runbooks.zip
cd aws-cloud-security-runbooks

git init
git add .
git commit -m "feat: initial AWS cloud security runbook library"
git branch -M main
git remote add origin https://github.com/<YOUR_USERNAME>/aws-cloud-security-runbooks.git
git push -u origin main
```

---

## Recommended GitHub Repository Settings

After pushing, configure these in **Settings → General** and **Settings → Pages**:

### Repository description
```
AWS cloud security runbook library — incident response, misconfiguration remediation, and governance framework mappings (NIST CSF, CIS, SOC 2, PCI-DSS)
```

### Topics (add in Settings → Topics)
```
aws  cloud-security  security-runbooks  incident-response
soc2  pci-dss  nist-csf  cis-controls  iam  devsecops  governance  grc
```

### GitHub Pages (optional — turns README into a website)
- Settings → Pages → Source: Deploy from a branch → main → / (root)
- Your repo will be live at `https://<username>.github.io/aws-cloud-security-runbooks`

---

## Maintaining the Project

Add and update runbooks as the project develops:

```bash
# Add a new runbook as you learn a topic
cp templates/new-runbook-template.md runbooks/incident-response/RB-021-new-topic.md
# Edit the file, then:
git add .
git commit -m "feat: add RB-021 new topic runbook"
git push

# Monthly: review and update existing runbooks
git add .
git commit -m "chore: review RB-019 GuardDuty finding references"
git push

# Add issues for planned runbooks
gh issue create --title "RB-021: New runbook topic" --body "Describe the topic and scope for a proposed runbook"
gh issue create --title "RB-022: New runbook topic" --body "Describe the topic and scope for a proposed runbook"
```

---

*Use this guide as a reference when publishing or maintaining the project.*
