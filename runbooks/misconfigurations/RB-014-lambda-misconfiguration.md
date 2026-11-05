# RB-014 — Lambda Function URL Public Exposure / Misconfiguration

![Severity](https://img.shields.io/badge/Severity-HIGH-orange?style=flat)
![Category](https://img.shields.io/badge/Category-Misconfiguration-yellow?style=flat)
![Service](https://img.shields.io/badge/AWS-Lambda_·_IAM_·_CloudTrail_·_CloudWatch-FF9900?style=flat&logo=amazonaws&logoColor=black)

**Frameworks:** NIST CSF PR.AC-3 · CIS Controls 4.1 · OWASP Cloud Top 10 C1

---

## Overview

Lambda function URLs (introduced 2022) allow a function to be invoked directly via HTTPS without API Gateway. When set to `AuthType: NONE`, the function is publicly invocable by anyone on the internet with no authentication. This is a frequently missed misconfiguration because Lambda functions are often considered "serverless" and therefore assumed to be protected.

Additional Lambda security issues covered: overly permissive execution roles, hardcoded secrets in environment variables, missing dead-letter queues masking errors.

---

## Detection Signals

```
AWS Config rule:  (custom) lambda-function-url-auth-type-check
Security Hub:     [Lambda.1] Lambda function policies should prohibit public access
Security Hub:     [Lambda.2] Lambda functions should use supported runtimes
CloudTrail:       CreateFunctionUrlConfig with AuthType=NONE
CloudTrail:       AddPermission with Principal=* on a Lambda function
GuardDuty:        Execution:Lambda/SuspiciousCodeExecution (if malicious payload executed)
```

---

## Phase 1 — Discovery & Assessment

### 1.1 Find all Lambda functions with public URLs

```bash
# List all functions with Function URLs configured
aws lambda list-functions \
  --query 'Functions[].FunctionName' \
  --output text | tr '\t' '\n' | while read FN; do
    URL_CONFIG=$(aws lambda get-function-url-config \
      --function-name $FN 2>/dev/null)
    if [ -n "$URL_CONFIG" ]; then
      AUTH=$(echo $URL_CONFIG | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('AuthType','?'))")
      URL=$(echo $URL_CONFIG | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('FunctionUrl','?'))")
      echo "Function: $FN | Auth: $AUTH | URL: $URL"
    fi
  done
```

`AuthType: NONE` = publicly accessible. `AuthType: AWS_IAM` = requires signed request (secure).

### 1.2 Find Lambda functions with overly permissive resource policies

```bash
# Check for * principal in Lambda resource policies
aws lambda list-functions --query 'Functions[].FunctionName' --output text | \
  tr '\t' '\n' | while read FN; do
    POLICY=$(aws lambda get-policy --function-name $FN 2>/dev/null)
    if echo "$POLICY" | grep -q '"Principal": "*"'; then
      echo "PUBLIC POLICY: $FN"
      echo "$POLICY" | python3 -m json.tool
    fi
  done
```

### 1.3 Audit execution role permissions

```bash
# Get role for each function and check for overly broad permissions
aws lambda list-functions \
  --query 'Functions[].{Name:FunctionName,Role:Role}' \
  --output table

# For a specific role — simulate what it can do
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<ACCOUNT>:role/<LAMBDA_ROLE> \
  --action-names "s3:GetObject" "s3:PutObject" "dynamodb:Scan" "iam:CreateUser" \
  --query 'EvaluationResults[?EvalDecision==`allowed`].EvalActionName'
```

### 1.4 Check for secrets in environment variables

```bash
# Scan all Lambda environment variables for secrets patterns
aws lambda list-functions --query 'Functions[].FunctionName' --output text | \
  tr '\t' '\n' | while read FN; do
    ENV=$(aws lambda get-function-configuration \
      --function-name $FN \
      --query 'Environment.Variables' 2>/dev/null)
    if echo "$ENV" | grep -iE 'password|secret|key|token|credential|pwd' | grep -v 'KMS\|ARN\|arn:aws'; then
      echo "⚠️  Potential secret in env vars: $FN"
    fi
  done
```

### 1.5 Check invocation logs for suspicious activity on public URLs

```bash
# Get recent invocation logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/<FUNCTION_NAME> \
  --start-time $(date -d '-24 hours' +%s)000 \
  --filter-pattern "ERROR" \
  --query 'events[].message' \
  --output text | head -50

# Check for high invocation volume (potential abuse/DoS)
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=<FUNCTION_NAME> \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 3600 \
  --statistics Sum \
  --query 'Datapoints[].{Time:Timestamp,Count:Sum}' \
  --output table
```

---

## Phase 2 — Containment

### 2.1 Disable the public function URL

```bash
# Option A: Change auth type to AWS_IAM (maintains URL, requires auth)
aws lambda update-function-url-config \
  --function-name <FUNCTION_NAME> \
  --auth-type AWS_IAM

# Option B: Delete the function URL entirely (safer if URL not needed)
aws lambda delete-function-url-config \
  --function-name <FUNCTION_NAME>
```

### 2.2 Remove public resource policy if present

```bash
# Get and review the policy first
aws lambda get-policy --function-name <FUNCTION_NAME>

# Remove the overly permissive statement
aws lambda remove-permission \
  --function-name <FUNCTION_NAME> \
  --statement-id <STATEMENT_ID_WITH_PUBLIC_PRINCIPAL>
```

### 2.3 Throttle the function if actively being abused

```bash
# Set concurrency to 0 — blocks all invocations immediately
aws lambda put-function-concurrency \
  --function-name <FUNCTION_NAME> \
  --reserved-concurrent-executions 0

# Restore after investigation:
aws lambda delete-function-concurrency \
  --function-name <FUNCTION_NAME>
```

---

## Phase 3 — Eradication & Hardening

### 3.1 Migrate secrets from environment variables to Secrets Manager

```bash
# Store secret in Secrets Manager
aws secretsmanager create-secret \
  --name /lambda/<FUNCTION_NAME>/db-password \
  --secret-string '{"password":"<VALUE>"}'

# Remove from Lambda env var
aws lambda update-function-configuration \
  --function-name <FUNCTION_NAME> \
  --environment Variables={}

# Grant Lambda role access to the secret
aws secretsmanager put-resource-policy \
  --secret-id /lambda/<FUNCTION_NAME>/db-password \
  --resource-policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::<ACCOUNT>:role/<LAMBDA_ROLE>"},
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*"
    }]
  }'
```

Then update Lambda code to retrieve from Secrets Manager at runtime using `boto3.client('secretsmanager').get_secret_value(...)`.

### 3.2 Enforce least-privilege execution role

Lambda roles should have only the permissions the function actually uses. Use IAM Access Advisor to find what's actually called:

```bash
aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::<ACCOUNT>:role/<LAMBDA_ROLE>

# Wait a few seconds, then:
aws iam get-service-last-accessed-details \
  --job-id <JOB_ID> \
  --query 'ServicesLastAccessed[?LastAuthenticated!=null].{Service:ServiceName,LastUsed:LastAuthenticated}'
```

Remove permissions for services the function has never called.

### 3.3 AWS Config rule for continuous detection

```bash
# Custom Config rule: detect Lambda Function URLs with AuthType=NONE
# Deploy via AWS Config Custom Rules or AWS Security Hub custom insight
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "lambda-function-url-no-auth",
    "Source": {
      "Owner": "CUSTOM_LAMBDA",
      "SourceIdentifier": "<CUSTOM_RULE_LAMBDA_ARN>",
      "SourceDetails": [{
        "EventSource": "aws.config",
        "MessageType": "ConfigurationItemChangeNotification"
      }]
    },
    "Scope": {
      "ComplianceResourceTypes": ["AWS::Lambda::Function"]
    }
  }'
```

---

## Lambda Security Baseline Checklist

For every Lambda function in production:

- [ ] Function URL: disabled or `AuthType: AWS_IAM`
- [ ] Resource policy: no `Principal: "*"` statements
- [ ] Execution role: least-privilege, scoped to specific resources (not `*`)
- [ ] Environment variables: no secrets, passwords, or API keys
- [ ] Runtime: on a supported version (no deprecated runtimes)
- [ ] Timeout: set appropriately (not max 15 min for a simple function)
- [ ] Reserved concurrency: set to prevent runaway invocations
- [ ] Dead-letter queue: configured (SQS or SNS) for async invocations
- [ ] VPC: deployed in VPC if accessing private resources (RDS, ElastiCache)
- [ ] X-Ray tracing: enabled for observability
- [ ] CloudWatch log group: retention set (not infinite)

---

## Related Runbooks

- [RB-003 — Exposed API Keys](../incident-response/RB-003-exposed-api-keys.md) — secrets in env vars
- [RB-001 — IAM Privilege Escalation](../incident-response/RB-001-iam-privilege-escalation.md) — overly permissive role

---

*Last reviewed: Q1 2025 · Maintainer: Student project · Severity: HIGH*
