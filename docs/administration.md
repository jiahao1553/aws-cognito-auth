# Administration Guide

Comprehensive guide to administrative features and policy management using `cogadmin`.

## Overview

The `cogadmin` command provides powerful tools for:
- Managing IAM roles and policies
- Deploying AWS infrastructure
- Configuring Identity Pool permissions
- Setting up Lambda proxy for extended credentials

## Configuration Management

### Interactive Configuration

Set up administrative configuration:

```bash
cogadmin configure
```

This prompts for:
- AWS service names (IAM users, roles, Lambda functions)
- AWS configuration parameters (regions, timeouts, session duration)
- Policy names for all components

### Configuration Files

#### Global Admin Config
`~/.cognito-admin-config.json` - User-level settings

#### Local Project Config
`admin-config.json` - Project-specific overrides

#### Example Configuration
```json
{
  "aws_service_names": {
    "iam_user_name": "CognitoCredentialProxyUser",
    "lambda_execution_role_name": "CognitoCredentialProxyRole",
    "long_lived_role_name": "CognitoLongLivedRole",
    "lambda_function_name": "cognito-credential-proxy",
    "identity_pool_name": "CognitoAuthIdentityPool",
    "policy_names": {
      "lambda_user_policy": "CognitoCredentialProxyPolicy",
      "lambda_execution_policy": "CognitoCredentialProxyPolicy",
      "s3_access_policy": "S3AccessPolicy"
    }
  },
  "aws_configuration": {
    "default_region": "ap-southeast-1",
    "lambda_runtime": "python3.9",
    "lambda_timeout": 30,
    "max_session_duration": 43200,
    "default_bucket": "my-s3-bucket"
  }
}
```

## Role Management

### View Role Information

```bash
cogadmin role info
```

Displays:
- Current Identity Pool authenticated role
- Attached policies
- Trust policy details
- Permission summary

### Apply Custom Policies

```bash
cogadmin role apply-policy --policy-file custom-policy.json --policy-name MyPolicy
```

#### Example Custom Policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue"
            ],
            "Resource": "arn:aws:secretsmanager:*:*:secret:app-secrets/*"
        }
    ]
}
```

## Policy Management

### S3 Policies

#### Basic S3 Access
```bash
cogadmin policy create-s3-policy --bucket-name my-bucket
```

#### S3 with User Isolation (Recommended)
```bash
cogadmin policy create-s3-policy --bucket-name my-bucket --user-specific
```

This creates a policy where each user can only access their own folder:
- Path: `s3://my-bucket/{user-cognito-id}/`
- Uses Cognito Identity ID for isolation

### DynamoDB Policies

#### User-Isolated DynamoDB Access
```bash
cogadmin policy create-dynamodb-policy --table-name my-table
```

Creates row-level security using Cognito Identity ID as partition key.

### Lambda Policies

#### Function Invocation
```bash
cogadmin policy create-lambda-policy --function-prefix user-function
```

Allows invocation of Lambda functions matching the prefix pattern.

## Infrastructure Deployment

### Lambda Proxy Setup

The Lambda proxy enables 12-hour credentials (vs 1-hour from Identity Pool).

#### Option 1: Create New IAM User
```bash
cogadmin lambda deploy --create-user
```

This will:
1. Create new IAM user for Lambda proxy
2. Create required IAM roles
3. Deploy Lambda function
4. Configure environment variables

#### Option 2: Use Existing IAM User
```bash
cogadmin lambda deploy --access-key-id AKIA... --secret-access-key ...
```

Requirements for existing IAM user:
- Permission to assume the long-lived role
- Access keys for Lambda environment variables

### Identity Pool Setup

```bash
cogadmin setup-identity-pool
```

Interactive setup for:
- Creating new Identity Pool
- Configuring authentication providers
- Setting up authenticated/unauthenticated roles

## Advanced Administration

### Multi-Environment Management

#### Development Environment
```json
{
  "aws_service_names": {
    "long_lived_role_name": "CognitoDevRole",
    "lambda_function_name": "cognito-proxy-dev"
  },
  "aws_configuration": {
    "default_bucket": "my-dev-bucket",
    "max_session_duration": 14400
  }
}
```

#### Production Environment
```json
{
  "aws_service_names": {
    "long_lived_role_name": "CognitoProdRole",
    "lambda_function_name": "cognito-proxy-prod"
  },
  "aws_configuration": {
    "default_bucket": "my-prod-bucket",
    "max_session_duration": 43200
  }
}
```

### Policy Templates

The system includes pre-built policy templates in `policies/`:

#### Core Infrastructure
- `lambda-execution-trust-policy.json` - Lambda execution role trust
- `lambda-user-policy.json` - IAM user for Lambda proxy
- `long-lived-role-trust-policy.json` - Long-lived role trust policy
- `cognito-identity-pool-auth-policy.json` - Basic Identity Pool permissions

#### Service Access
- `s3-access-policy.json` - Basic S3 access
- `s3-user-isolation-policy.json` - S3 with user folders
- `dynamodb-user-isolation-policy.json` - DynamoDB row-level security
- `lambda-invoke-policy.json` - Lambda function invocation

### Custom Policy Development

#### Creating Custom Policies

1. **Create JSON policy file:**
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": "service:action",
               "Resource": "arn:aws:service:region:account:resource/*"
           }
       ]
   }
   ```

2. **Use placeholder variables:**
   - `{account_id}` - AWS account ID
   - `{region}` - AWS region
   - `{bucket_name}` - S3 bucket name
   - `{table_name}` - DynamoDB table name

3. **Apply the policy:**
   ```bash
   cogadmin role apply-policy --policy-file my-custom-policy.json --policy-name MyCustomPolicy
   ```

#### Policy Variables for User Isolation

Use Cognito Identity variables for user-specific access:
- `${cognito-identity.amazonaws.com:sub}` - Unique user identity ID
- `${cognito-identity.amazonaws.com:aud}` - Identity Pool ID

## Monitoring and Maintenance

### CloudWatch Integration

Monitor Lambda proxy execution:
```bash
aws logs tail /aws/lambda/cognito-credential-proxy --follow
```

### Credential Usage Monitoring

Track credential usage via CloudTrail:
```bash
aws logs filter-log-events --log-group-name CloudTrail/CognitoAuth \
    --filter-pattern "{ $.userIdentity.type = AssumedRole }"
```

### Regular Maintenance Tasks

1. **Rotate IAM user credentials** (monthly)
2. **Review and update policies** (quarterly)
3. **Monitor credential usage** (ongoing)
4. **Update Lambda function code** (as needed)
5. **Review CloudTrail logs** (weekly)

## Security Best Practices

### IAM Policies
- Use least-privilege principle
- Implement user isolation where appropriate
- Regular policy audits
- Use condition statements for additional security

### Lambda Proxy Security
- Encrypt environment variables
- Use IAM roles instead of access keys where possible
- Implement request validation
- Monitor function invocations

### Credential Management
- Set appropriate session durations
- Enable MFA for Cognito User Pool
- Use strong password policies
- Monitor for unusual access patterns

## Troubleshooting Administration

### Common Issues

#### Policy Application Fails
```bash
# Check role permissions
aws iam get-role --role-name Cognito_IdentityPoolAuth_Role

# Verify policy syntax
aws iam validate-policy --policy-document file://policy.json
```

#### Lambda Deployment Issues
```bash
# Check Lambda function exists
aws lambda get-function --function-name cognito-credential-proxy

# Verify environment variables
aws lambda get-function-configuration --function-name cognito-credential-proxy
```

#### Role Trust Issues
```bash
# Verify trust policy
aws iam get-role --role-name CognitoLongLivedRole

# Test role assumption
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/CognitoLongLivedRole --role-session-name test
```

For more troubleshooting, see [Troubleshooting](troubleshooting.md).

## API Integration

### Programmatic Administration

The admin module can be used programmatically:

```python
from aws_cognito_auth.admin import AdminConfigManager, PolicyManager

# Load configuration
admin_config = AdminConfigManager.load_config()

# Create policy manager
policy_manager = PolicyManager(admin_config)

# Apply policy
policy_manager.apply_s3_policy("my-bucket", user_specific=True)
```

See [API Reference](modules.md) for detailed documentation.
