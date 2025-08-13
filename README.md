# AWS Cognito Authoriser

[![Release](https://img.shields.io/github/v/release/jiahao1553/aws-cognito-auth)](https://img.shields.io/github/v/release/jiahao1553/aws-cognito-auth)
[![Build status](https://img.shields.io/github/actions/workflow/status/jiahao1553/aws-cognito-auth/main.yml?branch=main)](https://github.com/jiahao1553/aws-cognito-auth/actions/workflows/main.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/jiahao1553/aws-cognito-auth/branch/main/graph/badge.svg)](https://codecov.io/gh/jiahao1553/aws-cognito-auth)
[![Commit activity](https://img.shields.io/github/commit-activity/m/jiahao1553/aws-cognito-auth)](https://img.shields.io/github/commit-activity/m/jiahao1553/aws-cognito-auth)
[![License](https://img.shields.io/github/license/jiahao1553/aws-cognito-auth)](https://img.shields.io/github/license/jiahao1553/aws-cognito-auth)

A robust command-line tool that provides seamless authentication with AWS Cognito User Pool and Identity Pool, automatically obtaining temporary AWS credentials that work without requiring local AWS profile configuration.

## 🚀 Overview

The AWS Cognito Authoriser solves a critical problem in AWS authentication workflows: obtaining temporary AWS credentials for CLI and SDK usage without requiring pre-configured AWS profiles or permanent credentials. It leverages AWS Cognito's User Pool for authentication and Identity Pool for credential exchange, with an optional Lambda proxy for extended credential duration.

### Key Features

- 🔐 **Secure Authentication**: Authenticates users via AWS Cognito User Pool
- ⏱️ **Flexible Credential Duration**: 1-hour (Identity Pool) or up to 12-hour (Lambda proxy) credentials
- 🛡️ **No AWS Profile Required**: Works in environments without pre-configured AWS credentials
- 📦 **Multiple Service Integration**: Supports S3, DynamoDB, Lambda, and other AWS services
- 🔧 **Automated Setup**: Helper scripts for complete AWS infrastructure deployment
- 📊 **Role Management**: Built-in tools for managing IAM policies and permissions
- 🎯 **Profile Management**: Updates standard AWS credentials and config files
- 🔄 **Graceful Fallback**: Always provides working credentials with intelligent upgrading

## 🏗️ Architecture

The system consists of three main components:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Tool      │───▶│ Cognito Identity │───▶│ Lambda Proxy    │
│                 │    │ Pool (1hr creds) │    │ (12hr creds)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ User Pool Auth  │    │ IAM Role         │    │ Long-lived Role │
│                 │    │ (Cognito Auth)   │    │ (Extended)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Authentication Flow

1. **User Authentication**: Authenticate with Cognito User Pool using username/password
2. **Identity Pool Exchange**: Exchange ID token for 1-hour AWS credentials via Identity Pool
3. **Lambda Upgrade** (Optional): Attempt to upgrade to 12-hour credentials via Lambda proxy
4. **Credential Storage**: Update AWS credentials file for seamless CLI/SDK usage

## 📦 Installation

### Prerequisites

- Python 3.7+
- AWS account with Cognito services
- Basic understanding of AWS IAM roles and policies

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd aws-cognito-auth
   ```

2. **Install the package:**
   ```bash
   pip install -e .
   ```

3. **Configure the tool:**
   ```bash
   cogauth configure
   ```

4. **Login and get credentials:**
   ```bash
   cogauth login -u your-username
   ```

## ⚙️ Configuration

### Method 1: Interactive Configuration
```bash
cogauth configure
```

### Method 2: Environment Variables
```bash
export COGNITO_USER_POOL_ID="us-east-1_xxxxxxxxx"
export COGNITO_CLIENT_ID="your-client-id"
export COGNITO_IDENTITY_POOL_ID="us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AWS_REGION="us-east-1"
```

### Method 3: Configuration File
Create `~/.cognito-cli-config.json`:
```json
{
    "user_pool_id": "us-east-1_xxxxxxxxx",
    "client_id": "your-client-id",
    "identity_pool_id": "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "region": "us-east-1"
}
```

## 🎯 Usage

### Authentication Client Commands

```bash
# Check configuration status
cogauth status

# Configure authentication settings
cogauth configure

# Login with username prompt
cogauth login

# Login with specific username
cogauth login -u your-username

# Login and update specific AWS profile
cogauth login -u your-username --profile my-profile

# Skip Lambda proxy and use only Identity Pool credentials
cogauth login -u your-username --no-lambda-proxy

# Set credential duration (Lambda proxy only)
cogauth login -u your-username --duration 8

# Get help
cogauth --help
```

### Administrative Commands

```bash
# View Identity Pool role information
cogadmin role info

# Create S3 access policy for a bucket
cogadmin policy create-s3-policy --bucket-name my-bucket

# Create S3 policy with user isolation (Cognito identity-based)
cogadmin policy create-s3-policy --bucket-name my-bucket --user-specific

# Create DynamoDB access policy with user isolation
cogadmin policy create-dynamodb-policy --table-name my-table

# Apply custom policy from JSON file
cogadmin role apply-policy --policy-file custom-policy.json --policy-name MyPolicy

# Deploy Lambda credential proxy
cogadmin lambda deploy --access-key-id AKIA... --secret-access-key ...

# Create new IAM user for Lambda proxy (requires admin permissions)
cogadmin lambda deploy --create-user

# Set up new Cognito Identity Pool interactively
cogadmin setup-identity-pool

# Get help for admin commands
cogadmin --help
```

### Example Workflow

```bash
# 1. Configure once
cogauth configure

# 2. Login and get credentials
cogauth login -u myuser

# Sample output:
# 🎫 Getting temporary credentials from Cognito Identity Pool...
# ✅ Successfully obtained Identity Pool credentials (expires at 2025-08-12 14:30:00 PST)
# 🎫 Attempting to upgrade to longer-lived credentials via Lambda proxy...
# ✅ Successfully upgraded to longer-lived credentials (expires at 2025-08-13 01:30:00 PST)

# 3. Use AWS CLI commands
aws s3 ls
aws sts get-caller-identity
aws s3 sync s3://my-bucket/my-folder ./local-folder
```

## 🛠️ AWS Infrastructure Setup

### Option 1: Automated Setup (Recommended)

Use the provided administrative commands:

```bash
# Deploy complete Lambda infrastructure with new IAM user
cogadmin lambda deploy --create-user

# Or deploy with existing IAM user credentials
cogadmin lambda deploy --access-key-id AKIA... --secret-access-key ...

# Set up new Cognito Identity Pool interactively
cogadmin setup-identity-pool

# View current role configuration
cogadmin role info
```

### Option 2: Manual Setup

If you prefer to set up AWS infrastructure manually, follow these steps:

#### 1. Cognito User Pool

Create a User Pool with the following settings:
- **Sign-in options**: Username
- **Password policy**: As per your security requirements
- **MFA**: Optional but recommended
- **App client**:
  - Client type: Public client
  - Authentication flows: `ALLOW_USER_PASSWORD_AUTH`, `ALLOW_REFRESH_TOKEN_AUTH`

Required information:
- User Pool ID (format: `us-east-1_xxxxxxxxx`)
- App Client ID

#### 2. Cognito Identity Pool

Create an Identity Pool with:
- **Authentication providers**: Cognito User Pool
- **User Pool ID**: Your User Pool ID from step 1
- **App Client ID**: Your App Client ID from step 1

Required information:
- Identity Pool ID (format: `us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

#### 3. IAM Roles

The Identity Pool creates two roles automatically. You need to configure the **authenticated role**:

**Minimum permissions for Cognito authenticated role:**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "cognito-identity:GetCredentialsForIdentity",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": "arn:aws:lambda:REGION:ACCOUNT:function:cognito-credential-proxy"
        }
    ]
}
```

#### 4. Lambda Proxy (Optional - for 12-hour credentials)

Create a Lambda function with:
- **Runtime**: Python 3.9+
- **Code**: Use `src/aws_cognito_auth/lambda_function.py`
- **Environment variables**:
  - `IAM_USER_ACCESS_KEY_ID`: IAM user access key ID
  - `IAM_USER_SECRET_ACCESS_KEY`: IAM user secret access key
  - `DEFAULT_ROLE_ARN`: Long-lived role ARN

**IAM User for Lambda** (minimum permissions):
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole",
                "sts:TagSession"
            ],
            "Resource": "arn:aws:iam::ACCOUNT:role/CognitoLongLivedRole"
        }
    ]
}
```

**Long-lived Role Trust Policy**:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::ACCOUNT:user/cognito-proxy-user"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": ["us-east-1", "us-west-2", "ap-southeast-1"]
                }
            }
        }
    ]
}
```

## 📋 Role and Policy Management

### Role Manager Tool

The project includes comprehensive administrative tools for handling IAM policies and AWS infrastructure:

```bash
# View current Identity Pool role information
cogadmin role info

# Create S3 policy with user isolation (Cognito identity-based)
cogadmin policy create-s3-policy --bucket-name my-bucket --user-specific

# Create S3 policy with full bucket access
cogadmin policy create-s3-policy --bucket-name my-bucket

# Create DynamoDB policy with user isolation
cogadmin policy create-dynamodb-policy --table-name my-table

# Apply custom policy from JSON file
cogadmin role apply-policy --policy-file my-policy.json --policy-name MyPolicy

# Deploy Lambda credential proxy infrastructure
cogadmin lambda deploy --create-user
```

### Service-Specific Permissions

#### S3 Access (User Isolation)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
            "Resource": "arn:aws:s3:::BUCKET/${cognito-identity.amazonaws.com:sub}/*"
        },
        {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::BUCKET",
            "Condition": {
                "StringLike": {
                    "s3:prefix": "${cognito-identity.amazonaws.com:sub}/*"
                }
            }
        }
    ]
}
```

#### DynamoDB Access
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:Query"
            ],
            "Resource": "arn:aws:dynamodb:REGION:ACCOUNT:table/TABLE_NAME",
            "Condition": {
                "ForAllValues:StringEquals": {
                    "dynamodb:LeadingKeys": "${cognito-identity.amazonaws.com:sub}"
                }
            }
        }
    ]
}
```

#### Lambda Execution
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": [
                "arn:aws:lambda:REGION:ACCOUNT:function:user-function-*",
                "arn:aws:lambda:REGION:ACCOUNT:function:cognito-credential-proxy"
            ]
        }
    ]
}
```

## 🔧 Advanced Configuration

### Environment Variables

```bash
# Cognito Configuration
export COGNITO_USER_POOL_ID="us-east-1_xxxxxxxxx"
export COGNITO_CLIENT_ID="your-client-id"
export COGNITO_IDENTITY_POOL_ID="us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AWS_REGION="us-east-1"

# Note: Lambda proxy credentials are configured in the Lambda function environment,
# not in the client application for security reasons
```

### Multiple Environment Setup

```bash
# Development environment
cogauth login -u dev-user --profile development

# Production environment
cogauth login -u prod-user --profile production

# Use with different profiles
aws --profile development s3 ls
aws --profile production s3 ls
```

## ⚙️ Admin Configuration

### Configuration System

The AWS Cognito Authoriser uses a hierarchical configuration system for administrative settings that allows you to customize AWS service names and parameters without modifying code.

### Configuration Files

1. **Global Admin Config**: `~/.cognito-admin-config.json` - User-level settings
2. **Local Project Config**: `admin-config.json` - Project-specific overrides
3. **Default Values**: Built-in defaults for all services

### Interactive Configuration

Set up admin configuration interactively:
```bash
cogadmin configure
```

This command will prompt you to configure:
- AWS service names (IAM users, roles, Lambda functions)
- AWS configuration parameters (regions, timeouts, session duration)
- Policy names for all components

### Configuration Template

Create `admin-config.json` in your project directory or `~/.cognito-admin-config.json` in your home directory:

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

### Environment-Specific Configurations

**Development Environment:**
```json
{
  "aws_service_names": {
    "long_lived_role_name": "CognitoDevRole",
    "lambda_function_name": "cognito-proxy-dev"
  },
  "aws_configuration": {
    "default_bucket": "my-dev-bucket"
  }
}
```

**Production Environment:**
```json
{
  "aws_service_names": {
    "long_lived_role_name": "CognitoProdRole",
    "lambda_function_name": "cognito-proxy-prod"
  },
  "aws_configuration": {
    "default_bucket": "my-prod-bucket",
    "max_session_duration": 28800
  }
}
```

### Configuration Loading Priority

1. **Built-in defaults** (lowest priority)
2. **Global config** (`~/.cognito-admin-config.json`)
3. **Local project config** (`admin-config.json`) (highest priority)

### Configurable Components

#### AWS Service Names
- **IAM User Name**: User for Lambda proxy authentication
- **Lambda Execution Role**: Role for Lambda function execution
- **Long-lived Role**: Role users assume for extended credentials
- **Lambda Function Name**: Name of the credential proxy function
- **Identity Pool Name**: Cognito Identity Pool name

#### AWS Configuration Parameters
- **Default Region**: Primary AWS region for deployments
- **Lambda Runtime**: Python version for Lambda functions
- **Lambda Timeout**: Function execution timeout in seconds
- **Max Session Duration**: Maximum credential lifetime (up to 12 hours)
- **Default Bucket**: S3 bucket for basic access policies

#### Policy Names
- **Lambda User Policy**: Policy for Lambda IAM user
- **Lambda Execution Policy**: Basic execution policy
- **S3 Access Policy**: Default S3 access policy name

### Admin Features

The administrative tool provides comprehensive AWS infrastructure management:

```bash
# Configure admin settings interactively
cogadmin configure

# View Identity Pool role configuration
cogadmin role info

# Create service-specific policies
cogadmin policy create-s3-policy --bucket-name my-bucket --user-specific
cogadmin policy create-dynamodb-policy --table-name my-table

# Apply custom policies
cogadmin role apply-policy --policy-file custom-policy.json --policy-name MyPolicy

# Deploy Lambda infrastructure
cogadmin lambda deploy --create-user

# Set up new Cognito Identity Pool
cogadmin setup-identity-pool
```

## 📊 Monitoring and Logging

### CloudWatch Logs

Monitor Lambda proxy execution:
```bash
aws logs tail /aws/lambda/cognito-credential-proxy --follow
```

### Debug Mode

Enable detailed logging:
```bash
export BOTO_DEBUG=1
cogauth login -u username
```

## ❗ Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "Missing configuration" | Run `configure` command or set environment variables |
| "Invalid username or password" | Verify credentials in Cognito console; check if password reset needed |
| "Access denied" with AWS commands | Check IAM policies on Identity Pool authenticated role |
| "Lambda proxy failed" | Check Lambda function logs; verify IAM user permissions |
| "Unable to locate credentials" | Ensure fallback credentials are configured; check Lambda environment variables |

### Error Messages

**"Identity Pool configuration error"**
- Solution: Configure Identity Pool to accept tokens from your User Pool
- Check: AWS Console → Cognito → Identity Pool → Authentication providers

**"AssumeRoleWithWebIdentity" access denied**
- Solution: Update role trust policy to allow web identity federation
- Check: IAM role trust policy for Identity Pool authenticated role

**"Lambda function not found"**
- Solution: Deploy Lambda function using `cogadmin lambda deploy`
- Verify: Function name matches your configuration (default: `cognito-credential-proxy`)

### Testing Setup

```bash
# Test configuration
cogauth status

# Test authentication (will show detailed error messages)
cogauth login -u test-user

# Test AWS access
aws sts get-caller-identity
aws s3 ls
```

## 🔒 Security Considerations

- **Credentials Storage**: Temporary credentials are stored in standard AWS credentials file
- **Password Handling**: Passwords are never logged or stored persistently
- **Network Security**: All communications use HTTPS/TLS
- **Access Control**: IAM policies enforce least-privilege access
- **Credential Expiration**: Automatic credential expiration (1-12 hours)
- **Audit Trail**: CloudTrail logs all AWS API calls made with temporary credentials

## 📚 Additional Resources

### Project Files

- `src/aws_cognito_auth/client.py` - Main authentication client
- `src/aws_cognito_auth/admin.py` - Administrative tools for AWS infrastructure
- `src/aws_cognito_auth/lambda_function.py` - Lambda proxy function
- `policies/` - IAM policy templates (JSON files)
- `pyproject.toml` - Project configuration and dependencies

### AWS Services Used

- **AWS Cognito User Pool**: User authentication and management
- **AWS Cognito Identity Pool**: Temporary credential exchange
- **AWS Lambda**: Extended credential duration (optional)
- **AWS IAM**: Role and policy management
- **AWS STS**: Security Token Service for temporary credentials

## 📄 License

This project is provided as-is for educational and development purposes. Please review and adapt the code according to your security requirements before using in production environments.

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Follow existing code style and patterns
- Add appropriate error handling
- Update documentation for new features
- Test thoroughly with different AWS configurations

---

**⚡ Quick Start Summary:**
1. `pip install -e .`
2. `cogauth configure`
3. `cogauth login -u username`
4. Use AWS CLI commands normally!

---

Repository initiated with [fpgmaas/cookiecutter-uv](https://github.com/fpgmaas/cookiecutter-uv).
