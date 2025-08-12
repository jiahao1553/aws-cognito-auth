# AWS Cognito Authoriser

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
   cd aws-authoriser
   ```

2. **Install the package:**
   ```bash
   pip install -e .
   ```

3. **Configure the tool:**
   ```bash
   aws-cognito-auth configure
   ```

4. **Login and get credentials:**
   ```bash
   aws-cognito-auth login -u your-username
   ```

## ⚙️ Configuration

### Method 1: Interactive Configuration
```bash
aws-cognito-auth configure
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
aws-cognito-auth status

# Configure authentication settings
aws-cognito-auth configure

# Login with username prompt
aws-cognito-auth login

# Login with specific username
aws-cognito-auth login -u your-username

# Login and update specific AWS profile
aws-cognito-auth login -u your-username --profile my-profile

# Skip Lambda proxy and use only Identity Pool credentials
aws-cognito-auth login -u your-username --no-lambda-proxy

# Set credential duration (Lambda proxy only)
aws-cognito-auth login -u your-username --duration 8

# Get help
aws-cognito-auth --help
```

### Administrative Commands

```bash
# View Identity Pool role information
aws-cognito-admin role info

# Create S3 access policy for a bucket
aws-cognito-admin policy create-s3-policy --bucket-name my-bucket

# Create S3 policy with user isolation (Cognito identity-based)
aws-cognito-admin policy create-s3-policy --bucket-name my-bucket --user-specific

# Create DynamoDB access policy with user isolation
aws-cognito-admin policy create-dynamodb-policy --table-name my-table

# Apply custom policy from JSON file
aws-cognito-admin role apply-policy --policy-file custom-policy.json --policy-name MyPolicy

# Deploy Lambda credential proxy
aws-cognito-admin lambda deploy --access-key-id AKIA... --secret-access-key ...

# Create new IAM user for Lambda proxy (requires admin permissions)
aws-cognito-admin lambda deploy --create-user

# Set up new Cognito Identity Pool interactively
aws-cognito-admin setup-identity-pool

# Get help for admin commands
aws-cognito-admin --help
```

### Example Workflow

```bash
# 1. Configure once
aws-cognito-auth configure

# 2. Login and get credentials
aws-cognito-auth login -u myuser

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
aws-cognito-admin lambda deploy --create-user

# Or deploy with existing IAM user credentials
aws-cognito-admin lambda deploy --access-key-id AKIA... --secret-access-key ...

# Set up new Cognito Identity Pool interactively
aws-cognito-admin setup-identity-pool

# View current role configuration
aws-cognito-admin role info
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
- **Code**: Use `lambda_credential_proxy.py`
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
aws-cognito-admin role info

# Create S3 policy with user isolation (Cognito identity-based)
aws-cognito-admin policy create-s3-policy --bucket-name my-bucket --user-specific

# Create S3 policy with full bucket access
aws-cognito-admin policy create-s3-policy --bucket-name my-bucket

# Create DynamoDB policy with user isolation
aws-cognito-admin policy create-dynamodb-policy --table-name my-table

# Apply custom policy from JSON file
aws-cognito-admin role apply-policy --policy-file my-policy.json --policy-name MyPolicy

# Deploy Lambda credential proxy infrastructure
aws-cognito-admin lambda deploy --create-user
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
python3 aws_cognito_auth.py login -u dev-user --profile development

# Production environment  
python3 aws_cognito_auth.py login -u prod-user --profile production

# Use with different profiles
aws --profile development s3 ls
aws --profile production s3 ls
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
python3 aws_cognito_auth.py login -u username
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
- Solution: Deploy Lambda function using `deploy_lambda.py`
- Verify: Function name is `cognito-credential-proxy`

### Testing Setup

```bash
# Test configuration
python3 aws_cognito_auth.py status

# Test authentication (will show detailed error messages)
python3 aws_cognito_auth.py login -u test-user

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
2. `aws-cognito-auth configure`
3. `aws-cognito-auth login -u username`
4. Use AWS CLI commands normally!