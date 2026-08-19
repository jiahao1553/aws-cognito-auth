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
aws sts get-caller-identity
aws s3 ls s3://my-bucket/
aws s3 sync s3://my-bucket/my-folder ./local-folder
```

> **Note:** `aws s3 ls` with no bucket argument lists *all* buckets in the account and needs
> account-wide `s3:ListAllMyBuckets`, which cannot be scoped per user. Always name the bucket:
> `aws s3 ls s3://my-bucket/`.

## 🪣 Bucket Access via Cognito Groups

Which S3 buckets you can reach is decided by the **Cognito user pool groups you belong to**. Each
group is named after a bucket, and one user can be in as many groups as they need.

When you run `cogauth login`, the Lambda proxy reads your group membership and issues credentials
scoped to exactly those buckets. From there you use the AWS CLI normally:

```bash
cogauth login -u alice

# alice is in the "acme-reports" group
aws s3 sync s3://acme-reports/data ./local-folder     # works
aws s3 sync s3://acme-finance ./local-folder          # AccessDenied
```

A few things worth knowing:

- **Scoping is fixed at login.** Your buckets are baked into the credentials when you log in, not
  re-checked per command. Being added to a group takes effect the next time you run `cogauth login`.
- **Removal is not immediate.** Credentials already issued keep their access until they expire (up
  to 12 hours). Use `--duration` to shorten that window.
- **`AccessDenied` on a bucket you expect to have** usually means you are not in that group. Check
  with your administrator.
- **If login prints `⚠️ Lambda proxy failed`**, you fell back to 1-hour Identity Pool credentials
  and will have no bucket access. This is also what a user belonging to *no* groups sees.

### For administrators

Groups are plain Cognito user pool groups — no special tooling required:

```bash
# Create a group named after the bucket it grants
aws cognito-idp create-group \
  --user-pool-id <USER_POOL_ID> --group-name acme-reports

# Add a user to it
aws cognito-idp admin-add-user-to-group \
  --user-pool-id <USER_POOL_ID> --username alice --group-name acme-reports

# Check a user's buckets
aws cognito-idp admin-list-groups-for-user \
  --user-pool-id <USER_POOL_ID> --username alice
```

Group names must be valid S3 bucket names (3–63 characters, lowercase letters, digits, hyphens and
dots). Every group in the pool is interpreted as a bucket grant, so do not create groups here for
unrelated purposes.

**How the enforcement works:** `CognitoLongLivedRole` holds a broad policy covering every managed
bucket, and the Lambda narrows each session at `AssumeRole` time with an inline session policy
naming only the caller's group-buckets. Effective access is the intersection of the two. The Lambda
establishes identity by passing the ID token to `cognito-identity:GetId` — Cognito must verify the
token's signature to federate on it, so a successful call proves the `cognito:groups` claim can be
trusted.

> **⚠️ The Identity Pool authenticated role must have no S3 permissions.** The client falls back to
> that role whenever the Lambda call fails, and `--no-lambda-proxy` skips the Lambda entirely.
> Either path bypasses group scoping completely. See
> [Group-Scoped Bucket Access](docs/group-bucket-access.md) for the full rollout procedure.

## 🔑 IAM Setup for Longer-Lived Credentials

### Complete IAM Configuration Requirements

For the Lambda proxy to provide longer-lived credentials (up to 12 hours), you need to set up three key IAM components:

#### 1. IAM User for Lambda Proxy

Create an IAM user that the Lambda function will use to assume the long-lived role:

**User Name**: `cognito-proxy-user` (or your configured name)

**Inline Policy**: `CognitoCredentialProxyAccess`
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
            "Resource": "arn:aws:iam::YOUR_ACCOUNT_ID:role/CognitoLongLivedRole"
        }
    ]
}
```

**Important**: Generate access keys for this user and configure them in the Lambda function's environment variables.

#### 2. Long-Lived IAM Role

Create a role that users will assume for extended access:

**Role Name**: `CognitoLongLivedRole` (or your configured name)

**Trust Policy** (Critical - must include both AssumeRole and TagSession):
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:user/cognito-proxy-user"
            },
            "Action": ["sts:AssumeRole", "sts:TagSession"],
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": [
                        "ap-southeast-1",
                        "us-east-1",
                        "us-west-2"
                    ]
                }
            }
        }
    ]
}
```

**Permissions Policy**: Add policies based on what AWS services your users need access to (S3, DynamoDB, etc.) with Longer-Lived Credentials

#### 3. Lambda Execution Role

The Lambda function itself needs an execution role:

**Role Name**: `CognitoCredentialProxyRole` (or your configured name)

**Trust Policy**:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

**Managed Policies**:
- `arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole`

### Lambda Environment Variables

Configure these in your Lambda function:

| Variable | Description | Example Value |
|----------|-------------|---------------|
| `IAM_USER_ACCESS_KEY_ID` | Access key ID of the IAM user | `AKIA...` |
| `IAM_USER_SECRET_ACCESS_KEY` | Secret access key of the IAM user | `Ke8TqmD2wgL...` |
| `DEFAULT_ROLE_ARN` | ARN of the long-lived role | `arn:aws:iam::123456789012:role/CognitoLongLivedRole` |
| `IDENTITY_POOL_ID` | Identity Pool used to validate the caller's ID token | `ap-southeast-1:1234abcd-...` |
| `USER_POOL_ID` | User Pool the groups belong to | `ap-southeast-1_AbCdEf123` |

`IDENTITY_POOL_ID` and `USER_POOL_ID` are required for group-based bucket access.
`cogadmin lambda deploy` sets them automatically from `admin-config.json`, falling back to
`~/.cognito-cli-config.json`.

### Identity Pool Configuration (Only setup for Cognito Identity Pool 1hr Credentials)

Your Cognito authenticated role (different from `Long-Lived IAM Role` and `Lambda Execution Role`) needs permission to invoke the Lambda function:

**Add to Identity Pool's authenticated role permission policy**:
```json
{
    "Effect": "Allow",
    "Action": "lambda:InvokeFunction",
    "Resource": "arn:aws:lambda:YOUR_REGION:YOUR_ACCOUNT:function:cognito-credential-proxy"
}
```
**Permissions Policy**: Add policies based on what AWS services your users need access to (S3, DynamoDB, etc.) with Cognito Identity Pool 1hr Credentials

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
