# CogAdmin - AWS Cognito Administration Tool

Administrative companion to CogAuth for managing AWS Cognito infrastructure, IAM policies, and Lambda deployment.

## 🚀 Quick Start

```bash
# Install (requires cogauth)
pip install cogadmin

# Configure admin settings
cogadmin configure

# Deploy Lambda infrastructure
cogadmin lambda deploy --create-user

# View Identity Pool role info
cogadmin role info
```

## ✨ Features

- 🏗️ **Infrastructure Management**: Deploy complete Lambda proxy infrastructure
- 🔧 **IAM Policy Management**: Create and apply custom IAM policies
- 📊 **Role Information**: View and manage Cognito Identity Pool roles
- 🛡️ **Security Policies**: Built-in templates for S3, DynamoDB, Lambda access
- ⚙️ **Configurable Names**: Customize all AWS service names and parameters
- 🎯 **Multi-Environment**: Support for dev, staging, production configurations

## 📦 Installation

```bash
pip install cogadmin
```

**Note**: CogAdmin requires the `cogauth` package as a dependency.

## ⚙️ Admin Configuration

CogAdmin uses a hierarchical configuration system:

1. **Built-in defaults**
2. **Global config**: `~/.cognito-admin-config.json`
3. **Local project config**: `admin-config.json`

### Interactive Configuration
```bash
cogadmin configure
```

### Configuration Template
Create `admin-config.json`:
```json
{
  "aws_service_names": {
    "iam_user_name": "CognitoCredentialProxyUser",
    "lambda_execution_role_name": "CognitoCredentialProxyRole",
    "long_lived_role_name": "CognitoLongLivedRole",
    "lambda_function_name": "cognito-credential-proxy",
    "identity_pool_name": "CognitoAuthIdentityPool"
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

## 🎯 Commands

### Role Management
```bash
# View Identity Pool role information
cogadmin role info

# Apply custom policy from JSON file
cogadmin role apply-policy --policy-file custom-policy.json --policy-name MyPolicy
```

### Policy Management
```bash
# Create S3 access policy
cogadmin policy create-s3-policy --bucket-name my-bucket

# Create S3 policy with user isolation
cogadmin policy create-s3-policy --bucket-name my-bucket --user-specific

# Create DynamoDB policy with user isolation
cogadmin policy create-dynamodb-policy --table-name my-table
```

### Lambda Infrastructure
```bash
# Deploy complete Lambda infrastructure (creates new IAM user)
cogadmin lambda deploy --create-user

# Deploy with existing IAM user credentials
cogadmin lambda deploy --access-key-id AKIA... --secret-access-key ...
```

### Identity Pool Setup
```bash
# Set up new Cognito Identity Pool
cogadmin setup-identity-pool
```

## 📄 Policy Templates

CogAdmin includes built-in policy templates for:

- **S3 Access**: Full bucket access and user isolation
- **DynamoDB Access**: User isolation with Cognito identity
- **Lambda Execution**: Function invocation permissions
- **IAM Management**: Core infrastructure policies

All templates use configurable placeholders that are automatically replaced during deployment.

## 🔧 Multi-Environment Support

Configure different environments using separate config files:

```bash
# Development
cogadmin configure  # saves to ~/.cognito-admin-config.json

# Production (in project directory)
# Create admin-config.json with production settings
cogadmin lambda deploy --create-user
```

## 📚 Documentation

For complete documentation, visit: https://jiahao1553.github.io/aws-cognito-auth/

## 🤝 Contributing

Contributions welcome! Please see the main repository for guidelines.
