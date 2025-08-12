# CogAuth - AWS Cognito Authentication CLI

A streamlined command-line tool for AWS Cognito User Pool and Identity Pool authentication. Get temporary AWS credentials seamlessly without requiring pre-configured AWS profiles.

## 🚀 Quick Start

```bash
# Install
pip install cogauth

# Configure
cogauth configure

# Login and get credentials
cogauth login -u your-username
```

## ✨ Features

- 🔐 **Secure Authentication**: Authenticate via AWS Cognito User Pool
- ⏱️ **Flexible Duration**: 1-hour (Identity Pool) or up to 12-hour credentials (with Lambda proxy)
- 🛡️ **Zero Configuration**: Works without pre-configured AWS credentials
- 📦 **Multiple Services**: Supports S3, DynamoDB, Lambda, and other AWS services
- 🎯 **Profile Management**: Updates AWS credentials and config files
- 🔄 **Graceful Fallback**: Always provides working credentials

## 📦 Installation

```bash
pip install cogauth
```

## ⚙️ Configuration

### Interactive Setup
```bash
cogauth configure
```

### Environment Variables
```bash
export COGNITO_USER_POOL_ID="us-east-1_xxxxxxxxx"
export COGNITO_CLIENT_ID="your-client-id"
export COGNITO_IDENTITY_POOL_ID="us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AWS_REGION="us-east-1"
```

### Configuration File
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

```bash
# Check configuration
cogauth status

# Login with username prompt
cogauth login

# Login with specific username
cogauth login -u your-username

# Login with specific AWS profile
cogauth login -u your-username --profile my-profile

# Skip Lambda proxy (1-hour credentials only)
cogauth login -u your-username --no-lambda-proxy

# Set credential duration for Lambda proxy
cogauth login -u your-username --duration 8

# Get help
cogauth --help
```

## 🔧 Extended Features

For advanced administrative features like IAM role management, Lambda deployment, and policy creation, install the companion package:

```bash
pip install cogadmin
```

## 📚 Documentation

For complete documentation, visit: https://jiahao1553.github.io/aws-cognito-auth/

## 🤝 Contributing

Contributions welcome! Please see the main repository for guidelines.
