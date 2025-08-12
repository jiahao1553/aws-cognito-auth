# AWS Cognito Authoriser

[![Release](https://img.shields.io/github/v/release/jiahao1553/aws-cognito-auth)](https://img.shields.io/github/v/release/jiahao1553/aws-cognito-auth)
[![Build status](https://img.shields.io/github/actions/workflow/status/jiahao1553/aws-cognito-auth/main.yml?branch=main)](https://github.com/jiahao1553/aws-cognito-auth/actions/workflows/main.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/jiahao1553/aws-cognito-auth/branch/main/graph/badge.svg)](https://codecov.io/gh/jiahao1553/aws-cognito-auth)
[![Commit activity](https://img.shields.io/github/commit-activity/m/jiahao1553/aws-cognito-auth)](https://img.shields.io/github/commit-activity/m/jiahao1553/aws-cognito-auth)
[![License](https://img.shields.io/github/license/jiahao1553/aws-cognito-auth)](https://img.shields.io/github/license/jiahao1553/aws-cognito-auth)

A robust command-line tool that provides seamless authentication with AWS Cognito User Pool and Identity Pool, automatically obtaining temporary AWS credentials that work without requiring local AWS profile configuration.

- **Github repository**: <https://github.com/jiahao1553/aws-cognito-auth/>
- **Documentation**: <https://jiahao1553.github.io/aws-cognito-auth/>

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

## 📦 Quick Start

### Installation

```bash
pip install -e .
```

### Basic Usage

```bash
# Configure the authentication client
cogauth configure

# Login and get credentials
cogauth login -u your-username

# Use AWS CLI commands normally
aws s3 ls
aws sts get-caller-identity
```

### Administrative Commands

```bash
# View Identity Pool role information
cogadmin role info

# Deploy Lambda credential proxy
cogadmin lambda deploy --create-user

# Create service-specific policies
cogadmin policy create-s3-policy --bucket-name my-bucket --user-specific
```

## 📚 Documentation Sections

- **[Installation & Setup](installation.md)** - Detailed installation and initial configuration
- **[Usage Guide](usage.md)** - Comprehensive guide to all CLI commands
- **[AWS Setup](aws-setup.md)** - Step-by-step AWS infrastructure setup
- **[Administration](administration.md)** - Administrative tools and policy management
- **[Configuration](configuration.md)** - Advanced configuration options
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions
- **[API Reference](modules.md)** - Python API documentation

## 🔒 Security

- **Credentials Storage**: Temporary credentials stored in standard AWS credentials file
- **Password Handling**: Passwords never logged or stored persistently
- **Network Security**: All communications use HTTPS/TLS
- **Access Control**: IAM policies enforce least-privilege access
- **Credential Expiration**: Automatic credential expiration (1-12 hours)
- **Audit Trail**: CloudTrail logs all AWS API calls

## 🤝 Contributing

Contributions are welcome! Please see our [contributing guidelines](https://github.com/jiahao1553/aws-cognito-auth/blob/main/CONTRIBUTING.md) and ensure:

- Follow existing code style and patterns
- Add appropriate error handling
- Update documentation for new features
- Test thoroughly with different AWS configurations

## 📄 License

This project is provided as-is for educational and development purposes. Please review and adapt the code according to your security requirements before using in production environments.
