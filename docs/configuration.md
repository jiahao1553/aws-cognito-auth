# Configuration Guide

Detailed guide to configuring the AWS Cognito Authoriser for different environments and use cases.

## Configuration Overview

The AWS Cognito Authoriser uses a hierarchical configuration system:

1. **Built-in defaults** (lowest priority)
2. **Global configuration** (`~/.cognito-cli-config.json`)
3. **Global admin configuration** (`~/.cognito-admin-config.json`)
4. **Local project configuration** (`cognito-cli-config.json` and `admin-config.json`)
5. **Environment variables** (highest priority)

## Client Configuration

### Configuration File Locations

#### Global Configuration
- **Path:** `~/.cognito-cli-config.json`
- **Scope:** All projects for current user
- **Use:** Common settings like default region

#### Project Configuration
- **Path:** `./cognito-cli-config.json` (in project directory)
- **Scope:** Current project only
- **Use:** Project-specific Cognito pools and settings

### Configuration File Format

```json
{
    "user_pool_id": "us-east-1_xxxxxxxxx",
    "client_id": "your-app-client-id",
    "identity_pool_id": "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "region": "us-east-1",
    "lambda_function_name": "cognito-credential-proxy"
}
```

### Configuration Fields

| Field | Description | Required | Example |
|-------|-------------|----------|---------|
| `user_pool_id` | Cognito User Pool ID | Yes | `us-east-1_ABC123DEF` |
| `client_id` | App Client ID | Yes | `1234567890abcdef` |
| `identity_pool_id` | Identity Pool ID | Yes | `us-east-1:12345678-abcd-1234-efgh-123456789012` |
| `region` | AWS region | Yes | `us-east-1` |
| `lambda_function_name` | Lambda proxy function name | No | `cognito-credential-proxy` |

## Environment Variables

Environment variables take precedence over configuration files:

```bash
# Required
export COGNITO_USER_POOL_ID="us-east-1_xxxxxxxxx"
export COGNITO_CLIENT_ID="your-client-id"
export COGNITO_IDENTITY_POOL_ID="us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AWS_REGION="us-east-1"

# Optional
export LAMBDA_FUNCTION_NAME="cognito-credential-proxy"
```

## Administrative Configuration

### Admin Configuration Files

#### Global Admin Configuration
- **Path:** `~/.cognito-admin-config.json`
- **Scope:** Administrative settings for all projects

#### Project Admin Configuration
- **Path:** `./admin-config.json`
- **Scope:** Project-specific administrative overrides

### Admin Configuration Format

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
    "default_region": "us-east-1",
    "lambda_runtime": "python3.9",
    "lambda_timeout": 30,
    "max_session_duration": 43200,
    "default_bucket": "my-default-bucket"
  }
}
```

### Admin Configuration Fields

#### AWS Service Names
| Field | Description | Default |
|-------|-------------|---------|
| `iam_user_name` | IAM user for Lambda proxy | `CognitoCredentialProxyUser` |
| `lambda_execution_role_name` | Lambda execution role | `CognitoCredentialProxyRole` |
| `long_lived_role_name` | Long-lived credentials role | `CognitoLongLivedRole` |
| `lambda_function_name` | Lambda function name | `cognito-credential-proxy` |
| `identity_pool_name` | Identity Pool name | `CognitoAuthIdentityPool` |

#### AWS Configuration Parameters
| Field | Description | Default |
|-------|-------------|---------|
| `default_region` | Primary AWS region | `us-east-1` |
| `lambda_runtime` | Python version for Lambda | `python3.9` |
| `lambda_timeout` | Lambda timeout (seconds) | `30` |
| `max_session_duration` | Max credential lifetime (seconds) | `43200` (12 hours) |
| `default_bucket` | Default S3 bucket for policies | `my-s3-bucket` |

## Environment-Specific Configuration

### Development Environment

**Client Config (`~/.cognito-cli-config-dev.json`)**:
```json
{
    "user_pool_id": "us-east-1_DEV123ABC",
    "client_id": "dev-client-id-123",
    "identity_pool_id": "us-east-1:dev-pool-12345678-abcd-1234-efgh-123456789012",
    "region": "us-east-1",
    "lambda_function_name": "cognito-proxy-dev"
}
```

**Admin Config (`admin-config-dev.json`)**:
```json
{
  "aws_service_names": {
    "long_lived_role_name": "CognitoDevRole",
    "lambda_function_name": "cognito-proxy-dev"
  },
  "aws_configuration": {
    "max_session_duration": 14400,
    "default_bucket": "my-dev-bucket"
  }
}
```

### Production Environment

**Client Config (`~/.cognito-cli-config-prod.json`)**:
```json
{
    "user_pool_id": "us-east-1_PROD789XYZ",
    "client_id": "prod-client-id-789",
    "identity_pool_id": "us-east-1:prod-pool-87654321-zyxw-4321-hgfe-210987654321",
    "region": "us-east-1",
    "lambda_function_name": "cognito-proxy-prod"
}
```

**Admin Config (`admin-config-prod.json`)**:
```json
{
  "aws_service_names": {
    "long_lived_role_name": "CognitoProdRole",
    "lambda_function_name": "cognito-proxy-prod"
  },
  "aws_configuration": {
    "max_session_duration": 43200,
    "default_bucket": "my-prod-bucket"
  }
}
```

## Multi-Region Configuration

### Primary Region Setup
```json
{
    "region": "us-east-1",
    "user_pool_id": "us-east-1_PRIMARY123",
    "identity_pool_id": "us-east-1:primary-pool-id"
}
```

### Secondary Region Setup
```json
{
    "region": "us-west-2",
    "user_pool_id": "us-west-2_BACKUP456",
    "identity_pool_id": "us-west-2:backup-pool-id"
}
```

## Advanced Configuration Options

### Custom Lambda Configuration
```json
{
  "aws_configuration": {
    "lambda_runtime": "python3.11",
    "lambda_timeout": 60,
    "lambda_memory": 256,
    "lambda_environment": {
      "LOG_LEVEL": "INFO",
      "CUSTOM_SETTING": "value"
    }
  }
}
```

### Security Configuration
```json
{
  "security_settings": {
    "require_mfa": true,
    "session_timeout": 3600,
    "max_login_attempts": 3,
    "password_complexity": "high"
  }
}
```

### Logging Configuration
```json
{
  "logging": {
    "level": "INFO",
    "file": "/var/log/cognito-auth.log",
    "max_size": "10MB",
    "backup_count": 5
  }
}
```

## Configuration Validation

### Interactive Validation
```bash
# Test client configuration
cogauth status

# Test admin configuration
cogadmin configure --validate
```

### Manual Validation
```bash
# Check configuration file syntax
python -m json.tool ~/.cognito-cli-config.json

# Test AWS connectivity
aws sts get-caller-identity

# Verify Cognito pools exist
aws cognito-idp describe-user-pool --user-pool-id us-east-1_xxxxxxxxx
aws cognito-identity describe-identity-pool --identity-pool-id "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

## Configuration Management Scripts

### Environment Switcher Script
```bash
#!/bin/bash
# switch-env.sh

ENV=$1
if [ -z "$ENV" ]; then
    echo "Usage: $0 [dev|staging|prod]"
    exit 1
fi

# Copy environment-specific config
cp ~/.cognito-cli-config-${ENV}.json ~/.cognito-cli-config.json
cp admin-config-${ENV}.json admin-config.json

echo "Switched to $ENV environment"
cogauth status
```

### Configuration Backup Script
```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="$HOME/.cognito-auth-backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup all configuration files
cp ~/.cognito-cli-config.json "$BACKUP_DIR/" 2>/dev/null
cp ~/.cognito-admin-config.json "$BACKUP_DIR/" 2>/dev/null
cp admin-config.json "$BACKUP_DIR/" 2>/dev/null
cp cognito-cli-config.json "$BACKUP_DIR/" 2>/dev/null

echo "Configuration backed up to $BACKUP_DIR"
```

## Troubleshooting Configuration

### Common Issues

#### Configuration Not Found
```bash
# Check file locations and permissions
ls -la ~/.cognito-cli-config.json
ls -la ./cognito-cli-config.json

# Verify JSON syntax
python -m json.tool ~/.cognito-cli-config.json
```

#### Environment Variable Issues
```bash
# Check environment variables
env | grep COGNITO
env | grep AWS_REGION

# Test with temporary variables
COGNITO_USER_POOL_ID="test" cogauth status
```

#### Permission Issues
```bash
# Check AWS credentials
aws sts get-caller-identity

# Check Cognito permissions
aws cognito-idp admin-get-user --user-pool-id us-east-1_xxxxxxxxx --username test-user
```

### Debug Mode

Enable debug logging:
```bash
export BOTO_DEBUG=1
export LOG_LEVEL=DEBUG
cogauth login -u test-user
```

## Best Practices

### Configuration Security
1. **Never commit credentials** to version control
2. **Use IAM roles** instead of access keys when possible
3. **Encrypt sensitive configuration** files
4. **Set appropriate file permissions** (600 for config files)
5. **Use environment-specific configurations**

### Configuration Management
1. **Use version control** for configuration templates
2. **Document environment differences**
3. **Test configuration changes** in development first
4. **Maintain configuration backups**
5. **Use consistent naming conventions**

### Performance Optimization
1. **Use local configuration files** for faster access
2. **Cache configuration data** when possible
3. **Minimize environment variable usage** in production
4. **Use appropriate session durations**

For additional help, see [Troubleshooting](troubleshooting.md).
