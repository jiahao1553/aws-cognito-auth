# Usage Guide

Complete guide to using the AWS Cognito Authoriser CLI commands.

## Authentication Client (`cogauth`)

The primary tool for authenticating and obtaining AWS credentials.

### Basic Commands

#### Check Status
```bash
cogauth status
```
Shows current configuration and authentication status.

#### Configure Settings
```bash
cogauth configure
```
Interactive configuration of Cognito settings.

#### Login
```bash
# Login with username prompt
cogauth login

# Login with specific username
cogauth login -u your-username

# Login with specific AWS profile
cogauth login -u your-username --profile my-profile

# Skip Lambda proxy (use only 1-hour Identity Pool credentials)
cogauth login -u your-username --no-lambda-proxy

# Set credential duration for Lambda proxy (1-12 hours)
cogauth login -u your-username --duration 8
```

### Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --username` | Username for authentication | Prompt |
| `--profile` | AWS profile to update | `default` |
| `--no-lambda-proxy` | Skip Lambda credential upgrade | False |
| `--duration` | Credential duration in hours (Lambda only) | 12 |

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

# 3. Use AWS CLI commands normally
aws s3 ls
aws sts get-caller-identity
aws s3 sync s3://my-bucket/my-folder ./local-folder
```

## Administrative Tool (`cogadmin`)

Tool for managing AWS infrastructure and policies.

### Role Management

#### View Role Information
```bash
cogadmin role info
```
Displays current Identity Pool role configuration and permissions.

#### Apply Custom Policies
```bash
cogadmin role apply-policy --policy-file custom-policy.json --policy-name MyPolicy
```

### Policy Management

#### S3 Policies
```bash
# Create S3 policy with full bucket access
cogadmin policy create-s3-policy --bucket-name my-bucket

# Create S3 policy with user isolation (recommended)
cogadmin policy create-s3-policy --bucket-name my-bucket --user-specific
```

#### DynamoDB Policies
```bash
# Create DynamoDB policy with user isolation
cogadmin policy create-dynamodb-policy --table-name my-table
```

### Infrastructure Deployment

#### Lambda Proxy Setup
```bash
# Deploy with new IAM user (requires elevated permissions)
cogadmin lambda deploy --create-user

# Deploy with existing IAM user credentials
cogadmin lambda deploy --access-key-id AKIA... --secret-access-key ...
```

#### Identity Pool Setup
```bash
# Interactive Identity Pool setup
cogadmin setup-identity-pool
```

### Configuration Management
```bash
# Interactive admin configuration
cogadmin configure
```

## Multiple Environment Usage

### Different AWS Profiles
```bash
# Development environment
cogauth login -u dev-user --profile development

# Production environment
cogauth login -u prod-user --profile production

# Use with specific profiles
aws --profile development s3 ls
aws --profile production s3 ls
```

### Environment-Specific Configuration

Create separate config files for different environments:

**Development (`~/.cognito-cli-config-dev.json`)**:
```json
{
    "user_pool_id": "us-east-1_devpool123",
    "client_id": "dev-client-id",
    "identity_pool_id": "us-east-1:dev-identity-pool-id",
    "region": "us-east-1"
}
```

**Production (`~/.cognito-cli-config-prod.json`)**:
```json
{
    "user_pool_id": "us-east-1_prodpool456",
    "client_id": "prod-client-id",
    "identity_pool_id": "us-east-1:prod-identity-pool-id",
    "region": "us-east-1"
}
```

Switch between environments using environment variables or by copying the appropriate config file.

## Advanced Usage

### Credential Duration Options

| Duration | Method | Max Hours | Use Case |
|----------|--------|-----------|----------|
| Short | Identity Pool only | 1 | Quick tasks, testing |
| Medium | Lambda proxy | 4-8 | Development work |
| Long | Lambda proxy | 12 | Long-running processes |

### Automation and Scripts

```bash
#!/bin/bash
# Automated login script
cogauth login -u automated-user --profile automation

# Run AWS commands
aws s3 sync s3://data-bucket/input ./data/
python process_data.py
aws s3 sync ./data/output s3://data-bucket/output/
```

### Security Best Practices

1. **Use user-specific policies** when possible
2. **Set appropriate credential durations**
3. **Use separate environments** for dev/prod
4. **Monitor credential usage** via CloudTrail
5. **Rotate Cognito user passwords** regularly

## Common Use Cases

### Data Processing Pipeline
```bash
# Get long-lived credentials for batch processing
cogauth login -u batch-processor --duration 12 --profile batch

# Process data
aws --profile batch s3 cp s3://input-bucket/data.csv ./
python process_large_dataset.py
aws --profile batch s3 cp results.csv s3://output-bucket/
```

### Development Workflow
```bash
# Daily development login
cogauth login -u developer --duration 8 --profile dev

# Regular development tasks
aws --profile dev s3 ls
aws --profile dev lambda invoke --function-name my-function
```

### CI/CD Integration
```bash
# In CI pipeline
export COGNITO_USER_POOL_ID="${DEV_USER_POOL_ID}"
export COGNITO_CLIENT_ID="${DEV_CLIENT_ID}"
export COGNITO_IDENTITY_POOL_ID="${DEV_IDENTITY_POOL_ID}"

cogauth login -u ci-user --profile ci --no-lambda-proxy
aws --profile ci s3 sync build/ s3://deployment-bucket/
```

## Help and Documentation

```bash
# Get help for main commands
cogauth --help
cogadmin --help

# Get help for specific subcommands
cogadmin role --help
cogadmin policy --help
cogadmin lambda --help
```
