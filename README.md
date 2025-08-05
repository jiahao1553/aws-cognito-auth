# AWS Cognito CLI Authoriser

A command-line tool that authenticates with AWS Cognito User Pool and Identity Pool to obtain temporary credentials and update your AWS CLI profile for seamless AWS CLI usage.

## Features

- ✅ **Secure password input**: Passwords are entered securely without echoing
- ✅ **Profile management**: Updates standard AWS credentials and config files
- ✅ **Multiple profiles**: Support for named profiles beyond default
- ✅ **Configuration persistence**: Saves settings to `~/.cognito-cli-config.json`
- ✅ **Environment variables**: Supports configuration via environment variables
- ✅ **New password challenges**: Handles first-time login password reset
- ✅ **Credential expiration info**: Shows when temporary credentials expire
- ✅ **Regional support**: Automatically detects region from User Pool ID

## Installation

1. **Clone or navigate to this directory:**
   ```bash
   cd /Users/jiahao.tan/Repos/aws-authoriser
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Make the script executable:**
   ```bash
   chmod +x cognito_cli.py
   ```

4. **Optionally, create a symlink for global access:**
   ```bash
   sudo ln -s $(pwd)/cognito_cli.py /usr/local/bin/aws-auth
   ```

## Prerequisites

**If you DON'T have a Cognito Identity Pool yet:**
- 📖 See [`NO_IDENTITY_POOL.md`](NO_IDENTITY_POOL.md) for setup instructions
- 🚀 Or run: `make setup-identity-pool` for automated setup

**If you already have both User Pool AND Identity Pool:**
- Continue with configuration below

## Configuration

### Method 1: Using the configure command
```bash
python cognito_cli.py configure
```

This will prompt you for:
- Cognito User Pool ID (e.g., `us-east-1_xxxxxxxxx`)
- Cognito User Pool Client ID
- Cognito Identity Pool ID
- AWS Region (optional)

### Method 2: Using environment variables
```bash
export COGNITO_USER_POOL_ID="us-east-1_xxxxxxxxx"
export COGNITO_CLIENT_ID="your-client-id"
export COGNITO_IDENTITY_POOL_ID="us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AWS_REGION="us-east-1"  # optional
```

## Usage

### Basic login (updates default profile)
```bash
python cognito_cli.py login
```

### Login with specific username
```bash
python cognito_cli.py login -u your-username
```

### Login and update a specific AWS profile
```bash
python cognito_cli.py login --profile my-cognito-profile
```

### Check configuration status
```bash
python cognito_cli.py status
```

### Get help
```bash
python cognito_cli.py --help
python cognito_cli.py login --help
```

## After Authentication

Once authenticated, you can use standard AWS CLI commands:

### Using default profile
```bash
aws s3 ls
aws s3 sync s3://your-bucket ./local-folder
aws sts get-caller-identity
```

### Using named profile
```bash
aws --profile my-cognito-profile s3 ls
aws --profile my-cognito-profile s3 sync s3://your-bucket ./local-folder
```

## Managing IAM Roles and Policies

The project includes a role manager tool to help you configure the Cognito Identity Pool authenticated role:

### Role Manager Commands

```bash
# View current role and policies
python role_manager.py info

# Create S3 policy automatically (user-specific folders)
python role_manager.py create-s3-policy --bucket your-bucket-name

# Create S3 policy automatically (full bucket access)
python role_manager.py create-s3-policy --bucket your-bucket-name --full-access

# Apply a custom policy from file
python role_manager.py apply-policy --policy-file policies/s3-user-folders.json --policy-name MyS3Policy

# Validate your setup
python role_manager.py validate
```

### Policy Templates

The `policies/` directory contains ready-to-use IAM policy templates:

- `s3-user-folders.json` - S3 access with user isolation
- `s3-full-bucket.json` - Full S3 bucket access
- `multi-service.json` - Access to S3, DynamoDB, API Gateway, and SES

See `policies/README.md` for detailed information on using these templates.

## Configuration Files

The tool creates/updates these files:
- `~/.aws/credentials` - AWS credentials
- `~/.aws/config` - AWS configuration 
- `~/.cognito-cli-config.json` - Tool configuration

## IAM Requirements

Your Cognito Identity Pool's authenticated role needs appropriate permissions for the AWS services you want to access. For S3 access, ensure the role has policies like:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::your-bucket/${cognito-identity.amazonaws.com:sub}/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::your-bucket"
            ],
            "Condition": {
                "StringLike": {
                    "s3:prefix": [
                        "${cognito-identity.amazonaws.com:sub}/*"
                    ]
                }
            }
        }
    ]
}
```

## Migration from Web App

If you're migrating from the original web application, you can use the same Cognito configuration:

```javascript
// From your original main.js:
var userPoolId = "us-east-1_xxxxxxxxx";     // → COGNITO_USER_POOL_ID
var clientId = "your-client-id";            // → COGNITO_CLIENT_ID  
var identityPoolId = "us-east-1:xxxx...";   // → COGNITO_IDENTITY_POOL_ID
var s3bucket = "your-bucket-name";          // → Use with AWS CLI commands
```

## Examples

### Complete workflow example:
```bash
# Configure once
python cognito_cli.py configure

# Login
python cognito_cli.py login -u myusername

# Use AWS CLI
aws s3 ls s3://my-bucket
aws s3 sync s3://my-bucket/my-folder ./local-folder
```

### Using with multiple profiles:
```bash
# Login to different profile
python cognito_cli.py login -u user1 --profile dev-env

# Login to another profile  
python cognito_cli.py login -u user2 --profile prod-env

# Use different profiles
aws --profile dev-env s3 ls
aws --profile prod-env s3 ls
```

## Troubleshooting

### Common Issues

1. **"Missing configuration" error**
   - Run `python cognito_cli.py configure` or set environment variables

2. **"Invalid username or password"**
   - Verify credentials in AWS Cognito console
   - Check if user needs to reset password

3. **"Access denied" when using AWS commands**
   - Check IAM policies on the Identity Pool's authenticated role
   - Verify the role has permissions for the AWS services you're accessing

4. **Credentials expire**
   - Re-run the login command to refresh credentials
   - Temporary credentials typically last 1 hour

### Debug Mode

For troubleshooting, you can enable AWS SDK debug logging:

```bash
export BOTO_DEBUG=1
python cognito_cli.py login
```

## Security Notes

- Passwords are never stored or logged
- Configuration file excludes sensitive credentials
- Temporary credentials automatically expire
- Identity-based access control via IAM policies
- Uses AWS Signature Version 4 for all API calls

## Development

### Project Structure
```
aws-authoriser/
├── cognito_cli.py      # Main CLI application
├── requirements.txt    # Python dependencies
├── README.md          # This file
└── setup.py           # Optional: for pip installation
```

### Adding Features
The code is structured with separate classes for:
- `CognitoAuthenticator`: Handles Cognito authentication
- `AWSProfileManager`: Manages AWS credential files
- CLI commands using Click framework

## License

This project is provided as-is for educational and development purposes.
