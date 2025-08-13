# AWS Infrastructure Setup

Complete guide for setting up the required AWS infrastructure to use the Cognito Authoriser.

## Overview

The AWS Cognito Authoriser requires several AWS components:

1. **Cognito User Pool** - User authentication
2. **Cognito Identity Pool** - Credential exchange
3. **IAM Roles** - Permission management
4. **Lambda Function** (Optional) - Extended credentials

## Quick Setup (Recommended)

Use the automated administrative commands for easiest setup:

```bash
# Deploy complete Lambda infrastructure with new IAM user
cogadmin lambda deploy --create-user

# Set up new Cognito Identity Pool interactively
cogadmin setup-identity-pool

# View current configuration
cogadmin role info
```

## Manual Setup

If you prefer manual setup or need custom configurations:

### Step 1: Cognito User Pool

1. **Go to AWS Console → Cognito → User Pools**
2. **Click "Create user pool"**
3. **Configure sign-in options:**
   - Sign-in options: **Username**
   - Username attributes: **Email** (optional)
4. **Password policy:** Set according to your security requirements
5. **MFA:** Optional but recommended for production
6. **Create the pool**

7. **Create App Client:**
   - Go to your User Pool → App integration → App clients
   - Click "Create app client"
   - Client type: **Public client**
   - App client name: `cognito-auth-client`
   - Authentication flows:
     - ✅ `ALLOW_USER_PASSWORD_AUTH`
     - ✅ `ALLOW_REFRESH_TOKEN_AUTH`

8. **Note the values:**
   - User Pool ID: `us-east-1_xxxxxxxxx`
   - App Client ID: `your-app-client-id`

### Step 2: Cognito Identity Pool

1. **Go to AWS Console → Cognito → Identity Pools**
2. **Click "Create new identity pool"**
3. **Identity pool name:** `CognitoAuthIdentityPool`
4. **Authentication providers:**
   - Select **Cognito User Pool**
   - User Pool ID: `us-east-1_xxxxxxxxx` (from Step 1)
   - App Client ID: `your-app-client-id` (from Step 1)
5. **Click "Create pool"**

6. **Configure IAM Roles:**
   - AWS will create two roles automatically
   - Note the **Authenticated role** ARN
   - Identity Pool ID: `us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

### Step 3: Configure Identity Pool Role

Add minimum permissions to the **Authenticated role**:

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

Replace `REGION` and `ACCOUNT` with your AWS region and account ID.

### Step 4: Lambda Proxy (Optional)

For 12-hour credentials, set up the Lambda proxy:

#### Create IAM User for Lambda

1. **Create IAM User:**
   ```bash
   aws iam create-user --user-name CognitoCredentialProxyUser
   aws iam create-access-key --user-name CognitoCredentialProxyUser
   ```

2. **Attach Policy:**
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

#### Create Long-Lived Role

1. **Trust Policy:**
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Principal": {
                   "AWS": "arn:aws:iam::ACCOUNT:user/CognitoCredentialProxyUser"
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

2. **Permission Policy:** Add your service-specific permissions (S3, DynamoDB, etc.)

#### Deploy Lambda Function

1. **Create Lambda Function:**
   - Runtime: Python 3.9+
   - Function name: `cognito-credential-proxy`
   - Code: Use `src/aws_cognito_auth/lambda_function.py`

2. **Environment Variables:**
   ```
   IAM_USER_ACCESS_KEY_ID=AKIA...
   IAM_USER_SECRET_ACCESS_KEY=...
   DEFAULT_ROLE_ARN=arn:aws:iam::ACCOUNT:role/CognitoLongLivedRole
   ```

3. **Execution Role:** Basic Lambda execution role with CloudWatch Logs access

## Service-Specific Permissions

### S3 Access

#### Basic S3 Policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::my-bucket",
                "arn:aws:s3:::my-bucket/*"
            ]
        }
    ]
}
```

#### S3 with User Isolation (Recommended)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
            "Resource": "arn:aws:s3:::my-bucket/${cognito-identity.amazonaws.com:sub}/*"
        },
        {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::my-bucket",
            "Condition": {
                "StringLike": {
                    "s3:prefix": "${cognito-identity.amazonaws.com:sub}/*"
                }
            }
        }
    ]
}
```

### DynamoDB Access

#### DynamoDB with User Isolation
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
            "Resource": "arn:aws:dynamodb:REGION:ACCOUNT:table/my-table",
            "Condition": {
                "ForAllValues:StringEquals": {
                    "dynamodb:LeadingKeys": "${cognito-identity.amazonaws.com:sub}"
                }
            }
        }
    ]
}
```

### Lambda Invocation
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

## Using Administrative Tools

The `cogadmin` command provides helpers for common setups:

### Create Service Policies
```bash
# S3 policy with user isolation
cogadmin policy create-s3-policy --bucket-name production-data --user-specific

# DynamoDB policy with user isolation
cogadmin policy create-dynamodb-policy --table-name user-sessions

# Apply custom policy
cogadmin role apply-policy --policy-file custom-permissions.json --policy-name CustomAccess
```

### Infrastructure Deployment
```bash
# Complete Lambda setup (creates IAM user, roles, Lambda function)
cogadmin lambda deploy --create-user

# View current setup
cogadmin role info
```

## Validation

Test your setup:

```bash
# Check configuration
cogauth status

# Test authentication
cogauth login -u test-user

# Verify AWS access
aws sts get-caller-identity
aws s3 ls  # (if S3 permissions configured)
```

## Security Considerations

1. **Use least-privilege permissions**
2. **Enable user isolation for multi-tenant scenarios**
3. **Set appropriate credential durations**
4. **Monitor usage via CloudTrail**
5. **Regularly rotate IAM user credentials**
6. **Use MFA for Cognito User Pool in production**

## Troubleshooting Setup

See [Troubleshooting](troubleshooting.md) for common setup issues and solutions.

## Environment-Specific Setup

### Development
- Shorter credential durations
- More permissive policies for testing
- Separate S3 buckets/DynamoDB tables

### Production
- Longer credential durations
- Strict user isolation
- MFA enabled
- Comprehensive monitoring

### Staging
- Mirror production setup
- Use separate AWS account if possible
- Test deployment procedures
