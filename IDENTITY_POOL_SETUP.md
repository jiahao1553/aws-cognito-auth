# Creating and Configuring Cognito Identity Pool

This guide walks you through creating a Cognito Identity Pool and configuring it to work with your existing User Pool.

## Prerequisites

You should already have:
- ✅ Cognito User Pool (from your original web app)
- ✅ Cognito User Pool Client ID
- ✅ Users created in your User Pool

You need to create:
- ❌ Cognito Identity Pool
- ❌ IAM Roles for authenticated/unauthenticated users

## Step 1: Create Identity Pool (AWS Console)

### 1.1 Navigate to Cognito Identity Pools
1. Go to [AWS Cognito Console](https://console.aws.amazon.com/cognito/)
2. Click **"Identity pools"** (not User pools)
3. Click **"Create identity pool"**

### 1.2 Configure Identity Pool
1. **Identity pool name**: Enter a name (e.g., `MyAppIdentityPool`)
2. **Enable access to unauthenticated identities**: 
   - ✅ Check this if you want to allow anonymous access
   - ❌ Uncheck if you only want authenticated users

### 1.3 Configure Authentication Providers
1. Expand **"Authentication providers"**
2. Click **"Cognito"** tab  
3. **User Pool ID**: Enter your existing User Pool ID (e.g., `us-east-1_XXXXXXXXX`)
4. **App client ID**: Enter your User Pool Client ID
5. Click **"Next"**

### 1.4 Configure IAM Roles
1. **Authenticated role**: 
   - Select **"Create a new IAM role"**
   - Role name: (will be auto-generated, like `Cognito_MyAppIdentityPoolAuth_Role`)
2. **Unauthenticated role** (if enabled):
   - Select **"Create a new IAM role"**  
   - Role name: (will be auto-generated)
3. Click **"Next"**

### 1.5 Review and Create
1. Review your configuration
2. Click **"Create identity pool"**
3. **Save the Identity Pool ID** - you'll need this for the CLI tool!

## Step 2: Configure Identity Pool (AWS CLI Method)

Alternative to console - create via CLI:

```bash
#!/bin/bash

# Set your variables
USER_POOL_ID="us-east-1_XXXXXXXXX"
USER_POOL_CLIENT_ID="your-client-id"
IDENTITY_POOL_NAME="MyAppIdentityPool"
REGION="us-east-1"

# Create Identity Pool
aws cognito-identity create-identity-pool \
    --identity-pool-name "$IDENTITY_POOL_NAME" \
    --allow-unauthenticated-identities \
    --cognito-identity-providers \
        ProviderName="cognito-idp.$REGION.amazonaws.com/$USER_POOL_ID",ClientId="$USER_POOL_CLIENT_ID" \
    --region "$REGION"
```

## Step 3: Set Up IAM Roles

The Identity Pool needs IAM roles to assume when issuing temporary credentials.

### 3.1 Authenticated Role Policy

Create a basic policy for authenticated users:

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
                "arn:aws:s3:::YOUR_BUCKET_NAME/${cognito-identity.amazonaws.com:sub}/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::YOUR_BUCKET_NAME"
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

### 3.2 Trust Relationship

The IAM role should have this trust relationship (usually auto-created):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "cognito-identity.amazonaws.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": "us-east-1:your-identity-pool-id"
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "authenticated"
                }
            }
        }
    ]
}
```

## Step 4: Test Your Setup

### 4.1 Update CLI Configuration
```bash
cd /Users/jiahao.tan/Repos/aws-authoriser

# Configure with your new Identity Pool ID
python3 cognito_cli.py configure
# Enter:
# - User Pool ID: us-east-1_XXXXXXXXX (your existing one)
# - Client ID: your-client-id (your existing one)  
# - Identity Pool ID: us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (newly created)
```

### 4.2 Test Authentication
```bash
# Login
python3 cognito_cli.py login -u your-username

# Test AWS access
aws sts get-caller-identity
aws s3 ls
```

### 4.3 Verify Role Configuration
```bash
# Check your role setup
python3 role_manager.py info
python3 role_manager.py validate
```

## Step 5: Configure S3 Access (Example)

Set up S3 permissions for your authenticated users:

```bash
# Create S3 policy automatically
python3 role_manager.py create-s3-policy --bucket your-bucket-name

# Or use a template
python3 role_manager.py apply-policy \
    --policy-file policies/s3-user-folders.json \
    --policy-name S3UserAccess
```

## Common Issues and Solutions

### Issue 1: "Invalid identity pool configuration"
**Solution**: 
- Verify User Pool ID and Client ID are correct
- Ensure the User Pool and Identity Pool are in the same region
- Check that the User Pool Client allows the required auth flows

### Issue 2: "Access denied" when using AWS CLI
**Solution**:
- Check IAM role has correct policies attached
- Verify trust relationship allows Cognito to assume the role  
- Wait a few minutes for IAM changes to propagate

### Issue 3: "Unable to get identity"
**Solution**:
- Verify Identity Pool allows authenticated identities
- Check that User Pool authentication is working
- Ensure ID token is valid (try re-authenticating)

### Issue 4: "Role not found"
**Solution**:
- Go to IAM console and verify the authenticated role exists
- Check the role name matches what's configured in Identity Pool
- Recreate the role if necessary

## Validation Checklist

After setup, verify:

- ✅ Identity Pool exists and shows your User Pool as authentication provider
- ✅ Authenticated IAM role exists with correct trust relationship
- ✅ Role has appropriate policies for your app's needs
- ✅ CLI tool can authenticate and get temporary credentials
- ✅ AWS CLI commands work with the temporary credentials

## Next Steps

1. **Test the complete flow**:
   ```bash  
   python3 cognito_cli.py login -u testuser
   aws s3 ls s3://your-bucket/
   ```

2. **Configure additional services** as needed (DynamoDB, API Gateway, etc.)

3. **Set up monitoring** (CloudTrail, CloudWatch) to track usage

4. **Create additional policies** for different user types if needed

## Useful Commands Reference

```bash
# Identity Pool operations
aws cognito-identity list-identity-pools --max-results 10
aws cognito-identity describe-identity-pool --identity-pool-id "us-east-1:xxx"
aws cognito-identity get-identity-pool-roles --identity-pool-id "us-east-1:xxx"

# Test authentication flow
aws cognito-identity get-id --identity-pool-id "us-east-1:xxx"
aws cognito-identity get-credentials-for-identity --identity-id "us-east-1:xxx"

# IAM role operations  
aws iam get-role --role-name "Cognito_MyPoolAuth_Role"
aws iam list-role-policies --role-name "Cognito_MyPoolAuth_Role"
```

Remember to replace placeholder values (like `YOUR_BUCKET_NAME`, `us-east-1_XXXXXXXXX`) with your actual resource names and IDs!
