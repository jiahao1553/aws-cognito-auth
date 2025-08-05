# 🆕 No Identity Pool? No Problem!

Since you don't have a Cognito Identity Pool yet, I've created tools to help you set one up quickly.

## What You Need

✅ **You already have (from your web app):**
- Cognito User Pool ID (e.g., `us-east-1_XXXXXXXXX`)
- Cognito User Pool Client ID
- Users created in your User Pool

❌ **You need to create:**
- Cognito Identity Pool
- IAM roles for authenticated users

## Quick Setup (Recommended)

### Option 1: Automated Setup Script
```bash
cd /Users/jiahao.tan/Repos/aws-authoriser

# Install dependencies
make install

# Run automated setup (will prompt for User Pool details)
make setup-identity-pool
```

This will:
1. ✅ Verify your existing User Pool
2. ✅ Create a new Identity Pool  
3. ✅ Create IAM roles with proper trust relationships
4. ✅ Set up basic S3 permissions
5. ✅ Update your CLI configuration
6. ✅ Test the setup

### Option 2: Manual Commands
```bash
# Create Identity Pool with your existing User Pool
python3 identity_pool_setup.py create-full-setup \
    --user-pool-id "us-east-1_XXXXXXXXX" \
    --client-id "your-client-id" \
    --identity-pool-name "MyAppIdentityPool" \
    --bucket-name "your-s3-bucket"

# Validate the setup
python3 identity_pool_setup.py validate-setup
```

## Manual Setup (AWS Console)

If you prefer using the AWS Console:

### 1. Create Identity Pool
1. Go to [AWS Cognito Console](https://console.aws.amazon.com/cognito/)
2. Click **"Identity pools"** → **"Create identity pool"**
3. **Identity pool name**: `MyAppIdentityPool`
4. **Authentication providers** → **Cognito** tab:
   - **User Pool ID**: `us-east-1_XXXXXXXXX` (your existing one)
   - **App client ID**: `your-client-id` (your existing one)
5. **Create new IAM roles** (both authenticated and unauthenticated)
6. Click **"Create identity pool"**
7. **Copy the Identity Pool ID** (e.g., `us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

### 2. Configure CLI
```bash
python3 cognito_cli.py configure
# Enter your User Pool ID, Client ID, and the NEW Identity Pool ID
```

### 3. Set up S3 permissions
```bash
# Find your role
python3 role_manager.py info

# Create S3 policy
python3 role_manager.py create-s3-policy --bucket your-bucket-name
```

## Test Your Setup

After creating the Identity Pool:

```bash
# Test authentication
python3 cognito_cli.py login -u your-username

# Verify you got temporary credentials  
aws sts get-caller-identity

# Test S3 access (if configured)
aws s3 ls s3://your-bucket/
```

## What Gets Created

### Identity Pool
- **Purpose**: Exchanges User Pool tokens for temporary AWS credentials
- **Configuration**: Connected to your existing User Pool
- **Location**: AWS Cognito → Identity pools

### IAM Roles
- **Authenticated Role**: `Cognito_[suffix]_Authenticated_Role`
  - Used when user is logged in via User Pool
  - Has permissions to access your AWS resources
- **Unauthenticated Role**: `Cognito_[suffix]_Unauthenticated_Role` (optional)
  - Used for anonymous access (if enabled)

### Trust Relationships
The IAM roles trust Cognito to assume them:
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
        }
      }
    }
  ]
}
```

## Common Issues

### "User Pool not found"
- Verify your User Pool ID is correct
- Ensure you're in the right AWS region
- Check AWS credentials have permission to access Cognito

### "Access denied creating roles"
- Your AWS credentials need IAM permissions:
  - `iam:CreateRole`
  - `iam:PutRolePolicy`
  - `cognito-identity:CreateIdentityPool`

### "Role already exists"
- The script will use existing roles if found
- You can safely re-run the setup script

## Next Steps

After setup:

1. **Test the complete flow**:
   ```bash
   python3 cognito_cli.py login -u testuser
   aws s3 ls
   ```

2. **Configure additional permissions**:
   ```bash
   python3 role_manager.py info
   python3 role_manager.py create-s3-policy --bucket your-bucket --full-access
   ```

3. **Add more services** (DynamoDB, API Gateway, etc.):
   ```bash
   python3 role_manager.py apply-policy --policy-file policies/multi-service.json --policy-name MultiService
   ```

## Migration Notes

Your web app flow was:
```
User Pool → ID Token → (manual credential handling)
```

Your new CLI flow is:
```
User Pool → ID Token → Identity Pool → Temporary AWS Credentials → AWS CLI
```

The Identity Pool is the missing piece that converts your User Pool tokens into AWS credentials!

---

**Need help?** Run `make validate-identity-pool` to check your setup or `python3 identity_pool_setup.py --help` for more options.
