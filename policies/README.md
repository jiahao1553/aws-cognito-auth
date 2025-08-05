# IAM Policy Templates

This directory contains example IAM policies for your Cognito Identity Pool authenticated role.

## Policy Files

### `s3-user-folders.json`
**Use Case**: S3 access with user isolation - each user can only access their own folder

**Features**:
- Users can read/write/delete objects in `s3://bucket/${identity-id}/`
- Users can list bucket contents but only see their own folder
- Provides complete isolation between users

**Usage**:
```bash
# Edit the file to replace YOUR_BUCKET_NAME
# Then apply the policy
python3 role_manager.py apply-policy --policy-file policies/s3-user-folders.json --policy-name S3UserFolders
```

### `s3-full-bucket.json`
**Use Case**: Full S3 bucket access for all authenticated users

**Features**:
- Users can read/write/delete any object in the bucket
- Users can list all bucket contents
- No isolation between users

**Usage**:
```bash
# Edit the file to replace YOUR_BUCKET_NAME
python3 role_manager.py apply-policy --policy-file policies/s3-full-bucket.json --policy-name S3FullAccess
```

### `multi-service.json`
**Use Case**: Access to multiple AWS services with user isolation

**Features**:
- S3 access with user-specific folders
- DynamoDB access with user-specific records (partition key = identity ID)
- API Gateway invoke permissions
- SES email sending (from specific address)

**Usage**:
```bash
# Edit the file to replace placeholders:
# - YOUR_BUCKET_NAME
# - YOUR_TABLE_NAME  
# - YOUR_API_ID (API Gateway)
# - yourdomain.com (SES from address)
# Then apply the policy
python3 role_manager.py apply-policy --policy-file policies/multi-service.json --policy-name MultiServiceAccess
```

## Quick Commands

### Using the Role Manager

```bash
# View current role and policies
python3 role_manager.py info

# Create S3 policy automatically (user-specific folders)
python3 role_manager.py create-s3-policy --bucket your-bucket-name

# Create S3 policy automatically (full bucket access)
python3 role_manager.py create-s3-policy --bucket your-bucket-name --full-access

# Apply a custom policy file
python3 role_manager.py apply-policy --policy-file policies/s3-user-folders.json --policy-name MyS3Policy

# Validate setup
python3 role_manager.py validate
```

## Customizing Policies

### 1. Replace Placeholders

Before applying any policy, replace these placeholders:

- `YOUR_BUCKET_NAME` - Your S3 bucket name
- `YOUR_TABLE_NAME` - Your DynamoDB table name  
- `YOUR_API_ID` - Your API Gateway API ID
- `us-east-1` - Your AWS region
- `yourdomain.com` - Your domain for SES

### 2. Understanding Variables

- `${cognito-identity.amazonaws.com:sub}` - The user's unique Identity ID
- This variable is automatically replaced by AWS with the actual Identity ID
- Ensures each user can only access their own resources

### 3. Resource ARN Formats

**S3**:
- Bucket: `arn:aws:s3:::bucket-name`
- Object: `arn:aws:s3:::bucket-name/object-key`

**DynamoDB**:
- Table: `arn:aws:dynamodb:region:account-id:table/table-name`
- Index: `arn:aws:dynamodb:region:account-id:table/table-name/index/index-name`

**API Gateway**:
- API: `arn:aws:execute-api:region:account-id:api-id/*`
- Specific method: `arn:aws:execute-api:region:account-id:api-id/stage/method/resource`

## Testing Your Policies

After applying a policy:

1. **Login with your CLI tool**:
   ```bash
   python3 cognito_cli.py login -u your-username
   ```

2. **Test S3 access**:
   ```bash
   aws s3 ls s3://your-bucket/
   aws s3 cp test.txt s3://your-bucket/$(aws sts get-caller-identity --query UserId --output text)/
   ```

3. **Check your identity**:
   ```bash
   aws sts get-caller-identity
   ```

4. **Test other services** (if included in your policy):
   ```bash
   # DynamoDB
   aws dynamodb get-item --table-name your-table --key '{"id":{"S":"test"}}'
   
   # API Gateway (replace with your API endpoint)
   curl -H "Authorization: AWS4-HMAC-SHA256 ..." https://your-api.execute-api.region.amazonaws.com/stage/resource
   ```

## Security Best Practices

### 1. Principle of Least Privilege
- Only grant permissions users actually need
- Use resource-level restrictions when possible
- Use condition blocks to limit access

### 2. User Isolation
- Always use `${cognito-identity.amazonaws.com:sub}` in resource ARNs
- This ensures users can only access their own data
- Test isolation by trying to access another user's resources

### 3. Resource Naming Convention
```
S3: s3://bucket/user-data/${cognito-identity.amazonaws.com:sub}/
DynamoDB: partition key = ${cognito-identity.amazonaws.com:sub}
```

### 4. Monitoring
- Enable CloudTrail for API calls
- Use S3 access logging
- Monitor IAM Access Analyzer recommendations
- Set up CloudWatch alarms for unusual activity

## Troubleshooting

### Common Issues

1. **Access Denied**
   - Check if the policy is correctly attached
   - Verify resource ARNs match your actual resources
   - Wait a few minutes for IAM changes to propagate

2. **Variables Not Working**
   - Ensure you're using the correct variable format: `${cognito-identity.amazonaws.com:sub}`
   - Check that you're authenticated through Cognito (not using permanent credentials)

3. **Resource Not Found**
   - Verify bucket names, table names, API IDs are correct
   - Check that resources exist in the same region
   - Ensure resource ARNs use correct format

### Validation

Use the validation command to check your setup:
```bash
python3 role_manager.py validate
```

This will verify:
- Identity Pool exists and has an authenticated role
- Role has policies attached
- Current AWS credentials are working
