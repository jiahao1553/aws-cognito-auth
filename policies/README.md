# IAM Policy Templates

This directory contains IAM policy templates used by the AWS Cognito Auth administration tools. These templates use placeholder variables that are automatically replaced when applied.

## Policy Templates

### Core Infrastructure Policies

#### `lambda-execution-trust-policy.json`
Trust policy for Lambda execution role that allows AWS Lambda service to assume the role.

#### `lambda-execution-policy.json`
Basic execution policy for Lambda functions that allows CloudWatch Logs access.

#### `lambda-user-policy.json`
Policy for the IAM user that the Lambda function uses to assume the long-lived role.
- **Placeholder**: `{account_id}` - AWS account ID

#### `long-lived-role-trust-policy.json`
Trust policy for the long-lived role that allows the Lambda IAM user to assume it.
- **Placeholder**: `{lambda_user_arn}` - ARN of the Lambda IAM user

#### `cognito-identity-pool-auth-policy.json`
Minimum policy required for the Cognito Identity Pool authenticated role.
- **Placeholder**: `{region}` - AWS region
- **Placeholder**: `{account_id}` - AWS account ID

### Service Access Policies

#### `s3-access-policy.json`
Basic S3 access policy for a specific bucket with full permissions.
- Default bucket: `my-s3-bucket`
- Actions: GetObject, PutObject, DeleteObject, ListBucket

#### `s3-user-isolation-policy.json`
S3 access policy with user-specific prefixes using Cognito Identity ID.
- **Placeholder**: `{bucket_name}` - S3 bucket name
- **Features**: User isolation using `${cognito-identity.amazonaws.com:sub}`

#### `dynamodb-user-isolation-policy.json`
DynamoDB access policy with user isolation using Cognito Identity ID as partition key.
- **Placeholder**: `{region}` - AWS region
- **Placeholder**: `{account_id}` - AWS account ID
- **Placeholder**: `{table_name}` - DynamoDB table name
- **Features**: Row-level security using `${cognito-identity.amazonaws.com:sub}`

#### `lambda-invoke-policy.json`
Policy allowing invocation of specific Lambda functions.
- **Placeholder**: `{region}` - AWS region
- **Placeholder**: `{account_id}` - AWS account ID
- **Functions**: User functions with prefix `user-function-*` and `cognito-credential-proxy`

## Usage

These policies are automatically loaded by the admin tool:

```bash
# Create S3 policy with user isolation
cogadmin policy create-s3-policy --bucket-name my-bucket --user-specific

# Create DynamoDB policy
cogadmin policy create-dynamodb-policy --table-name my-table

# Apply custom policy from file
cogadmin role apply-policy --policy-file custom-policy.json --policy-name CustomPolicy
```

## Placeholder Variables

Common placeholder variables used across policies:

- `{account_id}` - AWS account ID (12-digit number)
- `{region}` - AWS region (e.g., `us-east-1`, `ap-southeast-1`)
- `{bucket_name}` - S3 bucket name
- `{table_name}` - DynamoDB table name
- `{lambda_user_arn}` - ARN of the Lambda IAM user
- `{long_lived_role_name}` - Name of the long-lived role (configurable)
- `{default_bucket}` - Default S3 bucket name (configurable)

## Cognito Identity Variables

These policies use Cognito Identity Pool policy variables for user isolation:

- `${cognito-identity.amazonaws.com:sub}` - Unique user identity ID
- These variables are automatically resolved by AWS when the policy is evaluated

## Security Notes

1. **User Isolation**: Policies with user isolation ensure users can only access their own data
2. **Least Privilege**: Each policy grants minimal required permissions
3. **Regional Restrictions**: Some policies include regional restrictions for security
4. **Audit Trail**: All actions are logged in CloudTrail for monitoring

## Customization

To create custom policies:

1. Create a new JSON file in this directory
2. Use placeholder variables as needed
3. Reference the policy in the admin tool using `load_policy_template()`
4. Add appropriate CLI commands in `src/aws_cognito_auth/admin.py`
