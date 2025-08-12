# Long-Lived Cognito Credentials Setup

This solution provides up to 12-hour AWS credentials for users authenticated via Cognito User Pool, without requiring IAM users.

## Architecture

```
User -> Cognito User Pool -> Lambda Proxy -> STS AssumeRole -> Long-lived credentials (12h)
```

## Setup Instructions

### 1. Deploy Lambda Infrastructure

```bash
pip install boto3 click
python deploy_lambda.py --region ap-southeast-1
```

This creates:
- `CognitoCredentialProxyRole` - Lambda execution role
- `CognitoLongLivedRole` - Role users assume for long-lived credentials  
- `cognito-credential-proxy` - Lambda function

### 2. Configure Permissions

Update the `CognitoLongLivedRole` with appropriate policies:

```bash
# Example: S3 access policy
python role_manager.py create-s3-policy --bucket your-bucket-name
```

### 3. Test the Setup

```bash
# Use Lambda proxy (up to 12 hours)
python aws_cognito_auth.py login -u username --duration 12 --use-lambda

# Fallback to Identity Pool (1 hour only)  
python aws_cognito_auth.py login -u username --use-identity-pool
```

## How It Works

1. **User Authentication**: Users authenticate with Cognito User Pool
2. **Token Validation**: Lambda validates the ID token
3. **Role Assumption**: Lambda assumes `CognitoLongLivedRole` with user context
4. **Credential Return**: Returns STS credentials valid for up to 12 hours

## Security Features

- ✅ No IAM users required
- ✅ User isolation via session tags
- ✅ Token validation and expiration checks
- ✅ Proper role assumption with conditions
- ✅ Audit trail in CloudTrail

## Benefits vs AWS SSO

| Feature | This Solution | AWS SSO |
|---------|---------------|---------|
| Cognito Integration | ✅ Direct | ❌ Requires SAML setup |
| Setup Complexity | ✅ Simple | ❌ Complex |
| User Management | ✅ Cognito only | ❌ SSO + Cognito |
| Cost | ✅ Lambda + STS only | ❌ SSO + Lambda + STS |
| Credential Duration | ✅ Up to 12 hours | ✅ Up to 12 hours |

## Customization

### Modify Role Policies
```bash
python role_manager.py apply-policy --policy-file custom-policy.json --policy-name CustomPolicy
```

### Update Lambda Function
```bash
# Edit lambda_credential_proxy.py, then redeploy
python deploy_lambda.py --region ap-southeast-1
```

### Add API Gateway (Optional)
For web applications, you can add API Gateway in front of the Lambda function.

## Troubleshooting

**Lambda not found**: Run `python deploy_lambda.py`
**Role assumption failed**: Check role trust policy and permissions
**Token validation failed**: Verify Cognito User Pool configuration

## Alternative: Auto-Refresh Pattern

If you prefer not to use Lambda, you can implement automatic credential refresh:

```python
import threading
import time
from datetime import datetime, timedelta

def auto_refresh_credentials(auth, tokens, profile_manager, profile):
    """Automatically refresh credentials every 50 minutes"""
    while True:
        time.sleep(50 * 60)  # 50 minutes
        try:
            new_credentials = auth.get_temporary_credentials(tokens['id_token'], use_lambda_proxy=False)
            profile_manager.update_profile(profile, new_credentials, auth.region)
            print("✅ Credentials refreshed automatically")
        except Exception as e:
            print(f"⚠️ Auto-refresh failed: {e}")

# Start background refresh
refresh_thread = threading.Thread(target=auto_refresh_credentials, args=(auth, tokens, profile_manager, profile))
refresh_thread.daemon = True
refresh_thread.start()
```