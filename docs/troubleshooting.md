# Troubleshooting Guide

Complete troubleshooting guide for common issues with the AWS Cognito Authoriser.

## Quick Diagnostics

### Check System Status
```bash
# Verify installation
cogauth --version
cogadmin --version

# Check configuration
cogauth status

# Test AWS connectivity
aws sts get-caller-identity
```

### Debug Mode
```bash
# Enable detailed logging
export BOTO_DEBUG=1
export LOG_LEVEL=DEBUG
cogauth login -u test-user
```

## Common Issues

### Installation Issues

#### Command Not Found: `cogauth` or `cogadmin`

**Symptoms:**
```bash
$ cogauth --help
bash: cogauth: command not found
```

**Solutions:**

1. **Verify Installation:**
   ```bash
   pip show aws-cognito-auth
   pip list | grep aws-cognito-auth
   ```

2. **Reinstall Package:**
   ```bash
   pip uninstall aws-cognito-auth
   pip install -e .
   ```

3. **Check PATH:**
   ```bash
   which python
   python -m pip show aws-cognito-auth
   ```

4. **Use Full Path:**
   ```bash
   python -m aws_cognito_auth.client --help
   python -m aws_cognito_auth.admin --help
   ```

#### Import Errors

**Symptoms:**
```
ModuleNotFoundError: No module named 'aws_cognito_auth'
```

**Solutions:**

1. **Check Python Version:**
   ```bash
   python --version  # Should be 3.9+
   ```

2. **Install in Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # OR
   venv\Scripts\activate     # Windows
   pip install -e .
   ```

3. **Install Dependencies:**
   ```bash
   pip install boto3 click botocore
   ```

### Configuration Issues

#### Missing Configuration

**Symptoms:**
```
Error: Missing required configuration. Please run 'cogauth configure' first.
```

**Solutions:**

1. **Run Interactive Configuration:**
   ```bash
   cogauth configure
   ```

2. **Check Configuration File:**
   ```bash
   cat ~/.cognito-cli-config.json
   ```

3. **Set Environment Variables:**
   ```bash
   export COGNITO_USER_POOL_ID="us-east-1_xxxxxxxxx"
   export COGNITO_CLIENT_ID="your-client-id"
   export COGNITO_IDENTITY_POOL_ID="us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   export AWS_REGION="us-east-1"
   ```

#### Invalid Configuration Format

**Symptoms:**
```
JSONDecodeError: Expecting property name enclosed in double quotes
```

**Solutions:**

1. **Validate JSON Syntax:**
   ```bash
   python -m json.tool ~/.cognito-cli-config.json
   ```

2. **Fix Common JSON Errors:**
   - Use double quotes for strings
   - Remove trailing commas
   - Escape backslashes

3. **Recreate Configuration:**
   ```bash
   rm ~/.cognito-cli-config.json
   cogauth configure
   ```

### Authentication Issues

#### Invalid Username or Password

**Symptoms:**
```
Error: Invalid username or password
```

**Solutions:**

1. **Verify User Exists:**
   ```bash
   aws cognito-idp admin-get-user --user-pool-id us-east-1_xxxxxxxxx --username test-user
   ```

2. **Check Password Requirements:**
   - Verify password meets User Pool policy
   - Check if password reset is required

3. **Test with Different User:**
   ```bash
   cogauth login -u different-user
   ```

#### User Pool Configuration Error

**Symptoms:**
```
Error: User pool us-east-1_xxxxxxxxx does not exist or is not accessible
```

**Solutions:**

1. **Verify User Pool ID:**
   ```bash
   aws cognito-idp describe-user-pool --user-pool-id us-east-1_xxxxxxxxx
   ```

2. **Check Region:**
   ```bash
   aws configure get region
   export AWS_REGION=us-east-1
   ```

3. **Verify AWS Credentials:**
   ```bash
   aws sts get-caller-identity
   ```

#### App Client Configuration Error

**Symptoms:**
```
Error: App client does not exist or authentication flow not enabled
```

**Solutions:**

1. **Check App Client:**
   ```bash
   aws cognito-idp describe-user-pool-client --user-pool-id us-east-1_xxxxxxxxx --client-id your-client-id
   ```

2. **Verify Authentication Flows:**
   - Enable `ALLOW_USER_PASSWORD_AUTH`
   - Enable `ALLOW_REFRESH_TOKEN_AUTH`

3. **Update Client Configuration:**
   ```bash
   aws cognito-idp update-user-pool-client --user-pool-id us-east-1_xxxxxxxxx --client-id your-client-id --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH
   ```

### Identity Pool Issues

#### Identity Pool Configuration Error

**Symptoms:**
```
Error: Identity pool us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx does not exist
```

**Solutions:**

1. **Verify Identity Pool:**
   ```bash
   aws cognito-identity describe-identity-pool --identity-pool-id "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   ```

2. **Check Authentication Providers:**
   ```bash
   aws cognito-identity get-identity-pool-configuration --identity-pool-id "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   ```

3. **Set Up Identity Pool:**
   ```bash
   cogadmin setup-identity-pool
   ```

#### AssumeRoleWithWebIdentity Access Denied

**Symptoms:**
```
Error: User is not authorized to perform: sts:AssumeRoleWithWebIdentity
```

**Solutions:**

1. **Check Role Trust Policy:**
   ```bash
   aws iam get-role --role-name Cognito_IdentityPoolAuth_Role
   ```

2. **Update Trust Policy:**
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
                       "cognito-identity.amazonaws.com:aud": "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                   },
                   "ForAnyValue:StringLike": {
                       "cognito-identity.amazonaws.com:amr": "authenticated"
                   }
               }
           }
       ]
   }
   ```

### Lambda Proxy Issues

#### Lambda Function Not Found

**Symptoms:**
```
Error: Lambda function 'cognito-credential-proxy' not found. Please deploy it first using cogadmin lambda deploy
```

**Solutions:**

1. **Deploy Lambda Function:**
   ```bash
   cogadmin lambda deploy --create-user
   ```

2. **Check Function Exists:**
   ```bash
   aws lambda get-function --function-name cognito-credential-proxy
   ```

3. **Skip Lambda Proxy:**
   ```bash
   cogauth login -u test-user --no-lambda-proxy
   ```

#### Lambda Permission Denied

**Symptoms:**
```
Error: User is not authorized to perform: lambda:InvokeFunction
```

**Solutions:**

1. **Add Lambda Permission to Role:**
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": "lambda:InvokeFunction",
               "Resource": "arn:aws:lambda:*:*:function:cognito-credential-proxy"
           }
       ]
   }
   ```

2. **Apply Policy:**
   ```bash
   cogadmin role apply-policy --policy-file lambda-invoke-policy.json --policy-name LambdaInvokePolicy
   ```

#### Lambda Function Error

**Symptoms:**
```
Error: Lambda function execution failed
```

**Solutions:**

1. **Check Lambda Logs:**
   ```bash
   aws logs tail /aws/lambda/cognito-credential-proxy --follow
   ```

2. **Check Environment Variables:**
   ```bash
   aws lambda get-function-configuration --function-name cognito-credential-proxy
   ```

3. **Update Lambda Code:**
   ```bash
   cogadmin lambda deploy --access-key-id AKIA... --secret-access-key ...
   ```

### AWS CLI Integration Issues

#### Unable to Locate Credentials

**Symptoms:**
```bash
$ aws s3 ls
Unable to locate credentials. You can configure credentials by running "aws configure".
```

**Solutions:**

1. **Check AWS Credentials File:**
   ```bash
   cat ~/.aws/credentials
   ```

2. **Re-login with Cognito:**
   ```bash
   cogauth login -u your-username
   ```

3. **Specify Profile:**
   ```bash
   aws s3 ls --profile default
   ```

#### Access Denied with AWS Commands

**Symptoms:**
```bash
$ aws s3 ls
An error occurred (AccessDenied) when calling the ListBuckets operation
```

**Solutions:**

1. **Check Current Identity:**
   ```bash
   aws sts get-caller-identity
   ```

2. **Verify Role Permissions:**
   ```bash
   cogadmin role info
   ```

3. **Add Required Permissions:**
   ```bash
   cogadmin policy create-s3-policy --bucket-name your-bucket
   ```

## Performance Issues

### Slow Authentication

**Solutions:**

1. **Use Local Configuration:**
   ```bash
   # Create project-specific config
   cp ~/.cognito-cli-config.json ./cognito-cli-config.json
   ```

2. **Optimize Network:**
   - Use appropriate AWS region
   - Check network connectivity
   - Use VPC endpoints if in AWS

### Frequent Re-authentication

**Solutions:**

1. **Use Longer Credentials:**
   ```bash
   cogauth login -u your-username --duration 12
   ```

2. **Check Credential Expiration:**
   ```bash
   aws sts get-caller-identity
   ```

## Network and Connectivity Issues

### Connection Timeout

**Symptoms:**
```
Error: Connection timed out
```

**Solutions:**

1. **Check Internet Connection:**
   ```bash
   ping cognito-idp.us-east-1.amazonaws.com
   ```

2. **Verify AWS Region:**
   ```bash
   export AWS_REGION=us-east-1
   ```

3. **Use Corporate Proxy:**
   ```bash
   export HTTP_PROXY=http://proxy.company.com:8080
   export HTTPS_PROXY=http://proxy.company.com:8080
   ```

### SSL Certificate Errors

**Solutions:**

1. **Update CA Certificates:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update && sudo apt-get install ca-certificates

   # CentOS/RHEL
   sudo yum update ca-certificates
   ```

2. **Use System CA Bundle:**
   ```bash
   export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
   ```

## Advanced Troubleshooting

### Enable Debug Logging

```bash
# Maximum verbosity
export BOTO_DEBUG=1
export LOG_LEVEL=DEBUG
export PYTHONPATH=/path/to/aws-cognito-auth/src

# Run with debug
python -m aws_cognito_auth.client login -u test-user
```

### Capture Network Traffic

```bash
# Install mitmproxy
pip install mitmproxy

# Run with proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
mitmdump --mode transparent
```

### Test Individual Components

```bash
# Test Cognito User Pool authentication
aws cognito-idp admin-initiate-auth \
    --user-pool-id us-east-1_xxxxxxxxx \
    --client-id your-client-id \
    --auth-flow ADMIN_NO_SRP_AUTH \
    --auth-parameters USERNAME=test-user,PASSWORD=test-password

# Test Identity Pool
aws cognito-identity get-id \
    --identity-pool-id "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    --logins cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxxxxxxx=ID_TOKEN

# Test credential exchange
aws cognito-identity get-credentials-for-identity \
    --identity-id "us-east-1:12345678-1234-1234-1234-123456789012" \
    --logins cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxxxxxxx=ID_TOKEN
```

## Getting Help

### Documentation
- [Installation Guide](installation.md)
- [Usage Guide](usage.md)
- [AWS Setup](aws-setup.md)
- [Configuration](configuration.md)

### Support Channels
- **GitHub Issues:** https://github.com/jiahao1553/aws-cognito-auth/issues
- **Documentation:** https://jiahao1553.github.io/aws-cognito-auth/

### Providing Debug Information

When reporting issues, include:

1. **System Information:**
   ```bash
   python --version
   pip show aws-cognito-auth
   aws --version
   ```

2. **Configuration (sanitized):**
   ```bash
   # Remove sensitive values before sharing
   cat ~/.cognito-cli-config.json
   ```

3. **Error Output:**
   ```bash
   # Full command and error output
   cogauth login -u test-user 2>&1
   ```

4. **Debug Logs:**
   ```bash
   # Run with debug mode
   BOTO_DEBUG=1 cogauth login -u test-user > debug.log 2>&1
   ```
