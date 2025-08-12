#!/usr/bin/env python3
"""
Lambda-based AWS Credential Proxy
This Lambda function exchanges Cognito User Pool tokens for longer-lived STS credentials
"""

import base64
import json
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    """
    Lambda function to exchange Cognito tokens for STS credentials
    
    Expected event structure:
    {
        "id_token": "cognito_id_token",
        "duration_seconds": 43200,  # optional, default 12 hours
        "role_arn": "arn:aws:iam::ACCOUNT:role/ROLE_NAME"  # optional, uses default
    }
    """
    
    try:
        # Parse request
        body = json.loads(event.get('body', '{}')) if event.get('body') else event
        
        
        id_token = body.get('id_token')
        duration_seconds = body.get('duration_seconds', 43200)  # 12 hours default
        role_arn = body.get('role_arn', 'arn:aws:iam::767397975955:role/CognitoLongLivedRole')
        
        if not id_token:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'id_token is required'})
            }
        
        # Validate and decode the ID token
        token_claims = validate_cognito_token(id_token)
        if not token_claims:
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'Invalid or expired token'})
            }
        
        # Extract user info from token
        user_id = token_claims.get('sub')
        username = token_claims.get('cognito:username', token_claims.get('email', user_id))
        
        print(f"Attempting to assume role: {role_arn}")
        print(f"Duration: {duration_seconds} seconds")
        print(f"Token user info - sub: {user_id}, username: {username}")
        
        # Create STS client using IAM user credentials (not Lambda role)
        # This avoids the role chaining limitation
        import os
        access_key = os.environ.get('IAM_USER_ACCESS_KEY_ID')
        secret_key = os.environ.get('IAM_USER_SECRET_ACCESS_KEY')
        
        print(f"Debug - Using access key: {access_key[:4]}...{access_key[-4:] if access_key else 'None'}")
        print(f"Debug - Using secret key: {'***REDACTED***' if secret_key else 'None'}")
        
        if not access_key or not secret_key:
            raise Exception("Missing IAM user credentials in environment variables")
        
        try:
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
        except Exception as e:
            print(f"Debug - Failed to create STS client: {e}")
            raise Exception(f"Failed to create STS client: {e}")
        
        # Test the STS client credentials
        try:
            caller_identity = sts_client.get_caller_identity()
            print(f"Debug - STS client identity: {caller_identity['Arn']}")
        except Exception as e:
            print(f"Debug - STS client identity check failed: {e}")
            raise
        
        # Assume role for longer duration (temporarily without tags to debug)
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f'CognitoUser-{username[-8:]}-{int(datetime.now().timestamp())}',  # Truncate username for session name length
            DurationSeconds=min(duration_seconds, 43200)  # Max 12 hours
        )
        
        credentials = response['Credentials']
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'access_key_id': credentials['AccessKeyId'],
                'secret_access_key': credentials['SecretAccessKey'],
                'session_token': credentials['SessionToken'],
                'expiration': credentials['Expiration'].isoformat(),
                'user_id': user_id,
                'username': username
            }, default=str)
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        print(f"AWS ClientError: {error_code} - {error_message}")
        print(f"Full error: {e.response}")
        
        return {
            'statusCode': 403,
            'body': json.dumps({
                'error': f'AWS Error: {error_code}',
                'message': error_message,
                'details': str(e.response) if error_code == 'AccessDenied' else None
            })
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def validate_cognito_token(id_token):
    """
    Validate Cognito ID token and return claims
    This is a simplified version - in production, you should verify the signature
    """
    try:
        # Decode JWT payload (middle part)
        token_parts = id_token.split('.')
        if len(token_parts) != 3:
            return None
            
        payload = token_parts[1]
        # Add padding if needed
        payload += '=' * (4 - len(payload) % 4)
        decoded_payload = base64.urlsafe_b64decode(payload)
        token_claims = json.loads(decoded_payload)
        
        # Basic validation - check expiration
        exp = token_claims.get('exp', 0)
        if datetime.now().timestamp() >= exp:
            return None  # Token expired
            
        # Verify token type
        token_use = token_claims.get('token_use')
        if token_use != 'id':
            return None  # Not an ID token
            
        return token_claims
        
    except Exception as e:
        print(f"Token validation error: {e}")
        return None


# For testing locally
if __name__ == '__main__':
    # Test event
    test_event = {
        'body': json.dumps({
            'id_token': 'your_test_token_here',
            'duration_seconds': 7200  # 2 hours
        })
    }
    
    result = lambda_handler(test_event, {})
    print(json.dumps(result, indent=2))