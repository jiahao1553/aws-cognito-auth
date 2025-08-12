#!/usr/bin/env python3
"""
Deployment script for Lambda credential proxy
"""

import json
import os
import zipfile

import boto3
import click


def create_lambda_user():
    """Create IAM user for Lambda function to avoid role chaining limits"""
    iam = boto3.client("iam")
    
    # Get account ID for specific role ARN
    account_id = boto3.client('sts').get_caller_identity()['Account']
    
    user_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow", 
                "Action": [
                    "sts:AssumeRole",
                    "sts:TagSession"
                ], 
                "Resource": f"arn:aws:iam::{account_id}:role/CognitoLongLivedRole"
            },
        ],
    }

    user_name = "CognitoCredentialProxyUser"

    try:
        # Create user
        iam.create_user(
            UserName=user_name,
            Path="/",
        )

        # Attach inline policy
        iam.put_user_policy(
            UserName=user_name,
            PolicyName="CognitoCredentialProxyPolicy",
            PolicyDocument=json.dumps(user_policy),
        )
        
        # Create access keys
        keys_response = iam.create_access_key(UserName=user_name)
        access_key = keys_response['AccessKey']

        print(f"✅ Created IAM user: {user_name}")
        print(f"   Access Key ID: {access_key['AccessKeyId']}")
        print(f"   Secret Access Key: {access_key['SecretAccessKey']}")
        
        return {
            'user_arn': f"arn:aws:iam::{account_id}:user/{user_name}",
            'access_key_id': access_key['AccessKeyId'],
            'secret_access_key': access_key['SecretAccessKey']
        }

    except iam.exceptions.EntityAlreadyExistsException:
        print(f"ℹ️  IAM user {user_name} already exists")
        
        # Update the policy in case it changed
        try:
            iam.put_user_policy(
                UserName=user_name,
                PolicyName="CognitoCredentialProxyPolicy",
                PolicyDocument=json.dumps(user_policy),
            )
            print(f"✅ Updated policy for {user_name}")
        except Exception as e:
            print(f"⚠️  Could not update policy: {e}")
            
        # Try to get existing access key or create a new one
        try:
            keys = iam.list_access_keys(UserName=user_name)
            if keys['AccessKeyMetadata']:
                access_key_id = keys['AccessKeyMetadata'][0]['AccessKeyId']
                print(f"ℹ️  Using existing access key: {access_key_id}")
                print(f"⚠️  Cannot retrieve existing secret - you may need to create new keys manually")
                return {
                    'user_arn': f"arn:aws:iam::{account_id}:user/{user_name}",
                    'access_key_id': access_key_id,
                    'secret_access_key': 'EXISTING_KEY_SECRET_NOT_RETRIEVABLE'
                }
            else:
                # Create new access key
                keys_response = iam.create_access_key(UserName=user_name)
                access_key = keys_response['AccessKey']
                print(f"✅ Created new access key for existing user")
                return {
                    'user_arn': f"arn:aws:iam::{account_id}:user/{user_name}",
                    'access_key_id': access_key['AccessKeyId'],
                    'secret_access_key': access_key['SecretAccessKey']
                }
        except Exception as e:
            print(f"⚠️  Could not handle access keys: {e}")
            return {
                'user_arn': f"arn:aws:iam::{account_id}:user/{user_name}",
                'access_key_id': 'MANUAL_SETUP_REQUIRED',
                'secret_access_key': 'MANUAL_SETUP_REQUIRED'
            }


def create_lambda_role():
    """Create minimal IAM role for Lambda function (just for execution, not for assuming other roles)"""
    iam = boto3.client("iam")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    
    role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    }

    role_name = "CognitoCredentialProxyRole"

    try:
        # Create role
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Minimal execution role for Cognito credential proxy Lambda",
        )

        # Attach inline policy
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="CognitoCredentialProxyPolicy",
            PolicyDocument=json.dumps(role_policy),
        )

        print(f"✅ Created minimal IAM role: {role_name}")

    except iam.exceptions.EntityAlreadyExistsException:
        print(f"ℹ️  IAM role {role_name} already exists")
        
        # Update the policy in case it changed
        try:
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName="CognitoCredentialProxyPolicy",
                PolicyDocument=json.dumps(role_policy),
            )
            print(f"✅ Updated policy for {role_name}")
        except Exception as e:
            print(f"⚠️  Could not update policy: {e}")

    # Get role ARN
    role = iam.get_role(RoleName=role_name)
    return role["Role"]["Arn"]


def create_long_lived_role(lambda_role_arn):
    """Create the role that users will assume for long-lived credentials"""
    iam = boto3.client("iam")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": lambda_role_arn
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:RequestedRegion": ["ap-southeast-1", "us-east-1", "us-west-2"]}
                },
            }
        ],
    }

    role_name = "CognitoLongLivedRole"

    try:
        # Create role
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Long-lived role for Cognito authenticated users",
            MaxSessionDuration=43200,  # 12 hours
        )

        print(f"✅ Created long-lived role: {role_name}")

        # You can attach policies as needed
        # For example, S3 access:
        s3_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:ListBucket",
                    ],
                    "Resource": [
                        "arn:aws:s3:::precise-aws-setup",
                        "arn:aws:s3:::precise-aws-setup/*",
                    ],
                }
            ],
        }

        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="S3AccessPolicy",
            PolicyDocument=json.dumps(s3_policy),
        )

    except iam.exceptions.EntityAlreadyExistsException:
        print(f"ℹ️  Role {role_name} already exists")
        
        # Update the trust policy in case it changed
        try:
            iam.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(trust_policy)
            )
            print(f"✅ Updated trust policy for {role_name}")
        except Exception as e:
            print(f"⚠️  Could not update trust policy: {e}")
            
    except Exception as e:
        print(f"❌ Failed to create {role_name}: {e}")
        raise

    # Get role ARN
    role = iam.get_role(RoleName=role_name)
    return role["Role"]["Arn"]


def create_lambda_function(lambda_role_arn, user_credentials):
    """Create and deploy Lambda function"""

    # Create deployment package
    lambda_zip = "lambda_deployment.zip"

    with zipfile.ZipFile(lambda_zip, "w") as zip_file:
        zip_file.write("lambda_credential_proxy.py", "lambda_function.py")

    # Read the zip file
    with open(lambda_zip, "rb") as zip_file:
        zip_content = zip_file.read()

    # Create Lambda function
    lambda_client = boto3.client("lambda")
    function_name = "cognito-credential-proxy"
    
    environment_vars = {
        "DEFAULT_ROLE_ARN": "arn:aws:iam::767397975955:role/CognitoLongLivedRole",
        "IAM_USER_ACCESS_KEY_ID": user_credentials['access_key_id'],
        "IAM_USER_SECRET_ACCESS_KEY": user_credentials['secret_access_key']
    }

    try:
        response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.9",
            Role=lambda_role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": zip_content},
            Description="Exchange Cognito tokens for long-lived AWS credentials",
            Timeout=30,
            Environment={"Variables": environment_vars},
        )

        print(f"✅ Created Lambda function: {function_name}")
        print(f"   Function ARN: {response['FunctionArn']}")
        function_arn = response['FunctionArn']

    except lambda_client.exceptions.ResourceConflictException:
        print(f"ℹ️  Lambda function {function_name} already exists, updating...")

        # Update function code
        lambda_client.update_function_code(
            FunctionName=function_name, ZipFile=zip_content
        )
        
        # Update environment variables
        if user_credentials['secret_access_key'] != 'EXISTING_KEY_SECRET_NOT_RETRIEVABLE':
            try:
                lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    Environment={"Variables": environment_vars}
                )
                print(f"✅ Updated environment variables")
            except Exception as e:
                print(f"⚠️  Could not update environment variables: {e}")

        response = lambda_client.get_function(FunctionName=function_name)
        print(f"✅ Updated Lambda function: {function_name}")
        function_arn = response['Configuration']['FunctionArn']

    # Clean up
    os.remove(lambda_zip)

    return function_arn


@click.command()
@click.option("--region", default="ap-southeast-1", help="AWS region")
@click.option("--access-key-id", help="Your IAM user access key ID")
@click.option("--secret-access-key", help="Your IAM user secret access key")
@click.option("--create-user", is_flag=True, help="Create new IAM user (requires elevated permissions)")
def deploy(region, access_key_id, secret_access_key, create_user):
    """Deploy the Lambda credential proxy"""

    # Set region
    boto3.setup_default_session(region_name=region)

    try:
        print("🚀 Deploying Cognito Credential Proxy...")

        # Handle user credentials
        if access_key_id and secret_access_key:
            print("\n1. Using provided IAM user credentials...")
            user_credentials = {
                'user_arn': f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:user/cognito-proxy-user",
                'access_key_id': access_key_id,
                'secret_access_key': secret_access_key
            }
            print(f"✅ Using provided credentials for access key: {access_key_id}")
            
        elif create_user:
            print("\n1. Creating new IAM user...")
            user_credentials = create_lambda_user()
            
        else:
            print("❌ Error: You must either:")
            print("   1. Provide --access-key-id and --secret-access-key for your existing IAM user")
            print("   2. Use --create-user flag (requires elevated permissions)")
            print("\nExample:")
            print("   python deploy_lambda.py --access-key-id AKIA... --secret-access-key ...")
            return
            
        # Create roles
        print("\n2. Creating IAM roles...")
        lambda_role_arn = create_lambda_role()
        long_lived_role_arn = create_long_lived_role(user_credentials['user_arn'])

        print(f"   Lambda Role: {lambda_role_arn}")
        print(f"   Long-lived Role: {long_lived_role_arn}")

        # Wait a bit for role to propagate
        print("\n3. Waiting for role propagation...")
        import time

        time.sleep(10)

        # Create Lambda function
        print("\n4. Creating Lambda function...")
        function_arn = create_lambda_function(lambda_role_arn, user_credentials)

        print("\n✅ Deployment complete!")
        print("\n📋 Next steps:")
        print(f"1. Update your client code to call Lambda function: {function_arn}")
        print("2. Set up API Gateway if you want HTTP access")
        print("3. Update the long-lived role policies as needed")

    except Exception as e:
        print(f"❌ Deployment failed: {e}")


if __name__ == "__main__":
    deploy()
