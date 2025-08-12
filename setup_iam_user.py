#!/usr/bin/env python3
"""
IAM User Setup for Cognito Credential Proxy
Helps setup or check permissions for your existing IAM user
"""

import boto3
import json
import click
import sys
from botocore.exceptions import ClientError


def check_iam_user_permissions(username, access_key_id):
    """Check if IAM user has necessary permissions"""
    print(f"🔍 Checking permissions for IAM user: {username}")
    
    iam = boto3.client('iam')
    account_id = boto3.client('sts').get_caller_identity()['Account']
    
    required_permissions = [
        f"arn:aws:iam::{account_id}:role/CognitoLongLivedRole"
    ]
    
    # Check inline policies
    try:
        inline_policies = iam.list_user_policies(UserName=username)
        print(f"📋 Found {len(inline_policies['PolicyNames'])} inline policies")
        
        for policy_name in inline_policies['PolicyNames']:
            policy = iam.get_user_policy(UserName=username, PolicyName=policy_name)
            print(f"   • {policy_name}")
            
    except ClientError as e:
        print(f"⚠️ Could not check inline policies: {e}")
    
    # Check attached managed policies
    try:
        attached_policies = iam.list_attached_user_policies(UserName=username)
        print(f"📋 Found {len(attached_policies['AttachedPolicies'])} attached managed policies")
        
        for policy in attached_policies['AttachedPolicies']:
            print(f"   • {policy['PolicyName']} ({policy['PolicyArn']})")
            
    except ClientError as e:
        print(f"⚠️ Could not check attached policies: {e}")
    
    return True


def add_cognito_permissions(username):
    """Add necessary permissions to IAM user"""
    print(f"🔧 Adding Cognito credential proxy permissions to user: {username}")
    
    iam = boto3.client('iam')
    account_id = boto3.client('sts').get_caller_identity()['Account']
    
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "sts:AssumeRole",
                    "sts:TagSession"
                ],
                "Resource": f"arn:aws:iam::{account_id}:role/CognitoLongLivedRole"
            }
        ]
    }
    
    policy_name = "CognitoCredentialProxyAccess"
    
    try:
        iam.put_user_policy(
            UserName=username,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document)
        )
        print(f"✅ Added inline policy: {policy_name}")
        return True
        
    except ClientError as e:
        print(f"❌ Failed to add policy: {e}")
        return False


def get_username_from_access_key(access_key_id):
    """Try to get username from access key"""
    try:
        # Use the access key to get caller identity
        temp_sts = boto3.client('sts', 
            aws_access_key_id=access_key_id,
            aws_secret_access_key="dummy"  # This will fail but might give us info
        )
        identity = temp_sts.get_caller_identity()
        arn = identity.get('Arn', '')
        if ':user/' in arn:
            return arn.split(':user/')[-1]
    except:
        pass
    
    # Alternative: try to list access keys for common usernames
    print("⚠️ Could not automatically determine username from access key")
    return None


@click.command()
@click.option('--username', help='IAM username to check/setup')
@click.option('--access-key-id', help='Access key ID to determine username')
@click.option('--add-permissions', is_flag=True, help='Add required permissions to the user')
def main(username, access_key_id, add_permissions):
    """Check or setup IAM user permissions for Cognito credential proxy"""
    
    if not username and not access_key_id:
        print("❌ Error: Provide either --username or --access-key-id")
        print("Example: python setup_iam_user.py --username myuser --add-permissions")
        sys.exit(1)
    
    # Try to determine username if not provided
    if not username and access_key_id:
        username = get_username_from_access_key(access_key_id)
        if not username:
            username = click.prompt("Enter your IAM username")
    
    try:
        # Check current permissions
        check_iam_user_permissions(username, access_key_id)
        
        # Add permissions if requested
        if add_permissions:
            if add_cognito_permissions(username):
                print(f"\n✅ Successfully setup permissions for user: {username}")
                print(f"\nYou can now deploy with:")
                print(f"python deploy_lambda.py --access-key-id YOUR_KEY --secret-access-key YOUR_SECRET")
            else:
                print(f"\n❌ Failed to setup permissions")
                sys.exit(1)
        else:
            print(f"\nTo add required permissions, run:")
            print(f"python setup_iam_user.py --username {username} --add-permissions")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()