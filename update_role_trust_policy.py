#!/usr/bin/env python3
"""
Update IAM Role Trust Policy for Web Identity Federation
Updates the existing role to allow AssumeRoleWithWebIdentity from Cognito User Pool
"""

import boto3
import json
import click
import sys
from pathlib import Path
from botocore.exceptions import ClientError


def load_config():
    """Load configuration from the CLI tool"""
    config = {}
    
    # Try environment variables first
    import os
    config['user_pool_id'] = os.getenv('COGNITO_USER_POOL_ID')
    config['client_id'] = os.getenv('COGNITO_CLIENT_ID')
    config['identity_pool_id'] = os.getenv('COGNITO_IDENTITY_POOL_ID')
    config['region'] = os.getenv('AWS_REGION')
    
    # Try config file
    config_file = Path.home() / '.cognito-cli-config.json'
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                for key, value in file_config.items():
                    if not config.get(key):
                        config[key] = value
        except Exception:
            pass
    
    return config


def create_web_identity_trust_policy(client_id, user_pool_id, region):
    """Create trust policy for web identity federation"""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "cognito-idp.amazonaws.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "cognito-idp.amazonaws.com:aud": client_id
                    },
                    "ForAnyValue:StringLike": {
                        "cognito-idp.amazonaws.com:amr": "authenticated"
                    }
                }
            }
        ]
    }


@click.command()
@click.option('--role-arn', required=True, help='ARN of the IAM role to update')
@click.option('--dry-run', is_flag=True, help='Show the new trust policy without applying it')
def update_trust_policy(role_arn, dry_run):
    """Update IAM role trust policy to support web identity federation"""
    
    # Load configuration
    config = load_config()
    
    required_fields = ['user_pool_id', 'client_id']
    missing_fields = [field for field in required_fields if not config.get(field)]
    
    if missing_fields:
        click.echo(f"❌ Missing configuration: {', '.join(missing_fields)}")
        click.echo("Run 'aws-cognito-auth configure' first or set environment variables")
        sys.exit(1)
    
    # Extract role name from ARN
    role_name = role_arn.split('/')[-1]
    region = config.get('region') or config['user_pool_id'].split('_')[0]
    
    try:
        # Initialize IAM client
        iam = boto3.client('iam', region_name=region)
        
        # Get current trust policy
        click.echo(f"🔍 Getting current trust policy for role: {role_name}")
        current_policy_response = iam.get_role(RoleName=role_name)
        current_trust_policy = current_policy_response['Role']['AssumeRolePolicyDocument']
        
        click.echo("📄 Current Trust Policy:")
        click.echo(json.dumps(current_trust_policy, indent=2))
        
        # Create new trust policy
        new_trust_policy = create_web_identity_trust_policy(
            config['client_id'], 
            config['user_pool_id'], 
            region
        )
        
        click.echo(f"\n📄 New Trust Policy:")
        click.echo(json.dumps(new_trust_policy, indent=2))
        
        if dry_run:
            click.echo(f"\n🔍 Dry run - policy not applied")
            click.echo(f"To apply: python update_role_trust_policy.py --role-arn {role_arn}")
            return
        
        # Confirm update
        click.echo(f"\n⚠️  This will replace the current trust policy.")
        if not click.confirm("Do you want to continue?"):
            click.echo("❌ Operation cancelled")
            return
        
        # Update trust policy
        click.echo(f"📝 Updating trust policy for role: {role_name}")
        iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(new_trust_policy)
        )
        
        click.echo(f"✅ Trust policy updated successfully!")
        click.echo(f"\n🧪 Test your setup with:")
        click.echo(f"   aws-cognito-auth login -u your-username")
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'NoSuchEntity':
            click.echo(f"❌ Role not found: {role_name}")
        elif error_code == 'AccessDenied':
            click.echo(f"❌ Access denied. Make sure you have IAM permissions to update roles")
        else:
            click.echo(f"❌ Error: {error_message}")
        
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    update_trust_policy()