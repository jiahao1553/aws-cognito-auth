#!/usr/bin/env python3
"""
Cognito Role Manager
Helper script to find and manage Cognito Identity Pool authenticated roles
"""

import boto3
import json
import click
import sys
from pathlib import Path
from botocore.exceptions import ClientError


class CognitoRoleManager:
    def __init__(self, identity_pool_id, region=None):
        self.identity_pool_id = identity_pool_id
        self.region = region or identity_pool_id.split(':')[0]
        
        self.cognito_identity = boto3.client('cognito-identity', region_name=self.region)
        self.iam = boto3.client('iam', region_name=self.region)
        self.sts = boto3.client('sts', region_name=self.region)
    
    def get_authenticated_role(self):
        """Get the authenticated role ARN and name"""
        try:
            response = self.cognito_identity.get_identity_pool_roles(
                IdentityPoolId=self.identity_pool_id
            )
            
            if 'Roles' not in response or 'authenticated' not in response['Roles']:
                raise Exception("No authenticated role found for this Identity Pool")
            
            role_arn = response['Roles']['authenticated']
            role_name = role_arn.split('/')[-1]
            
            return {
                'arn': role_arn,
                'name': role_name
            }
        except ClientError as e:
            raise Exception(f"Failed to get Identity Pool roles: {e.response['Error']['Message']}")
    
    def get_role_policies(self, role_name):
        """Get all policies attached to the role"""
        try:
            # Get managed policies
            managed_policies = self.iam.list_attached_role_policies(RoleName=role_name)
            
            # Get inline policies
            inline_policies = self.iam.list_role_policies(RoleName=role_name)
            
            return {
                'managed': managed_policies['AttachedPolicies'],
                'inline': inline_policies['PolicyNames']
            }
        except ClientError as e:
            raise Exception(f"Failed to get role policies: {e.response['Error']['Message']}")
    
    def get_inline_policy(self, role_name, policy_name):
        """Get inline policy document"""
        try:
            response = self.iam.get_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )
            return response['PolicyDocument']
        except ClientError as e:
            raise Exception(f"Failed to get policy: {e.response['Error']['Message']}")
    
    def update_inline_policy(self, role_name, policy_name, policy_document):
        """Update or create inline policy"""
        try:
            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document, indent=2)
            )
            return True
        except ClientError as e:
            raise Exception(f"Failed to update policy: {e.response['Error']['Message']}")


def load_config():
    """Load configuration from the CLI tool"""
    config = {}
    
    # Try environment variables first
    import os
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


def create_s3_policy(bucket_name, user_specific=True):
    """Create S3 access policy template"""
    if user_specific:
        # Users can only access their own folder
        return {
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
                        f"arn:aws:s3:::{bucket_name}/${{cognito-identity.amazonaws.com:sub}}/*"
                    ]
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}"
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
    else:
        # Users can access entire bucket
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:ListBucket"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*"
                    ]
                }
            ]
        }


@click.group()
def cli():
    """Cognito Role Manager - Manage Identity Pool authenticated roles"""
    pass


@cli.command()
@click.option('--identity-pool-id', help='Identity Pool ID (will use config if not provided)')
def info(identity_pool_id):
    """Show information about the authenticated role"""
    
    # Load config if pool ID not provided
    if not identity_pool_id:
        config = load_config()
        identity_pool_id = config.get('identity_pool_id')
        
        if not identity_pool_id:
            click.echo("❌ Identity Pool ID not found. Provide --identity-pool-id or run cognito_cli.py configure first")
            sys.exit(1)
    
    try:
        click.echo(f"🔍 Analyzing Identity Pool: {identity_pool_id}")
        
        manager = CognitoRoleManager(identity_pool_id)
        
        # Get role info
        role_info = manager.get_authenticated_role()
        click.echo(f"✅ Authenticated Role ARN: {role_info['arn']}")
        click.echo(f"✅ Authenticated Role Name: {role_info['name']}")
        
        # Get policies
        policies = manager.get_role_policies(role_info['name'])
        
        click.echo(f"\n📋 Managed Policies ({len(policies['managed'])}):")
        for policy in policies['managed']:
            click.echo(f"   • {policy['PolicyName']} ({policy['PolicyArn']})")
        
        click.echo(f"\n📋 Inline Policies ({len(policies['inline'])}):")
        for policy_name in policies['inline']:
            click.echo(f"   • {policy_name}")
        
        # Show inline policy details
        if policies['inline']:
            click.echo(f"\n📄 Inline Policy Details:")
            for policy_name in policies['inline']:
                try:
                    policy_doc = manager.get_inline_policy(role_info['name'], policy_name)
                    click.echo(f"\n--- {policy_name} ---")
                    click.echo(json.dumps(policy_doc, indent=2))
                except Exception as e:
                    click.echo(f"   ❌ Could not retrieve {policy_name}: {e}")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@cli.command()
@click.option('--identity-pool-id', help='Identity Pool ID (will use config if not provided)')
@click.option('--bucket', required=True, help='S3 bucket name')
@click.option('--user-specific/--full-access', default=True, help='User-specific folders vs full bucket access')
@click.option('--policy-name', default='CognitoS3Policy', help='Name for the inline policy')
@click.option('--dry-run', is_flag=True, help='Show policy without applying')
def create_s3_policy_cmd(identity_pool_id, bucket, user_specific, policy_name, dry_run):
    """Create S3 access policy for the authenticated role"""
    
    # Load config if pool ID not provided
    if not identity_pool_id:
        config = load_config()
        identity_pool_id = config.get('identity_pool_id')
        
        if not identity_pool_id:
            click.echo("❌ Identity Pool ID not found. Provide --identity-pool-id or run cognito_cli.py configure first")
            sys.exit(1)
    
    try:
        click.echo(f"🔧 Creating S3 policy for bucket: {bucket}")
        click.echo(f"📁 Access type: {'User-specific folders' if user_specific else 'Full bucket access'}")
        
        # Create policy
        policy_doc = create_s3_policy(bucket, user_specific)
        
        click.echo(f"\n📄 Policy Document:")
        click.echo(json.dumps(policy_doc, indent=2))
        
        if dry_run:
            click.echo(f"\n🔍 Dry run - policy not applied")
            return
        
        # Apply policy
        manager = CognitoRoleManager(identity_pool_id)
        role_info = manager.get_authenticated_role()
        
        click.echo(f"\n📝 Applying policy '{policy_name}' to role '{role_info['name']}'...")
        manager.update_inline_policy(role_info['name'], policy_name, policy_doc)
        
        click.echo(f"✅ Policy applied successfully!")
        click.echo(f"\n🧪 Test your access with:")
        click.echo(f"   python3 cognito_cli.py login -u your-username")
        click.echo(f"   aws s3 ls s3://{bucket}/")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@cli.command()
@click.option('--identity-pool-id', help='Identity Pool ID (will use config if not provided)')
@click.option('--policy-file', required=True, type=click.Path(exists=True), help='JSON file containing policy document')
@click.option('--policy-name', required=True, help='Name for the inline policy')
def apply_policy(identity_pool_id, policy_file, policy_name):
    """Apply a custom policy from JSON file"""
    
    # Load config if pool ID not provided
    if not identity_pool_id:
        config = load_config()
        identity_pool_id = config.get('identity_pool_id')
        
        if not identity_pool_id:
            click.echo("❌ Identity Pool ID not found. Provide --identity-pool-id or run cognito_cli.py configure first")
            sys.exit(1)
    
    try:
        # Load policy document
        with open(policy_file, 'r') as f:
            policy_doc = json.load(f)
        
        click.echo(f"📄 Loaded policy from: {policy_file}")
        click.echo(json.dumps(policy_doc, indent=2))
        
        # Apply policy
        manager = CognitoRoleManager(identity_pool_id)
        role_info = manager.get_authenticated_role()
        
        click.echo(f"\n📝 Applying policy '{policy_name}' to role '{role_info['name']}'...")
        manager.update_inline_policy(role_info['name'], policy_name, policy_doc)
        
        click.echo(f"✅ Policy applied successfully!")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@cli.command()
def validate():
    """Validate current setup and test access"""
    
    config = load_config()
    identity_pool_id = config.get('identity_pool_id')
    
    if not identity_pool_id:
        click.echo("❌ Identity Pool ID not found. Run cognito_cli.py configure first")
        sys.exit(1)
    
    try:
        click.echo("🔍 Validating Cognito setup...")
        
        manager = CognitoRoleManager(identity_pool_id)
        
        # Check role exists
        role_info = manager.get_authenticated_role()
        click.echo(f"✅ Found authenticated role: {role_info['name']}")
        
        # Check policies
        policies = manager.get_role_policies(role_info['name'])
        total_policies = len(policies['managed']) + len(policies['inline'])
        click.echo(f"✅ Found {total_policies} policies attached to role")
        
        # Test current credentials
        try:
            sts = boto3.client('sts')
            identity = sts.get_caller_identity()
            click.echo(f"✅ Current AWS identity: {identity.get('Arn', 'Unknown')}")
            
            # Check if using Cognito credentials
            if ':assumed-role/' in identity.get('Arn', ''):
                click.echo("✅ Currently using temporary credentials (likely from Cognito)")
            else:
                click.echo("ℹ️  Using permanent credentials (not from Cognito)")
                
        except Exception as e:
            click.echo(f"❌ Cannot verify current AWS credentials: {e}")
        
        click.echo(f"\n✅ Validation complete!")
        
    except Exception as e:
        click.echo(f"❌ Validation failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    cli()
