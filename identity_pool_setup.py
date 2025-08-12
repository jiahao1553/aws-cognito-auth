#!/usr/bin/env python3
"""
Identity Pool Setup Helper
Automates the creation and configuration of Cognito Identity Pool for the CLI tool
"""

import boto3
import json
import click
import sys
import time
from pathlib import Path
from botocore.exceptions import ClientError


class IdentityPoolSetup:
    def __init__(self, region):
        self.region = region
        self.cognito_identity = boto3.client('cognito-identity', region_name=region)
        self.cognito_idp = boto3.client('cognito-idp', region_name=region)
        self.iam = boto3.client('iam', region_name=region)
        
    def verify_user_pool(self, user_pool_id, client_id):
        """Verify User Pool and Client exist"""
        try:
            # Check User Pool
            response = self.cognito_idp.describe_user_pool(UserPoolId=user_pool_id)
            user_pool_name = response['UserPool']['Name']
            click.echo(f"✅ Found User Pool: {user_pool_name} ({user_pool_id})")
            
            # Check User Pool Client
            response = self.cognito_idp.describe_user_pool_client(
                UserPoolId=user_pool_id,
                ClientId=client_id
            )
            client_name = response['UserPoolClient']['ClientName']
            click.echo(f"✅ Found User Pool Client: {client_name} ({client_id})")
            
            return True
        except ClientError as e:
            click.echo(f"❌ Error verifying User Pool: {e.response['Error']['Message']}")
            return False
    
    def create_identity_pool(self, name, user_pool_id, client_id, allow_unauth=False):
        """Create Cognito Identity Pool"""
        try:
            cognito_provider = {
                'ProviderName': f'cognito-idp.{self.region}.amazonaws.com/{user_pool_id}',
                'ClientId': client_id
            }
            
            response = self.cognito_identity.create_identity_pool(
                IdentityPoolName=name,
                AllowUnauthenticatedIdentities=allow_unauth,
                CognitoIdentityProviders=[cognito_provider]
            )
            
            identity_pool_id = response['IdentityPoolId']
            click.echo(f"✅ Created Identity Pool: {name} ({identity_pool_id})")
            return identity_pool_id
            
        except ClientError as e:
            if 'already exists' in str(e):
                click.echo(f"⚠️  Identity Pool with name '{name}' already exists")
                # Try to find existing pool
                existing_pools = self.cognito_identity.list_identity_pools(MaxResults=60)
                for pool in existing_pools['IdentityPools']:
                    if pool['IdentityPoolName'] == name:
                        click.echo(f"✅ Found existing Identity Pool: {pool['IdentityPoolId']}")
                        return pool['IdentityPoolId']
            raise Exception(f"Failed to create Identity Pool: {e.response['Error']['Message']}")
    
    def create_iam_role(self, role_name, trust_policy, description):
        """Create IAM role"""
        try:
            response = self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=description
            )
            click.echo(f"✅ Created IAM role: {role_name}")
            return response['Role']['Arn']
        except ClientError as e:
            if 'already exists' in str(e):
                click.echo(f"⚠️  IAM role '{role_name}' already exists")
                response = self.iam.get_role(RoleName=role_name)
                return response['Role']['Arn']
            raise Exception(f"Failed to create IAM role: {e.response['Error']['Message']}")
    
    def create_authenticated_role(self, identity_pool_id, role_name_suffix=""):
        """Create authenticated IAM role for Identity Pool"""
        if not role_name_suffix:
            role_name_suffix = identity_pool_id.split(':')[1][:8]
        
        role_name = f"Cognito_{role_name_suffix}_Authenticated_Role"
        
        # Trust policy for Cognito Identity Pool
        trust_policy = {
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
                            "cognito-identity.amazonaws.com:aud": identity_pool_id
                        },
                        "ForAnyValue:StringLike": {
                            "cognito-identity.amazonaws.com:amr": "authenticated"
                        }
                    }
                }
            ]
        }
        
        description = f"Role for authenticated users in Cognito Identity Pool {identity_pool_id}"
        role_arn = self.create_iam_role(role_name, trust_policy, description)
        
        return role_name, role_arn
    
    def create_unauthenticated_role(self, identity_pool_id, role_name_suffix=""):
        """Create unauthenticated IAM role for Identity Pool"""
        if not role_name_suffix:
            role_name_suffix = identity_pool_id.split(':')[1][:8]
        
        role_name = f"Cognito_{role_name_suffix}_Unauthenticated_Role"
        
        # Trust policy for Cognito Identity Pool
        trust_policy = {
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
                            "cognito-identity.amazonaws.com:aud": identity_pool_id
                        },
                        "ForAnyValue:StringLike": {
                            "cognito-identity.amazonaws.com:amr": "unauthenticated"
                        }
                    }
                }
            ]
        }
        
        description = f"Role for unauthenticated users in Cognito Identity Pool {identity_pool_id}"
        role_arn = self.create_iam_role(role_name, trust_policy, description)
        
        return role_name, role_arn
    
    def attach_role_to_identity_pool(self, identity_pool_id, auth_role_arn, unauth_role_arn=None):
        """Attach IAM roles to Identity Pool"""
        try:
            roles = {
                'authenticated': auth_role_arn
            }
            if unauth_role_arn:
                roles['unauthenticated'] = unauth_role_arn
            
            self.cognito_identity.set_identity_pool_roles(
                IdentityPoolId=identity_pool_id,
                Roles=roles
            )
            click.echo(f"✅ Attached roles to Identity Pool")
            
        except ClientError as e:
            raise Exception(f"Failed to attach roles: {e.response['Error']['Message']}")
    
    def create_basic_s3_policy(self, role_name, bucket_name=None):
        """Create basic S3 policy for authenticated role"""
        if not bucket_name:
            bucket_name = "YOUR_BUCKET_NAME"
            click.echo(f"⚠️  Using placeholder bucket name. Update policy later with actual bucket name.")
        
        policy_document = {
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
        
        try:
            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName='CognitoUserS3Policy',
                PolicyDocument=json.dumps(policy_document)
            )
            click.echo(f"✅ Created S3 policy for role {role_name}")
            
        except ClientError as e:
            raise Exception(f"Failed to create S3 policy: {e.response['Error']['Message']}")


def load_config():
    """Load existing configuration"""
    config = {}
    
    # Try environment variables
    import os
    config['user_pool_id'] = os.getenv('COGNITO_USER_POOL_ID')
    config['client_id'] = os.getenv('COGNITO_CLIENT_ID') 
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


def save_config(config):
    """Save configuration to file"""
    config_file = Path.home() / '.cognito-cli-config.json'
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        click.echo(f"✅ Configuration saved to {config_file}")
    except Exception as e:
        click.echo(f"Error saving configuration: {e}", err=True)


@click.group()
def cli():
    """Identity Pool Setup Helper - Create and configure Cognito Identity Pool"""
    pass


@cli.command()
@click.option('--user-pool-id', help='Cognito User Pool ID (e.g., us-east-1_XXXXXXXXX)')
@click.option('--client-id', help='Cognito User Pool Client ID')
@click.option('--identity-pool-name', default='MyAppIdentityPool', help='Name for new Identity Pool')
@click.option('--bucket-name', help='S3 bucket name for default policy (optional)')
@click.option('--allow-unauth', is_flag=True, help='Allow unauthenticated access')
@click.option('--region', help='AWS region (will be inferred from User Pool ID if not provided)')
def create_full_setup(user_pool_id, client_id, identity_pool_name, bucket_name, allow_unauth, region):
    """Create complete Identity Pool setup with IAM roles and basic policies"""
    
    # Load existing config if parameters not provided
    config = load_config()
    
    if not user_pool_id:
        user_pool_id = config.get('user_pool_id')
        if not user_pool_id:
            user_pool_id = click.prompt('User Pool ID (e.g., us-east-1_XXXXXXXXX)')
    
    if not client_id:
        client_id = config.get('client_id')  
        if not client_id:
            client_id = click.prompt('User Pool Client ID')
    
    if not region:
        region = config.get('region') or user_pool_id.split('_')[0]
    
    try:
        click.echo(f"🚀 Creating Identity Pool setup in region: {region}")
        click.echo(f"📋 Configuration:")
        click.echo(f"   User Pool ID: {user_pool_id}")
        click.echo(f"   Client ID: {client_id[:8]}...")
        click.echo(f"   Identity Pool Name: {identity_pool_name}")
        click.echo(f"   Allow Unauthenticated: {allow_unauth}")
        if bucket_name:
            click.echo(f"   S3 Bucket: {bucket_name}")
        
        if not click.confirm('\nProceed with creation?'):
            click.echo("Aborted.")
            return
        
        setup = IdentityPoolSetup(region)
        
        # Step 1: Verify User Pool
        click.echo(f"\n🔍 Step 1: Verifying User Pool...")
        if not setup.verify_user_pool(user_pool_id, client_id):
            click.echo("❌ User Pool verification failed. Please check your User Pool ID and Client ID.")
            sys.exit(1)
        
        # Step 2: Create Identity Pool
        click.echo(f"\n🔧 Step 2: Creating Identity Pool...")
        identity_pool_id = setup.create_identity_pool(
            identity_pool_name, 
            user_pool_id, 
            client_id, 
            allow_unauth
        )
        
        # Step 3: Create IAM Roles
        click.echo(f"\n🛡️  Step 3: Creating IAM roles...")
        auth_role_name, auth_role_arn = setup.create_authenticated_role(identity_pool_id)
        
        unauth_role_name, unauth_role_arn = None, None
        if allow_unauth:
            unauth_role_name, unauth_role_arn = setup.create_unauthenticated_role(identity_pool_id)
        
        # Step 4: Attach roles to Identity Pool
        click.echo(f"\n🔗 Step 4: Attaching roles to Identity Pool...")
        setup.attach_role_to_identity_pool(identity_pool_id, auth_role_arn, unauth_role_arn)
        
        # Step 5: Create basic S3 policy
        click.echo(f"\n📄 Step 5: Creating basic S3 policy...")
        setup.create_basic_s3_policy(auth_role_name, bucket_name)
        
        # Step 6: Update CLI configuration
        click.echo(f"\n⚙️  Step 6: Updating CLI configuration...")
        config.update({
            'user_pool_id': user_pool_id,
            'client_id': client_id,
            'identity_pool_id': identity_pool_id,
            'region': region
        })
        save_config(config)
        
        # Success summary
        click.echo(f"\n🎉 Setup Complete!")
        click.echo(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        click.echo(f"✅ Identity Pool ID: {identity_pool_id}")
        click.echo(f"✅ Authenticated Role: {auth_role_name}")
        if unauth_role_name:
            click.echo(f"✅ Unauthenticated Role: {unauth_role_name}")
        click.echo(f"✅ Configuration saved")
        
        click.echo(f"\n🧪 Next Steps:")
        click.echo(f"1. Test authentication:")
        click.echo(f"   aws-cognito-auth login -u your-username")
        click.echo(f"")
        click.echo(f"2. Test AWS access:")
        click.echo(f"   aws sts get-caller-identity")
        if bucket_name:
            click.echo(f"   aws s3 ls s3://{bucket_name}/")
        else:
            click.echo(f"   aws s3 ls")
        click.echo(f"")
        click.echo(f"3. Configure additional policies if needed:")
        click.echo(f"   python3 role_manager.py info")
        click.echo(f"   python3 role_manager.py create-s3-policy --bucket your-bucket")
        
        if not bucket_name:
            click.echo(f"\n⚠️  Remember to update the S3 policy with your actual bucket name:")
            click.echo(f"   python3 role_manager.py create-s3-policy --bucket your-actual-bucket")
        
    except Exception as e:
        click.echo(f"❌ Setup failed: {e}")
        sys.exit(1)


@cli.command()
@click.option('--identity-pool-id', help='Identity Pool ID to validate')
def validate_setup(identity_pool_id):
    """Validate existing Identity Pool setup"""
    
    if not identity_pool_id:
        config = load_config()
        identity_pool_id = config.get('identity_pool_id')
        
        if not identity_pool_id:
            click.echo("❌ Identity Pool ID not found. Provide --identity-pool-id or run setup first")
            sys.exit(1)
    
    try:
        region = identity_pool_id.split(':')[0]
        setup = IdentityPoolSetup(region)
        
        click.echo(f"🔍 Validating Identity Pool: {identity_pool_id}")
        
        # Check Identity Pool exists
        response = setup.cognito_identity.describe_identity_pool(IdentityPoolId=identity_pool_id)
        click.echo(f"✅ Identity Pool exists: {response['IdentityPoolName']}")
        
        # Check roles
        roles_response = setup.cognito_identity.get_identity_pool_roles(IdentityPoolId=identity_pool_id)
        roles = roles_response.get('Roles', {})
        
        if 'authenticated' in roles:
            auth_role_arn = roles['authenticated']
            auth_role_name = auth_role_arn.split('/')[-1]
            click.echo(f"✅ Authenticated role: {auth_role_name}")
            
            # Check role policies
            try:
                policies = setup.iam.list_role_policies(RoleName=auth_role_name)
                click.echo(f"✅ Role has {len(policies['PolicyNames'])} inline policies")
            except Exception as e:
                click.echo(f"⚠️  Could not check role policies: {e}")
        else:
            click.echo(f"❌ No authenticated role found")
        
        if 'unauthenticated' in roles:
            click.echo(f"✅ Unauthenticated role configured")
        
        click.echo(f"\n✅ Validation complete!")
        
    except Exception as e:
        click.echo(f"❌ Validation failed: {e}")
        sys.exit(1)


@cli.command()
def cleanup_test():
    """Remove test resources (use with caution!)"""
    click.echo("⚠️  This will help you identify resources to clean up manually.")
    click.echo("⚠️  Automatic cleanup is not implemented for safety.")
    
    config = load_config()
    
    if config.get('identity_pool_id'):
        click.echo(f"\nTo clean up Identity Pool:")
        click.echo(f"1. Go to Cognito Console → Identity pools")
        click.echo(f"2. Find: {config['identity_pool_id']}")
        click.echo(f"3. Delete the Identity Pool")
    
    click.echo(f"\nTo clean up IAM roles:")
    click.echo(f"1. Go to IAM Console → Roles")  
    click.echo(f"2. Search for roles containing 'Cognito' and your pool name")
    click.echo(f"3. Delete the roles if no longer needed")
    
    click.echo(f"\n⚠️  Only delete resources you created for testing!")


if __name__ == '__main__':
    cli()
