#!/usr/bin/env python3
"""
Cognito CLI Authentication Tool
Authenticates with AWS Cognito User Pool and Identity Pool to obtain temporary credentials
and updates the AWS CLI profile for seamless AWS CLI usage.
"""

import configparser
import getpass
import json
import os
import sys
from pathlib import Path

import boto3
import click
from botocore.exceptions import ClientError


class CognitoAuthenticator:
    def __init__(self, user_pool_id, client_id, identity_pool_id, region=None):
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.identity_pool_id = identity_pool_id
        
        # Extract region from user pool ID if not provided
        if region is None:
            self.region = user_pool_id.split('_')[0]
        else:
            self.region = region
            
        # Initialize AWS clients
        # Note: Cognito User Pool operations still require AWS credentials, but they can be minimal
        # The actual user authentication happens via Cognito tokens, not AWS credentials
        self.cognito_idp = boto3.client('cognito-idp', region_name=self.region)
        self.cognito_identity = boto3.client('cognito-identity', region_name=self.region)
        
    def authenticate_user(self, username, password):
        """Authenticate user with Cognito User Pool"""
        try:
            response = self.cognito_idp.initiate_auth(
                ClientId=self.client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                }
            )
            
            if 'ChallengeName' in response:
                if response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED':
                    click.echo("New password required. Please set a new password.")
                    new_password = getpass.getpass("Enter new password: ")
                    
                    response = self.cognito_idp.respond_to_auth_challenge(
                        ClientId=self.client_id,
                        ChallengeName='NEW_PASSWORD_REQUIRED',
                        Session=response['Session'],
                        ChallengeResponses={
                            'USERNAME': username,
                            'NEW_PASSWORD': new_password
                        }
                    )
                else:
                    raise Exception(f"Unsupported challenge: {response['ChallengeName']}")
            
            tokens = response['AuthenticationResult']
            return {
                'access_token': tokens['AccessToken'],
                'id_token': tokens['IdToken'],
                'refresh_token': tokens['RefreshToken']
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NotAuthorizedException':
                raise Exception("Invalid username or password")
            elif error_code == 'UserNotFoundException':
                raise Exception("User not found")
            else:
                raise Exception(f"Authentication failed: {e.response['Error']['Message']}")
    
    def get_temporary_credentials(self, id_token, use_lambda_proxy=True, duration_hours=12):
        """Exchange ID token for temporary AWS credentials"""
        try:
            # Step 1: Always get 1-hour credentials from Identity Pool first
            print("🎫 Getting temporary credentials from Cognito Identity Pool...")
            identity_pool_creds = self._get_cognito_identity_credentials(id_token)
            print(f"✅ Successfully obtained Identity Pool credentials (expires at {identity_pool_creds['expiration']})")
            
            # Step 2: If Lambda proxy is enabled, try to upgrade to longer-lived credentials
            if use_lambda_proxy:
                try:
                    print("🎫 Attempting to upgrade to longer-lived credentials via Lambda proxy...")
                    lambda_creds = self._get_lambda_credentials(id_token, duration_hours, fallback_creds=identity_pool_creds)
                    print(f"✅ Successfully upgraded to longer-lived credentials (expires at {lambda_creds['expiration']})")
                    return lambda_creds
                except Exception as lambda_error:
                    print(f"⚠️  Lambda proxy failed: {lambda_error}")
                    print("📝 Keeping Identity Pool credentials (1 hour limit)")
                    return identity_pool_creds
            else:
                return identity_pool_creds
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            print(f"Debug - Error Code: {error_code}")
            print(f"Debug - Error Message: {error_message}")
            
            if 'not from a supported provider' in error_message:
                raise Exception(f"Identity Pool configuration error: {error_message}\n"
                               f"Solution: Your Identity Pool (ID: {self.identity_pool_id}) needs to be configured to accept tokens from your User Pool (ID: {self.user_pool_id}).\n"
                               f"Check AWS Console -> Cognito -> Identity Pool -> Authentication providers -> Cognito User Pool")
            elif error_code == 'AccessDenied' and 'AssumeRoleWithWebIdentity' in error_message:
                raise Exception(f"IAM Role Trust Policy Issue: {error_message}\n"
                               f"The role trust policy needs to be updated to allow web identity federation.\n"
                               f"Check the trust policy of your Identity Pool's authenticated role in the IAM console.")
            else:
                raise Exception(f"Failed to get temporary credentials: {error_message}")
    
    def _get_lambda_credentials(self, id_token, duration_hours=12, fallback_creds=None):
        """Get long-lived credentials via Lambda proxy"""
        # Create Lambda client using the Identity Pool credentials we already have
        if fallback_creds:
            # Use the Identity Pool credentials to invoke Lambda
            lambda_client = boto3.client(
                'lambda',
                region_name=self.region,
                aws_access_key_id=fallback_creds['access_key_id'],
                aws_secret_access_key=fallback_creds['secret_access_key'],
                aws_session_token=fallback_creds['session_token']
            )
        else:
            # Try to use current environment credentials if no fallback creds provided
            lambda_client = boto3.client('lambda', region_name=self.region)
        
        # Get current AWS account ID dynamically
        sts_client = boto3.client('sts', region_name=self.region)
        account_id = sts_client.get_caller_identity()['Account']
        
        payload = {
            'id_token': id_token,
            'duration_seconds': duration_hours * 3600,  # Convert hours to seconds
            'role_arn': f'arn:aws:iam::{account_id}:role/CognitoLongLivedRole'
        }
        
        try:
            response = lambda_client.invoke(
                FunctionName='cognito-credential-proxy',
                InvocationType='RequestResponse',
                Payload=json.dumps(payload)
            )
            
            # Parse response
            response_payload = json.loads(response['Payload'].read())
            
            if response_payload.get('statusCode') != 200:
                error_body = json.loads(response_payload.get('body', '{}'))
                raise Exception(f"Lambda error: {error_body.get('error', 'Unknown error')}")
            
            # Parse successful response
            credentials_data = json.loads(response_payload['body'])
            
            # Convert expiration string back to datetime and convert to local time
            from datetime import datetime
            expiration = datetime.fromisoformat(credentials_data['expiration'].replace('Z', '+00:00'))
            # Convert to local timezone for display consistency
            expiration = expiration.astimezone()
            
            return {
                'identity_id': credentials_data.get('user_id'),
                'access_key_id': credentials_data['access_key_id'],
                'secret_access_key': credentials_data['secret_access_key'],
                'session_token': credentials_data['session_token'],
                'expiration': expiration,
                'username': credentials_data.get('username')
            }
            
        except lambda_client.exceptions.ResourceNotFoundException:
            raise Exception("Lambda function 'cognito-credential-proxy' not found. Please deploy it first using deploy_lambda.py")
        except Exception as e:
            # Don't fallback here - let the main method handle it
            raise e
    
    def _get_cognito_identity_credentials(self, id_token):
        """Get 1-hour credentials via Cognito Identity Pool"""
        # Create the login map for the identity pool
        logins_map = {
            f'cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}': id_token
        }
        
        # Get identity ID
        identity_response = self.cognito_identity.get_id(
            IdentityPoolId=self.identity_pool_id,
            Logins=logins_map
        )
        
        identity_id = identity_response['IdentityId']
        # Get temporary credentials
        credentials_response = self.cognito_identity.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins=logins_map
        )
        
        credentials = credentials_response['Credentials']
        
        
        return {
            'identity_id': identity_id,
            'access_key_id': credentials['AccessKeyId'],
            'secret_access_key': credentials['SecretKey'],
            'session_token': credentials['SessionToken'],
            'expiration': credentials['Expiration']
        }


class AWSProfileManager:
    def __init__(self):
        self.aws_dir = Path.home() / '.aws'
        self.credentials_file = self.aws_dir / 'credentials'
        self.config_file = self.aws_dir / 'config'
        
        # Ensure .aws directory exists
        self.aws_dir.mkdir(exist_ok=True)
        
    def update_profile(self, profile_name, credentials, region):
        """Update AWS credentials profile"""
        # Update credentials file
        creds_parser = configparser.ConfigParser()
        if self.credentials_file.exists():
            creds_parser.read(self.credentials_file)
        
        if not creds_parser.has_section(profile_name):
            creds_parser.add_section(profile_name)
        
        creds_parser.set(profile_name, 'aws_access_key_id', credentials['access_key_id'])
        creds_parser.set(profile_name, 'aws_secret_access_key', credentials['secret_access_key'])
        creds_parser.set(profile_name, 'aws_session_token', credentials['session_token'])
        
        with open(self.credentials_file, 'w') as f:
            creds_parser.write(f)
        
        # Update config file
        config_parser = configparser.ConfigParser()
        if self.config_file.exists():
            config_parser.read(self.config_file)
        
        # For non-default profiles, the section name should be "profile <name>"
        config_section = f'profile {profile_name}' if profile_name != 'default' else profile_name
        
        if not config_parser.has_section(config_section):
            config_parser.add_section(config_section)
        
        config_parser.set(config_section, 'region', region)
        
        with open(self.config_file, 'w') as f:
            config_parser.write(f)


def load_config():
    """Load configuration from environment variables or config file"""
    config = {}
    
    # Try environment variables first
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
                # Only use values from file if not already set from environment
                for key, value in file_config.items():
                    if not config.get(key):
                        config[key] = value
        except Exception:
            pass  # Ignore config file errors, use environment variables
    
    return config


def save_config(config):
    """Save configuration to config file"""
    config_file = Path.home() / '.cognito-cli-config.json'
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)


@click.group()
def cli():
    """Cognito CLI Authentication Tool
    
    Authenticate with AWS Cognito and update AWS CLI profiles with temporary credentials.
    """
    pass


@cli.command()
def configure():
    """Configure Cognito authentication settings"""
    click.echo("🔧 Cognito CLI Configuration")
    
    config = load_config()
    
    # Get user pool configuration
    user_pool_id = click.prompt(
        'Cognito User Pool ID', 
        default=config.get('user_pool_id', ''),
        show_default=True if config.get('user_pool_id') else False
    )
    
    client_id = click.prompt(
        'Cognito User Pool Client ID',
        default=config.get('client_id', ''),
        show_default=True if config.get('client_id') else False
    )
    
    identity_pool_id = click.prompt(
        'Cognito Identity Pool ID',
        default=config.get('identity_pool_id', ''),
        show_default=True if config.get('identity_pool_id') else False
    )
    
    # Region is optional, can be auto-detected from User Pool ID
    region = click.prompt(
        'AWS Region (optional, will auto-detect if not provided)',
        default=config.get('region', ''),
        show_default=False,
        required=False
    )
    
    # Save configuration
    new_config = {
        'user_pool_id': user_pool_id,
        'client_id': client_id,
        'identity_pool_id': identity_pool_id,
    }
    
    if region:
        new_config['region'] = region
    
    save_config(new_config)
    
    click.echo("✅ Configuration saved!")
    click.echo(f"📁 Config file: {Path.home() / '.cognito-cli-config.json'}")


@cli.command()
@click.option('--username', '-u', help='Username for authentication')
@click.option('--profile', default='default', help='AWS profile name to update')
@click.option('--no-lambda-proxy', is_flag=True, help='Skip Lambda proxy and use only Identity Pool credentials')
@click.option('--duration', default=12, help='Credential duration in hours (Lambda proxy only)')
def login(username, profile, no_lambda_proxy, duration):
    """Authenticate with Cognito and update AWS profile"""
    config = load_config()
    
    # Check required configuration
    required_fields = ['user_pool_id', 'client_id', 'identity_pool_id']
    missing_fields = [field for field in required_fields if not config.get(field)]
    
    if missing_fields:
        click.echo(f"❌ Missing configuration: {', '.join(missing_fields)}")
        click.echo("Please run 'configure' command first or set environment variables:")
        for field in missing_fields:
            env_var = f"COGNITO_{field.upper()}"
            click.echo(f"   export {env_var}=<value>")
        sys.exit(1)
    
    # Get username if not provided
    if not username:
        username = click.prompt('Username')
    
    # Get password
    password = getpass.getpass('Password: ')
    
    try:
        # Initialize authenticator
        authenticator = CognitoAuthenticator(
            user_pool_id=config['user_pool_id'],
            client_id=config['client_id'],
            identity_pool_id=config['identity_pool_id'],
            region=config.get('region')
        )
        
        # Authenticate user
        print(f"🔐 Authenticating user: {username}")
        tokens = authenticator.authenticate_user(username, password)
        print("✅ User authenticated successfully")
        
        # Get temporary credentials
        use_lambda_proxy = not no_lambda_proxy
        credentials = authenticator.get_temporary_credentials(
            tokens['id_token'], 
            use_lambda_proxy=use_lambda_proxy,
            duration_hours=duration
        )
        
        # Update AWS profile
        profile_manager = AWSProfileManager()
        profile_manager.update_profile(
            profile_name=profile,
            credentials=credentials,
            region=authenticator.region
        )
        
        print(f"✅ AWS profile '{profile}' updated successfully")
        print(f"⏰ Credentials expire at: {credentials['expiration']}")
        print(f"🔑 Identity ID: {credentials.get('identity_id', 'N/A')}")
        
        print(f"\n🎯 You can now use AWS CLI with profile '{profile}':")
        if profile == 'default':
            print("   aws s3 ls")
            print("   aws sts get-caller-identity")
        else:
            print(f"   aws --profile {profile} s3 ls")
            print(f"   aws --profile {profile} sts get-caller-identity")
        
    except Exception as e:
        click.echo(f"❌ Authentication failed: {e}")
        sys.exit(1)


@cli.command()
def status():
    """Show current configuration status"""
    config = load_config()
    
    click.echo("📋 Current Configuration:")
    
    # Show configuration (truncated for security)
    for key in ['user_pool_id', 'client_id', 'identity_pool_id', 'region']:
        value = config.get(key)
        if value:
            if key in ['user_pool_id', 'client_id', 'identity_pool_id']:
                # Show first 8 and last 4 characters for security
                display_value = f"{value[:8]}...{value[-4:]}" if len(value) > 12 else value
            else:
                display_value = value
            click.echo(f"  {key}: {display_value}")
        else:
            click.echo(f"  {key}: Not set")
    
    # Show AWS credentials file status
    aws_dir = Path.home() / '.aws'
    credentials_file = aws_dir / 'credentials'
    
    if credentials_file.exists():
        click.echo(f"\n📁 AWS credentials file exists at: {credentials_file}")
    else:
        click.echo(f"\n❌ AWS credentials file not found at: {credentials_file}")


if __name__ == '__main__':
    cli()