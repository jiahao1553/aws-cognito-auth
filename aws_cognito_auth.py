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
                               f"Check the trust policy of role: arn:aws:iam::897039363324:role/service-role/s3-access-identitypool-role")
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
        
        payload = {
            'id_token': id_token,
            'duration_seconds': duration_hours * 3600,  # Convert hours to seconds
            'role_arn': 'arn:aws:iam::767397975955:role/CognitoLongLivedRole'
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
            
            # Convert expiration string back to datetime
            from datetime import datetime
            expiration = datetime.fromisoformat(credentials_data['expiration'].replace('Z', '+00:00'))
            
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
        credentials_config = configparser.ConfigParser()
        
        if self.credentials_file.exists():
            credentials_config.read(self.credentials_file)
        
        if profile_name not in credentials_config:
            credentials_config.add_section(profile_name)
        
        credentials_config[profile_name]['aws_access_key_id'] = credentials['access_key_id']
        credentials_config[profile_name]['aws_secret_access_key'] = credentials['secret_access_key']
        credentials_config[profile_name]['aws_session_token'] = credentials['session_token']
        
        with open(self.credentials_file, 'w') as f:
            credentials_config.write(f)
        
        # Update config file for region
        config_config = configparser.ConfigParser()
        
        if self.config_file.exists():
            config_config.read(self.config_file)
        
        profile_section = f'profile {profile_name}' if profile_name != 'default' else 'default'
        
        if profile_section not in config_config:
            config_config.add_section(profile_section)
        
        config_config[profile_section]['region'] = region
        
        with open(self.config_file, 'w') as f:
            config_config.write(f)
    
    def show_credentials_info(self, profile_name, credentials):
        """Display credentials information"""
        click.echo(f"\n✅ Successfully updated AWS profile: {profile_name}")
        click.echo(f"🔑 Identity ID: {credentials['identity_id']}")
        local_expiration = credentials['expiration'].astimezone()
        click.echo(f"🕒 Credentials expire at: {local_expiration.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        click.echo("\n🚀 You can now use AWS CLI commands like:")
        if profile_name == 'default':
            click.echo("   aws s3 ls")
            click.echo("   aws s3 sync s3://your-bucket ./local-folder")
        else:
            click.echo(f"   aws --profile {profile_name} s3 ls")
            click.echo(f"   aws --profile {profile_name} s3 sync s3://your-bucket ./local-folder")


def load_config():
    """Load configuration from environment variables or config file"""
    config = {}
    
    # Try to load from environment variables
    config['user_pool_id'] = os.getenv('COGNITO_USER_POOL_ID')
    config['client_id'] = os.getenv('COGNITO_CLIENT_ID') 
    config['identity_pool_id'] = os.getenv('COGNITO_IDENTITY_POOL_ID')
    config['region'] = os.getenv('AWS_REGION')
    
    # Try to load from config file
    config_file = Path.home() / '.cognito-cli-config.json'
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                for key, value in file_config.items():
                    if not config.get(key):  # Only use file config if env var not set
                        config[key] = value
        except Exception as e:
            click.echo(f"Warning: Could not load config file: {e}", err=True)
    
    return config


def save_config(config):
    """Save configuration to config file"""
    config_file = Path.home() / '.cognito-cli-config.json'
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        click.echo(f"✅ Configuration saved to {config_file}")
    except Exception as e:
        click.echo(f"Error saving configuration: {e}", err=True)


def start_auto_refresh(auth, tokens, profile_manager, profile, region):
    """Start automatic credential refresh every 50 minutes"""
    import threading
    import time
    from datetime import datetime, timedelta
    
    def refresh_loop():
        refresh_count = 0
        while True:
            try:
                # Wait 50 minutes
                time.sleep(50 * 60)
                refresh_count += 1
                
                click.echo(f"\n🔄 Auto-refresh #{refresh_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Get new credentials
                new_credentials = auth.get_temporary_credentials(
                    tokens['id_token'], 
                    use_lambda_proxy=False,  # Always use Identity Pool for refresh
                    duration_hours=1
                )
                
                # Update profile
                profile_manager.update_profile(profile, new_credentials, region)
                
                # Show expiration time
                local_expiration = new_credentials['expiration'].astimezone()
                click.echo(f"✅ Credentials refreshed! New expiration: {local_expiration.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                
            except Exception as e:
                click.echo(f"⚠️ Auto-refresh failed: {e}")
                click.echo(f"   Will retry in 50 minutes...")
                continue
    
    # Start background thread
    refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
    refresh_thread.start()
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo(f"\n👋 Auto-refresh stopped by user")
        sys.exit(0)


@click.group()
def cli():
    """Cognito CLI Authentication Tool
    
    Authenticate with AWS Cognito and update AWS CLI profiles with temporary credentials.
    """
    pass


@cli.command()
@click.option('--user-pool-id', prompt=True, help='Cognito User Pool ID')
@click.option('--client-id', prompt=True, help='Cognito User Pool Client ID')
@click.option('--identity-pool-id', prompt=True, help='Cognito Identity Pool ID')
@click.option('--region', help='AWS Region (optional, will be inferred from User Pool ID)')
def configure(user_pool_id, client_id, identity_pool_id, region):
    """Configure Cognito authentication settings"""
    config = {
        'user_pool_id': user_pool_id,
        'client_id': client_id,
        'identity_pool_id': identity_pool_id
    }
    
    if region:
        config['region'] = region
    
    save_config(config)


@cli.command()
@click.option('--username', '-u', help='Username (will prompt if not provided)')
@click.option('--password', '-p', help='Password (will prompt securely if not provided)')
@click.option('--profile', default='default', help='AWS profile name to update (default: default)')
@click.option('--region', help='AWS region to set in profile')
@click.option('--duration', default=12, help='Credential duration in hours (default: 12, max: 12)')
@click.option('--auto-refresh', is_flag=True, help='Start background process to auto-refresh credentials every 50 minutes')
@click.option('--use-lambda/--use-identity-pool', default=True, help='Use Lambda proxy for long-lived credentials vs Cognito Identity Pool (1 hour limit)')
def login(username, password, profile, region, duration, auto_refresh, use_lambda):
    """Authenticate with Cognito and update AWS profile"""
    
    # Load configuration
    config = load_config()
    
    required_fields = ['user_pool_id', 'client_id', 'identity_pool_id']
    missing_fields = [field for field in required_fields if not config.get(field)]
    
    if missing_fields:
        click.echo(f"❌ Missing configuration: {', '.join(missing_fields)}")
        click.echo("Run 'aws-cognito-auth configure' first or set environment variables:")
        click.echo("  COGNITO_USER_POOL_ID")
        click.echo("  COGNITO_CLIENT_ID") 
        click.echo("  COGNITO_IDENTITY_POOL_ID")
        sys.exit(1)
    
    # Get credentials if not provided
    if not username:
        username = click.prompt('Username')
    
    if not password:
        password = getpass.getpass('Password: ')
    
    # Set region
    if not region:
        region = config.get('region') or config['user_pool_id'].split('_')[0]
    
    try:
        click.echo("🔐 Authenticating with Cognito User Pool...")
        
        # Initialize authenticator
        auth = CognitoAuthenticator(
            user_pool_id=config['user_pool_id'],
            client_id=config['client_id'],
            identity_pool_id=config['identity_pool_id'],
            region=region
        )
        
        # Authenticate user
        tokens = auth.authenticate_user(username, password)
        click.echo("✅ Successfully authenticated with User Pool")
        
        # Get temporary credentials
        method = "Lambda proxy" if use_lambda else "Cognito Identity Pool"
        click.echo(f"🎫 Getting temporary credentials via {method}...")
        
        credentials = auth.get_temporary_credentials(
            tokens['id_token'], 
            use_lambda_proxy=use_lambda, 
            duration_hours=duration if use_lambda else 1  # Full duration for Lambda, 1 hour for Identity Pool
        )
        click.echo("✅ Successfully obtained temporary credentials")
        
        # Update AWS profile
        click.echo(f"📝 Updating AWS profile '{profile}'...")
        profile_manager = AWSProfileManager()
        profile_manager.update_profile(profile, credentials, region)
        profile_manager.show_credentials_info(profile, credentials)
        
        # Start auto-refresh if requested
        if auto_refresh:
            click.echo(f"\n🔄 Starting auto-refresh background process...")
            click.echo(f"   Credentials will be refreshed every 50 minutes")
            click.echo(f"   Keep this terminal open or the process will stop")
            
            start_auto_refresh(auth, tokens, profile_manager, profile, region)
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
def status():
    """Show current configuration status"""
    config = load_config()
    
    click.echo("📋 Current Configuration:")
    for key, value in config.items():
        if value:
            if key in ['user_pool_id', 'client_id', 'identity_pool_id']:
                # Show partial values for security
                masked_value = value[:8] + '...' + value[-4:] if len(value) > 12 else value
                click.echo(f"  {key}: {masked_value}")
            else:
                click.echo(f"  {key}: {value}")
        else:
            click.echo(f"  {key}: Not set")
    
    # Check AWS credentials file
    aws_dir = Path.home() / '.aws'
    credentials_file = aws_dir / 'credentials'
    
    if credentials_file.exists():
        click.echo(f"\n📁 AWS credentials file exists at: {credentials_file}")
    else:
        click.echo(f"\n❌ AWS credentials file not found at: {credentials_file}")


if __name__ == '__main__':
    cli()
