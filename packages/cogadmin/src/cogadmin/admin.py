#!/usr/bin/env python3
"""
AWS Cognito Auth Administration Tool
Combines all administrative functions for setting up and managing AWS infrastructure
"""

import json
import os
import sys
import zipfile
from pathlib import Path

import boto3
import click
from botocore.exceptions import ClientError


class CognitoRoleManager:
    def __init__(self, identity_pool_id, region=None):
        self.identity_pool_id = identity_pool_id
        self.region = region or identity_pool_id.split(":")[0]

        self.cognito_identity = boto3.client("cognito-identity", region_name=self.region)
        self.iam = boto3.client("iam", region_name=self.region)
        self.sts = boto3.client("sts", region_name=self.region)

    def get_authenticated_role(self):
        """Get the authenticated role ARN and name"""
        try:
            response = self.cognito_identity.get_identity_pool_roles(IdentityPoolId=self.identity_pool_id)

            if "Roles" not in response or "authenticated" not in response["Roles"]:
                raise Exception("No authenticated role found for this Identity Pool")

            role_arn = response["Roles"]["authenticated"]
            role_name = role_arn.split("/")[-1]

            return {"arn": role_arn, "name": role_name}
        except ClientError as e:
            raise Exception(f"Failed to get Identity Pool roles: {e.response['Error']['Message']}") from e

    def get_role_policies(self, role_name):
        """Get all policies attached to the role"""
        try:
            # Get managed policies
            managed_policies = self.iam.list_attached_role_policies(RoleName=role_name)

            # Get inline policies
            inline_policies = self.iam.list_role_policies(RoleName=role_name)

            return {"managed": managed_policies["AttachedPolicies"], "inline": inline_policies["PolicyNames"]}
        except ClientError as e:
            raise Exception(f"Failed to get role policies: {e.response['Error']['Message']}") from e

    def get_inline_policy(self, role_name, policy_name):
        """Get inline policy document"""
        try:
            response = self.iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            return response["PolicyDocument"]
        except ClientError as e:
            raise Exception(f"Failed to get policy: {e.response['Error']['Message']}") from e

    def update_inline_policy(self, role_name, policy_name, policy_document):
        """Update or create inline policy"""
        try:
            self.iam.put_role_policy(
                RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document, indent=2)
            )
            return True
        except ClientError as e:
            raise Exception(f"Failed to update policy: {e.response['Error']['Message']}") from e


class LambdaDeployer:
    def __init__(self, region="ap-southeast-1"):
        self.region = region
        self.lambda_client = boto3.client("lambda", region_name=region)
        self.iam = boto3.client("iam", region_name=region)
        self.sts = boto3.client("sts", region_name=region)
        self.admin_config = load_admin_config()

    def create_lambda_user(self):
        """Create IAM user for Lambda function to avoid role chaining limits"""
        account_id = self.sts.get_caller_identity()["Account"]

        user_policy_template = load_policy_template("lambda-user-policy")
        # Replace placeholders in policy template
        user_policy = json.dumps(user_policy_template)
        user_policy = user_policy.replace("{account_id}", account_id)
        user_policy = user_policy.replace(
            "{long_lived_role_name}", self.admin_config["aws_service_names"]["long_lived_role_name"]
        )
        user_policy = json.loads(user_policy)

        user_name = self.admin_config["aws_service_names"]["iam_user_name"]

        try:
            # Create user
            self.iam.create_user(
                UserName=user_name,
                Path="/",
            )

            # Attach inline policy
            self.iam.put_user_policy(
                UserName=user_name,
                PolicyName=self.admin_config["aws_service_names"]["policy_names"]["lambda_user_policy"],
                PolicyDocument=json.dumps(user_policy),
            )

            # Create access keys
            keys_response = self.iam.create_access_key(UserName=user_name)
            access_key = keys_response["AccessKey"]

            print(f"✅ Created IAM user: {user_name}")
            print(f"   Access Key ID: {access_key['AccessKeyId']}")
            print(f"   Secret Access Key: {access_key['SecretAccessKey']}")

            return {
                "user_arn": f"arn:aws:iam::{account_id}:user/{user_name}",
                "access_key_id": access_key["AccessKeyId"],
                "secret_access_key": access_key["SecretAccessKey"],
            }

        except self.iam.exceptions.EntityAlreadyExistsException:
            print(f"   IAM user {user_name} already exists")

            # Update the policy in case it changed
            try:
                self.iam.put_user_policy(
                    UserName=user_name,
                    PolicyName=self.admin_config["aws_service_names"]["policy_names"]["lambda_user_policy"],
                    PolicyDocument=json.dumps(user_policy),
                )
                print(f"✅ Updated policy for {user_name}")
            except Exception as e:
                print(f"⚠️  Could not update policy: {e}")

            # Try to get existing access key or create a new one
            try:
                keys = self.iam.list_access_keys(UserName=user_name)
                if keys["AccessKeyMetadata"]:
                    access_key_id = keys["AccessKeyMetadata"][0]["AccessKeyId"]
                    print(f"   Using existing access key: {access_key_id}")
                    print("⚠️  Cannot retrieve existing secret - you may need to create new keys manually")
                    return {
                        "user_arn": f"arn:aws:iam::{account_id}:user/{user_name}",
                        "access_key_id": access_key_id,
                        "secret_access_key": "",
                    }
                else:
                    # Create new access key
                    keys_response = self.iam.create_access_key(UserName=user_name)
                    access_key = keys_response["AccessKey"]
                    print("✅ Created new access key for existing user")
                    return {
                        "user_arn": f"arn:aws:iam::{account_id}:user/{user_name}",
                        "access_key_id": access_key["AccessKeyId"],
                        "secret_access_key": access_key["SecretAccessKey"],
                    }
            except Exception as e:
                print(f"⚠️  Could not handle access keys: {e}")
                return {
                    "user_arn": f"arn:aws:iam::{account_id}:user/{user_name}",
                    "access_key_id": "MANUAL_SETUP_REQUIRED",
                    "secret_access_key": "MANUAL_SETUP_REQUIRED",
                }

    def create_lambda_role(self):
        """Create minimal IAM role for Lambda function"""
        trust_policy = load_policy_template("lambda-execution-trust-policy")
        role_policy = load_policy_template("lambda-execution-policy")

        role_name = self.admin_config["aws_service_names"]["lambda_execution_role_name"]

        try:
            # Create role
            self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Minimal execution role for Cognito credential proxy Lambda",
            )

            # Attach inline policy
            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName=self.admin_config["aws_service_names"]["policy_names"]["lambda_execution_policy"],
                PolicyDocument=json.dumps(role_policy),
            )

            print(f"✅ Created minimal IAM role: {role_name}")

        except self.iam.exceptions.EntityAlreadyExistsException:
            print(f"   IAM role {role_name} already exists")

            # Update the policy in case it changed
            try:
                self.iam.put_role_policy(
                    RoleName=role_name,
                    PolicyName=self.admin_config["aws_service_names"]["policy_names"]["lambda_execution_policy"],
                    PolicyDocument=json.dumps(role_policy),
                )
                print(f"✅ Updated policy for {role_name}")
            except Exception as e:
                print(f"⚠️  Could not update policy: {e}")

        # Get role ARN
        role = self.iam.get_role(RoleName=role_name)
        return role["Role"]["Arn"]

    def create_long_lived_role(self, lambda_user_arn):
        """Create the role that users will assume for long-lived credentials"""
        trust_policy_template = load_policy_template("long-lived-role-trust-policy")
        trust_policy = json.dumps(trust_policy_template).replace("{lambda_user_arn}", lambda_user_arn)
        trust_policy = json.loads(trust_policy)

        role_name = self.admin_config["aws_service_names"]["long_lived_role_name"]

        try:
            # Create role
            self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Long-lived role for Cognito authenticated users",
                MaxSessionDuration=self.admin_config["aws_configuration"]["max_session_duration"],
            )

            print(f"✅ Created long-lived role: {role_name}")

            # Basic S3 access policy as example
            s3_policy_template = load_policy_template("s3-access-policy")
            # Replace placeholder with configured bucket name
            s3_policy = json.dumps(s3_policy_template).replace(
                "{default_bucket}", self.admin_config["aws_configuration"]["default_bucket"]
            )
            s3_policy = json.loads(s3_policy)

            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName=self.admin_config["aws_service_names"]["policy_names"]["s3_access_policy"],
                PolicyDocument=json.dumps(s3_policy),
            )

        except self.iam.exceptions.EntityAlreadyExistsException:
            print(f"   Role {role_name} already exists")

            # Update the trust policy in case it changed
            try:
                self.iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(trust_policy))
                print(f"✅ Updated trust policy for {role_name}")
            except Exception as e:
                print(f"⚠️  Could not update trust policy: {e}")

        except Exception as e:
            print(f"❌ Failed to create {role_name}: {e}")
            raise

        # Get role ARN
        role = self.iam.get_role(RoleName=role_name)
        return role["Role"]["Arn"]

    def deploy_lambda_function(self, lambda_role_arn, user_credentials, lambda_code_path=None):
        """Create and deploy Lambda function"""
        # Use default lambda function if no path provided
        if not lambda_code_path:
            lambda_code_path = Path(__file__).parent / "lambda_function.py"

        # Create deployment package
        lambda_zip = "lambda_deployment.zip"

        with zipfile.ZipFile(lambda_zip, "w") as zip_file:
            zip_file.write(lambda_code_path, "lambda_function.py")

        # Read the zip file
        with open(lambda_zip, "rb") as zip_file:
            zip_content = zip_file.read()

        function_name = self.admin_config["aws_service_names"]["lambda_function_name"]
        account_id = self.sts.get_caller_identity()["Account"]

        environment_vars = {
            "DEFAULT_ROLE_ARN": f"arn:aws:iam::{account_id}:role/{self.admin_config['aws_service_names']['long_lived_role_name']}",
            "IAM_USER_AWS_ACCESS_KEY_ID": user_credentials["access_key_id"],
            "IAM_USER_AWS_SECRET_ACCESS_KEY": user_credentials["secret_access_key"],
        }

        try:
            response = self.lambda_client.create_function(
                FunctionName=function_name,
                Runtime=self.admin_config["aws_configuration"]["lambda_runtime"],
                Role=lambda_role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_content},
                Description="Exchange Cognito tokens for long-lived AWS credentials",
                Timeout=self.admin_config["aws_configuration"]["lambda_timeout"],
                Environment={"Variables": environment_vars},
            )

            print(f"✅ Created Lambda function: {function_name}")
            print(f"   Function ARN: {response['FunctionArn']}")
            function_arn = response["FunctionArn"]

        except self.lambda_client.exceptions.ResourceConflictException:
            print(f"   Lambda function {function_name} already exists, updating...")

            # Update function code
            self.lambda_client.update_function_code(FunctionName=function_name, ZipFile=zip_content)

            # Update environment variables
            if user_credentials["secret_access_key"] != "":
                try:
                    self.lambda_client.update_function_configuration(
                        FunctionName=function_name, Environment={"Variables": environment_vars}
                    )
                    print("✅ Updated environment variables")
                except Exception as e:
                    print(f"⚠️  Could not update environment variables: {e}")

            response = self.lambda_client.get_function(FunctionName=function_name)
            print(f"✅ Updated Lambda function: {function_name}")
            function_arn = response["Configuration"]["FunctionArn"]

        # Clean up
        os.remove(lambda_zip)

        return function_arn


def load_config():
    """Load configuration from the CLI tool"""
    config = {}

    # Try environment variables first
    config["identity_pool_id"] = os.getenv("COGNITO_IDENTITY_POOL_ID")
    config["region"] = os.getenv("AWS_REGION")

    # Try config file
    config_file = Path.home() / ".cognito-cli-config.json"
    if config_file.exists():
        try:
            with open(config_file) as f:
                file_config = json.load(f)
                for key, value in file_config.items():
                    if not config.get(key):
                        config[key] = value
        except Exception:
            import logging

            logging.exception("Exception occurred while loading config file")

    return config


def _merge_config(default_config, file_config):
    """Helper to merge file_config into default_config with partial overrides"""
    for section, values in file_config.items():
        if section in default_config:
            if isinstance(values, dict):
                default_config[section].update(values)
            else:
                default_config[section] = values
        else:
            default_config[section] = values
    return default_config


def load_admin_config():
    """Load administrative configuration for AWS service names and settings"""
    default_config = {
        "aws_service_names": {
            "iam_user_name": "CognitoCredentialProxyUser",
            "lambda_execution_role_name": "CognitoCredentialProxyRole",
            "long_lived_role_name": "CognitoLongLivedRole",
            "lambda_function_name": "cognito-credential-proxy",
            "identity_pool_name": "CognitoAuthIdentityPool",
            "policy_names": {
                "lambda_user_policy": "CognitoCredentialProxyPolicy",
                "lambda_execution_policy": "CognitoCredentialProxyPolicy",
                "s3_access_policy": "S3AccessPolicy",
            },
        },
        "aws_configuration": {
            "default_region": "ap-southeast-1",
            "lambda_runtime": "python3.9",
            "lambda_timeout": 30,
            "max_session_duration": 43200,
            "default_bucket": "my-s3-bucket",
        },
    }

    admin_config_file = Path.home() / ".cognito-admin-config.json"
    if admin_config_file.exists():
        try:
            with open(admin_config_file) as f:
                file_config = json.load(f)
                default_config = _merge_config(default_config, file_config)
        except Exception:
            import logging

            logging.exception("Exception occurred while loading admin config file")

    local_admin_config = Path(__file__).parent.parent.parent / "admin-config.json"
    if local_admin_config.exists():
        try:
            with open(local_admin_config) as f:
                file_config = json.load(f)
                default_config = _merge_config(default_config, file_config)
        except Exception:
            import logging

            logging.exception("Exception occurred while loading local admin config file")

    return default_config


def load_policy_template(policy_name):
    """Load policy template from policies folder"""
    # Try to find policies folder in the package
    policies_dir = Path(__file__).parent / "policies"
    if not policies_dir.exists():
        # Fallback to parent directory for development
        policies_dir = Path(__file__).parent.parent.parent / "policies"

    policy_file = policies_dir / f"{policy_name}.json"

    if not policy_file.exists():
        raise FileNotFoundError(f"Policy template not found: {policy_file}")

    with open(policy_file) as f:
        return json.load(f)


@click.group()
def admin_cli():
    """AWS Cognito Auth Administration Tool

    Manage AWS infrastructure for Cognito authentication system.
    """
    pass


@admin_cli.group()
def role():
    """IAM role management commands"""
    pass


@role.command()
@click.option("--identity-pool-id", help="Identity Pool ID (will use config if not provided)")
def info(identity_pool_id):
    """Show information about the authenticated role"""

    # Load config if pool ID not provided
    if not identity_pool_id:
        config = load_config()
        identity_pool_id = config.get("identity_pool_id")

        if not identity_pool_id:
            click.echo("❌ Identity Pool ID not found. Provide --identity-pool-id or run client.py configure first")
            sys.exit(1)

    try:
        click.echo(f"🔍 Analyzing Identity Pool: {identity_pool_id}")

        manager = CognitoRoleManager(identity_pool_id)

        # Get role info
        role_info = manager.get_authenticated_role()
        click.echo(f"✅ Authenticated Role ARN: {role_info['arn']}")
        click.echo(f"✅ Authenticated Role Name: {role_info['name']}")

        # Get policies
        policies = manager.get_role_policies(role_info["name"])

        click.echo(f"\n📋 Managed Policies ({len(policies['managed'])}):")
        for policy in policies["managed"]:
            click.echo(f"   • {policy['PolicyName']} ({policy['PolicyArn']})")

        click.echo(f"\n📋 Inline Policies ({len(policies['inline'])}):")
        for policy_name in policies["inline"]:
            click.echo(f"   • {policy_name}")

        # Show inline policy details
        if policies["inline"]:
            click.echo("\n📄 Inline Policy Details:")
            for policy_name in policies["inline"]:
                try:
                    policy_doc = manager.get_inline_policy(role_info["name"], policy_name)
                    click.echo(f"\n--- {policy_name} ---")
                    click.echo(json.dumps(policy_doc, indent=2))
                except Exception as e:
                    click.echo(f"   ❌ Could not retrieve {policy_name}: {e}")

    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@role.command()
@click.option("--identity-pool-id", help="Identity Pool ID (will use config if not provided)")
@click.option("--policy-file", required=True, type=click.Path(exists=True), help="JSON file containing policy document")
@click.option("--policy-name", required=True, help="Name for the inline policy")
def apply_policy(identity_pool_id, policy_file, policy_name):
    """Apply a custom policy from JSON file"""

    # Load config if pool ID not provided
    if not identity_pool_id:
        config = load_config()
        identity_pool_id = config.get("identity_pool_id")

        if not identity_pool_id:
            click.echo("❌ Identity Pool ID not found. Provide --identity-pool-id or run client.py configure first")
            sys.exit(1)

    try:
        # Load policy document
        with open(policy_file) as f:
            policy_doc = json.load(f)

        click.echo(f"📄 Loaded policy from: {policy_file}")
        click.echo(json.dumps(policy_doc, indent=2))

        # Apply policy
        manager = CognitoRoleManager(identity_pool_id)
        role_info = manager.get_authenticated_role()

        click.echo(f"\n📝 Applying policy '{policy_name}' to role '{role_info['name']}'...")
        manager.update_inline_policy(role_info["name"], policy_name, policy_doc)

        click.echo("✅ Policy applied successfully!")

    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@admin_cli.group()
def policy():
    """IAM policy management commands"""
    pass


@policy.command()
@click.option("--identity-pool-id", help="Identity Pool ID (will use config if not provided)")
@click.option("--bucket-name", required=True, help="S3 bucket name")
@click.option("--user-specific", is_flag=True, help="Create user-specific policy with Cognito identity isolation")
def create_s3_policy(identity_pool_id, bucket_name, user_specific):
    """Create S3 access policy for the authenticated role"""

    # Load config if pool ID not provided
    if not identity_pool_id:
        config = load_config()
        identity_pool_id = config.get("identity_pool_id")

        if not identity_pool_id:
            click.echo("❌ Identity Pool ID not found. Provide --identity-pool-id or run client.py configure first")
            sys.exit(1)

    try:
        manager = CognitoRoleManager(identity_pool_id)
        role_info = manager.get_authenticated_role()

        if user_specific:
            policy_template = load_policy_template("s3-user-isolation-policy")
            policy_name = f"S3UserIsolationPolicy_{bucket_name.replace('-', '_')}"
        else:
            policy_template = load_policy_template("s3-access-policy")
            policy_name = f"S3AccessPolicy_{bucket_name.replace('-', '_')}"

        # Replace placeholders in policy
        policy_doc = json.dumps(policy_template)
        policy_doc = policy_doc.replace("{bucket_name}", bucket_name)
        policy_doc = json.loads(policy_doc)

        click.echo(f"📝 Creating {'user-specific' if user_specific else 'full'} S3 policy for bucket: {bucket_name}")
        click.echo(json.dumps(policy_doc, indent=2))

        if click.confirm("Apply this policy to the authenticated role?"):
            manager.update_inline_policy(role_info["name"], policy_name, policy_doc)
            click.echo(f"✅ Policy '{policy_name}' applied successfully!")

    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@policy.command()
@click.option("--identity-pool-id", help="Identity Pool ID (will use config if not provided)")
@click.option("--table-name", required=True, help="DynamoDB table name")
@click.option("--region", default="ap-southeast-1", help="AWS region")
def create_dynamodb_policy(identity_pool_id, table_name, region):
    """Create DynamoDB access policy with user isolation"""

    # Load config if pool ID not provided
    if not identity_pool_id:
        config = load_config()
        identity_pool_id = config.get("identity_pool_id")

        if not identity_pool_id:
            click.echo("❌ Identity Pool ID not found. Provide --identity-pool-id or run client.py configure first")
            sys.exit(1)

    try:
        manager = CognitoRoleManager(identity_pool_id)
        role_info = manager.get_authenticated_role()
        account_id = manager.sts.get_caller_identity()["Account"]

        policy_template = load_policy_template("dynamodb-user-isolation-policy")
        policy_name = f"DynamoDBUserIsolationPolicy_{table_name.replace('-', '_')}"

        # Replace placeholders in policy
        policy_doc = json.dumps(policy_template)
        policy_doc = policy_doc.replace("{region}", region)
        policy_doc = policy_doc.replace("{account_id}", account_id)
        policy_doc = policy_doc.replace("{table_name}", table_name)
        policy_doc = json.loads(policy_doc)

        click.echo(f"📝 Creating DynamoDB user isolation policy for table: {table_name}")
        click.echo(json.dumps(policy_doc, indent=2))

        if click.confirm("Apply this policy to the authenticated role?"):
            manager.update_inline_policy(role_info["name"], policy_name, policy_doc)
            click.echo(f"✅ Policy '{policy_name}' applied successfully!")

    except Exception as e:
        click.echo(f"❌ Error: {e}")
        sys.exit(1)


@admin_cli.group()
def lambda_cmd():
    """Lambda function management commands"""
    pass


@lambda_cmd.command()
@click.option("--region", default="ap-southeast-1", help="AWS region")
@click.option("--access-key-id", help="Your IAM user access key ID")
@click.option("--secret-access-key", help="Your IAM user secret access key")
@click.option("--create-user", is_flag=True, help="Create new IAM user (requires elevated permissions)")
@click.option(
    "--lambda-code", type=click.Path(exists=True), help="Path to Lambda function code (uses built-in if not provided)"
)
def deploy(region, access_key_id, secret_access_key, create_user, lambda_code):
    """Deploy the Lambda credential proxy"""

    # Set region
    boto3.setup_default_session(region_name=region)
    deployer = LambdaDeployer(region)

    try:
        print("🚀 Deploying Cognito Credential Proxy...")

        # Handle user credentials
        if access_key_id and secret_access_key:
            print("\n1. Using provided IAM user credentials...")
            user_credentials = {
                "user_arn": f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:user/cognito-proxy-user",
                "access_key_id": access_key_id,
                "secret_access_key": secret_access_key,
            }
            print(f"✅ Using provided credentials for access key: {access_key_id}")

        elif create_user:
            print("\n1. Creating new IAM user...")
            user_credentials = deployer.create_lambda_user()

        else:
            print("❌ Error: You must either:")
            print("   1. Provide --access-key-id and --secret-access-key for your existing IAM user")
            print("   2. Use --create-user flag (requires elevated permissions)")
            print("\nExample:")
            print("   cogadmin lambda deploy --access-key-id AKIA... --secret-access-key ...")
            return

        # Create roles
        print("\n2. Creating IAM roles...")
        lambda_role_arn = deployer.create_lambda_role()
        long_lived_role_arn = deployer.create_long_lived_role(user_credentials["user_arn"])

        print(f"   Lambda Role: {lambda_role_arn}")
        print(f"   Long-lived Role: {long_lived_role_arn}")

        # Wait a bit for role to propagate
        print("\n3. Waiting for role propagation...")
        import time

        time.sleep(10)

        # Create Lambda function
        print("\n4. Creating Lambda function...")
        function_arn = deployer.deploy_lambda_function(lambda_role_arn, user_credentials, lambda_code)

        print("\n✅ Deployment complete!")
        print("\n📋 Next steps:")
        print(f"1. Update your client code to call Lambda function: {function_arn}")
        print("2. Set up API Gateway if you want HTTP access")
        print("3. Update the long-lived role policies as needed")

    except Exception as e:
        print(f"❌ Deployment failed: {e}")


@admin_cli.command()
def configure():
    """Configure administrative settings for AWS service names and parameters"""
    click.echo("🔧 AWS Cognito Admin Configuration")
    click.echo("This will create/update your administrative configuration file")

    # Load existing config or defaults
    current_config = load_admin_config()

    click.echo("\n📋 AWS Service Names Configuration:")

    # Configure service names
    service_names = {}
    service_names["iam_user_name"] = click.prompt(
        "IAM User name for Lambda proxy", default=current_config["aws_service_names"]["iam_user_name"]
    )
    service_names["lambda_execution_role_name"] = click.prompt(
        "Lambda execution role name", default=current_config["aws_service_names"]["lambda_execution_role_name"]
    )
    service_names["long_lived_role_name"] = click.prompt(
        "Long-lived role name", default=current_config["aws_service_names"]["long_lived_role_name"]
    )
    service_names["lambda_function_name"] = click.prompt(
        "Lambda function name", default=current_config["aws_service_names"]["lambda_function_name"]
    )
    service_names["identity_pool_name"] = click.prompt(
        "Identity Pool name", default=current_config["aws_service_names"]["identity_pool_name"]
    )

    click.echo("\n📋 AWS Configuration Parameters:")

    # Configure AWS parameters
    aws_config = {}
    aws_config["default_region"] = click.prompt(
        "Default AWS region", default=current_config["aws_configuration"]["default_region"]
    )
    aws_config["lambda_runtime"] = click.prompt(
        "Lambda runtime", default=current_config["aws_configuration"]["lambda_runtime"]
    )
    aws_config["lambda_timeout"] = click.prompt(
        "Lambda timeout (seconds)", default=current_config["aws_configuration"]["lambda_timeout"], type=int
    )
    aws_config["max_session_duration"] = click.prompt(
        "Maximum session duration (seconds)",
        default=current_config["aws_configuration"]["max_session_duration"],
        type=int,
    )
    aws_config["default_bucket"] = click.prompt(
        "Default S3 bucket name", default=current_config["aws_configuration"]["default_bucket"]
    )

    # Build final config
    admin_config = {
        "aws_service_names": {**service_names, "policy_names": current_config["aws_service_names"]["policy_names"]},
        "aws_configuration": aws_config,
    }

    # Save to user's home directory
    config_file = Path.home() / ".cognito-admin-config.json"
    with open(config_file, "w") as f:
        json.dump(admin_config, f, indent=2)

    click.echo(f"\n✅ Admin configuration saved to: {config_file}")
    click.echo(
        "You can also create a local admin-config.json file in the project directory to override these settings."
    )


@admin_cli.command()
def setup_identity_pool():
    """Set up Cognito Identity Pool (interactive)"""
    click.echo("🔧 Cognito Identity Pool Setup")
    click.echo("This command will guide you through setting up a Cognito Identity Pool")
    click.echo("⚠️  This requires User Pool to already exist")

    # Load admin config for default values
    admin_config = load_admin_config()

    # Get User Pool information
    user_pool_id = click.prompt("Enter your Cognito User Pool ID")
    app_client_id = click.prompt("Enter your User Pool App Client ID")
    region = click.prompt("Enter AWS region", default=admin_config["aws_configuration"]["default_region"])

    # Allow customization of Identity Pool name
    identity_pool_name = click.prompt(
        "Identity Pool name", default=admin_config["aws_service_names"]["identity_pool_name"]
    )

    # Create Identity Pool
    cognito_identity = boto3.client("cognito-identity", region_name=region)

    try:
        response = cognito_identity.create_identity_pool(
            IdentityPoolName=identity_pool_name,
            AllowUnauthenticatedIdentities=False,
            CognitoIdentityProviders=[
                {"ProviderName": f"cognito-idp.{region}.amazonaws.com/{user_pool_id}", "ClientId": app_client_id}
            ],
        )

        identity_pool_id = response["IdentityPoolId"]
        click.echo(f"✅ Created Identity Pool: {identity_pool_id}")

        # The Identity Pool automatically creates IAM roles
        # Get the role ARNs
        roles_response = cognito_identity.get_identity_pool_roles(IdentityPoolId=identity_pool_id)

        if "Roles" in roles_response:
            click.echo("\n📋 Created IAM Roles:")
            for role_type, role_arn in roles_response["Roles"].items():
                click.echo(f"   {role_type}: {role_arn}")

        click.echo("\n🎯 Next steps:")
        click.echo(f"1. Update your configuration with Identity Pool ID: {identity_pool_id}")
        click.echo("2. Configure IAM policies on the authenticated role")
        click.echo("3. Test authentication with the client tool")

    except ClientError as e:
        click.echo(f"❌ Failed to create Identity Pool: {e}")
        sys.exit(1)


if __name__ == "__main__":
    admin_cli()
