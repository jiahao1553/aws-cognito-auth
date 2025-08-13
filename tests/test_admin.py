"""
Unit tests for the admin module (CognitoRoleManager, LambdaDeployer, and CLI commands)
"""

import json
from unittest.mock import MagicMock, mock_open, patch

import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner

from aws_cognito_auth.admin import (
    CognitoRoleManager,
    LambdaDeployer,
    admin_cli,
    apply_policy,
    configure,
    create_dynamodb_policy,
    create_s3_policy,
    deploy,
    info,
    load_admin_config,
    load_config,
    load_policy_template,
    setup_identity_pool,
)


class TestCognitoRoleManager:
    """Test cases for CognitoRoleManager class"""

    @patch("boto3.client")
    def test_init_with_region(self, mock_boto_client):
        """Test CognitoRoleManager initialization with explicit region"""
        manager = CognitoRoleManager(identity_pool_id="us-east-1:test-pool-123", region="us-west-2")

        assert manager.identity_pool_id == "us-east-1:test-pool-123"
        assert manager.region == "us-west-2"
        mock_boto_client.assert_called_with("cognito-identity", region_name="us-west-2")

    @patch("boto3.client")
    def test_init_region_from_pool_id(self, mock_boto_client):
        """Test region extraction from identity pool ID"""
        manager = CognitoRoleManager(identity_pool_id="eu-west-1:test-pool-456")

        assert manager.region == "eu-west-1"
        mock_boto_client.assert_called_with("cognito-identity", region_name="eu-west-1")

    @patch("boto3.client")
    def test_get_authenticated_role_success(self, mock_boto_client, mock_iam_role):
        """Test getting authenticated role successfully"""
        mock_cognito_identity = MagicMock()
        mock_iam = MagicMock()

        def client_factory(service_name, **kwargs):
            if service_name == "cognito-identity":
                return mock_cognito_identity
            elif service_name == "iam":
                return mock_iam

        mock_boto_client.side_effect = client_factory

        # Mock Identity Pool response
        mock_cognito_identity.describe_identity_pool.return_value = {
            "Roles": {"authenticated": "arn:aws:iam::123456789012:role/TestCognitoRole"}
        }

        # Mock IAM response
        mock_iam.get_role.return_value = mock_iam_role

        manager = CognitoRoleManager("us-east-1:test-pool-123")
        role_info = manager.get_authenticated_role()

        assert role_info is not None
        assert role_info["RoleName"] == "TestCognitoRole"
        mock_cognito_identity.describe_identity_pool.assert_called_once()
        mock_iam.get_role.assert_called_once()

    @patch("boto3.client")
    def test_get_authenticated_role_not_found(self, mock_boto_client):
        """Test getting authenticated role when not found"""
        mock_cognito_identity = MagicMock()
        mock_boto_client.return_value = mock_cognito_identity

        mock_cognito_identity.describe_identity_pool.return_value = {
            "Roles": {}  # No authenticated role
        }

        manager = CognitoRoleManager("us-east-1:test-pool-123")

        with pytest.raises(Exception) as exc_info:
            manager.get_authenticated_role()

        assert "No authenticated role found" in str(exc_info.value)

    @patch("boto3.client")
    def test_get_role_policies(self, mock_boto_client):
        """Test getting role policies"""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyName": "TestPolicy1", "PolicyArn": "arn:aws:iam::123456789012:policy/TestPolicy1"}
            ]
        }
        mock_iam.list_role_policies.return_value = {"PolicyNames": ["InlinePolicy1"]}

        manager = CognitoRoleManager("us-east-1:test-pool-123")
        policies = manager.get_role_policies("TestRole")

        assert "managed_policies" in policies
        assert "inline_policies" in policies
        assert len(policies["managed_policies"]) == 1
        assert len(policies["inline_policies"]) == 1

    @patch("boto3.client")
    def test_update_inline_policy(self, mock_boto_client):
        """Test updating inline policy"""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        policy_document = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
        }

        manager = CognitoRoleManager("us-east-1:test-pool-123")
        manager.update_inline_policy("TestRole", "TestPolicy", policy_document)

        mock_iam.put_role_policy.assert_called_once_with(
            RoleName="TestRole", PolicyName="TestPolicy", PolicyDocument=json.dumps(policy_document)
        )


class TestLambdaDeployer:
    """Test cases for LambdaDeployer class"""

    @patch("boto3.client")
    def test_init(self, mock_boto_client):
        """Test LambdaDeployer initialization"""
        deployer = LambdaDeployer(region="us-east-1")

        assert deployer.region == "us-east-1"
        # Should create IAM and Lambda clients
        assert mock_boto_client.call_count >= 2

    @patch("boto3.client")
    def test_create_lambda_user_success(self, mock_boto_client):
        """Test creating Lambda IAM user successfully"""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        # Mock successful user creation
        mock_iam.create_user.return_value = {
            "User": {"UserName": "TestLambdaUser", "Arn": "arn:aws:iam::123456789012:user/TestLambdaUser"}
        }
        mock_iam.create_access_key.return_value = {
            "AccessKey": {"AccessKeyId": "AKIATEST123", "SecretAccessKey": "test-secret-key"}
        }

        deployer = LambdaDeployer()
        credentials = deployer.create_lambda_user()

        assert credentials["access_key_id"] == "AKIATEST123"
        assert credentials["secret_access_key"] == "test-secret-key"  # noqa: S105
        assert "user_arn" in credentials

    @patch("boto3.client")
    def test_create_lambda_user_already_exists(self, mock_boto_client):
        """Test creating Lambda user when it already exists"""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        # Mock user already exists error
        mock_iam.create_user.side_effect = ClientError({"Error": {"Code": "EntityAlreadyExists"}}, "create_user")
        mock_iam.get_user.return_value = {
            "User": {"UserName": "TestLambdaUser", "Arn": "arn:aws:iam::123456789012:user/TestLambdaUser"}
        }
        mock_iam.create_access_key.return_value = {
            "AccessKey": {"AccessKeyId": "AKIATEST123", "SecretAccessKey": "test-secret-key"}
        }

        deployer = LambdaDeployer()
        credentials = deployer.create_lambda_user()

        assert credentials["access_key_id"] == "AKIATEST123"
        mock_iam.get_user.assert_called_once()

    @patch("boto3.client")
    def test_create_lambda_role_success(self, mock_boto_client):
        """Test creating Lambda execution role"""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        mock_iam.create_role.return_value = {
            "Role": {"RoleName": "TestLambdaRole", "Arn": "arn:aws:iam::123456789012:role/TestLambdaRole"}
        }

        with patch("aws_cognito_auth.admin.load_policy_template") as mock_load_policy:
            mock_load_policy.return_value = {"Version": "2012-10-17"}

            deployer = LambdaDeployer()
            role_arn = deployer.create_lambda_role()

            assert role_arn == "arn:aws:iam::123456789012:role/TestLambdaRole"
            mock_iam.create_role.assert_called_once()

    @patch("boto3.client")
    def test_create_long_lived_role(self, mock_boto_client):
        """Test creating long-lived role"""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        mock_iam.create_role.return_value = {
            "Role": {"RoleName": "TestLongLivedRole", "Arn": "arn:aws:iam::123456789012:role/TestLongLivedRole"}
        }

        with patch("aws_cognito_auth.admin.load_policy_template") as mock_load_policy:
            mock_load_policy.return_value = {"Version": "2012-10-17"}

            deployer = LambdaDeployer()
            role_arn = deployer.create_long_lived_role("arn:aws:iam::123456789012:user/TestUser")

            assert role_arn == "arn:aws:iam::123456789012:role/TestLongLivedRole"

    @patch("boto3.client")
    @patch("pathlib.Path.exists", return_value=True)
    def test_deploy_lambda_function(self, mock_exists, mock_boto_client):
        """Test deploying Lambda function"""
        mock_lambda = MagicMock()
        mock_boto_client.return_value = mock_lambda

        mock_lambda.create_function.return_value = {
            "FunctionName": "test-function",
            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-function",
        }

        deployer = LambdaDeployer()
        user_credentials = {"access_key_id": "AKIATEST123", "secret_access_key": "test-secret"}

        function_arn = deployer.deploy_lambda_function(
            lambda_role_arn="arn:aws:iam::123456789012:role/TestRole", user_credentials=user_credentials
        )

        assert function_arn == "arn:aws:lambda:us-east-1:123456789012:function:test-function"
        mock_lambda.create_function.assert_called_once()


class TestConfigurationFunctions:
    """Test configuration loading functions"""

    def test_load_config_default_values(self):
        """Test loading default configuration values"""
        config = load_config()

        # Should return default values
        assert "aws_service_names" in config
        assert "aws_configuration" in config
        assert config["aws_service_names"]["iam_user_name"] == "CognitoCredentialProxyUser"

    def test_load_admin_config_default(self):
        """Test loading default admin configuration"""
        with patch("pathlib.Path.exists", return_value=False):
            config = load_admin_config()

            assert "aws_service_names" in config
            assert "aws_configuration" in config

    @patch("builtins.open", mock_open(read_data='{"custom": "value"}'))
    @patch("pathlib.Path.exists", return_value=True)
    def test_load_admin_config_from_file(self, mock_exists, mock_admin_config_data):
        """Test loading admin config from file"""
        with patch("json.load", return_value=mock_admin_config_data):
            config = load_admin_config()

            assert config["aws_service_names"]["iam_user_name"] == "TestCognitoProxyUser"

    def test_load_policy_template_success(self):
        """Test loading policy template successfully"""
        mock_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
        }

        with (
            patch("builtins.open", mock_open(read_data=json.dumps(mock_policy))),
            patch("pathlib.Path.exists", return_value=True),
        ):
            policy = load_policy_template("s3-access-policy.json")
            assert policy == mock_policy

    def test_load_policy_template_not_found(self):
        """Test loading policy template when file not found"""
        with patch("pathlib.Path.exists", return_value=False), pytest.raises(FileNotFoundError):
            load_policy_template("nonexistent-policy.json")


class TestCLICommands:
    """Test admin CLI commands"""

    def test_admin_cli_help(self):
        """Test admin CLI help command"""
        runner = CliRunner()
        result = runner.invoke(admin_cli, ["--help"])

        assert result.exit_code == 0
        assert "Administrative tools" in result.output

    @patch("aws_cognito_auth.admin.CognitoRoleManager")
    def test_info_command_success(self, mock_role_manager, mock_iam_role):
        """Test role info command success"""
        runner = CliRunner()

        # Mock role manager
        mock_manager = MagicMock()
        mock_role_manager.return_value = mock_manager
        mock_manager.get_authenticated_role.return_value = mock_iam_role["Role"]
        mock_manager.get_role_policies.return_value = {"managed_policies": [], "inline_policies": []}

        result = runner.invoke(info, ["--identity-pool-id", "us-east-1:test-pool"])

        assert result.exit_code == 0
        assert "TestCognitoRole" in result.output

    @patch("aws_cognito_auth.admin.CognitoRoleManager")
    def test_info_command_no_role(self, mock_role_manager):
        """Test role info command when no role found"""
        runner = CliRunner()

        mock_manager = MagicMock()
        mock_role_manager.return_value = mock_manager
        mock_manager.get_authenticated_role.side_effect = Exception("No authenticated role found")

        result = runner.invoke(info, ["--identity-pool-id", "us-east-1:test-pool"])

        assert result.exit_code == 1
        assert "❌" in result.output

    @patch("aws_cognito_auth.admin.CognitoRoleManager")
    @patch("builtins.open", mock_open(read_data='{"Version": "2012-10-17"}'))
    @patch("pathlib.Path.exists", return_value=True)
    def test_apply_policy_command(self, mock_exists, mock_role_manager):
        """Test apply policy command"""
        runner = CliRunner()

        mock_manager = MagicMock()
        mock_role_manager.return_value = mock_manager
        mock_manager.get_authenticated_role.return_value = {"RoleName": "TestRole"}

        result = runner.invoke(
            apply_policy,
            [
                "--identity-pool-id",
                "us-east-1:test-pool",
                "--policy-file",
                "test-policy.json",
                "--policy-name",
                "TestPolicy",
            ],
        )

        assert result.exit_code == 0
        mock_manager.update_inline_policy.assert_called_once()

    @patch("aws_cognito_auth.admin.CognitoRoleManager")
    @patch("aws_cognito_auth.admin.load_policy_template")
    def test_create_s3_policy_command(self, mock_load_policy, mock_role_manager):
        """Test create S3 policy command"""
        runner = CliRunner()

        mock_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket"}]}
        mock_load_policy.return_value = mock_policy

        mock_manager = MagicMock()
        mock_role_manager.return_value = mock_manager
        mock_manager.get_authenticated_role.return_value = {"RoleName": "TestRole"}

        result = runner.invoke(
            create_s3_policy, ["--identity-pool-id", "us-east-1:test-pool", "--bucket-name", "test-bucket"]
        )

        assert result.exit_code == 0
        mock_manager.update_inline_policy.assert_called_once()

    @patch("aws_cognito_auth.admin.CognitoRoleManager")
    @patch("aws_cognito_auth.admin.load_policy_template")
    def test_create_s3_policy_user_specific(self, mock_load_policy, mock_role_manager):
        """Test create S3 policy with user isolation"""
        runner = CliRunner()

        mock_policy = {"Version": "2012-10-17", "Statement": [{"Resource": "{bucket_name}/*"}]}
        mock_load_policy.return_value = mock_policy

        mock_manager = MagicMock()
        mock_role_manager.return_value = mock_manager
        mock_manager.get_authenticated_role.return_value = {"RoleName": "TestRole"}

        result = runner.invoke(
            create_s3_policy,
            ["--identity-pool-id", "us-east-1:test-pool", "--bucket-name", "test-bucket", "--user-specific"],
        )

        assert result.exit_code == 0
        # Should use user-isolation template
        mock_load_policy.assert_called_with("s3-user-isolation-policy.json")

    @patch("aws_cognito_auth.admin.CognitoRoleManager")
    @patch("aws_cognito_auth.admin.load_policy_template")
    def test_create_dynamodb_policy_command(self, mock_load_policy, mock_role_manager):
        """Test create DynamoDB policy command"""
        runner = CliRunner()

        mock_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Resource": "arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"}],
        }
        mock_load_policy.return_value = mock_policy

        mock_manager = MagicMock()
        mock_role_manager.return_value = mock_manager
        mock_manager.get_authenticated_role.return_value = {"RoleName": "TestRole"}

        with patch("boto3.client") as mock_boto:
            mock_sts = MagicMock()
            mock_boto.return_value = mock_sts
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

            result = runner.invoke(
                create_dynamodb_policy,
                ["--identity-pool-id", "us-east-1:test-pool", "--table-name", "test-table", "--region", "us-east-1"],
            )

        assert result.exit_code == 0
        mock_manager.update_inline_policy.assert_called_once()

    @patch("aws_cognito_auth.admin.LambdaDeployer")
    def test_deploy_command_create_user(self, mock_deployer):
        """Test Lambda deploy command with --create-user"""
        runner = CliRunner()

        mock_deployer_instance = MagicMock()
        mock_deployer.return_value = mock_deployer_instance

        # Mock successful deployment
        mock_deployer_instance.create_lambda_user.return_value = {
            "access_key_id": "AKIATEST123",
            "secret_access_key": "test-secret",
            "user_arn": "arn:aws:iam::123456789012:user/TestUser",
        }
        mock_deployer_instance.create_lambda_role.return_value = "arn:aws:iam::123456789012:role/TestRole"
        mock_deployer_instance.create_long_lived_role.return_value = "arn:aws:iam::123456789012:role/LongLivedRole"
        mock_deployer_instance.deploy_lambda_function.return_value = (
            "arn:aws:lambda:us-east-1:123456789012:function:test"
        )

        result = runner.invoke(deploy, ["--create-user"])

        assert result.exit_code == 0
        assert "✅ Lambda proxy deployment completed successfully!" in result.output
        mock_deployer_instance.create_lambda_user.assert_called_once()

    @patch("aws_cognito_auth.admin.LambdaDeployer")
    def test_deploy_command_with_credentials(self, mock_deployer):
        """Test Lambda deploy command with provided credentials"""
        runner = CliRunner()

        mock_deployer_instance = MagicMock()
        mock_deployer.return_value = mock_deployer_instance

        # Mock successful deployment
        mock_deployer_instance.create_lambda_role.return_value = "arn:aws:iam::123456789012:role/TestRole"
        mock_deployer_instance.create_long_lived_role.return_value = "arn:aws:iam::123456789012:role/LongLivedRole"
        mock_deployer_instance.deploy_lambda_function.return_value = (
            "arn:aws:lambda:us-east-1:123456789012:function:test"
        )

        result = runner.invoke(deploy, ["--access-key-id", "AKIATEST123", "--secret-access-key", "test-secret"])

        assert result.exit_code == 0
        mock_deployer_instance.create_lambda_user.assert_not_called()

    @patch("aws_cognito_auth.admin.save_config")
    def test_configure_command(self, mock_save_config):
        """Test admin configure command"""
        runner = CliRunner()

        # Mock user input - providing minimal input to test
        input_data = "\n".join([
            "TestUser",  # IAM user name
            "TestRole",  # Lambda role name
            "TestLongRole",  # Long-lived role name
            "test-function",  # Lambda function name
            "TestPool",  # Identity pool name
            "us-east-1",  # Region
            "3600",  # Session duration
            "test-bucket",  # Default bucket
        ])

        result = runner.invoke(configure, input=input_data)

        assert result.exit_code == 0
        mock_save_config.assert_called_once()

    @patch("click.prompt")
    @patch("boto3.client")
    def test_setup_identity_pool_command(self, mock_boto_client, mock_prompt):
        """Test setup identity pool command"""
        runner = CliRunner()

        # Mock user input
        mock_prompt.side_effect = [
            "TestIdentityPool",  # Pool name
            "us-east-1_TEST123",  # User pool ID
            "test-client-id",  # Client ID
            "y",  # Confirm creation
        ]

        # Mock AWS clients
        mock_cognito_identity = MagicMock()
        mock_cognito_idp = MagicMock()
        mock_iam = MagicMock()

        def client_factory(service_name, **kwargs):
            clients = {
                "cognito-identity": mock_cognito_identity,
                "cognito-idp": mock_cognito_idp,
                "iam": mock_iam,
            }
            return clients.get(service_name, MagicMock())

        mock_boto_client.side_effect = client_factory

        # Mock successful creation
        mock_cognito_identity.create_identity_pool.return_value = {
            "IdentityPoolId": "us-east-1:new-pool-123",
            "IdentityPoolName": "TestIdentityPool",
        }

        result = runner.invoke(setup_identity_pool)

        assert result.exit_code == 0
        mock_cognito_identity.create_identity_pool.assert_called_once()
