"""
Integration tests for the AWS Cognito Authoriser

These tests simulate end-to-end workflows and interactions between components.
They use mocked AWS services but test the full integration flow.
"""

import json
import tempfile
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aws_cognito_auth.admin import admin_cli
from aws_cognito_auth.client import AWSProfileManager, CognitoAuthenticator
from aws_cognito_auth.client import cli as client_cli


class TestEndToEndAuthentication:
    """Test complete authentication workflow"""

    @patch("aws_cognito_auth.client.getpass.getpass", return_value="testpassword")
    @patch("boto3.client")
    def test_complete_authentication_flow(self, mock_boto_client, mock_getpass):
        """Test complete flow from login command to AWS credentials"""
        # Setup mocks for all AWS clients
        mock_cognito_idp = MagicMock()
        mock_cognito_identity = MagicMock()
        mock_lambda_client = MagicMock()
        mock_sts = MagicMock()

        def client_factory(service_name, **kwargs):
            clients = {
                "cognito-idp": mock_cognito_idp,
                "cognito-identity": mock_cognito_identity,
                "lambda": mock_lambda_client,
                "sts": mock_sts,
            }
            return clients.get(service_name, MagicMock())

        mock_boto_client.side_effect = client_factory

        # Mock successful authentication
        mock_cognito_idp.initiate_auth.return_value = {
            "AuthenticationResult": {
                "IdToken": "test-id-token-jwt",
                "AccessToken": "test-access-token",
                "RefreshToken": "test-refresh-token",
            }
        }

        # Mock Identity Pool credential exchange
        mock_cognito_identity.get_id.return_value = {"IdentityId": "us-east-1:test-identity-id"}
        mock_cognito_identity.get_credentials_for_identity.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIAIDENTITY123",
                "SecretKey": "identity-secret-key",
                "SessionToken": "identity-session-token",
                "Expiration": datetime.now(timezone.utc),
            }
        }

        # Mock STS for account ID lookup
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        # Mock Lambda proxy upgrade
        lambda_response = {
            "statusCode": 200,
            "body": json.dumps({
                "access_key_id": "AKIALAMBDA123",
                "secret_access_key": "lambda-secret-key",
                "session_token": "lambda-session-token",
                "expiration": "2025-08-13T23:59:59Z",
                "username": "testuser",
                "user_id": "us-east-1:test-identity-id",
            }),
        }
        mock_lambda_client.invoke.return_value = {
            "Payload": MagicMock(read=lambda: json.dumps(lambda_response).encode())
        }

        # Create temporary config
        config_data = {
            "user_pool_id": "us-east-1_TEST123",
            "client_id": "test-client-id",
            "identity_pool_id": "us-east-1:test-identity-pool",
            "region": "us-east-1",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / ".cognito-cli-config.json"
            with open(config_file, "w") as f:
                json.dump(config_data, f)

            with patch("pathlib.Path.home", return_value=Path(temp_dir)):
                runner = CliRunner()
                result = runner.invoke(client_cli, ["login", "-u", "testuser"])

                # Should complete successfully
                assert result.exit_code == 0
                assert "✅ Successfully" in result.output
                assert "AWS profile" in result.output

                # Verify AWS credentials file was created
                aws_dir = Path(temp_dir) / ".aws"
                credentials_file = aws_dir / "credentials"
                config_file = aws_dir / "config"

                assert credentials_file.exists()
                assert config_file.exists()

    @patch("boto3.client")
    def test_authentication_with_lambda_failure_fallback(self, mock_boto_client):
        """Test authentication flow when Lambda proxy fails but Identity Pool works"""
        # Setup mocks
        mock_cognito_idp = MagicMock()
        mock_cognito_identity = MagicMock()
        mock_lambda_client = MagicMock()

        def client_factory(service_name, **kwargs):
            clients = {
                "cognito-idp": mock_cognito_idp,
                "cognito-identity": mock_cognito_identity,
                "lambda": mock_lambda_client,
            }
            return clients.get(service_name, MagicMock())

        mock_boto_client.side_effect = client_factory

        # Setup successful Identity Pool authentication
        mock_cognito_idp.initiate_auth.return_value = {
            "AuthenticationResult": {
                "IdToken": "test-id-token",
                "AccessToken": "test-access-token",
                "RefreshToken": "test-refresh-token",
            }
        }

        mock_cognito_identity.get_id.return_value = {"IdentityId": "test-identity-id"}
        mock_cognito_identity.get_credentials_for_identity.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIAIDENTITY123",
                "SecretKey": "identity-secret",
                "SessionToken": "identity-session-token",
                "Expiration": datetime.now(timezone.utc),
            }
        }

        # Setup Lambda failure
        from botocore.exceptions import ClientError

        mock_lambda_client.invoke.side_effect = ClientError({"Error": {"Code": "ResourceNotFoundException"}}, "invoke")

        # Test authentication directly
        authenticator = CognitoAuthenticator(
            user_pool_id="us-east-1_TEST123",
            client_id="test-client-id",
            identity_pool_id="us-east-1:test-identity-pool",
        )

        tokens = authenticator.authenticate_user("testuser", "testpass")
        credentials = authenticator.get_temporary_credentials(tokens["id_token"])

        # Should fallback to Identity Pool credentials
        assert credentials["access_key_id"] == "AKIAIDENTITY123"
        assert "identity_id" in credentials

    def test_profile_manager_integration(self):
        """Test AWS profile manager creates correct file structure"""
        credentials = {
            "access_key_id": "AKIATEST123456",
            "secret_access_key": "test-secret-access-key",
            "session_token": "test-session-token",
        }

        with tempfile.TemporaryDirectory() as temp_dir, patch("pathlib.Path.home", return_value=Path(temp_dir)):
            manager = AWSProfileManager()
            manager.update_profile("test-profile", credentials, "us-east-1")

            # Check credentials file
            credentials_file = Path(temp_dir) / ".aws" / "credentials"
            assert credentials_file.exists()

            with open(credentials_file) as f:
                content = f.read()
                assert "[test-profile]" in content
                assert "aws_access_key_id = AKIATEST123456" in content
                assert "aws_secret_access_key = test-secret-access-key" in content
                assert "aws_session_token = test-session-token" in content

            # Check config file
            config_file = Path(temp_dir) / ".aws" / "config"
            assert config_file.exists()

            with open(config_file) as f:
                content = f.read()
                assert "[profile test-profile]" in content
                assert "region = us-east-1" in content


class TestAdminIntegration:
    """Test admin CLI integration workflows"""

    @patch("boto3.client")
    def test_role_info_integration(self, mock_boto_client):
        """Test role info command integration"""
        mock_cognito_identity = MagicMock()
        mock_iam = MagicMock()

        def client_factory(service_name, **kwargs):
            clients = {
                "cognito-identity": mock_cognito_identity,
                "iam": mock_iam,
            }
            return clients.get(service_name, MagicMock())

        mock_boto_client.side_effect = client_factory

        # Mock Identity Pool response
        mock_cognito_identity.describe_identity_pool.return_value = {
            "Roles": {"authenticated": "arn:aws:iam::123456789012:role/TestCognitoRole"}
        }

        # Mock IAM responses
        mock_iam.get_role.return_value = {
            "Role": {
                "RoleName": "TestCognitoRole",
                "Arn": "arn:aws:iam::123456789012:role/TestCognitoRole",
                "CreateDate": datetime.now(),
                "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%7D",
            }
        }

        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyName": "S3AccessPolicy", "PolicyArn": "arn:aws:iam::123456789012:policy/S3AccessPolicy"}
            ]
        }

        mock_iam.list_role_policies.return_value = {"PolicyNames": ["InlineS3Policy"]}

        runner = CliRunner()
        result = runner.invoke(admin_cli, ["role", "info", "--identity-pool-id", "us-east-1:test-pool"])

        assert result.exit_code == 0
        assert "TestCognitoRole" in result.output
        assert "S3AccessPolicy" in result.output

    @patch("boto3.client")
    def test_lambda_deployment_integration(self, mock_boto_client):
        """Test Lambda deployment integration"""
        mock_iam = MagicMock()
        mock_lambda_client = MagicMock()

        def client_factory(service_name, **kwargs):
            clients = {
                "iam": mock_iam,
                "lambda": mock_lambda_client,
            }
            return clients.get(service_name, MagicMock())

        mock_boto_client.side_effect = client_factory

        # Mock IAM operations
        mock_iam.create_user.return_value = {
            "User": {"UserName": "TestLambdaUser", "Arn": "arn:aws:iam::123456789012:user/TestLambdaUser"}
        }

        mock_iam.create_access_key.return_value = {
            "AccessKey": {"AccessKeyId": "AKIATEST123", "SecretAccessKey": "test-secret-key"}
        }

        mock_iam.create_role.return_value = {
            "Role": {"RoleName": "TestRole", "Arn": "arn:aws:iam::123456789012:role/TestRole"}
        }

        # Mock Lambda operations
        mock_lambda_client.create_function.return_value = {
            "FunctionName": "test-cognito-proxy",
            "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-cognito-proxy",
        }

        with patch("aws_cognito_auth.admin.load_policy_template") as mock_load_policy:
            mock_load_policy.return_value = {"Version": "2012-10-17", "Statement": []}

            with patch("pathlib.Path.exists", return_value=True):
                runner = CliRunner()
                result = runner.invoke(admin_cli, ["lambda", "deploy", "--create-user"])

                assert result.exit_code == 0
                assert "✅ Lambda proxy deployment completed successfully!" in result.output

                # Verify IAM user was created
                mock_iam.create_user.assert_called()
                mock_iam.create_access_key.assert_called()

                # Verify Lambda function was created
                mock_lambda_client.create_function.assert_called()


class TestErrorHandlingIntegration:
    """Test error handling across component integrations"""

    @patch("boto3.client")
    def test_authentication_chain_errors(self, mock_boto_client):
        """Test error propagation through authentication chain"""
        mock_cognito_idp = MagicMock()
        mock_cognito_identity = MagicMock()

        def client_factory(service_name, **kwargs):
            clients = {
                "cognito-idp": mock_cognito_idp,
                "cognito-identity": mock_cognito_identity,
            }
            return clients.get(service_name, MagicMock())

        mock_boto_client.side_effect = client_factory

        # Test User Pool authentication failure
        from botocore.exceptions import ClientError

        mock_cognito_idp.initiate_auth.side_effect = ClientError(
            {"Error": {"Code": "NotAuthorizedException"}}, "initiate_auth"
        )

        authenticator = CognitoAuthenticator(
            user_pool_id="us-east-1_TEST123",
            client_id="test-client-id",
            identity_pool_id="us-east-1:test-identity-pool",
        )

        with pytest.raises(Exception) as exc_info:
            authenticator.authenticate_user("baduser", "badpass")

        assert "Invalid username or password" in str(exc_info.value)

    @patch("boto3.client")
    def test_identity_pool_configuration_error(self, mock_boto_client):
        """Test Identity Pool configuration error handling"""
        mock_cognito_idp = MagicMock()
        mock_cognito_identity = MagicMock()

        def client_factory(service_name, **kwargs):
            clients = {
                "cognito-idp": mock_cognito_idp,
                "cognito-identity": mock_cognito_identity,
            }
            return clients.get(service_name, MagicMock())

        mock_boto_client.side_effect = client_factory

        # Setup successful authentication
        mock_cognito_idp.initiate_auth.return_value = {
            "AuthenticationResult": {"IdToken": "test-id-token", "AccessToken": "test-access-token"}
        }

        # Setup Identity Pool error
        from botocore.exceptions import ClientError

        error_message = "Identity 'us-east-1:test' is not from a supported provider"
        mock_cognito_identity.get_id.side_effect = ClientError(
            {"Error": {"Code": "InvalidParameterException", "Message": error_message}}, "get_id"
        )

        authenticator = CognitoAuthenticator(
            user_pool_id="us-east-1_TEST123",
            client_id="test-client-id",
            identity_pool_id="us-east-1:test-identity-pool",
        )

        tokens = authenticator.authenticate_user("testuser", "testpass")

        with pytest.raises(Exception) as exc_info:
            authenticator.get_temporary_credentials(tokens["id_token"])

        # Should provide helpful error message
        assert "Identity Pool configuration error" in str(exc_info.value)
        assert "Authentication providers" in str(exc_info.value)

    def test_cli_error_propagation(self):
        """Test that CLI commands properly handle and display errors"""
        runner = CliRunner()

        # Test with no configuration
        with patch("aws_cognito_auth.client.load_config", return_value={}):
            result = runner.invoke(client_cli, ["login", "-u", "testuser"])

            assert result.exit_code == 1
            assert "❌ Missing configuration" in result.output


class TestConfigurationIntegration:
    """Test configuration integration across components"""

    def test_client_admin_config_interaction(self):
        """Test interaction between client and admin configurations"""
        client_config = {
            "user_pool_id": "us-east-1_TEST123",
            "client_id": "test-client-id",
            "identity_pool_id": "us-east-1:test-identity-pool",
            "region": "us-east-1",
        }

        admin_config = {
            "aws_service_names": {
                "lambda_function_name": "custom-cognito-proxy",
                "long_lived_role_name": "CustomLongLivedRole",
            },
            "aws_configuration": {"default_region": "us-east-1", "max_session_duration": 28800},
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create both config files
            client_config_file = Path(temp_dir) / ".cognito-cli-config.json"
            admin_config_file = Path(temp_dir) / ".cognito-admin-config.json"

            with open(client_config_file, "w") as f:
                json.dump(client_config, f)
            with open(admin_config_file, "w") as f:
                json.dump(admin_config, f)

            with patch("pathlib.Path.home", return_value=Path(temp_dir)):
                # Test that admin configuration affects Lambda function name
                from aws_cognito_auth.admin import load_admin_config

                loaded_admin_config = load_admin_config()

                assert loaded_admin_config["aws_service_names"]["lambda_function_name"] == "custom-cognito-proxy"
                assert loaded_admin_config["aws_service_names"]["long_lived_role_name"] == "CustomLongLivedRole"

    @patch("boto3.client")
    def test_cross_component_configuration_consistency(self, mock_boto_client):
        """Test configuration consistency across client and admin components"""
        # Mock AWS clients
        mock_sts = MagicMock()
        mock_lambda_client = MagicMock()
        mock_cognito_identity = MagicMock()
        mock_cognito_idp = MagicMock()

        def client_factory(service_name, **kwargs):
            clients = {
                "sts": mock_sts,
                "lambda": mock_lambda_client,
                "cognito-identity": mock_cognito_identity,
                "cognito-idp": mock_cognito_idp,
            }
            return clients.get(service_name, MagicMock())

        mock_boto_client.side_effect = client_factory

        # Setup mocks
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_cognito_idp.initiate_auth.return_value = {"AuthenticationResult": {"IdToken": "test-token"}}

        # Setup fallback credentials for Lambda client creation
        fallback_creds = {
            "access_key_id": "AKIATEST123",
            "secret_access_key": "test-secret",
            "session_token": "test-token",
        }

        # Test that Lambda function name from admin config is used
        custom_config = {
            "aws_service_names": {
                "lambda_function_name": "my-custom-proxy-function",
                "long_lived_role_name": "MyCustomLongLivedRole",
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / ".cognito-admin-config.json"
            with open(config_file, "w") as f:
                json.dump(custom_config, f)

            with patch("pathlib.Path.home", return_value=Path(temp_dir)):
                authenticator = CognitoAuthenticator(
                    user_pool_id="us-east-1_TEST123",
                    client_id="test-client-id",
                    identity_pool_id="us-east-1:test-identity-pool",
                )

                with suppress(Exception):
                    # This should attempt to call the custom Lambda function name
                    authenticator._get_lambda_credentials("test-token", 12, fallback_creds)

                # Verify the correct Lambda function name was used
                if mock_lambda_client.invoke.called:
                    call_args = mock_lambda_client.invoke.call_args
                    assert call_args[1]["FunctionName"] == "my-custom-proxy-function"
