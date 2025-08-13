"""
Unit tests for the client module (CognitoAuthenticator and AWSProfileManager)
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner

from aws_cognito_auth.client import (
    AWSProfileManager,
    CognitoAuthenticator,
    cli,
    configure,
    load_config,
    login,
    save_config,
    status,
)


class TestCognitoAuthenticator:
    """Test cases for CognitoAuthenticator class"""

    def test_init_with_region(self):
        """Test CognitoAuthenticator initialization with explicit region"""
        auth = CognitoAuthenticator(
            user_pool_id="us-east-1_TEST123",
            client_id="test-client-id",
            identity_pool_id="us-east-1:test-identity-pool",
            region="us-west-2",
        )

        assert auth.user_pool_id == "us-east-1_TEST123"
        assert auth.client_id == "test-client-id"
        assert auth.identity_pool_id == "us-east-1:test-identity-pool"
        assert auth.region == "us-west-2"

    def test_init_region_from_pool_id(self):
        """Test region extraction from user pool ID when not provided"""
        auth = CognitoAuthenticator(
            user_pool_id="us-west-1_TEST456",
            client_id="test-client-id",
            identity_pool_id="us-west-1:test-identity-pool",
        )

        assert auth.region == "us-west-1"

    @patch("boto3.client")
    def test_authenticate_user_success(self, mock_boto_client, mock_cognito_user_response):
        """Test successful user authentication"""
        mock_cognito_idp = MagicMock()
        mock_boto_client.return_value = mock_cognito_idp
        mock_cognito_idp.initiate_auth.return_value = mock_cognito_user_response

        auth = CognitoAuthenticator(
            user_pool_id="us-east-1_TEST123",
            client_id="test-client-id",
            identity_pool_id="us-east-1:test-identity-pool",
        )

        result = auth.authenticate_user("testuser", "testpass")

        assert result is not None
        assert result["IdToken"] is not None
        mock_cognito_idp.initiate_auth.assert_called_once_with(
            ClientId="test-client-id",
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": "testuser", "PASSWORD": "testpass"},
        )

    @patch("boto3.client")
    def test_authenticate_user_new_password_required(self, mock_boto_client):
        """Test authentication with new password required challenge"""
        mock_cognito_idp = MagicMock()
        mock_boto_client.return_value = mock_cognito_idp

        # First call returns challenge
        challenge_response = {
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "Session": "test-session",
            "ChallengeParameters": {},
        }
        # Second call returns success
        success_response = {"AuthenticationResult": {"IdToken": "new-id-token", "AccessToken": "new-access-token"}}

        mock_cognito_idp.initiate_auth.return_value = challenge_response
        mock_cognito_idp.admin_respond_to_auth_challenge.return_value = success_response

        auth = CognitoAuthenticator(
            user_pool_id="us-east-1_TEST123",
            client_id="test-client-id",
            identity_pool_id="us-east-1:test-identity-pool",
        )

        with patch("getpass.getpass", return_value="newpassword123"):
            result = auth.authenticate_user("testuser", "oldpassword")

        assert result is not None
        assert result["IdToken"] == "new-id-token"

    @patch("boto3.client")
    def test_authenticate_user_failure(self, mock_boto_client):
        """Test authentication failure"""
        mock_cognito_idp = MagicMock()
        mock_boto_client.return_value = mock_cognito_idp
        mock_cognito_idp.initiate_auth.side_effect = ClientError(
            {"Error": {"Code": "NotAuthorizedException"}}, "initiate_auth"
        )

        auth = CognitoAuthenticator(
            user_pool_id="us-east-1_TEST123",
            client_id="test-client-id",
            identity_pool_id="us-east-1:test-identity-pool",
        )

        with pytest.raises(Exception, match="Invalid username or password"):
            auth.authenticate_user("baduser", "badpass")

    @patch("boto3.client")
    def test_get_cognito_identity_credentials(self, mock_boto_client, mock_identity_id, mock_aws_credentials):
        """Test getting credentials from Cognito Identity Pool"""
        mock_cognito_identity = MagicMock()
        mock_boto_client.return_value = mock_cognito_identity

        mock_cognito_identity.get_id.return_value = {"IdentityId": mock_identity_id}
        mock_cognito_identity.get_credentials_for_identity.return_value = {"Credentials": mock_aws_credentials}

        auth = CognitoAuthenticator(
            user_pool_id="us-east-1_TEST123",
            client_id="test-client-id",
            identity_pool_id="us-east-1:test-identity-pool",
        )

        credentials = auth._get_cognito_identity_credentials("test-id-token")

        assert credentials is not None
        assert credentials["AccessKeyId"] == mock_aws_credentials["AccessKeyId"]
        assert credentials["username"] is not None

    @patch("boto3.client")
    def test_get_lambda_credentials_success(self, mock_boto_client, mock_lambda_response):
        """Test getting credentials from Lambda proxy"""
        mock_lambda = MagicMock()
        mock_boto_client.return_value = mock_lambda

        # Mock successful Lambda invocation
        mock_lambda.invoke.return_value = {"Payload": Mock(read=lambda: json.dumps(mock_lambda_response).encode())}

        auth = CognitoAuthenticator(
            user_pool_id="us-east-1_TEST123",
            client_id="test-client-id",
            identity_pool_id="us-east-1:test-identity-pool",
        )

        fallback_creds = {"AccessKeyId": "fallback", "username": "test"}
        credentials = auth._get_lambda_credentials("test-id-token", 12, fallback_creds)

        assert credentials is not None
        assert credentials["AccessKeyId"] == "AKIALAMBDA123456"
        assert credentials["username"] == "test-user"

    @patch("boto3.client")
    def test_get_lambda_credentials_function_not_found(self, mock_boto_client):
        """Test Lambda credentials when function not found"""
        mock_lambda = MagicMock()
        mock_boto_client.return_value = mock_lambda

        mock_lambda.invoke.side_effect = ClientError({"Error": {"Code": "ResourceNotFoundException"}}, "invoke")

        auth = CognitoAuthenticator(
            user_pool_id="us-east-1_TEST123",
            client_id="test-client-id",
            identity_pool_id="us-east-1:test-identity-pool",
        )

        with pytest.raises(Exception, match="Please deploy it first using cogadmin lambda deploy"):
            auth._get_lambda_credentials("test-id-token", 12, None)


class TestAWSProfileManager:
    """Test cases for AWSProfileManager class"""

    def test_init(self):
        """Test AWSProfileManager initialization"""
        manager = AWSProfileManager()
        assert manager is not None

    def test_update_profile(self, temp_aws_dir, mock_aws_credentials):
        """Test updating AWS profile"""
        with patch("pathlib.Path.home", return_value=temp_aws_dir.parent):
            manager = AWSProfileManager()

            manager.update_profile("test-profile", mock_aws_credentials, "us-east-1")

            # Check credentials file was updated
            credentials_file = temp_aws_dir / "credentials"
            assert credentials_file.exists()

            # Check config file was updated
            config_file = temp_aws_dir / "config"
            assert config_file.exists()

    def test_update_profile_creates_directories(self, mock_aws_credentials):
        """Test that update_profile creates AWS directory if it doesn't exist"""
        with tempfile.TemporaryDirectory() as temp_dir:
            home_path = Path(temp_dir)

            with patch("pathlib.Path.home", return_value=home_path):
                manager = AWSProfileManager()
                manager.update_profile("test", mock_aws_credentials, "us-east-1")

                assert (home_path / ".aws").exists()
                assert (home_path / ".aws" / "credentials").exists()
                assert (home_path / ".aws" / "config").exists()


class TestConfigurationFunctions:
    """Test configuration loading and saving functions"""

    def test_load_config_from_file(self, temp_config_file, mock_config_data):
        """Test loading configuration from file"""
        with patch("pathlib.Path.home") as mock_home:
            mock_home.return_value = Path(temp_config_file).parent

            # Create the expected config file name
            config_path = Path(temp_config_file).parent / ".cognito-cli-config.json"
            with open(config_path, "w") as f:
                json.dump(mock_config_data, f)

            try:
                config = load_config()
                assert config["user_pool_id"] == mock_config_data["user_pool_id"]
                assert config["client_id"] == mock_config_data["client_id"]
            finally:
                if config_path.exists():
                    config_path.unlink()

    def test_load_config_from_environment(self, mock_environment):
        """Test loading configuration from environment variables"""
        with patch("pathlib.Path.exists", return_value=False):  # No config files exist
            config = load_config()

            assert config["user_pool_id"] == "us-east-1_ENV123"
            assert config["client_id"] == "env-client-123"
            assert config["region"] == "us-west-2"

    def test_load_config_missing(self):
        """Test loading configuration when no config available"""
        with patch("pathlib.Path.exists", return_value=False), patch.dict(os.environ, {}, clear=True):
            config = load_config()
            assert config is None

    def test_save_config(self, mock_config_data):
        """Test saving configuration to file"""
        with tempfile.TemporaryDirectory() as temp_dir, patch("pathlib.Path.home", return_value=Path(temp_dir)):
            save_config(mock_config_data)

            config_file = Path(temp_dir) / ".cognito-cli-config.json"
            assert config_file.exists()

            with open(config_file) as f:
                saved_config = json.load(f)

            assert saved_config == mock_config_data


class TestCLICommands:
    """Test CLI command functions"""

    def test_cli_help(self):
        """Test CLI help command"""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "AWS Cognito authentication CLI" in result.output

    @patch("aws_cognito_auth.client.save_config")
    def test_configure_command(self, mock_save_config):
        """Test configure command"""
        runner = CliRunner()

        # Mock user input
        input_data = "\n".join([
            "us-east-1_TEST123",  # user_pool_id
            "test-client-id",  # client_id
            "us-east-1:test-identity-pool",  # identity_pool_id
            "us-east-1",  # region
            "test-lambda-function",  # lambda_function_name
        ])

        result = runner.invoke(configure, input=input_data)

        assert result.exit_code == 0
        assert mock_save_config.called

    def test_status_command_no_config(self):
        """Test status command with no configuration"""
        runner = CliRunner()

        with patch("aws_cognito_auth.client.load_config", return_value=None):
            result = runner.invoke(status)

            assert result.exit_code == 0
            assert "❌ Configuration not found" in result.output

    def test_status_command_with_config(self, mock_config_data):
        """Test status command with valid configuration"""
        runner = CliRunner()

        with patch("aws_cognito_auth.client.load_config", return_value=mock_config_data):
            result = runner.invoke(status)

            assert result.exit_code == 0
            assert "✅ Configuration loaded" in result.output
            assert mock_config_data["user_pool_id"] in result.output

    @patch("getpass.getpass", return_value="testpass")
    @patch("aws_cognito_auth.client.load_config")
    @patch("aws_cognito_auth.client.CognitoAuthenticator")
    @patch("aws_cognito_auth.client.AWSProfileManager")
    def test_login_command_success(
        self,
        mock_profile_manager,
        mock_authenticator,
        mock_load_config,
        mock_getpass,
        mock_config_data,
        mock_cognito_user_response,
        mock_aws_credentials,
    ):
        """Test successful login command"""
        runner = CliRunner()

        # Configure mocks
        mock_load_config.return_value = mock_config_data

        mock_auth_instance = MagicMock()
        mock_authenticator.return_value = mock_auth_instance
        mock_auth_instance.authenticate_user.return_value = mock_cognito_user_response["AuthenticationResult"]
        mock_auth_instance.get_temporary_credentials.return_value = mock_aws_credentials

        mock_profile_instance = MagicMock()
        mock_profile_manager.return_value = mock_profile_instance

        result = runner.invoke(login, ["-u", "testuser"])

        assert result.exit_code == 0
        assert "✅ Successfully" in result.output
        mock_auth_instance.authenticate_user.assert_called_once_with("testuser", "testpass")
        mock_profile_instance.update_profile.assert_called_once()

    @patch("aws_cognito_auth.client.load_config")
    def test_login_command_no_config(self, mock_load_config):
        """Test login command with no configuration"""
        runner = CliRunner()
        mock_load_config.return_value = None

        result = runner.invoke(login, ["-u", "testuser"])

        assert result.exit_code == 1
        assert "❌ No configuration found" in result.output

    @patch("getpass.getpass", return_value="badpass")
    @patch("aws_cognito_auth.client.load_config")
    @patch("aws_cognito_auth.client.CognitoAuthenticator")
    def test_login_command_auth_failure(self, mock_authenticator, mock_load_config, mock_getpass, mock_config_data):
        """Test login command with authentication failure"""
        runner = CliRunner()

        mock_load_config.return_value = mock_config_data

        mock_auth_instance = MagicMock()
        mock_authenticator.return_value = mock_auth_instance
        mock_auth_instance.authenticate_user.side_effect = Exception("Invalid credentials")

        result = runner.invoke(login, ["-u", "testuser"])

        assert result.exit_code == 1
        assert "❌" in result.output
