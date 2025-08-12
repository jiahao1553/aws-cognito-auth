"""
Test file demonstrating the use of pytest markers and categorizing tests
"""

from unittest.mock import MagicMock, patch

import pytest

from aws_cognito_auth.client import CognitoAuthenticator
from tests.test_utils import create_aws_credentials, create_cognito_user_token


@pytest.mark.unit
class TestUnitExamples:
    """Examples of unit tests - test individual functions/methods in isolation"""

    def test_cognito_authenticator_init(self):
        """Test CognitoAuthenticator initialization - pure unit test"""
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

    def test_region_extraction_from_pool_id(self):
        """Test region extraction logic - pure unit test"""
        auth = CognitoAuthenticator(
            user_pool_id="eu-west-1_TEST456",
            client_id="test-client-id",
            identity_pool_id="eu-west-1:test-identity-pool",
        )

        assert auth.region == "eu-west-1"


@pytest.mark.integration
@pytest.mark.aws
class TestIntegrationExamples:
    """Examples of integration tests - test component interactions with mocked AWS"""

    @patch("boto3.client")
    def test_authentication_flow(self, mock_boto_client):
        """Test complete authentication flow - integration test"""
        # Setup mocks
        mock_cognito_idp = MagicMock()
        mock_cognito_identity = MagicMock()

        def client_factory(service_name, **kwargs):
            if service_name == "cognito-idp":
                return mock_cognito_idp
            elif service_name == "cognito-identity":
                return mock_cognito_identity
            return MagicMock()

        mock_boto_client.side_effect = client_factory

        # Configure responses
        mock_cognito_idp.initiate_auth.return_value = {
            "AuthenticationResult": {
                "IdToken": create_cognito_user_token("testuser"),
                "AccessToken": "test-access-token",
                "RefreshToken": "test-refresh-token",
            }
        }

        mock_cognito_identity.get_id.return_value = {"IdentityId": "test-identity-id"}
        mock_cognito_identity.get_credentials_for_identity.return_value = {"Credentials": create_aws_credentials()}

        # Test integration
        auth = CognitoAuthenticator(
            user_pool_id="us-east-1_TEST123",
            client_id="test-client-id",
            identity_pool_id="us-east-1:test-identity-pool",
        )

        tokens = auth.authenticate_user("testuser", "testpass")
        credentials = auth._get_cognito_identity_credentials(tokens["id_token"])

        assert credentials["access_key_id"].startswith("AKIA")
        assert "identity_id" in credentials


@pytest.mark.cli
class TestCLIExamples:
    """Examples of CLI tests - test command-line interface"""

    def test_cli_help_command(self):
        """Test CLI help output"""
        from click.testing import CliRunner

        from aws_cognito_auth.client import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "Cognito CLI Authentication Tool" in result.output

    @patch("aws_cognito_auth.client.load_config")
    def test_cli_status_no_config(self, mock_load_config):
        """Test CLI status command with no configuration"""
        from click.testing import CliRunner

        from aws_cognito_auth.client import status

        mock_load_config.return_value = {}

        runner = CliRunner()
        result = runner.invoke(status)

        assert result.exit_code == 0
        assert "Not set" in result.output


@pytest.mark.config
class TestConfigExamples:
    """Examples of configuration tests"""

    def test_config_loading_precedence(self):
        """Test that environment variables override file configuration"""
        import os
        from unittest.mock import patch

        from aws_cognito_auth.client import load_config

        env_vars = {"COGNITO_USER_POOL_ID": "us-east-1_ENV123", "AWS_REGION": "us-west-2"}

        with patch.dict(os.environ, env_vars), patch("pathlib.Path.exists", return_value=False):
            config = load_config()

            assert config["user_pool_id"] == "us-east-1_ENV123"
            assert config["region"] == "us-west-2"


@pytest.mark.slow
@pytest.mark.integration
class TestSlowIntegrationExamples:
    """Examples of slow integration tests"""

    @patch("time.sleep")  # Mock sleep to make test faster
    def test_retry_mechanism(self, mock_sleep):
        """Test retry mechanism - marked as slow even though mocked"""
        # This would be a test that involves retries or timeouts
        # Even with mocking, it might be conceptually slow
        pass


# Example of custom markers for specific components
pytestmark = pytest.mark.aws  # Mark entire module as aws-related


class TestComponentSpecificMarkers:
    """Example of using component-specific markers"""

    @pytest.mark.lambda_function
    def test_lambda_handler(self):
        """Test Lambda function handler - custom marker"""
        from aws_cognito_auth.lambda_function import validate_cognito_token

        # This would test Lambda-specific functionality
        token = create_cognito_user_token("testuser")
        claims = validate_cognito_token(token)

        assert claims["cognito:username"] == "testuser"

    @pytest.mark.role_manager
    def test_role_manager_functionality(self):
        """Test role manager functionality - custom marker"""
        # This would test role manager specific features
        pass


# Conditional test - only run if certain conditions are met
@pytest.mark.skipif(not hasattr(pytest, "param"), reason="pytest version too old")
class TestConditionalExamples:
    """Example of conditional tests"""

    def test_modern_pytest_feature(self):
        """Test that only runs with newer pytest versions"""
        pass


# Parameterized test example
@pytest.mark.parametrize(
    "pool_id,expected_region",
    [
        ("us-east-1_TEST123", "us-east-1"),
        ("us-west-2_TEST456", "us-west-2"),
        ("eu-west-1_TEST789", "eu-west-1"),
        ("ap-southeast-1_TEST000", "ap-southeast-1"),
    ],
)
def test_region_extraction_parametrized(pool_id, expected_region):
    """Parametrized test for region extraction"""
    auth = CognitoAuthenticator(
        user_pool_id=pool_id, client_id="test-client-id", identity_pool_id=f"{expected_region}:test-identity-pool"
    )

    assert auth.region == expected_region
