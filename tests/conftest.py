"""
Pytest configuration and shared fixtures for AWS Cognito Authoriser tests
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_config_data():
    """Sample configuration data for testing"""
    return {
        "user_pool_id": "us-east-1_TEST123",
        "client_id": "test-client-id-123",
        "identity_pool_id": "us-east-1:test-identity-pool-id-123",
        "region": "us-east-1",
        "lambda_function_name": "test-cognito-proxy",
    }


@pytest.fixture
def mock_admin_config_data():
    """Sample admin configuration data for testing"""
    return {
        "aws_service_names": {
            "iam_user_name": "TestCognitoProxyUser",
            "lambda_execution_role_name": "TestCognitoProxyRole",
            "long_lived_role_name": "TestLongLivedRole",
            "lambda_function_name": "test-cognito-proxy",
            "identity_pool_name": "TestIdentityPool",
            "policy_names": {
                "lambda_user_policy": "TestLambdaUserPolicy",
                "lambda_execution_policy": "TestLambdaExecutionPolicy",
                "s3_access_policy": "TestS3Policy",
            },
        },
        "aws_configuration": {
            "default_region": "us-east-1",
            "lambda_runtime": "python3.9",
            "lambda_timeout": 30,
            "max_session_duration": 43200,
            "default_bucket": "test-bucket",
        },
    }


@pytest.fixture
def temp_config_file(mock_config_data):
    """Create a temporary configuration file for testing"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(mock_config_data, f)
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def temp_admin_config_file(mock_admin_config_data):
    """Create a temporary admin configuration file for testing"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(mock_admin_config_data, f)
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def mock_aws_credentials():
    """Mock AWS credentials response"""
    return {
        "AccessKeyId": "AKIATEST123456789",
        "SecretAccessKey": "test-secret-key-123456789",
        "SessionToken": "test-session-token-very-long-string",
        "Expiration": "2025-08-13T12:00:00Z",
    }


@pytest.fixture
def mock_cognito_user_response():
    """Mock Cognito User Pool authentication response"""
    return {
        "AuthenticationResult": {
            "AccessToken": "test-access-token-123",
            "IdToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJhdWQiOiJ0ZXN0LWNsaWVudCIsImV4cCI6MTk5OTk5OTk5OX0.test-signature",
            "RefreshToken": "test-refresh-token-123",
            "ExpiresIn": 3600,
            "TokenType": "Bearer",
        }
    }


@pytest.fixture
def mock_identity_id():
    """Mock Cognito Identity ID"""
    return "us-east-1:test-identity-id-12345678-abcd-1234-efgh-123456789012"


@pytest.fixture
def mock_lambda_response():
    """Mock Lambda function response"""
    return {
        "statusCode": 200,
        "body": json.dumps({
            "credentials": {
                "AccessKeyId": "AKIALAMBDA123456",
                "SecretAccessKey": "lambda-secret-key-123",
                "SessionToken": "lambda-session-token-123",
                "Expiration": "2025-08-13T23:59:59Z",
            },
            "username": "test-user",
        }),
    }


@pytest.fixture
def mock_iam_role():
    """Mock IAM role response"""
    return {
        "Role": {
            "RoleName": "TestCognitoRole",
            "Arn": "arn:aws:iam::123456789012:role/TestCognitoRole",
            "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%7D",
            "CreateDate": "2025-01-01T00:00:00Z",
        }
    }


@pytest.fixture
def mock_lambda_function():
    """Mock Lambda function configuration"""
    return {
        "FunctionName": "test-cognito-proxy",
        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-cognito-proxy",
        "Runtime": "python3.9",
        "Role": "arn:aws:iam::123456789012:role/TestLambdaRole",
        "Environment": {
            "Variables": {
                "IAM_USER_ACCESS_KEY_ID": "AKIATEST123",
                "DEFAULT_ROLE_ARN": "arn:aws:iam::123456789012:role/TestLongLivedRole",
            }
        },
    }


@pytest.fixture
def mock_boto3_clients():
    """Mock all AWS clients used by the application"""
    with patch("boto3.client") as mock_client:
        # Create separate mocks for each service
        cognito_idp_mock = MagicMock()
        cognito_identity_mock = MagicMock()
        iam_mock = MagicMock()
        lambda_mock = MagicMock()
        sts_mock = MagicMock()

        # Configure the client factory to return appropriate mocks
        def client_factory(service_name, **kwargs):
            if service_name == "cognito-idp":
                return cognito_idp_mock
            elif service_name == "cognito-identity":
                return cognito_identity_mock
            elif service_name == "iam":
                return iam_mock
            elif service_name == "lambda":
                return lambda_mock
            elif service_name == "sts":
                return sts_mock
            else:
                return MagicMock()

        mock_client.side_effect = client_factory

        yield {
            "cognito_idp": cognito_idp_mock,
            "cognito_identity": cognito_identity_mock,
            "iam": iam_mock,
            "lambda": lambda_mock,
            "sts": sts_mock,
        }


@pytest.fixture
def temp_aws_dir():
    """Create temporary AWS directory structure for testing"""
    with tempfile.TemporaryDirectory() as temp_dir:
        aws_dir = Path(temp_dir) / ".aws"
        aws_dir.mkdir()

        # Create empty credentials and config files
        (aws_dir / "credentials").touch()
        (aws_dir / "config").touch()

        yield aws_dir


@pytest.fixture
def mock_environment():
    """Mock environment variables"""
    env_vars = {
        "HOME": "/tmp/test-home",  # noqa: S108
        "COGNITO_USER_POOL_ID": "us-east-1_ENV123",
        "COGNITO_CLIENT_ID": "env-client-123",
        "COGNITO_IDENTITY_POOL_ID": "us-east-1:env-identity-123",
        "AWS_REGION": "us-west-2",
    }

    with patch.dict(os.environ, env_vars):
        yield env_vars


@pytest.fixture(autouse=True)
def reset_click_context():
    """Reset Click context between tests"""
    import click

    try:
        yield
    finally:
        # Clear any existing Click context
        if hasattr(click, "_local") and hasattr(click._local, "context_stack"):
            click._local.context_stack.clear()
