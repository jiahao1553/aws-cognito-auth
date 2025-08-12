"""
Utility functions and helpers for testing
"""

import base64
import json
import time
from datetime import datetime, timezone
from typing import Any, Optional


def create_mock_jwt_token(payload_data: dict[str, Any]) -> str:
    """
    Create a mock JWT token for testing purposes.

    Args:
        payload_data: Dictionary containing JWT payload claims

    Returns:
        Base64 encoded JWT token string
    """
    # Add default required fields if not present
    if "exp" not in payload_data:
        payload_data["exp"] = int(time.time()) + 3600  # 1 hour from now

    if "iat" not in payload_data:
        payload_data["iat"] = int(time.time())

    # Create header
    header = {"alg": "RS256", "typ": "JWT", "kid": "test-key-id"}

    # Encode parts
    header_encoded = base64.b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_encoded = base64.b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
    signature_encoded = base64.b64encode(b"mock-signature").decode().rstrip("=")

    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def create_cognito_user_token(username: str = "testuser", user_id: Optional[str] = None) -> str:
    """
    Create a realistic Cognito User Pool JWT token for testing.

    Args:
        username: The username to include in the token
        user_id: The user ID (sub claim). If None, generates a realistic one.

    Returns:
        Mock JWT token string
    """
    if user_id is None:
        user_id = f"us-east-1:{username}-12345678-abcd-1234-efgh-123456789012"

    payload = {
        "sub": user_id,
        "cognito:username": username,
        "email": f"{username}@example.com",
        "email_verified": True,
        "aud": "test-client-id",
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST123",
        "token_use": "id",
        "auth_time": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }

    return create_mock_jwt_token(payload)


def create_expired_token(username: str = "testuser") -> str:
    """
    Create an expired JWT token for testing error scenarios.

    Args:
        username: The username to include in the token

    Returns:
        Expired mock JWT token string
    """
    payload = {
        "sub": f"us-east-1:{username}-expired",
        "cognito:username": username,
        "exp": int(time.time()) - 3600,  # Expired 1 hour ago
        "iat": int(time.time()) - 7200,  # Issued 2 hours ago
    }

    return create_mock_jwt_token(payload)


def create_aws_credentials(
    access_key_id: str = "AKIATEST123456789",
    secret_access_key: str = "test-secret-access-key-123456789",  # noqa: S107
    session_token: str = "test-session-token-very-long-string",  # noqa: S107
    expires_in_seconds: int = 3600,
) -> dict[str, Any]:
    """
    Create mock AWS credentials for testing.

    Args:
        access_key_id: AWS access key ID
        secret_access_key: AWS secret access key
        session_token: AWS session token
        expires_in_seconds: Seconds until expiration

    Returns:
        Dictionary containing AWS credentials
    """
    expiration = datetime.now(timezone.utc)
    from datetime import timedelta

    expiration += timedelta(seconds=expires_in_seconds)

    return {
        "AccessKeyId": access_key_id,
        "SecretAccessKey": secret_access_key,
        "SessionToken": session_token,
        "Expiration": expiration,
    }


def create_lambda_response(
    credentials: Optional[dict[str, Any]] = None,
    username: str = "testuser",
    user_id: Optional[str] = None,
    status_code: int = 200,
) -> dict[str, Any]:
    """
    Create a mock Lambda function response for testing.

    Args:
        credentials: AWS credentials to include in response
        username: Username to include in response
        user_id: User ID to include in response
        status_code: HTTP status code for response

    Returns:
        Dictionary representing Lambda response
    """
    if credentials is None:
        credentials = create_aws_credentials()

    if user_id is None:
        user_id = f"us-east-1:{username}-lambda-test"

    if status_code == 200:
        body = {
            "access_key_id": credentials["AccessKeyId"],
            "secret_access_key": credentials["SecretAccessKey"],
            "session_token": credentials["SessionToken"],
            "expiration": credentials["Expiration"].isoformat(),
            "username": username,
            "user_id": user_id,
        }
    else:
        body = {"error": "Lambda function error"}

    return {
        "statusCode": status_code,
        "body": json.dumps(body),
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
    }


def create_iam_role_response(role_name: str = "TestCognitoRole", account_id: str = "123456789012") -> dict[str, Any]:
    """
    Create a mock IAM role response for testing.

    Args:
        role_name: Name of the IAM role
        account_id: AWS account ID

    Returns:
        Dictionary representing IAM GetRole response
    """
    return {
        "Role": {
            "RoleName": role_name,
            "Path": "/",
            "Arn": f"arn:aws:iam::{account_id}:role/{role_name}",
            "CreateDate": datetime.now(timezone.utc),
            "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%7D",
            "Description": f"Test role {role_name}",
            "MaxSessionDuration": 43200,
            "Tags": [],
        }
    }


def create_lambda_function_response(
    function_name: str = "test-cognito-proxy", account_id: str = "123456789012", region: str = "us-east-1"
) -> dict[str, Any]:
    """
    Create a mock Lambda function configuration response.

    Args:
        function_name: Name of the Lambda function
        account_id: AWS account ID
        region: AWS region

    Returns:
        Dictionary representing Lambda GetFunction response
    """
    return {
        "Configuration": {
            "FunctionName": function_name,
            "FunctionArn": f"arn:aws:lambda:{region}:{account_id}:function:{function_name}",
            "Runtime": "python3.9",
            "Role": f"arn:aws:iam::{account_id}:role/TestLambdaRole",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 1024,
            "Description": "Test Lambda function for Cognito proxy",
            "Timeout": 30,
            "MemorySize": 256,
            "LastModified": "2025-01-01T00:00:00.000+0000",
            "CodeSha256": "test-code-sha256",
            "Version": "$LATEST",
            "Environment": {
                "Variables": {
                    "IAM_USER_ACCESS_KEY_ID": "AKIATEST123",
                    "DEFAULT_ROLE_ARN": f"arn:aws:iam::{account_id}:role/TestLongLivedRole",
                }
            },
        }
    }


def create_identity_pool_response(
    identity_pool_id: str = "us-east-1:test-identity-pool",
    name: str = "TestIdentityPool",
    authenticated_role_arn: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create a mock Identity Pool response.

    Args:
        identity_pool_id: Identity Pool ID
        name: Identity Pool name
        authenticated_role_arn: ARN of authenticated role

    Returns:
        Dictionary representing Cognito Identity Pool response
    """
    if authenticated_role_arn is None:
        authenticated_role_arn = "arn:aws:iam::123456789012:role/TestCognitoRole"

    return {
        "IdentityPoolId": identity_pool_id,
        "IdentityPoolName": name,
        "AllowUnauthenticatedIdentities": False,
        "SupportedLoginProviders": {},
        "CognitoIdentityProviders": [
            {
                "ProviderName": "cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST123",
                "ClientId": "test-client-id",
                "ServerSideTokenCheck": False,
            }
        ],
        "Roles": {"authenticated": authenticated_role_arn},
    }


def assert_aws_credentials_valid(credentials: dict[str, Any]) -> None:
    """
    Assert that AWS credentials dictionary contains required fields.

    Args:
        credentials: Credentials dictionary to validate

    Raises:
        AssertionError: If credentials are missing required fields
    """
    required_fields = ["access_key_id", "secret_access_key", "session_token"]
    for field in required_fields:
        assert field in credentials, f"Missing required credential field: {field}"
        assert credentials[field], f"Credential field {field} is empty"

    # Check that access key looks realistic
    assert credentials["access_key_id"].startswith("AKIA"), "Access key should start with AKIA"
    assert len(credentials["access_key_id"]) >= 16, "Access key should be at least 16 characters"

    # Check that secret key looks realistic
    assert len(credentials["secret_access_key"]) >= 16, "Secret key should be at least 16 characters"


def assert_lambda_response_valid(response: dict[str, Any]) -> None:
    """
    Assert that Lambda response contains required fields.

    Args:
        response: Lambda response dictionary to validate

    Raises:
        AssertionError: If response is missing required fields
    """
    assert "statusCode" in response, "Lambda response missing statusCode"
    assert "body" in response, "Lambda response missing body"

    if response["statusCode"] == 200:
        body = json.loads(response["body"]) if isinstance(response["body"], str) else response["body"]

        required_fields = ["access_key_id", "secret_access_key", "session_token", "expiration", "username", "user_id"]

        for field in required_fields:
            assert field in body, f"Lambda response body missing field: {field}"
            assert body[field], f"Lambda response body field {field} is empty"


def create_test_config_files(
    temp_dir: str, client_config: Optional[dict[str, Any]] = None, admin_config: Optional[dict[str, Any]] = None
):
    """
    Create test configuration files in a temporary directory.

    Args:
        temp_dir: Path to temporary directory
        client_config: Client configuration data (uses defaults if None)
        admin_config: Admin configuration data (uses defaults if None)

    Returns:
        Tuple of (client_config_path, admin_config_path)
    """
    import json
    from pathlib import Path

    temp_path = Path(temp_dir)

    if client_config is None:
        client_config = {
            "user_pool_id": "us-east-1_TEST123",
            "client_id": "test-client-id",
            "identity_pool_id": "us-east-1:test-identity-pool",
            "region": "us-east-1",
        }

    if admin_config is None:
        admin_config = {
            "aws_service_names": {
                "lambda_function_name": "test-cognito-proxy",
                "long_lived_role_name": "TestLongLivedRole",
            },
            "aws_configuration": {"default_region": "us-east-1"},
        }

    # Create client config file
    client_config_path = temp_path / ".cognito-cli-config.json"
    with open(client_config_path, "w") as f:
        json.dump(client_config, f, indent=2)

    # Create admin config file
    admin_config_path = temp_path / ".cognito-admin-config.json"
    with open(admin_config_path, "w") as f:
        json.dump(admin_config, f, indent=2)

    return client_config_path, admin_config_path


class MockAWSClient:
    """
    Mock AWS client that can be configured to return specific responses.
    """

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.responses = {}
        self.call_history = []

    def set_response(self, method_name: str, response: Any):
        """Set a response for a specific method call."""
        self.responses[method_name] = response

    def set_exception(self, method_name: str, exception: Exception):
        """Set an exception to be raised for a specific method call."""
        self.responses[method_name] = exception

    def __getattr__(self, name):
        """Return a mock method that records calls and returns configured responses."""

        def mock_method(*args, **kwargs):
            self.call_history.append({"method": name, "args": args, "kwargs": kwargs})

            if name in self.responses:
                response = self.responses[name]
                if isinstance(response, Exception):
                    raise response
                return response

            # Return a reasonable default response
            return {}

        return mock_method

    def was_called(self, method_name: str) -> bool:
        """Check if a method was called."""
        return any(call["method"] == method_name for call in self.call_history)

    def get_call_count(self, method_name: str) -> int:
        """Get the number of times a method was called."""
        return sum(1 for call in self.call_history if call["method"] == method_name)

    def get_last_call(self, method_name: str) -> Optional[dict[str, Any]]:
        """Get the last call made to a specific method."""
        calls = [call for call in self.call_history if call["method"] == method_name]
        return calls[-1] if calls else None


def create_mock_client_factory(*service_configs):
    """
    Create a mock boto3 client factory that returns configured mock clients.

    Args:
        service_configs: Tuples of (service_name, mock_client) configurations

    Returns:
        Function that can be used to patch boto3.client
    """
    clients = dict(service_configs)

    def client_factory(service_name, **kwargs):
        if service_name in clients:
            return clients[service_name]
        return MockAWSClient(service_name)

    return client_factory
