"""
Unit tests for the Lambda function module
"""

import json
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from aws_cognito_auth.lambda_function import lambda_handler, validate_cognito_token


class TestLambdaHandler:
    """Test cases for the main lambda_handler function"""

    def test_lambda_handler_missing_id_token(self):
        """Test lambda handler with missing id_token"""
        event = {}
        context = MagicMock()

        response = lambda_handler(event, context)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert "id_token is required" in body["error"]

    def test_lambda_handler_invalid_duration(self):
        """Test lambda handler with invalid duration"""
        event = {
            "id_token": "test-token",
            "duration_seconds": 50000,  # Too high
        }
        context = MagicMock()

        response = lambda_handler(event, context)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert "Duration must be between" in body["error"]

    @patch.dict(
        os.environ,
        {
            "IAM_USER_ACCESS_KEY_ID": "AKIATEST123",
            "IAM_USER_SECRET_ACCESS_KEY": "test-secret-key",
            "DEFAULT_ROLE_ARN": "arn:aws:iam::123456789012:role/TestRole",
        },
    )
    @patch("aws_cognito_auth.lambda_function.validate_cognito_token")
    @patch("boto3.client")
    def test_lambda_handler_success(self, mock_boto_client, mock_validate_token):
        """Test successful lambda handler execution"""
        # Mock token validation
        mock_validate_token.return_value = {"sub": "test-user-id", "cognito:username": "testuser"}

        # Mock STS client
        mock_sts = MagicMock()
        mock_boto_client.return_value = mock_sts

        # Mock assume role response
        expiration = datetime.now(timezone.utc)
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIALAMBDA123",
                "SecretAccessKey": "lambda-secret",
                "SessionToken": "lambda-session-token",
                "Expiration": expiration,
            }
        }

        event = {
            "id_token": "valid-jwt-token",
            "duration_seconds": 7200,
            "role_arn": "arn:aws:iam::123456789012:role/CustomRole",
        }
        context = MagicMock()
        context.aws_request_id = "test-request-id"

        response = lambda_handler(event, context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["access_key_id"] == "AKIALAMBDA123"
        assert body["secret_access_key"] == "lambda-secret"  # noqa: S105
        assert body["session_token"] == "lambda-session-token"  # noqa: S105
        assert body["username"] == "testuser"
        assert body["user_id"] == "test-user-id"

        # Verify assume_role was called with correct parameters
        mock_sts.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::123456789012:role/CustomRole",
            RoleSessionName="CognitoAuth-testuser-test-request-id",
            DurationSeconds=7200,
            Tags=[
                {"Key": "CognitoUsername", "Value": "testuser"},
                {"Key": "CognitoSubject", "Value": "test-user-id"},
                {"Key": "Source", "Value": "CognitoCredentialProxy"},
            ],
        )

    @patch.dict(
        os.environ,
        {
            "IAM_USER_ACCESS_KEY_ID": "AKIATEST123",
            "IAM_USER_SECRET_ACCESS_KEY": "test-secret-key",
            "DEFAULT_ROLE_ARN": "arn:aws:iam::123456789012:role/TestRole",
        },
    )
    @patch("aws_cognito_auth.lambda_function.validate_cognito_token")
    def test_lambda_handler_default_role(self, mock_validate_token):
        """Test lambda handler using default role from environment"""
        mock_validate_token.return_value = {"sub": "test-user-id", "cognito:username": "testuser"}

        with patch("boto3.client") as mock_boto_client:
            mock_sts = MagicMock()
            mock_boto_client.return_value = mock_sts

            expiration = datetime.now(timezone.utc)
            mock_sts.assume_role.return_value = {
                "Credentials": {
                    "AccessKeyId": "AKIALAMBDA123",
                    "SecretAccessKey": "lambda-secret",
                    "SessionToken": "lambda-session-token",
                    "Expiration": expiration,
                }
            }

            event = {
                "id_token": "valid-jwt-token",
                "duration_seconds": 3600,
                # No role_arn provided - should use default
            }
            context = MagicMock()
            context.aws_request_id = "test-request-id"

            response = lambda_handler(event, context)

            assert response["statusCode"] == 200

            # Should use DEFAULT_ROLE_ARN from environment
            mock_sts.assume_role.assert_called_once()
            call_args = mock_sts.assume_role.call_args
            assert call_args[1]["RoleArn"] == "arn:aws:iam::123456789012:role/TestRole"

    @patch.dict(
        os.environ,
        {
            "IAM_USER_ACCESS_KEY_ID": "AKIATEST123",
            "IAM_USER_SECRET_ACCESS_KEY": "test-secret-key",
            "DEFAULT_ROLE_ARN": "arn:aws:iam::123456789012:role/TestRole",
        },
    )
    @patch("aws_cognito_auth.lambda_function.validate_cognito_token")
    @patch("boto3.client")
    def test_lambda_handler_assume_role_failure(self, mock_boto_client, mock_validate_token):
        """Test lambda handler when assume role fails"""
        mock_validate_token.return_value = {"sub": "test-user-id", "cognito:username": "testuser"}

        mock_sts = MagicMock()
        mock_boto_client.return_value = mock_sts

        # Mock assume role failure
        mock_sts.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "User not authorized"}}, "AssumeRole"
        )

        event = {"id_token": "valid-jwt-token", "duration_seconds": 3600}
        context = MagicMock()

        response = lambda_handler(event, context)

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert "Failed to assume role" in body["error"]

    @patch.dict(
        os.environ,
        {
            "IAM_USER_ACCESS_KEY_ID": "AKIATEST123",
            "IAM_USER_SECRET_ACCESS_KEY": "test-secret-key",
            "DEFAULT_ROLE_ARN": "arn:aws:iam::123456789012:role/TestRole",
        },
    )
    @patch("aws_cognito_auth.lambda_function.validate_cognito_token")
    def test_lambda_handler_invalid_token(self, mock_validate_token):
        """Test lambda handler with invalid Cognito token"""
        mock_validate_token.side_effect = Exception("Invalid token")

        event = {"id_token": "invalid-jwt-token", "duration_seconds": 3600}
        context = MagicMock()

        response = lambda_handler(event, context)

        assert response["statusCode"] == 401
        body = json.loads(response["body"])
        assert "Token validation failed" in body["error"]

    def test_lambda_handler_missing_environment_variables(self):
        """Test lambda handler with missing environment variables"""
        event = {"id_token": "test-token", "duration_seconds": 3600}
        context = MagicMock()

        # Clear environment variables
        with patch.dict(os.environ, {}, clear=True):
            response = lambda_handler(event, context)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert "Missing required environment variable" in body["error"]

    @patch.dict(
        os.environ,
        {
            "IAM_USER_ACCESS_KEY_ID": "AKIATEST123",
            "IAM_USER_SECRET_ACCESS_KEY": "test-secret-key",
            "DEFAULT_ROLE_ARN": "arn:aws:iam::123456789012:role/TestRole",
        },
    )
    @patch("aws_cognito_auth.lambda_function.validate_cognito_token")
    @patch("boto3.client")
    def test_lambda_handler_long_username_truncation(self, mock_boto_client, mock_validate_token):
        """Test lambda handler with long username that needs truncation"""
        # Mock token with very long username
        long_username = "a" * 100  # Very long username
        mock_validate_token.return_value = {"sub": "test-user-id", "cognito:username": long_username}

        mock_sts = MagicMock()
        mock_boto_client.return_value = mock_sts

        expiration = datetime.now(timezone.utc)
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIALAMBDA123",
                "SecretAccessKey": "lambda-secret",
                "SessionToken": "lambda-session-token",
                "Expiration": expiration,
            }
        }

        event = {"id_token": "valid-jwt-token", "duration_seconds": 3600}
        context = MagicMock()
        context.aws_request_id = "test-request-id"

        response = lambda_handler(event, context)

        assert response["statusCode"] == 200

        # Check that session name was truncated to 64 characters max
        call_args = mock_sts.assume_role.call_args
        session_name = call_args[1]["RoleSessionName"]
        assert len(session_name) <= 64


class TestValidateCognitoToken:
    """Test cases for the validate_cognito_token function"""

    def test_validate_cognito_token_invalid_format(self):
        """Test token validation with invalid JWT format"""
        with pytest.raises(Exception) as exc_info:
            validate_cognito_token("not-a-jwt-token")

        assert "Invalid token format" in str(exc_info.value)

    def test_validate_cognito_token_invalid_parts(self):
        """Test token validation with wrong number of parts"""
        with pytest.raises(Exception) as exc_info:
            validate_cognito_token("header.payload")  # Missing signature

        assert "Invalid token format" in str(exc_info.value)

    def test_validate_cognito_token_invalid_json(self):
        """Test token validation with invalid JSON in payload"""
        # Create a token with invalid JSON payload
        import base64

        header = base64.b64encode(b'{"alg":"RS256"}').decode()
        payload = base64.b64encode(b"invalid-json").decode()
        signature = base64.b64encode(b"signature").decode()
        token = f"{header}.{payload}.{signature}"

        with pytest.raises(Exception) as exc_info:
            validate_cognito_token(token)

        assert "Invalid token payload" in str(exc_info.value)

    def test_validate_cognito_token_expired(self):
        """Test token validation with expired token"""
        import base64
        import time

        # Create an expired token
        expired_time = int(time.time()) - 3600  # 1 hour ago
        payload_data = {"sub": "test-user", "exp": expired_time, "cognito:username": "testuser"}

        header = base64.b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
        payload = base64.b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
        signature = base64.b64encode(b"signature").decode().rstrip("=")
        token = f"{header}.{payload}.{signature}"

        with pytest.raises(Exception) as exc_info:
            validate_cognito_token(token)

        assert "Token has expired" in str(exc_info.value)

    def test_validate_cognito_token_missing_fields(self):
        """Test token validation with missing required fields"""
        import base64
        import time

        # Token missing 'sub' field
        payload_data = {
            "exp": int(time.time()) + 3600,  # Valid expiration
            "cognito:username": "testuser",
            # Missing 'sub'
        }

        header = base64.b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
        payload = base64.b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
        signature = base64.b64encode(b"signature").decode().rstrip("=")
        token = f"{header}.{payload}.{signature}"

        with pytest.raises(Exception) as exc_info:
            validate_cognito_token(token)

        assert "Missing required field" in str(exc_info.value)

    def test_validate_cognito_token_success(self):
        """Test successful token validation"""
        import base64
        import time

        # Create a valid token
        payload_data = {
            "sub": "test-user-id",
            "exp": int(time.time()) + 3600,  # Valid for 1 hour
            "cognito:username": "testuser",
            "aud": "test-audience",
        }

        header = base64.b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
        payload = base64.b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
        signature = base64.b64encode(b"signature").decode().rstrip("=")
        token = f"{header}.{payload}.{signature}"

        claims = validate_cognito_token(token)

        assert claims["sub"] == "test-user-id"
        assert claims["cognito:username"] == "testuser"
        assert claims["aud"] == "test-audience"

    def test_validate_cognito_token_base64_padding(self):
        """Test token validation with proper base64 padding handling"""
        import base64
        import time

        # Create token that might need padding
        payload_data = {
            "sub": "user",  # Short value that might cause padding issues
            "exp": int(time.time()) + 3600,
            "cognito:username": "u",  # Very short username
        }

        header_str = json.dumps({"alg": "RS256"})
        payload_str = json.dumps(payload_data)

        # Encode without padding
        header = base64.b64encode(header_str.encode()).decode().rstrip("=")
        payload = base64.b64encode(payload_str.encode()).decode().rstrip("=")
        signature = base64.b64encode(b"sig").decode().rstrip("=")
        token = f"{header}.{payload}.{signature}"

        claims = validate_cognito_token(token)

        assert claims["sub"] == "user"
        assert claims["cognito:username"] == "u"


class TestLambdaIntegration:
    """Integration-style tests for the Lambda function"""

    @patch.dict(
        os.environ,
        {
            "IAM_USER_ACCESS_KEY_ID": "AKIATEST123",
            "IAM_USER_SECRET_ACCESS_KEY": "test-secret-key",
            "DEFAULT_ROLE_ARN": "arn:aws:iam::123456789012:role/TestRole",
        },
    )
    @patch("boto3.client")
    def test_end_to_end_credential_generation(self, mock_boto_client):
        """Test end-to-end credential generation process"""
        import base64
        import time

        # Create a realistic JWT token
        payload_data = {
            "sub": "us-east-1:12345678-abcd-1234-efgh-123456789012",
            "exp": int(time.time()) + 3600,
            "cognito:username": "john.doe@example.com",
            "aud": "test-audience",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST123",
            "iat": int(time.time()),
            "token_use": "id",
        }

        header = base64.b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
        payload = base64.b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
        signature = base64.b64encode(b"realistic-signature").decode().rstrip("=")
        token = f"{header}.{payload}.{signature}"

        # Mock STS client
        mock_sts = MagicMock()
        mock_boto_client.return_value = mock_sts

        # Mock realistic credentials response
        expiration = datetime.now(timezone.utc)
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIALAMBDATEST123",
                "SecretAccessKey": "lambda-generated-secret-key",
                "SessionToken": "long-session-token-string-here",
                "Expiration": expiration,
            }
        }

        event = {
            "id_token": token,
            "duration_seconds": 43200,  # 12 hours
        }
        context = MagicMock()
        context.aws_request_id = "lambda-request-123"

        response = lambda_handler(event, context)

        # Verify successful response
        assert response["statusCode"] == 200

        body = json.loads(response["body"])
        assert body["access_key_id"] == "AKIALAMBDATEST123"
        assert body["secret_access_key"] == "lambda-generated-secret-key"  # noqa: S105
        assert body["session_token"] == "long-session-token-string-here"  # noqa: S105
        assert body["username"] == "john.doe@example.com"
        assert body["user_id"] == "us-east-1:12345678-abcd-1234-efgh-123456789012"
        assert "expiration" in body

        # Verify assume_role call
        mock_sts.assume_role.assert_called_once()
        call_args = mock_sts.assume_role.call_args

        # Check role session name format
        session_name = call_args[1]["RoleSessionName"]
        assert "CognitoAuth-john.doe@example.com" in session_name
        assert "lambda-request-123" in session_name

        # Check tags
        tags = call_args[1]["Tags"]
        tag_dict = {tag["Key"]: tag["Value"] for tag in tags}
        assert tag_dict["CognitoUsername"] == "john.doe@example.com"
        assert tag_dict["CognitoSubject"] == "us-east-1:12345678-abcd-1234-efgh-123456789012"
        assert tag_dict["Source"] == "CognitoCredentialProxy"

    def test_error_response_format(self):
        """Test that error responses follow consistent format"""
        event = {}  # Missing required fields
        context = MagicMock()

        response = lambda_handler(event, context)

        # Verify error response structure
        assert "statusCode" in response
        assert "body" in response
        assert "headers" in response

        # Verify CORS headers
        headers = response["headers"]
        assert headers["Access-Control-Allow-Origin"] == "*"
        assert headers["Content-Type"] == "application/json"

        # Verify error body structure
        body = json.loads(response["body"])
        assert "error" in body
        assert isinstance(body["error"], str)

    def test_success_response_format(self):
        """Test that success responses follow consistent format"""
        import base64
        import time

        with patch.dict(
            os.environ,
            {
                "IAM_USER_ACCESS_KEY_ID": "AKIATEST123",
                "IAM_USER_SECRET_ACCESS_KEY": "test-secret-key",
                "DEFAULT_ROLE_ARN": "arn:aws:iam::123456789012:role/TestRole",
            },
        ):
            # Create valid token
            payload_data = {"sub": "test-user-id", "exp": int(time.time()) + 3600, "cognito:username": "testuser"}

            header = base64.b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
            payload = base64.b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
            signature = base64.b64encode(b"signature").decode().rstrip("=")
            token = f"{header}.{payload}.{signature}"

            with patch("boto3.client") as mock_boto_client:
                mock_sts = MagicMock()
                mock_boto_client.return_value = mock_sts

                expiration = datetime.now(timezone.utc)
                mock_sts.assume_role.return_value = {
                    "Credentials": {
                        "AccessKeyId": "AKIATEST123",
                        "SecretAccessKey": "test-secret",
                        "SessionToken": "test-token",
                        "Expiration": expiration,
                    }
                }

                event = {"id_token": token, "duration_seconds": 3600}
                context = MagicMock()

                response = lambda_handler(event, context)

                # Verify success response structure
                assert response["statusCode"] == 200
                assert "body" in response
                assert "headers" in response

                # Verify CORS headers
                headers = response["headers"]
                assert headers["Access-Control-Allow-Origin"] == "*"
                assert headers["Content-Type"] == "application/json"

                # Verify success body structure
                body = json.loads(response["body"])
                required_fields = [
                    "access_key_id",
                    "secret_access_key",
                    "session_token",
                    "expiration",
                    "username",
                    "user_id",
                ]
                for field in required_fields:
                    assert field in body, f"Missing required field: {field}"
