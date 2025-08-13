"""
Unit tests for configuration management and file handling
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import mock_open, patch

from aws_cognito_auth.admin import _merge_config, load_admin_config, load_config
from aws_cognito_auth.client import load_config as client_load_config
from aws_cognito_auth.client import save_config


class TestClientConfiguration:
    """Test client configuration loading and saving"""

    def test_load_config_environment_variables(self):
        """Test loading configuration from environment variables"""
        env_vars = {
            "COGNITO_USER_POOL_ID": "us-east-1_ENV123",
            "COGNITO_CLIENT_ID": "env-client-123",
            "COGNITO_IDENTITY_POOL_ID": "us-east-1:env-identity-123",
            "AWS_REGION": "us-west-2",
        }

        with patch.dict(os.environ, env_vars), patch("pathlib.Path.exists", return_value=False):
            config = client_load_config()

            assert config["user_pool_id"] == "us-east-1_ENV123"
            assert config["client_id"] == "env-client-123"
            assert config["identity_pool_id"] == "us-east-1:env-identity-123"
            assert config["region"] == "us-west-2"

    def test_load_config_from_file(self):
        """Test loading configuration from file"""
        config_data = {
            "user_pool_id": "us-east-1_FILE123",
            "client_id": "file-client-123",
            "identity_pool_id": "us-east-1:file-identity-123",
            "region": "us-east-1",
            "lambda_function_name": "file-lambda-function",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / ".cognito-cli-config.json"
            with open(config_file, "w") as f:
                json.dump(config_data, f)

            with patch("pathlib.Path.home", return_value=Path(temp_dir)):
                config = client_load_config()

                assert config["user_pool_id"] == "us-east-1_FILE123"
                assert config["lambda_function_name"] == "file-lambda-function"

    def test_load_config_env_overrides_file(self):
        """Test that environment variables override file configuration"""
        file_config = {
            "user_pool_id": "us-east-1_FILE123",
            "client_id": "file-client-123",
            "identity_pool_id": "us-east-1:file-identity-123",
            "region": "us-east-1",
        }

        env_vars = {
            "COGNITO_USER_POOL_ID": "us-east-1_ENV123",  # Should override file
            "AWS_REGION": "us-west-2",  # Should override file
            # Other vars not set, should use file values
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / ".cognito-cli-config.json"
            with open(config_file, "w") as f:
                json.dump(file_config, f)

            with patch("pathlib.Path.home", return_value=Path(temp_dir)), patch.dict(os.environ, env_vars):
                config = client_load_config()

                # Environment should override
                assert config["user_pool_id"] == "us-east-1_ENV123"
                assert config["region"] == "us-west-2"

                # File values should be used where env not set
                assert config["client_id"] == "file-client-123"
                assert config["identity_pool_id"] == "us-east-1:file-identity-123"

    def test_load_config_corrupted_file(self):
        """Test loading configuration with corrupted JSON file"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / ".cognito-cli-config.json"
            with open(config_file, "w") as f:
                f.write("invalid json content")

            with patch("pathlib.Path.home", return_value=Path(temp_dir)), patch.dict(os.environ, {}, clear=True):
                config = client_load_config()

                # Should return empty config when file is corrupted and no env vars
                assert all(not config.get(key) for key in ["user_pool_id", "client_id", "identity_pool_id"])

    def test_save_config(self):
        """Test saving configuration to file"""
        config_data = {
            "user_pool_id": "us-east-1_TEST123",
            "client_id": "test-client-123",
            "identity_pool_id": "us-east-1:test-identity-123",
            "region": "us-east-1",
        }

        with tempfile.TemporaryDirectory() as temp_dir, patch("pathlib.Path.home", return_value=Path(temp_dir)):
            save_config(config_data)

            config_file = Path(temp_dir) / ".cognito-cli-config.json"
            assert config_file.exists()

            with open(config_file) as f:
                saved_config = json.load(f)

            assert saved_config == config_data


class TestAdminConfiguration:
    """Test admin configuration loading and merging"""

    def test_load_admin_config_defaults(self):
        """Test loading default admin configuration"""
        with patch("pathlib.Path.exists", return_value=False):
            config = load_admin_config()

            # Should return default configuration
            assert "aws_service_names" in config
            assert "aws_configuration" in config
            assert config["aws_service_names"]["iam_user_name"] == "CognitoCredentialProxyUser"
            assert config["aws_configuration"]["default_region"] == "us-east-1"

    def test_load_admin_config_global_file(self):
        """Test loading admin configuration from global file"""
        custom_config = {
            "aws_service_names": {"iam_user_name": "CustomProxyUser", "lambda_function_name": "custom-lambda-function"},
            "aws_configuration": {"default_region": "eu-west-1", "lambda_timeout": 60},
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / ".cognito-admin-config.json"
            with open(config_file, "w") as f:
                json.dump(custom_config, f)

            with patch("pathlib.Path.home", return_value=Path(temp_dir)), patch("pathlib.Path.exists") as mock_exists:
                # Only global config file exists
                def exists_side_effect(path):
                    return str(path).endswith(".cognito-admin-config.json")

                mock_exists.side_effect = exists_side_effect

                config = load_admin_config()

                # Should merge with defaults
                assert config["aws_service_names"]["iam_user_name"] == "CustomProxyUser"
                assert config["aws_service_names"]["lambda_function_name"] == "custom-lambda-function"
                assert config["aws_configuration"]["default_region"] == "eu-west-1"
                assert config["aws_configuration"]["lambda_timeout"] == 60

                # Should keep default values not overridden
                assert config["aws_service_names"]["long_lived_role_name"] == "CognitoLongLivedRole"

    def test_load_admin_config_local_file(self):
        """Test loading admin configuration from local project file"""
        local_config = {
            "aws_service_names": {"lambda_function_name": "project-specific-lambda"},
            "aws_configuration": {
                "max_session_duration": 28800  # 8 hours
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create local config file
            local_config_file = Path(temp_dir) / "admin-config.json"
            with open(local_config_file, "w") as f:
                json.dump(local_config, f)

            with (
                patch("pathlib.Path.cwd", return_value=Path(temp_dir)),
                patch("pathlib.Path.home", return_value=Path("/fake-home")),
                patch("pathlib.Path.exists") as mock_exists,
            ):
                # Only local config file exists
                def exists_side_effect(path):
                    return str(path).endswith("admin-config.json") and temp_dir in str(path)

                mock_exists.side_effect = exists_side_effect

                config = load_admin_config()

                # Should merge with defaults
                assert config["aws_service_names"]["lambda_function_name"] == "project-specific-lambda"
                assert config["aws_configuration"]["max_session_duration"] == 28800

                # Should keep defaults
                assert config["aws_service_names"]["iam_user_name"] == "CognitoCredentialProxyUser"

    def test_load_admin_config_precedence(self):
        """Test configuration precedence: local > global > defaults"""
        global_config = {
            "aws_service_names": {"iam_user_name": "GlobalUser", "lambda_function_name": "global-function"},
            "aws_configuration": {"default_region": "us-west-1", "lambda_timeout": 45},
        }

        local_config = {
            "aws_service_names": {
                "lambda_function_name": "local-function"  # Should override global
            },
            "aws_configuration": {
                "lambda_timeout": 90  # Should override global
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create both config files
            global_config_file = Path(temp_dir) / ".cognito-admin-config.json"
            local_config_file = Path(temp_dir) / "admin-config.json"

            with open(global_config_file, "w") as f:
                json.dump(global_config, f)
            with open(local_config_file, "w") as f:
                json.dump(local_config, f)

            with (
                patch("pathlib.Path.cwd", return_value=Path(temp_dir)),
                patch("pathlib.Path.home", return_value=Path(temp_dir)),
            ):
                config = load_admin_config()

                # Local should override global
                assert config["aws_service_names"]["lambda_function_name"] == "local-function"
                assert config["aws_configuration"]["lambda_timeout"] == 90

                # Global should override defaults
                assert config["aws_service_names"]["iam_user_name"] == "GlobalUser"
                assert config["aws_configuration"]["default_region"] == "us-west-1"

                # Defaults should be kept where not overridden
                assert config["aws_service_names"]["long_lived_role_name"] == "CognitoLongLivedRole"

    def test_merge_config_nested_dicts(self):
        """Test merging nested configuration dictionaries"""
        default_config = {
            "level1": {
                "key1": "default1",
                "key2": "default2",
                "nested": {"nested_key1": "default_nested1", "nested_key2": "default_nested2"},
            },
            "level2": {"key3": "default3"},
        }

        file_config = {
            "level1": {
                "key1": "override1",  # Should override
                "key3": "new3",  # Should be added
                "nested": {
                    "nested_key1": "override_nested1",  # Should override
                    "nested_key3": "new_nested3",  # Should be added
                },
            },
            "level3": {
                "key4": "new4"  # Should be added
            },
        }

        result = _merge_config(default_config, file_config)

        # Check overrides
        assert result["level1"]["key1"] == "override1"
        assert result["level1"]["nested"]["nested_key1"] == "override_nested1"

        # Check preserved defaults
        assert result["level1"]["key2"] == "default2"
        assert result["level1"]["nested"]["nested_key2"] == "default_nested2"
        assert result["level2"]["key3"] == "default3"

        # Check new additions
        assert result["level1"]["key3"] == "new3"
        assert result["level1"]["nested"]["nested_key3"] == "new_nested3"
        assert result["level3"]["key4"] == "new4"

    def test_load_config_project_config(self):
        """Test loading project-specific configuration"""
        project_config = {
            "aws_service_names": {"lambda_function_name": "project-lambda", "identity_pool_name": "ProjectIdentityPool"}
        }

        with (
            patch("builtins.open", mock_open(read_data=json.dumps(project_config))),
            patch("pathlib.Path.exists", return_value=True),
        ):
            config = load_config()

            # Should merge with defaults
            assert config["aws_service_names"]["lambda_function_name"] == "project-lambda"
            assert config["aws_service_names"]["identity_pool_name"] == "ProjectIdentityPool"

            # Should keep defaults not overridden
            assert config["aws_service_names"]["iam_user_name"] == "CognitoCredentialProxyUser"


class TestConfigurationValidation:
    """Test configuration validation and error handling"""

    def test_load_config_file_permission_error(self):
        """Test loading configuration when file exists but can't be read"""
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("builtins.open", side_effect=PermissionError("Access denied")),
        ):
            # Should not raise exception, should return defaults
            config = load_admin_config()
            assert config is not None
            assert config["aws_service_names"]["iam_user_name"] == "CognitoCredentialProxyUser"

    def test_load_config_invalid_json(self):
        """Test loading configuration with invalid JSON"""
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("builtins.open", mock_open(read_data="invalid json {")),
        ):
            # Should not raise exception, should return defaults
            config = load_admin_config()
            assert config is not None
            assert config["aws_service_names"]["iam_user_name"] == "CognitoCredentialProxyUser"

    def test_merge_config_type_safety(self):
        """Test that merge_config handles type mismatches gracefully"""
        default_config = {"dict_value": {"key": "value"}, "string_value": "default_string", "int_value": 42}

        # File config has type mismatches
        file_config = {
            "dict_value": "not_a_dict",  # String instead of dict
            "string_value": {"key": "value"},  # Dict instead of string
            "int_value": "not_an_int",  # String instead of int
        }

        result = _merge_config(default_config, file_config)

        # Should use file values even with type mismatches
        assert result["dict_value"] == "not_a_dict"
        assert result["string_value"] == {"key": "value"}
        assert result["int_value"] == "not_an_int"


class TestConfigurationIntegration:
    """Integration tests for configuration loading across modules"""

    def test_client_admin_config_consistency(self):
        """Test that client and admin configs work together"""
        client_config = {
            "user_pool_id": "us-east-1_TEST123",
            "client_id": "test-client-123",
            "identity_pool_id": "us-east-1:test-identity-123",
            "region": "us-east-1",
        }

        admin_config = {
            "aws_service_names": {"lambda_function_name": "test-cognito-proxy"},
            "aws_configuration": {"default_region": "us-east-1"},
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
                # Load both configs
                client_cfg = client_load_config()
                admin_cfg = load_admin_config()

                # Verify consistency
                assert client_cfg["region"] == admin_cfg["aws_configuration"]["default_region"]
                assert admin_cfg["aws_service_names"]["lambda_function_name"] == "test-cognito-proxy"

    def test_environment_config_integration(self):
        """Test environment variables work across both client and admin"""
        env_vars = {
            "AWS_REGION": "us-west-2",
            "COGNITO_USER_POOL_ID": "us-west-2_ENV123",
            "COGNITO_CLIENT_ID": "env-client-123",
        }

        with patch.dict(os.environ, env_vars), patch("pathlib.Path.exists", return_value=False):
            client_cfg = client_load_config()
            admin_cfg = load_admin_config()

            # Client should use environment variables
            assert client_cfg["region"] == "us-west-2"
            assert client_cfg["user_pool_id"] == "us-west-2_ENV123"

            # Admin should use defaults but region preference could be consistent
            assert admin_cfg["aws_configuration"]["default_region"] == "us-east-1"  # Default

    def test_config_file_locations(self):
        """Test that configuration files are looked up in correct locations"""
        with tempfile.TemporaryDirectory() as home_dir, tempfile.TemporaryDirectory() as project_dir:
            # Create global admin config
            global_admin_config = {"aws_service_names": {"iam_user_name": "GlobalUser"}}
            global_config_file = Path(home_dir) / ".cognito-admin-config.json"
            with open(global_config_file, "w") as f:
                json.dump(global_admin_config, f)

            # Create local admin config
            local_admin_config = {"aws_service_names": {"lambda_function_name": "local-function"}}
            local_config_file = Path(project_dir) / "admin-config.json"
            with open(local_config_file, "w") as f:
                json.dump(local_admin_config, f)

            with (
                patch("pathlib.Path.home", return_value=Path(home_dir)),
                patch("pathlib.Path.cwd", return_value=Path(project_dir)),
            ):
                config = load_admin_config()

                # Should have both global and local config values
                assert config["aws_service_names"]["iam_user_name"] == "GlobalUser"
                assert config["aws_service_names"]["lambda_function_name"] == "local-function"
