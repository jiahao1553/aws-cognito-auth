# Test Suite for AWS Cognito Authoriser

This directory contains comprehensive unit and integration tests for the AWS Cognito Authoriser CLI tool.

## Test Structure

### Test Files

- `test_client.py` - Unit tests for the client module (CognitoAuthenticator, AWSProfileManager, CLI commands)
- `test_admin.py` - Unit tests for the admin module (CognitoRoleManager, LambdaDeployer, admin CLI commands)
- `test_lambda_function.py` - Unit tests for the Lambda function module
- `test_config.py` - Tests for configuration loading and management
- `test_integration.py` - Integration tests that test component interactions
- `test_utils.py` - Utility functions and helpers for testing
- `test_markers.py` - Examples of using pytest markers and test categorization
- `conftest.py` - Pytest configuration and shared fixtures

### Test Categories

Tests are organized using pytest markers:

- `@pytest.mark.unit` - Unit tests for individual functions/methods
- `@pytest.mark.integration` - Integration tests for component interactions
- `@pytest.mark.cli` - Tests for command-line interface
- `@pytest.mark.config` - Configuration-related tests
- `@pytest.mark.aws` - Tests that interact with AWS services (mocked)
- `@pytest.mark.slow` - Tests that take longer to run

## Running Tests

### Run All Tests
```bash
pytest
```

### Run Specific Test Categories
```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run only CLI tests
pytest -m cli

# Run only configuration tests
pytest -m config

# Exclude slow tests
pytest -m "not slow"
```

### Run Tests with Coverage
```bash
# Generate coverage report
pytest --cov=aws_cognito_auth

# Generate HTML coverage report
pytest --cov=aws_cognito_auth --cov-report=html

# View coverage in browser
open htmlcov/index.html
```

### Run Specific Test Files
```bash
# Run client tests only
pytest tests/test_client.py

# Run specific test class
pytest tests/test_client.py::TestCognitoAuthenticator

# Run specific test method
pytest tests/test_client.py::TestCognitoAuthenticator::test_authenticate_user_success
```

### Verbose Output
```bash
# Show detailed test output
pytest -v

# Show test output even for passing tests
pytest -s

# Show extra test summary
pytest -ra
```

## Test Configuration

### pytest.ini
The `pytest.ini` file in the project root configures:
- Test discovery patterns
- Coverage reporting
- Default command-line options
- Custom markers
- Warning filters

### Fixtures
Common test fixtures are defined in `conftest.py`:
- `mock_config_data` - Sample configuration data
- `mock_admin_config_data` - Sample admin configuration
- `mock_aws_credentials` - Mock AWS credential responses
- `mock_cognito_user_response` - Mock Cognito authentication responses
- `mock_boto3_clients` - Mock AWS client factory
- `temp_aws_dir` - Temporary AWS directory structure

## Writing Tests

### Unit Tests
Unit tests should:
- Test individual functions/methods in isolation
- Use mocks for external dependencies (AWS clients, file I/O)
- Be fast and independent
- Use the `@pytest.mark.unit` marker

```python
@pytest.mark.unit
def test_function_logic():
    # Test pure logic without external dependencies
    pass
```

### Integration Tests
Integration tests should:
- Test interactions between components
- Mock AWS services but test real integration flows
- Use the `@pytest.mark.integration` and `@pytest.mark.aws` markers

```python
@pytest.mark.integration
@pytest.mark.aws
@patch('boto3.client')
def test_authentication_flow(self, mock_boto_client):
    # Test complete authentication workflow
    pass
```

### CLI Tests
CLI tests should:
- Use Click's `CliRunner` for testing commands
- Mock external dependencies
- Test both success and error scenarios
- Use the `@pytest.mark.cli` marker

```python
@pytest.mark.cli
def test_login_command():
    runner = CliRunner()
    result = runner.invoke(cli, ['login', '-u', 'testuser'])
    assert result.exit_code == 0
```

## Test Utilities

### Mock Helpers
The `test_utils.py` module provides helper functions:

- `create_mock_jwt_token()` - Create mock JWT tokens
- `create_cognito_user_token()` - Create realistic Cognito tokens
- `create_aws_credentials()` - Create mock AWS credentials
- `create_lambda_response()` - Create mock Lambda responses
- `MockAWSClient` - Configurable mock AWS client

### Example Usage
```python
from tests.test_utils import create_cognito_user_token, create_aws_credentials

def test_with_mock_data():
    token = create_cognito_user_token('testuser')
    credentials = create_aws_credentials()
    # Use in test...
```

## Mocking Strategy

### AWS Services
All AWS service interactions are mocked using `unittest.mock`:
- `boto3.client` is patched to return mock clients
- Mock clients return realistic response structures
- Errors are simulated using `ClientError` exceptions

### File I/O
File operations are mocked using:
- `tempfile.TemporaryDirectory()` for real temporary files
- `mock_open()` for simulating file content
- `patch('pathlib.Path.exists')` for file existence checks

### Environment Variables
Environment variables are mocked using:
- `patch.dict(os.environ, {...})` to set test values
- Clean separation between test and real environment

## Coverage Goals

The test suite aims for:
- **>90% line coverage** for core business logic
- **>80% overall coverage** (enforced by pytest configuration)
- **100% coverage** for critical authentication paths
- **Good branch coverage** for error handling

### Viewing Coverage
```bash
# Generate coverage report
pytest --cov=aws_cognito_auth --cov-report=term-missing

# Generate HTML report for detailed view
pytest --cov=aws_cognito_auth --cov-report=html
open htmlcov/index.html
```

## Common Test Patterns

### Testing CLI Commands
```python
from click.testing import CliRunner

def test_cli_command():
    runner = CliRunner()
    with patch('module.dependency'):
        result = runner.invoke(command, ['--option', 'value'])
        assert result.exit_code == 0
        assert 'expected output' in result.output
```

### Testing AWS Interactions
```python
@patch('boto3.client')
def test_aws_interaction(self, mock_boto_client):
    mock_client = MagicMock()
    mock_boto_client.return_value = mock_client
    mock_client.method.return_value = {'Response': 'data'}

    # Test code that uses AWS
    result = function_under_test()

    # Verify interactions
    mock_client.method.assert_called_once_with(expected_params)
```

### Testing Configuration
```python
def test_config_loading():
    config_data = {'key': 'value'}

    with tempfile.TemporaryDirectory() as temp_dir:
        config_file = Path(temp_dir) / 'config.json'
        with open(config_file, 'w') as f:
            json.dump(config_data, f)

        with patch('pathlib.Path.home', return_value=Path(temp_dir)):
            result = load_config()
            assert result['key'] == 'value'
```

## Best Practices

1. **Test Isolation** - Each test should be independent and not rely on state from other tests
2. **Descriptive Names** - Test names should clearly describe what is being tested
3. **Arrange-Act-Assert** - Structure tests with clear setup, execution, and verification phases
4. **Mock External Dependencies** - Mock all external services, file I/O, and network calls
5. **Test Edge Cases** - Include tests for error conditions, boundary values, and edge cases
6. **Keep Tests Simple** - Each test should verify one specific behavior
7. **Use Fixtures** - Reuse common test data and setup through pytest fixtures

## Troubleshooting Tests

### Common Issues

1. **Import Errors**
   ```bash
   # Make sure to install the package in development mode
   pip install -e .
   ```

2. **Path Issues**
   ```bash
   # Run tests from project root
   cd /path/to/aws-authoriser
   pytest
   ```

3. **Mock Issues**
   - Ensure mocks are applied before the code under test runs
   - Use `patch.object()` for specific method mocking
   - Check mock call history with `mock.assert_called_with()`

4. **Configuration Issues**
   - Use temporary directories for file-based tests
   - Clear environment variables between tests
   - Isolate configuration state

### Debugging Tests
```bash
# Run with pdb debugger
pytest --pdb

# Run with detailed output
pytest -vvv -s

# Run single test with debugging
pytest tests/test_client.py::test_specific_function -vvv -s --pdb
```
