# Installation & Setup

This guide walks you through installing the AWS Cognito Authoriser and performing initial setup.

## Prerequisites

- Python 3.9+
- AWS account with Cognito services
- Basic understanding of AWS IAM roles and policies

## Installation

### Option 1: Install from Source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/jiahao1553/aws-cognito-auth.git
   cd aws-cognito-auth
   ```

2. **Install the package:**
   ```bash
   pip install -e .
   ```

3. **Verify installation:**
   ```bash
   cogauth --help
   cogadmin --help
   ```

### Option 2: Install from PyPI

```bash
pip install aws-cognito-auth
```

## Initial Configuration

### Method 1: Interactive Configuration

The easiest way to get started is with the interactive configuration:

```bash
cogauth configure
```

This will prompt you for:
- Cognito User Pool ID
- Cognito App Client ID
- Cognito Identity Pool ID
- AWS Region

### Method 2: Environment Variables

Set the following environment variables:

```bash
export COGNITO_USER_POOL_ID="us-east-1_xxxxxxxxx"
export COGNITO_CLIENT_ID="your-client-id"
export COGNITO_IDENTITY_POOL_ID="us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export AWS_REGION="us-east-1"
```

### Method 3: Configuration File

Create `~/.cognito-cli-config.json`:

```json
{
    "user_pool_id": "us-east-1_xxxxxxxxx",
    "client_id": "your-client-id",
    "identity_pool_id": "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "region": "us-east-1"
}
```

## Verification

Test your configuration:

```bash
# Check configuration status
cogauth status

# Test authentication (you'll need valid Cognito user credentials)
cogauth login -u test-user
```

## Next Steps

1. **Set up AWS infrastructure** - See [AWS Setup](aws-setup.md)
2. **Learn command usage** - See [Usage Guide](usage.md)
3. **Configure administrative settings** - See [Administration](administration.md)

## Development Setup

For contributors and developers:

```bash
# Clone and install development dependencies
git clone https://github.com/jiahao1553/aws-cognito-auth.git
cd aws-cognito-auth
uv sync

# Install pre-commit hooks
uv run pre-commit install

# Run tests
make test

# Check formatting
make check
```

## Troubleshooting Installation

### Common Issues

**Import Errors**
- Ensure you're using Python 3.9+
- Try installing in a virtual environment

**Command Not Found**
- Verify the package installed correctly: `pip show aws-cognito-auth`
- Check your PATH includes pip's bin directory

**Permission Errors**
- Use `pip install --user` for user-only installation
- Consider using a virtual environment

For more troubleshooting, see [Troubleshooting](troubleshooting.md).
