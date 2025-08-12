# Package Structure Guide

## Overview

AWS Cognito Authoriser has been restructured into two separate PyPI packages:

1. **`cogauth`** - Core authentication functionality
2. **`cogadmin`** - Administrative tools and infrastructure management

## Package Details

### CogAuth (`cogauth`)
- **Purpose**: Core AWS Cognito authentication
- **Command**: `cogauth`
- **Features**:
  - User authentication via Cognito User Pool
  - Temporary credential generation (Identity Pool + Lambda proxy)
  - AWS CLI profile management
  - Configuration management

### CogAdmin (`cogadmin`)
- **Purpose**: Infrastructure and policy management
- **Command**: `cogadmin`
- **Dependencies**: Requires `cogauth`
- **Features**:
  - Lambda function deployment
  - IAM role and policy management
  - AWS infrastructure setup
  - Policy templates (included in package)
  - Multi-environment configuration

## Directory Structure

```
packages/
├── cogauth/                    # Authentication package
│   ├── src/cogauth/
│   │   ├── __init__.py
│   │   └── client.py          # Main authentication logic
│   ├── pyproject.toml         # Package configuration
│   ├── README.md              # Package-specific docs
│   ├── LICENSE
│   └── MANIFEST.in
│
└── cogadmin/                   # Administration package
    ├── src/cogadmin/
    │   ├── __init__.py
    │   ├── admin.py           # Administration logic
    │   ├── lambda_function.py # Lambda proxy code
    │   └── policies/          # IAM policy templates
    │       ├── *.json
    │       └── README.md
    ├── pyproject.toml         # Package configuration
    ├── README.md              # Package-specific docs
    ├── LICENSE
    └── MANIFEST.in
```

## Command Changes

| Old Command | New Command |
|-------------|-------------|
| `aws-cognito-auth` | `cogauth` |
| `aws-cognito-admin` | `cogadmin` |

## Installation Options

### Option 1: Authentication Only
```bash
pip install cogauth
```
Use when you only need to authenticate and get credentials.

### Option 2: Full Suite
```bash
pip install cogadmin
```
Installs both `cogauth` and `cogadmin` packages.

## Usage Examples

### Authentication
```bash
# Configure
cogauth configure

# Login
cogauth login -u username

# Check status
cogauth status
```

### Administration
```bash
# Configure admin settings
cogadmin configure

# Deploy Lambda infrastructure
cogadmin lambda deploy --create-user

# Manage IAM policies
cogadmin policy create-s3-policy --bucket-name my-bucket --user-specific

# View role information
cogadmin role info
```

## Build and Publish

### Building Packages
```bash
# Build both packages
./build-packages.sh

# Or build individually
cd packages/cogauth && python -m build
cd packages/cogadmin && python -m build
```

### Publishing to PyPI

#### Test PyPI (Recommended first)
```bash
python -m twine upload --repository testpypi packages/cogauth/dist/*
python -m twine upload --repository testpypi packages/cogadmin/dist/*
```

#### Production PyPI
```bash
python -m twine upload packages/cogauth/dist/*
python -m twine upload packages/cogadmin/dist/*
```

**Important**: Always publish `cogauth` before `cogadmin` since cogadmin depends on cogauth.

## Configuration Compatibility

Both packages share the same configuration system:
- **Client config**: `~/.cognito-cli-config.json` (for authentication)
- **Admin config**: `~/.cognito-admin-config.json` (for infrastructure)
- **Local project config**: `admin-config.json` (project-specific overrides)

## Migration Guide

### For Users
1. Uninstall old package: `pip uninstall aws-cognito-auth`
2. Install new package: `pip install cogauth` (or `cogadmin` for full suite)
3. Update command usage: `aws-cognito-auth` → `cogauth`

### For Administrators
1. Install admin tools: `pip install cogadmin`
2. Update command usage: `aws-cognito-admin` → `cogadmin`
3. All existing configuration files remain compatible

## Benefits of Split Packages

1. **Reduced Dependencies**: Users who only need authentication don't install admin dependencies
2. **Clearer Separation**: Authentication vs. administration concerns separated
3. **Easier Maintenance**: Each package can be versioned and updated independently
4. **Better Distribution**: Policies are properly distributed with the admin package
5. **Shorter Commands**: `cogauth` and `cogadmin` are much shorter than original names