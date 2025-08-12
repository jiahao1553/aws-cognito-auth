"""AWS Cognito Authentication Tools

This package provides tools for authenticating with AWS Cognito User Pool and Identity Pool,
obtaining temporary AWS credentials, and managing related AWS infrastructure.

Main components:
- client: Main CLI application for authentication
- admin: Administrative tools for AWS infrastructure management
"""

from .admin import CognitoRoleManager, LambdaDeployer
from .client import AWSProfileManager, CognitoAuthenticator

__version__ = "1.0.0"
__author__ = "AWS Cognito Auth Team"

__all__ = [
    "AWSProfileManager",
    "CognitoAuthenticator",
    "CognitoRoleManager",
    "LambdaDeployer",
]
