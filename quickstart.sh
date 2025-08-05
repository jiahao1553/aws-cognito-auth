#!/bin/bash

# Quick start script for AWS Cognito Authoriser
# This script helps you get started quickly with the CLI tool

echo "🚀 AWS Cognito Authoriser - Quick Start"
echo "======================================"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed. Please install Python 3 first."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed. Please install pip3 first."
    exit 1
fi

# Install dependencies
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

# Make the script executable
echo "🔧 Making script executable..."
chmod +x cognito_cli.py

# Check if configuration exists
if [ ! -f "$HOME/.cognito-cli-config.json" ]; then
    echo ""
    echo "⚙️  Configuration not found. Let's set it up!"
    echo "You'll need your Cognito User Pool ID, Client ID, and Identity Pool ID."
    echo ""
    python3 cognito_cli.py configure
else
    echo "✅ Configuration already exists."
fi

echo ""
echo "🎉 Setup complete! You can now use the following commands:"
echo ""
echo "  # Login with your credentials:"
echo "  python3 cognito_cli.py login -u your-username"
echo ""
echo "  # Check status:"
echo "  python3 cognito_cli.py status"
echo ""
echo "  # After login, use AWS CLI normally:"
echo "  aws s3 ls"
echo "  aws sts get-caller-identity"
echo ""
echo "📖 For more information, see README.md"
