# AWS Cognito Authoriser Makefile

.PHONY: install configure login status clean help setup-identity-pool validate-identity-pool

# Default target
help:
	@echo "AWS Cognito Authoriser - Available commands:"
	@echo ""
	@echo "  make install              - Install dependencies and setup"
	@echo "  make configure            - Configure Cognito settings"
	@echo "  make setup-identity-pool  - Create new Identity Pool (if you don't have one)"
	@echo "  make validate-identity-pool - Validate Identity Pool setup"
	@echo "  make login                - Login and update AWS profile"
	@echo "  make status               - Show configuration status"
	@echo "  make clean                - Clean up temporary files"
	@echo "  make help                 - Show this help message"

# Install dependencies and setup
install:
	@echo "📦 Installing dependencies..."
	pip3 install -r requirements.txt
	@echo "🔧 Making scripts executable..."
	chmod +x cognito_cli.py role_manager.py identity_pool_setup.py quickstart.sh
	@echo "✅ Installation complete!"

# Configure Cognito settings
configure:
	python3 cognito_cli.py configure

# Setup Identity Pool (for new users who don't have one)
setup-identity-pool:
	@echo "🚀 Setting up new Identity Pool..."
	python3 identity_pool_setup.py create-full-setup

# Validate Identity Pool setup
validate-identity-pool:
	@echo "🔍 Validating Identity Pool setup..."
	python3 identity_pool_setup.py validate-setup

# Login with prompt for username
login:
	python3 cognito_cli.py login

# Show status
status:
	python3 cognito_cli.py status

# Clean up
clean:
	@echo "🧹 Cleaning up..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	@echo "✅ Cleanup complete!"

# Quick setup using the shell script
quickstart:
	@echo "🚀 Running quick start setup..."
	chmod +x quickstart.sh
	./quickstart.sh
