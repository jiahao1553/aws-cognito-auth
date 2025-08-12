#!/usr/bin/env python3
"""Quick test script for authentication debugging"""

import json
from pathlib import Path
from aws_cognito_auth import CognitoAuthenticator

def load_config():
    """Load configuration from the CLI tool"""
    config = {}
    
    # Try config file
    config_file = Path.home() / '.cognito-cli-config.json'
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                for key, value in file_config.items():
                    config[key] = value
        except Exception:
            pass
    
    return config

if __name__ == '__main__':
    config = load_config()
    
    if not all(config.get(field) for field in ['user_pool_id', 'client_id', 'identity_pool_id']):
        print("❌ Missing configuration")
        exit(1)
    
    print("Testing authentication...")
    
    # You'll need to replace these with actual test credentials
    username = input("Username: ")
    password = input("Password: ")
    
    try:
        auth = CognitoAuthenticator(
            user_pool_id=config['user_pool_id'],
            client_id=config['client_id'],
            identity_pool_id=config['identity_pool_id']
        )
        
        print("🔐 Authenticating...")
        tokens = auth.authenticate_user(username, password)
        print("✅ Authentication successful")
        
        print("🎫 Getting temporary credentials...")
        credentials = auth.get_temporary_credentials(tokens['id_token'])
        print("✅ Credentials obtained successfully")
        
    except Exception as e:
        print(f"❌ Error: {e}")