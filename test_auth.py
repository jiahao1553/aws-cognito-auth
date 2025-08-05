#!/usr/bin/env python3

import boto3
import getpass
from botocore.exceptions import ClientError

# Configuration
USER_POOL_ID = "ap-southeast-1_03PmCcqlF"
CLIENT_ID = "53pe79o2v0mmtbitpbvnanleo"
IDENTITY_POOL_ID = "ap-southeast-1:8772ee98-f531-4346-ad80-477d19357c93"
REGION = "ap-southeast-1"

def test_user_pool_auth():
    """Test User Pool authentication"""
    print("🔐 Testing User Pool Authentication...")
    
    cognito_idp = boto3.client('cognito-idp', region_name=REGION)
    
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    
    try:
        response = cognito_idp.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )
        
        if 'ChallengeName' in response:
            print(f"❌ Challenge required: {response['ChallengeName']}")
            return None
        
        tokens = response['AuthenticationResult']
        print("✅ User Pool authentication successful!")
        print(f"Access Token: {tokens['AccessToken'][:50]}...")
        print(f"ID Token: {tokens['IdToken'][:50]}...")
        
        return tokens['IdToken']
        
    except ClientError as e:
        print(f"❌ User Pool auth failed: {e.response['Error']['Message']}")
        return None

def test_identity_pool(id_token):
    """Test Identity Pool token exchange"""
    print("\n🎫 Testing Identity Pool token exchange...")
    
    cognito_identity = boto3.client('cognito-identity', region_name=REGION)
    
    logins_map = {
        f'cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}': id_token
    }
    
    try:
        # Get identity ID
        print("Getting identity ID...")
        identity_response = cognito_identity.get_id(
            IdentityPoolId=IDENTITY_POOL_ID,
            Logins=logins_map
        )
        
        identity_id = identity_response['IdentityId']
        print(f"✅ Identity ID: {identity_id}")
        
        # Get credentials
        print("Getting temporary credentials...")
        credentials_response = cognito_identity.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins=logins_map
        )
        
        credentials = credentials_response['Credentials']
        print("✅ Successfully obtained temporary credentials!")
        print(f"Access Key: {credentials['AccessKeyId']}")
        print(f"Expiration: {credentials['Expiration']}")
        
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        print(f"❌ Identity Pool failed:")
        print(f"   Error Code: {error_code}")
        print(f"   Error Message: {error_message}")
        print(f"   Full Response: {e.response}")
        
        return False

if __name__ == "__main__":
    print("=== Cognito Authentication Test ===")
    print(f"User Pool ID: {USER_POOL_ID}")
    print(f"Client ID: {CLIENT_ID}")
    print(f"Identity Pool ID: {IDENTITY_POOL_ID}")
    print(f"Region: {REGION}")
    print()
    
    # Test User Pool authentication
    id_token = test_user_pool_auth()
    
    if id_token:
        # Test Identity Pool
        success = test_identity_pool(id_token)
        
        if success:
            print("\n🎉 Complete authentication flow successful!")
        else:
            print("\n❌ Identity Pool integration failed")
    else:
        print("\n❌ User Pool authentication failed")