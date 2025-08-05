# 🎉 Your AWS Cognito Authoriser is Ready!

## Project Structure Created

```
/Users/jiahao.tan/Repos/aws-authoriser/
├── cognito_cli.py           # Main CLI application
├── requirements.txt         # Python dependencies
├── README.md               # Complete documentation
├── setup.py                # For pip installation
├── .gitignore              # Git ignore rules
├── config.example.json     # Example configuration
├── quickstart.sh           # Quick setup script
├── Makefile               # Common tasks
└── GETTING_STARTED.md     # This file
```

## Quick Start (Choose One Method)

### Method 1: Using the Quick Start Script
```bash
cd /Users/jiahao.tan/Repos/aws-authoriser
./quickstart.sh
```

### Method 2: Using Make
```bash
cd /Users/jiahao.tan/Repos/aws-authoriser
make quickstart
```

### Method 3: Manual Setup
```bash
cd /Users/jiahao.tan/Repos/aws-authoriser

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x cognito_cli.py

# Configure
python3 cognito_cli.py configure

# Login
python3 cognito_cli.py login -u your-username
```

## What You Need

Before running the tool, you need:

**Required:**
1. **Cognito User Pool ID** (e.g., `us-east-1_XXXXXXXXX`) - from your web app
2. **Cognito User Pool Client ID** - from your web app
3. **Cognito Identity Pool ID** (e.g., `us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
4. **AWS Region** (optional, auto-detected from User Pool ID)

**⚠️ Don't have an Identity Pool?**
- 📖 See [`NO_IDENTITY_POOL.md`](NO_IDENTITY_POOL.md) for detailed setup
- 🚀 Or run: `make setup-identity-pool` for quick automated setup

## First Time Usage

1. **Configure the tool:**
   ```bash
   python3 cognito_cli.py configure
   ```

2. **Login with your credentials:**
   ```bash
   python3 cognito_cli.py login -u your-username
   ```

3. **Test AWS CLI access:**
   ```bash
   aws sts get-caller-identity
   aws s3 ls
   ```

## Daily Usage

After initial setup, just run:
```bash
python3 cognito_cli.py login -u your-username
```

Then use AWS CLI normally:
```bash
aws s3 sync s3://your-bucket ./local-folder
aws s3 cp file.txt s3://your-bucket/
```

## Optional: Global Installation

To use the tool from anywhere, create a symlink:
```bash
sudo ln -s /Users/jiahao.tan/Repos/aws-authoriser/cognito_cli.py /usr/local/bin/aws-auth
```

Then use it as:
```bash
aws-auth login -u your-username
```

## Need Help?

- Run `python3 cognito_cli.py --help` for command help
- Check `README.md` for detailed documentation
- Use `python3 cognito_cli.py status` to check configuration

## Migration from Your Web App

Use the same configuration values from your original `main.js`:
- `userPoolId` → User Pool ID
- `clientId` → Client ID  
- `identityPoolId` → Identity Pool ID
- `s3bucket` → Use with AWS CLI commands after authentication

🚀 **You're all set! Happy coding!**
