#!/bin/bash
set -e

echo "Building AWS Cognito Auth packages..."

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf packages/cogauth/dist/ packages/cogauth/build/ packages/cogauth/*.egg-info/
rm -rf packages/cogadmin/dist/ packages/cogadmin/build/ packages/cogadmin/*.egg-info/

# Build cogauth package first (cogadmin depends on it)
echo "Building cogauth package..."
cd packages/cogauth
python -m build
cd ../..

# Build cogadmin package
echo "Building cogadmin package..."
cd packages/cogadmin
python -m build
cd ../..

echo "Packages built successfully!"
echo ""
echo "To publish to PyPI (test):"
echo "  python -m twine upload --repository testpypi packages/cogauth/dist/*"
echo "  python -m twine upload --repository testpypi packages/cogadmin/dist/*"
echo ""
echo "To publish to PyPI (production):"
echo "  python -m twine upload packages/cogauth/dist/*"
echo "  python -m twine upload packages/cogadmin/dist/*"