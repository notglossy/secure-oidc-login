#!/bin/bash
#
# Secure OIDC Login Plugin Packaging Script
#
# This script packages the plugin with production dependencies into a zip file
# ready for distribution or installation on WordPress sites.
#
# Usage: ./package.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Plugin details
PLUGIN_SLUG="secure-oidc-login"
PLUGIN_VERSION=$(grep "Version:" secure-oidc-login.php | awk '{print $3}')
BUILD_DIR="build"
PACKAGE_NAME="${PLUGIN_SLUG}-${PLUGIN_VERSION}"
TEMP_DIR="${BUILD_DIR}/${PLUGIN_SLUG}"

echo -e "${GREEN}Secure OIDC Login Plugin Packager${NC}"
echo "================================================"
echo ""

# Check if composer is installed
if ! command -v composer &> /dev/null; then
    echo -e "${RED}Error: Composer is not installed${NC}"
    echo "Please install Composer from https://getcomposer.org/"
    exit 1
fi

# Check if zip is installed
if ! command -v zip &> /dev/null; then
    echo -e "${RED}Error: zip command is not installed${NC}"
    echo "Please install zip utility"
    exit 1
fi

echo -e "${YELLOW}Step 1/5: Cleaning previous builds...${NC}"
rm -rf "${BUILD_DIR}"
mkdir -p "${TEMP_DIR}"

echo -e "${YELLOW}Step 2/5: Installing production dependencies...${NC}"
composer install --no-dev --optimize-autoloader --quiet

echo -e "${YELLOW}Step 3/5: Copying plugin files...${NC}"

# Copy main plugin file
cp secure-oidc-login.php "${TEMP_DIR}/"

# Copy includes directory
cp -r includes "${TEMP_DIR}/"

# Copy vendor directory (production dependencies)
cp -r vendor "${TEMP_DIR}/"

# Copy documentation
cp README.md "${TEMP_DIR}/"

# Copy .editorconfig if you want to include it (optional)
# cp .editorconfig "${TEMP_DIR}/"

echo -e "${YELLOW}Step 4/5: Creating zip archive...${NC}"
cd "${BUILD_DIR}"
zip -q -r "${PACKAGE_NAME}.zip" "${PLUGIN_SLUG}"
cd ..

# Calculate zip size
ZIP_SIZE=$(du -h "${BUILD_DIR}/${PACKAGE_NAME}.zip" | cut -f1)

echo -e "${YELLOW}Step 5/5: Cleaning up temporary files...${NC}"
rm -rf "${TEMP_DIR}"

# Restore dev dependencies
composer install --quiet

echo ""
echo -e "${GREEN}✓ Package created successfully!${NC}"
echo ""
echo "Package: ${BUILD_DIR}/${PACKAGE_NAME}.zip"
echo "Size: ${ZIP_SIZE}"
echo ""
echo "To install on WordPress:"
echo "1. Go to Plugins > Add New > Upload Plugin"
echo "2. Choose ${PACKAGE_NAME}.zip"
echo "3. Click 'Install Now' and then 'Activate'"
echo ""
