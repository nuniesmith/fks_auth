#!/bin/bash
# Test script for configuration generation from master.yaml

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Configuration Generation Test ===${NC}"

# Check if running from project root
if [ ! -f "config/master.yaml" ]; then
    echo -e "${RED}Error: config/master.yaml not found. Please run from project root.${NC}"
    exit 1
fi

# Build the Rust config manager
echo -e "${YELLOW}Building config-manager...${NC}"
cd src/rust/config
cargo build --release
cd ../../..

CONFIG_MANAGER="./src/rust/config/target/release/config-manager"

# Check if build succeeded
if [ ! -f "$CONFIG_MANAGER" ]; then
    echo -e "${RED}Error: Failed to build config-manager${NC}"
    exit 1
fi

# Test environments
ENVIRONMENTS=("development" "staging" "production")

# Clean up previous test outputs
rm -rf generated/

for ENV in "${ENVIRONMENTS[@]}"; do
    echo -e "${YELLOW}Generating configurations for $ENV environment...${NC}"
    
    # Generate configurations
    $CONFIG_MANAGER gen-from-master \
        --master-file config/master.yaml \
        --environment "$ENV" \
        --output-dir "./generated/$ENV"
    
    # Check if files were generated
    if [ -f "./generated/$ENV/docker-compose.yml" ] && [ -f "./generated/$ENV/.env.$ENV" ]; then
        echo -e "${GREEN}✓ Successfully generated configurations for $ENV${NC}"
        echo "  - docker-compose.yml"
        echo "  - .env.$ENV"
    else
        echo -e "${RED}✗ Failed to generate configurations for $ENV${NC}"
        exit 1
    fi
done

echo -e "${GREEN}=== All configurations generated successfully! ===${NC}"
echo -e "${YELLOW}Generated files can be found in:${NC}"
tree generated/

# Optional: Validate the generated docker-compose files
echo -e "${YELLOW}Validating docker-compose files...${NC}"
for ENV in "${ENVIRONMENTS[@]}"; do
    if docker-compose -f "./generated/$ENV/docker-compose.yml" config > /dev/null 2>&1; then
        echo -e "${GREEN}✓ docker-compose.yml for $ENV is valid${NC}"
    else
        echo -e "${RED}✗ docker-compose.yml for $ENV has syntax errors${NC}"
        docker-compose -f "./generated/$ENV/docker-compose.yml" config
    fi
done
