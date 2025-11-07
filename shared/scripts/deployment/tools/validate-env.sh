#!/bin/bash

# =================================================================
# Environment Validation Script
# =================================================================
# This script validates that all required environment variables 
# are properly set for the Docker build and compose setup

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
MISSING_COUNT=0
WARNINGS_COUNT=0

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}FKS Trading Systems - Environment Validation${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo

# Function to check if variable is set
check_var() {
    local var_name="$1"
    local var_value="${!var_name}"
    local required="$2"
    local description="$3"
    
    if [ -z "$var_value" ]; then
        if [ "$required" = "true" ]; then
            echo -e "${RED}✗ Missing required variable: $var_name${NC}"
            echo -e "  Description: $description"
            echo
            ((MISSING_COUNT++))
        else
            echo -e "${YELLOW}⚠ Optional variable not set: $var_name${NC}"
            echo -e "  Description: $description"
            echo
            ((WARNINGS_COUNT++))
        fi
    else
        echo -e "${GREEN}✓ $var_name = $var_value${NC}"
    fi
}

# Load environment file
ENV_FILE="${1:-.env}"
if [ -f "$PROJECT_ROOT/$ENV_FILE" ]; then
    echo -e "${BLUE}Loading environment from: $ENV_FILE${NC}"
    set -a  # automatically export all variables
    source "$PROJECT_ROOT/$ENV_FILE"
    set +a
    echo
else
    echo -e "${RED}Environment file not found: $ENV_FILE${NC}"
    echo "Please create the environment file or specify a different one."
    exit 1
fi

echo -e "${BLUE}Core Application Variables:${NC}"
check_var "APP_NAME" true "Application name"
check_var "APP_VERSION" true "Application version"
check_var "APP_ENV" true "Application environment (development/production/staging/testing)"
check_var "APP_LOG_LEVEL" true "Logging level"

echo -e "${BLUE}Build Configuration:${NC}"
check_var "BUILD_CONTEXT" true "Docker build context"
check_var "DOCKERFILE_PATH" true "Path to Dockerfile"
check_var "PYTHON_VERSION" true "Python version for builds"
check_var "SERVICE_RUNTIME" true "Service runtime (python/rust/hybrid/dotnet/node)"
check_var "BUILD_PYTHON" true "Enable Python builds"

echo -e "${BLUE}Service Configuration:${NC}"
check_var "API_SERVICE_PORT" true "API service port"
check_var "API_SERVICE_HOST" true "API service host"
check_var "API_SERVICE_TYPE" true "API service type"
check_var "DATA_SERVICE_PORT" true "Data service port"
check_var "WORKER_SERVICE_PORT" true "Worker service port"

echo -e "${BLUE}Database Configuration:${NC}"
check_var "POSTGRES_PASSWORD" true "PostgreSQL password"
check_var "REDIS_PASSWORD" true "Redis password"
check_var "POSTGRES_DB" true "PostgreSQL database name"
check_var "POSTGRES_USER" true "PostgreSQL username"

echo -e "${BLUE}Container Configuration:${NC}"
check_var "API_CONTAINER_NAME" true "API container name"
check_var "DATA_CONTAINER_NAME" true "Data container name"
check_var "WORKER_CONTAINER_NAME" true "Worker container name"
check_var "API_IMAGE_TAG" true "API image tag"

echo -e "${BLUE}Network and Volume Configuration:${NC}"
check_var "NETWORK_FRONTEND" true "Frontend network name"
check_var "NETWORK_BACKEND" true "Backend network name"
check_var "NETWORK_DATABASE" true "Database network name"
check_var "VOLUME_POSTGRES_DATA" true "PostgreSQL data volume"
check_var "VOLUME_REDIS_DATA" true "Redis data volume"

echo -e "${BLUE}Requirements Configuration:${NC}"
check_var "API_REQUIREMENTS_FILE" true "API requirements file"
check_var "DATA_REQUIREMENTS_FILE" true "Data requirements file"
check_var "WORKER_REQUIREMENTS_FILE" true "Worker requirements file"

echo -e "${BLUE}Optional Build Variables:${NC}"
check_var "BUILD_RUST_NETWORK" false "Enable Rust network builds"
check_var "BUILD_RUST_EXECUTION" false "Enable Rust execution builds"
check_var "BUILD_CONNECTOR" false "Enable connector builds"
check_var "BUILD_DOTNET" false "Enable .NET builds"
check_var "BUILD_NODE" false "Enable Node.js builds"

echo -e "${BLUE}Optional API Keys:${NC}"
check_var "ALPHA_VANTAGE_API_KEY" false "Alpha Vantage API key"
check_var "OANDA_API_KEY" false "OANDA API key"
check_var "OANDA_ACCOUNT_ID" false "OANDA account ID"

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}Validation Summary${NC}"
echo -e "${BLUE}==================================================================${NC}"

if [ $MISSING_COUNT -eq 0 ]; then
    echo -e "${GREEN}✓ All required variables are set!${NC}"
else
    echo -e "${RED}✗ $MISSING_COUNT required variables are missing${NC}"
fi

if [ $WARNINGS_COUNT -gt 0 ]; then
    echo -e "${YELLOW}⚠ $WARNINGS_COUNT optional variables are not set${NC}"
fi

echo
echo -e "${BLUE}Docker Compose Configuration Test:${NC}"
if command -v docker-compose >/dev/null 2>&1; then
    if docker-compose config >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Docker Compose configuration is valid${NC}"
    else
        echo -e "${RED}✗ Docker Compose configuration has errors${NC}"
        echo "Run 'docker-compose config' for details"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ docker-compose not found, skipping configuration test${NC}"
fi

echo
echo -e "${BLUE}Recommendations:${NC}"
echo "1. Review missing required variables above"
echo "2. Set optional variables as needed for your environment"
echo "3. Run 'docker-compose config' to validate Docker Compose configuration"
echo "4. Use environment-specific files (.env.development, .env.production, etc.)"
echo "5. Create .env.local for local development overrides"

if [ $MISSING_COUNT -gt 0 ]; then
    exit 1
else
    exit 0
fi
