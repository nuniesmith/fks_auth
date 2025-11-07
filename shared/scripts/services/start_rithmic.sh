#!/bin/bash
# Rithmic Service Startup Script
# Usage: ./start_rithmic.sh [test|live]

# Set working directory
cd /home/jordan/fks

# Set environment
ENVIRONMENT=${1:-test}

# Load configuration
if [ -f "config/rithmic.env" ]; then
    echo "Loading Rithmic configuration..."
    export $(cat config/rithmic.env | grep -v '^#' | xargs)
else
    echo "Warning: config/rithmic.env not found"
fi

# Override environment if specified
export RITHMIC_ENVIRONMENT=$ENVIRONMENT

# Check required variables
if [ -z "$RITHMIC_USERNAME" ] || [ -z "$RITHMIC_PASSWORD" ]; then
    echo "Error: RITHMIC_USERNAME and RITHMIC_PASSWORD must be set"
    echo "Please update config/rithmic.env with your credentials"
    exit 1
fi

echo "Starting Rithmic service in $ENVIRONMENT environment..."
echo "Username: $RITHMIC_USERNAME"
echo "Symbols: $RITHMIC_SYMBOLS"
echo "Host: $RITHMIC_HOST:$RITHMIC_PORT"

# Start the service
cd src/python
python -m services.rithmic.service \
    --environment $ENVIRONMENT \
    --username $RITHMIC_USERNAME \
    --password $RITHMIC_PASSWORD \
    --symbols $RITHMIC_SYMBOLS
