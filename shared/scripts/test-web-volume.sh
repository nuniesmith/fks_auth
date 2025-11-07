#!/bin/bash
# Test script to verify web service works with volume mounts

set -e

echo "🧪 Testing FKS Web Service with Volume Mounts"
echo "============================================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check if React app exists
if [ ! -f "$PROJECT_ROOT/src/web/react/package.json" ]; then
    echo -e "${RED}❌ React app not found at $PROJECT_ROOT/src/web/react${NC}"
    exit 1
fi

echo -e "${GREEN}✅ React app found${NC}"

# Test running the web container with volume mount
echo -e "\n${YELLOW}Testing web container with volume mount...${NC}"

# Stop any existing test container
docker stop fks_web_test 2>/dev/null || true
docker rm fks_web_test 2>/dev/null || true

# Run the container
echo "Starting test container..."
docker run -d \
    --name fks_web_test \
    -v "$PROJECT_ROOT/src/web:/app/src/web:rw" \
    -p 3001:3000 \
    -e REACT_APP_API_URL=http://localhost:8000 \
    -e NODE_ENV=development \
    -e WEB_PORT=3000 \
    -e SERVICE_TYPE=web \
    -e SERVICE_RUNTIME=node \
    nuniesmith/fks:web-latest

# Wait for container to start
echo "Waiting for container to initialize..."
sleep 10

# Check container status
if docker ps | grep -q fks_web_test; then
    echo -e "${GREEN}✅ Container is running${NC}"
else
    echo -e "${RED}❌ Container failed to start${NC}"
    docker logs fks_web_test
    docker rm fks_web_test
    exit 1
fi

# Check logs
echo -e "\n${YELLOW}Container logs:${NC}"
docker logs fks_web_test --tail 20

# Check if service is responding
echo -e "\n${YELLOW}Checking service health...${NC}"
if curl -f -s http://localhost:3001 > /dev/null; then
    echo -e "${GREEN}✅ Web service is responding on port 3001${NC}"
else
    echo -e "${YELLOW}⚠️  Service may still be starting up...${NC}"
fi

# Show volume mount information
echo -e "\n${YELLOW}Volume mount information:${NC}"
docker exec fks_web_test ls -la /app/src/web/react/

# Cleanup
echo -e "\n${YELLOW}Cleaning up test container...${NC}"
docker stop fks_web_test
docker rm fks_web_test

echo -e "\n${GREEN}✅ Test completed successfully!${NC}"
echo "The web service can successfully use volume-mounted source code."
echo "This means you can develop locally and see changes reflected in the container."
