#!/bin/bash

# FKS Trading Systems - Quick Status Check
# This script provides a quick overview of system status

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Determine compose command
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    echo -e "${RED}❌ Docker Compose is not available!${NC}"
    exit 1
fi

echo -e "${BLUE}📊 FKS Trading Systems Status${NC}"
echo "=============================="
echo ""

# Docker services
echo -e "${BLUE}🐳 Docker Services:${NC}"
$COMPOSE_CMD ps 2>/dev/null || echo "No services found"
echo ""

# Quick connectivity check
echo -e "${BLUE}🔌 Quick Connectivity Check:${NC}"

# Load environment variables
if [ -f ".env" ]; then
    source .env
fi

# Check web service
if curl -s -f http://localhost:${WEB_PORT:-3000} >/dev/null 2>&1; then
    echo -e "Web Interface (${WEB_PORT:-3000}): ${GREEN}✅ Accessible${NC}"
else
    echo -e "Web Interface (${WEB_PORT:-3000}): ${RED}❌ Not accessible${NC}"
fi

# Check API service
if curl -s -f http://localhost:${API_PORT:-8000} >/dev/null 2>&1; then
    echo -e "API Service (${API_PORT:-8000}): ${GREEN}✅ Accessible${NC}"
else
    echo -e "API Service (${API_PORT:-8000}): ${RED}❌ Not accessible${NC}"
fi

echo ""
echo -e "${BLUE}🔧 Management Commands:${NC}"
echo "• Full health check: ./health-check.sh"
echo "• Restart services: ./restart.sh"
echo "• Stop services: ./stop.sh"
echo "• View logs: docker compose logs -f"
