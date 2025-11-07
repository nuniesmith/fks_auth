#!/bin/bash

# FKS Trading Systems - Health Check Script
# This script provides comprehensive health monitoring

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Health check function
check_service() {
    local service_name="$1"
    local url="$2"
    local expected_status="$3"
    
    echo -n "🔍 Checking $service_name... "
    
    if command -v curl &> /dev/null; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$url" --connect-timeout 5 --max-time 10 || echo "000")
        
        if [[ "$HTTP_CODE" =~ ^(200|301|302|${expected_status:-200})$ ]]; then
            echo -e "${GREEN}✅ Healthy${NC} (HTTP $HTTP_CODE)"
            return 0
        else
            echo -e "${RED}❌ Unhealthy${NC} (HTTP $HTTP_CODE)"
            return 1
        fi
    else
        echo -e "${YELLOW}⚠️ curl not available${NC}"
        return 1
    fi
}

# Determine compose command
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    echo -e "${RED}❌ Docker Compose is not available!${NC}"
    exit 1
fi

main() {
    echo -e "${BLUE}🩺 FKS Trading Systems Health Check${NC}"
    echo "========================================"
    echo ""
    
    # Check Docker services
    echo -e "${BLUE}📊 Docker Services Status:${NC}"
    if $COMPOSE_CMD ps 2>/dev/null; then
        echo ""
    else
        echo -e "${RED}❌ Could not get Docker service status${NC}"
        echo ""
    fi
    
    # Check service health
    echo -e "${BLUE}🔌 Service Connectivity:${NC}"
    
    # Load environment variables
    if [ -f "$SCRIPT_DIR/.env" ]; then
        source "$SCRIPT_DIR/.env"
    fi
    
    # Check web service
    check_service "Web Interface" "http://localhost:${WEB_PORT:-3000}" "200"
    
    # Check API service
    check_service "API Service" "http://localhost:${API_PORT:-8000}" "200"
    
    # Check nginx if running
    if netstat -tln 2>/dev/null | grep -q ":${NGINX_PORT:-80} " || docker ps | grep -q nginx; then
        check_service "Nginx" "http://localhost:${NGINX_PORT:-80}" "200"
    fi
    
    # Check database if accessible
    if command -v pg_isready &> /dev/null && [ -n "${POSTGRES_USER:-}" ]; then
        echo -n "🔍 Checking Database... "
        if pg_isready -h localhost -p "${POSTGRES_PORT:-5432}" -U "${POSTGRES_USER}" &> /dev/null; then
            echo -e "${GREEN}✅ Healthy${NC}"
        else
            echo -e "${RED}❌ Unhealthy${NC}"
        fi
    fi
    
    echo ""
    
    # System resources
    echo -e "${BLUE}💻 System Resources:${NC}"
    echo "Memory Usage:"
    free -h | grep -E "Mem|Swap"
    echo ""
    echo "Disk Usage:"
    df -h "$SCRIPT_DIR" | tail -1
    echo ""
    
    # Docker resources
    if command -v docker &> /dev/null; then
        echo -e "${BLUE}🐳 Docker Resources:${NC}"
        docker system df 2>/dev/null || echo "Docker system info not available"
        echo ""
    fi
    
    # Service logs (last few lines)
    echo -e "${BLUE}📝 Recent Service Logs:${NC}"
    $COMPOSE_CMD logs --tail=3 2>/dev/null || echo "No recent logs available"
    
    echo ""
    echo -e "${GREEN}✅ Health check completed${NC}"
}

# Run health check
main "$@"
