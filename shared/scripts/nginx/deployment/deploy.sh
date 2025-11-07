#!/bin/bash

# NGINX Deployment Script
# Based on successful ATS project pattern

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "==============================================="
echo "   NGINX Reverse Proxy - Deployment Script"
echo "==============================================="
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_menu() {
    echo "Select deployment option:"
    echo "1. 🚀 Quick Deploy (Production)"
    echo "2. 🔧 Development Setup"
    echo "3. 🔄 Update & Restart"
    echo "4. 🛑 Stop Services"
    echo "5. 📊 Status Check"
    echo "6. 🧹 Cleanup"
    echo "0. Exit"
    echo ""
    read -p "Enter your choice [0-6]: " choice
    
    case $choice in
        1) deploy_production ;;
        2) deploy_development ;;
        3) update_restart ;;
        4) stop_services ;;
        5) status_check ;;
        6) cleanup ;;
        0) exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" && show_menu ;;
    esac
}

deploy_production() {
    echo -e "${GREEN}Starting production deployment...${NC}"
    
    # Check if .env exists
    if [ ! -f "$SCRIPT_DIR/.env" ]; then
        echo -e "${YELLOW}Creating .env from template...${NC}"
        cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
        echo -e "${RED}Please edit .env file with your configuration before continuing!${NC}"
        exit 1
    fi
    
    # Load environment variables
    source "$SCRIPT_DIR/.env"
    
    # Stop existing services
    echo -e "${YELLOW}Stopping existing services...${NC}"
    docker-compose down || true
    
    # Pull latest images
    echo -e "${YELLOW}Pulling latest images...${NC}"
    docker-compose pull
    
    # Start services
    echo -e "${YELLOW}Starting services...${NC}"
    docker-compose up -d
    
    # Wait for services to be ready
    echo -e "${YELLOW}Waiting for services to be ready...${NC}"
    sleep 30
    
    # Check health
    health_check
    
    echo -e "${GREEN}Production deployment completed!${NC}"
    echo -e "${BLUE}Access your nginx proxy at: https://${DOMAIN_NAME}${NC}"
}

deploy_development() {
    echo -e "${GREEN}Starting development setup...${NC}"
    
    # Use development override
    docker-compose up -d
    
    echo -e "${GREEN}Development setup completed!${NC}"
    echo -e "${BLUE}Nginx running on: http://localhost${NC}"
}

update_restart() {
    echo -e "${GREEN}Updating and restarting services...${NC}"
    
    docker-compose pull
    docker-compose up -d --force-recreate
    
    echo -e "${GREEN}Services updated and restarted!${NC}"
}

stop_services() {
    echo -e "${YELLOW}Stopping all services...${NC}"
    docker-compose down
    echo -e "${GREEN}All services stopped!${NC}"
}

status_check() {
    echo -e "${GREEN}Checking service status...${NC}"
    echo ""
    
    docker-compose ps
    echo ""
    
    health_check
}

health_check() {
    echo -e "${YELLOW}Performing health checks...${NC}"
    
    # Check nginx
    if curl -f -s http://localhost/health > /dev/null; then
        echo -e "${GREEN}✅ Nginx: Healthy${NC}"
    else
        echo -e "${RED}❌ Nginx: Not responding${NC}"
    fi
    
    # Check SSL (if production)
    if [ "${NODE_ENV}" = "production" ] && [ ! -z "${DOMAIN_NAME}" ]; then
        if curl -f -s "https://${DOMAIN_NAME}/health" > /dev/null; then
            echo -e "${GREEN}✅ SSL: Healthy${NC}"
        else
            echo -e "${RED}❌ SSL: Not working${NC}"
        fi
    fi
    
    # Check Tailscale
    if docker-compose exec -T tailscale tailscale status > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Tailscale: Connected${NC}"
    else
        echo -e "${RED}❌ Tailscale: Not connected${NC}"
    fi
}

cleanup() {
    echo -e "${YELLOW}Cleaning up unused resources...${NC}"
    
    docker system prune -f
    docker volume prune -f
    
    echo -e "${GREEN}Cleanup completed!${NC}"
}

# Check for command line argument
if [ $# -eq 0 ]; then
    show_menu
    exit 0
fi

# Direct command execution
command="$1"

case "$command" in
    "prod") deploy_production ;;
    "dev") deploy_development ;;
    "update") update_restart ;;
    "stop") stop_services ;;
    "status") status_check ;;
    "clean") cleanup ;;
    *) echo -e "${RED}Invalid command: $command${NC}" && exit 1 ;;
esac
