#!/bin/bash

# FKS System Status Check
# Quick diagnostic script to check Docker and system status

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}FKS Trading Systems Status Check${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# System Info
echo -e "${BLUE}📋 System Information${NC}"
echo "  Hostname: $(hostname)"
echo "  OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -s)"
echo "  Uptime: $(uptime -p 2>/dev/null || uptime)"
echo "  Load: $(uptime | grep -o 'load average.*')"
echo ""

# Docker Status
echo -e "${BLUE}🐳 Docker Status${NC}"
if systemctl is-active --quiet docker.service; then
    echo -e "  Service: ${GREEN}✅ Running${NC}"
    echo "  Version: $(docker --version | cut -d' ' -f3 | cut -d',' -f1)"
    
    # Test Docker networking
    if docker network create fks_status-test-$$ >/dev/null 2>&1; then
        docker network rm fks_status-test-$$ >/dev/null 2>&1
        echo -e "  Networking: ${GREEN}✅ Working${NC}"
    else
        echo -e "  Networking: ${RED}❌ Failed${NC}"
        echo -e "    ${YELLOW}Run: sudo ./scripts/utils/fix-docker-startup.sh${NC}"
    fi
    
    # Show Docker networks
    echo "  Networks:"
    docker network ls | grep -E "(NAME|fks_)" | while read line; do
        echo "    $line"
    done
    
else
    echo -e "  Service: ${RED}❌ Not Running${NC}"
    echo -e "    ${YELLOW}Run: sudo systemctl start docker${NC}"
fi
echo ""

# Docker Compose Status
echo -e "${BLUE}🔧 Docker Compose Status${NC}"
if [ -f "docker-compose.yml" ]; then
    echo -e "  Config: ${GREEN}✅ Found${NC}"
    
    # Check if containers are running
    RUNNING=$(docker compose ps --services --filter "status=running" 2>/dev/null | wc -l)
    TOTAL=$(docker compose ps --services 2>/dev/null | wc -l)
    
    if [ "$TOTAL" -gt 0 ]; then
        echo "  Containers: $RUNNING/$TOTAL running"
        if [ "$RUNNING" -eq "$TOTAL" ]; then
            echo -e "  Status: ${GREEN}✅ All services running${NC}"
        elif [ "$RUNNING" -gt 0 ]; then
            echo -e "  Status: ${YELLOW}⚠️ Some services down${NC}"
        else
            echo -e "  Status: ${RED}❌ No services running${NC}"
            echo -e "    ${YELLOW}Run: ./start.sh${NC}"
        fi
    else
        echo -e "  Status: ${YELLOW}⚠️ No containers defined${NC}"
    fi
else
    echo -e "  Config: ${RED}❌ docker-compose.yml not found${NC}"
    echo "    Current directory: $(pwd)"
fi
echo ""

# Networking
echo -e "${BLUE}🌐 Network Status${NC}"
if command -v ip >/dev/null 2>&1; then
    # Primary IP
    PRIMARY_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || echo "unknown")
    echo "  Primary IP: $PRIMARY_IP"
    
    # Tailscale
    if command -v tailscale >/dev/null 2>&1; then
        if tailscale status >/dev/null 2>&1; then
            TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "unknown")
            echo -e "  Tailscale: ${GREEN}✅ Connected ($TAILSCALE_IP)${NC}"
        else
            echo -e "  Tailscale: ${YELLOW}⚠️ Not connected${NC}"
        fi
    else
        echo -e "  Tailscale: ${YELLOW}⚠️ Not installed${NC}"
    fi
    
    # Docker Bridge
    if ip link show docker0 >/dev/null 2>&1; then
        DOCKER_IP=$(ip addr show docker0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
        echo -e "  Docker Bridge: ${GREEN}✅ Active ($DOCKER_IP)${NC}"
    else
        echo -e "  Docker Bridge: ${YELLOW}⚠️ Not active${NC}"
    fi
fi
echo ""

# Ports
echo -e "${BLUE}🔌 Port Status${NC}"
if command -v ss >/dev/null 2>&1; then
    # Check common FKS ports
    PORTS=(3000 8000 8001 8002 8003 5432 6379)
    for port in "${PORTS[@]}"; do
        if ss -tln | grep ":$port " >/dev/null 2>&1; then
            echo -e "  Port $port: ${GREEN}✅ Open${NC}"
        else
            echo -e "  Port $port: ${YELLOW}⚠️ Closed${NC}"
        fi
    done
fi
echo ""

# Firewall
echo -e "${BLUE}🔥 Firewall Status${NC}"
if command -v iptables >/dev/null 2>&1; then
    # Check if Docker chains exist
    if sudo iptables -L DOCKER -n >/dev/null 2>&1; then
        echo -e "  Docker chains: ${GREEN}✅ Present${NC}"
    else
        echo -e "  Docker chains: ${RED}❌ Missing${NC}"
        echo -e "    ${YELLOW}Run: sudo ./scripts/utils/fix-docker-startup.sh${NC}"
    fi
    
    # Check basic rules
    RULES=$(sudo iptables -L INPUT | wc -l)
    echo "  Iptables rules: $RULES total"
fi
echo ""

# Quick Actions
echo -e "${BLUE}🚀 Quick Actions${NC}"
echo "  Start FKS:     ./start.sh"
echo "  Fix Docker:    sudo ./scripts/utils/fix-docker-startup.sh"
echo "  View logs:     docker compose logs -f"
echo "  Stop FKS:      docker compose down"
echo "  System status: ./scripts/utils/system-status.sh"
echo ""

# Access URLs (if containers are running)
if [ -f "docker-compose.yml" ] && docker compose ps --services --filter "status=running" >/dev/null 2>&1; then
    RUNNING_SERVICES=$(docker compose ps --services --filter "status=running" 2>/dev/null)
    if [ -n "$RUNNING_SERVICES" ]; then
        echo -e "${BLUE}🔗 Access URLs${NC}"
        echo "  Web UI:    http://localhost:3000"
        echo "  API:       http://localhost:8000"
        echo "  Adminer:   http://localhost:8080"
        echo "  Redis UI:  http://localhost:8081"
        
        if command -v tailscale >/dev/null 2>&1 && tailscale status >/dev/null 2>&1; then
            TAILSCALE_IP=$(tailscale ip -4 2>/dev/null)
            if [ -n "$TAILSCALE_IP" ]; then
                echo ""
                echo "  Tailscale (secure):"
                echo "    Web UI:  http://$TAILSCALE_IP:3000"
                echo "    API:     http://$TAILSCALE_IP:8000"
            fi
        fi
        echo ""
    fi
fi

echo -e "${BLUE}================================${NC}"
