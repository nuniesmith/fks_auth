#!/bin/bash
# =================================================================
# FKS Trading Systems - Exchange Node Management Script
# =================================================================
# Script to manage exchange-specific nodes in the FKS network
# Usage: ./manage-exchange-nodes.sh [command] [options]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_PROJECT_NAME="fks"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.exchange-nodes.yml"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Change to project root
cd "$PROJECT_ROOT"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        exit 1
    fi
    
    #!/usr/bin/env bash
    # Shim: manage-exchange-nodes moved to orchestration/manage-exchange-nodes.sh
    set -euo pipefail
    NEW_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/orchestration/manage-exchange-nodes.sh"
    if [[ -f "$NEW_PATH" ]]; then exec "$NEW_PATH" "$@"; else echo "[WARN] Missing $NEW_PATH (placeholder)." >&2; exit 2; fi
        asx|ASX)
            service="node-network-asx"
            ;;
        tse|TSE)
            service="node-network-tse"
            ;;
        sgx|SGX)
            service="node-network-sgx"
            ;;
        *)
            print_error "Unknown exchange: $exchange"
            echo "Available exchanges: NYSE, CME, LSE, EUREX, ASX, TSE, SGX"
            exit 1
            ;;
    esac
    
    $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" $COMPOSE_FILES up -d "$service"
    print_success "${exchange} node started"
}

# Function to stop all exchange nodes
stop_all() {
    print_info "Stopping all exchange nodes..."
    $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" $COMPOSE_FILES down
    print_success "All exchange nodes stopped"
}

# Function to stop specific exchange node
stop_exchange() {
    local exchange=$1
    print_info "Stopping ${exchange} node..."
    
    # Map exchange names to container names
    case $exchange in
        nyse|NYSE)
            container="fks_nodes_nyse"
            ;;
        cme|CME)
            container="fks_nodes_cme"
            ;;
        lse|LSE)
            container="fks_nodes_lse"
            ;;
        eurex|EUREX)
            container="fks_nodes_eurex"
            ;;
        asx|ASX)
            container="fks_nodes_asx"
            ;;
        tse|TSE)
            container="fks_nodes_tse"
            ;;
        sgx|SGX)
            container="fks_nodes_sgx"
            ;;
        *)
            print_error "Unknown exchange: $exchange"
            exit 1
            ;;
    esac
    
    docker stop "$container" 2>/dev/null || true
    docker rm "$container" 2>/dev/null || true
    print_success "${exchange} node stopped"
}

# Function to show status of all nodes
show_status() {
    print_info "Exchange Node Status:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check each exchange node
    local exchanges=("NYSE" "CME" "LSE" "EUREX" "ASX" "TSE" "SGX")
    for exchange in "${exchanges[@]}"; do
        local container="fks_nodes_${exchange,,}"
        if docker ps | grep -q "$container"; then
            local port=$(docker port "$container" 2>/dev/null | grep -oP '0.0.0.0:\K\d+' | head -1)
            echo -e "${exchange}: ${GREEN}Running${NC} - Port: ${port:-N/A}"
        else
            echo -e "${exchange}: ${RED}Stopped${NC}"
        fi
    done
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Show endpoints
    print_info "Exchange Node Endpoints:"
    echo "NYSE:  http://localhost:8090"
    echo "CME:   http://localhost:8091"
    echo "LSE:   http://localhost:8092"
    echo "EUREX: http://localhost:8093"
    echo "ASX:   http://localhost:8094"
    echo "TSE:   http://localhost:8095"
    echo "SGX:   http://localhost:8096"
    echo ""
    echo "Load Balancer: http://localhost:8089"
}

# Function to show logs for specific exchange
show_logs() {
    local exchange=$1
    local follow=${2:-false}
    
    # Map exchange names to service names
    case $exchange in
        nyse|NYSE)
            service="node-network-nyse"
            ;;
        cme|CME)
            service="node-network-cme"
            ;;
        lse|LSE)
            service="node-network-lse"
            ;;
        eurex|EUREX)
            service="node-network-eurex"
            ;;
        asx|ASX)
            service="node-network-asx"
            ;;
        tse|TSE)
            service="node-network-tse"
            ;;
        sgx|SGX)
            service="node-network-sgx"
            ;;
        all)
            service=""
            ;;
        *)
            print_error "Unknown exchange: $exchange"
            exit 1
            ;;
    esac
    
    if [ "$follow" = true ]; then
        print_info "Following logs for ${exchange}... (Ctrl+C to stop)"
        $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" $COMPOSE_FILES logs -f $service
    else
        $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" $COMPOSE_FILES logs --tail=50 $service
    fi
}

# Function to test node connectivity
test_connectivity() {
    print_info "Testing exchange node connectivity..."
    
    local exchanges=("NYSE:8090" "CME:8091" "LSE:8092" "EUREX:8093" "ASX:8094" "TSE:8095" "SGX:8096")
    
    for exchange_port in "${exchanges[@]}"; do
        IFS=':' read -r exchange port <<< "$exchange_port"
        
        echo -n "Testing $exchange node... "
        if curl -s -f "http://localhost:${port}/health" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Healthy${NC}"
        else
            echo -e "${RED}✗ Not responding${NC}"
        fi
    done
}

# Function to show help
show_help() {
    cat << EOF
FKS Exchange Node Management Script

Usage: $0 [command] [options]

Commands:
    start [exchange]    Start exchange node(s)
                       If no exchange specified, starts all nodes
                       Examples: start, start CME, start NYSE
    
    stop [exchange]     Stop exchange node(s)
                       If no exchange specified, stops all nodes
                       Examples: stop, stop CME, stop NYSE
    
    status             Show status of all exchange nodes
    
    logs [exchange]    Show logs for exchange node(s)
                       Use 'all' to show logs for all nodes
                       Add -f to follow logs
                       Examples: logs CME, logs all, logs NYSE -f
    
    test               Test connectivity to all exchange nodes
    
    help               Show this help message

Available Exchanges:
    NYSE   - New York Stock Exchange
    CME    - Chicago Mercantile Exchange
    LSE    - London Stock Exchange
    EUREX  - Eurex (Frankfurt)
    ASX    - Australian Securities Exchange
    TSE    - Tokyo Stock Exchange
    SGX    - Singapore Exchange

Examples:
    $0 start                # Start all exchange nodes
    $0 start CME           # Start only CME node
    $0 stop NYSE           # Stop NYSE node
    $0 status              # Show status of all nodes
    $0 logs CME -f         # Follow CME logs
    $0 test                # Test connectivity

EOF
}

# Main script logic
main() {
    check_prerequisites
    
    case ${1:-help} in
        start)
            if [ -z "${2:-}" ]; then
                start_all
            else
                start_exchange "$2"
            fi
            ;;
        stop)
            if [ -z "${2:-}" ]; then
                stop_all
            else
                stop_exchange "$2"
            fi
            ;;
        status)
            show_status
            ;;
        logs)
            if [ -z "${2:-}" ]; then
                print_error "Please specify an exchange or 'all'"
                exit 1
            fi
            follow=false
            if [ "${3:-}" = "-f" ]; then
                follow=true
            fi
            show_logs "$2" "$follow"
            ;;
        test)
            test_connectivity
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
