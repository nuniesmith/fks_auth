#!/bin/bash

# FKS Trading Systems - Tailscale IP Verification Script
# This script verifies Tailscale configuration and IP address assignment

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_tailscale_status() {
    print_step "Checking Tailscale Status"
    
    if ! command -v tailscale >/dev/null 2>&1; then
        print_error "Tailscale is not installed"
        print_info "Install Tailscale: curl -fsSL https://tailscale.com/install.sh | sh"
        return 1
    fi
    
    local status
    status=$(tailscale status --json 2>/dev/null || echo "{}")
    
    if echo "$status" | jq -e '.BackendState == "Running"' >/dev/null 2>&1; then
        print_info "✓ Tailscale is running"
        
        local hostname
        hostname=$(echo "$status" | jq -r '.Self.HostName // "unknown"')
        print_info "✓ Hostname: $hostname"
        
        local ips
        ips=$(echo "$status" | jq -r '.Self.TailscaleIPs[]? // empty' | tr '\n' ' ')
        if [[ -n "$ips" ]]; then
            print_info "✓ Tailscale IPs: $ips"
            echo "$ips" | head -1 | xargs
        else
            print_error "No Tailscale IPs found"
            return 1
        fi
    else
        print_error "Tailscale is not running or not authenticated"
        print_info "Start Tailscale: sudo tailscale up"
        return 1
    fi
}

get_primary_tailscale_ip() {
    if command -v tailscale >/dev/null 2>&1; then
        tailscale ip -4 2>/dev/null | head -1
    else
        echo ""
    fi
}

test_dns_resolution() {
    local domain="$1"
    local expected_ip="$2"
    
    print_step "Testing DNS Resolution for $domain"
    
    local subdomains=("app" "api" "data" "code" "db" "cache" "ninja" "monitor")
    
    for subdomain in "${subdomains[@]}"; do
        local fqdn="${subdomain}.${domain}"
        if command -v dig >/dev/null 2>&1; then
            local resolved_ip
            resolved_ip=$(dig +short "$fqdn" 2>/dev/null | head -1)
            if [[ -n "$resolved_ip" ]]; then
                if [[ "$resolved_ip" == "$expected_ip" ]]; then
                    print_info "✓ ${fqdn} -> ${resolved_ip}"
                else
                    print_warning "✗ ${fqdn} -> ${resolved_ip} (expected ${expected_ip})"
                fi
            else
                print_warning "✗ ${fqdn} - No DNS record found"
            fi
        elif command -v nslookup >/dev/null 2>&1; then
            if nslookup "$fqdn" >/dev/null 2>&1; then
                print_info "✓ ${fqdn} - DNS record exists"
            else
                print_warning "✗ ${fqdn} - No DNS record found"
            fi
        else
            print_warning "No DNS lookup tools available (dig/nslookup)"
            break
        fi
    done
}

test_local_connectivity() {
    local tailscale_ip="$1"
    
    print_step "Testing Local Service Connectivity"
    
    local services=(
        "web:3000"
        "api:8000"
        "data:9001"
        "nginx:80"
    )
    
    for service in "${services[@]}"; do
        local name="${service%:*}"
        local port="${service#*:}"
        
        if command -v nc >/dev/null 2>&1; then
            if nc -z "$tailscale_ip" "$port" 2>/dev/null; then
                print_info "✓ $name service is accessible on port $port"
            else
                print_warning "✗ $name service is not accessible on port $port"
            fi
        elif command -v telnet >/dev/null 2>&1; then
            if timeout 3 telnet "$tailscale_ip" "$port" >/dev/null 2>&1; then
                print_info "✓ $name service is accessible on port $port"
            else
                print_warning "✗ $name service is not accessible on port $port"
            fi
        else
            print_warning "No connectivity test tools available (nc/telnet)"
            break
        fi
    done
}

check_docker_services() {
    print_step "Checking Docker Services"
    
    if ! command -v docker >/dev/null 2>&1; then
        print_warning "Docker is not installed or not in PATH"
        return 1
    fi
    
    local fks_containers
    fks_containers=$(docker ps --filter "name=fks" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || true)
    
    if [[ -n "$fks_containers" ]]; then
        print_info "FKS Docker Services:"
        echo "$fks_containers"
    else
        print_warning "No FKS Docker containers running"
        print_info "Start services with: docker-compose up -d"
    fi
}

generate_curl_tests() {
    local domain="$1"
    local tailscale_ip="$2"
    
    print_step "Generating Connectivity Tests"
    
    cat <<EOF

# Test FKS Services Connectivity
# Run these commands to test your services:

# Test main website
curl -k https://app.${domain}/

# Test API health
curl -k https://api.${domain}/health

# Test data service
curl -k https://data.${domain}/health

# Test VS Code server
curl -k https://code.${domain}/

# Test direct Tailscale IP access
curl -k http://${tailscale_ip}:3000/  # Web service
curl -k http://${tailscale_ip}:8000/health  # API service
curl -k http://${tailscale_ip}:9001/health  # Data service

# Test WebSocket connection
wscat -c wss://api.${domain}/ws

EOF
}

show_network_info() {
    print_step "Network Configuration Summary"
    
    echo
    print_info "Network Interfaces:"
    if command -v ip >/dev/null 2>&1; then
        ip addr show | grep -E "(inet|tailscale)" | sed 's/^/  /'
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig | grep -E "(inet|tailscale)" | sed 's/^/  /'
    fi
    
    echo
    print_info "Routing Table:"
    if command -v ip >/dev/null 2>&1; then
        ip route | head -10 | sed 's/^/  /'
    elif command -v route >/dev/null 2>&1; then
        route -n | head -10 | sed 's/^/  /'
    fi
}

main() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "  FKS Trading Tailscale Verification"
    echo "========================================"
    echo -e "${NC}"
    
    local domain="fkstrading.xyz"
    local tailscale_ip
    
    # Check Tailscale status and get IP
    if tailscale_ip=$(check_tailscale_status); then
        echo
        print_info "Primary Tailscale IP: $tailscale_ip"
    else
        print_error "Failed to get Tailscale IP"
        exit 1
    fi
    
    echo
    
    # Run diagnostic tests
    test_dns_resolution "$domain" "$tailscale_ip"
    echo
    
    test_local_connectivity "$tailscale_ip"
    echo
    
    check_docker_services
    echo
    
    show_network_info
    echo
    
    generate_curl_tests "$domain" "$tailscale_ip"
    
    echo
    print_info "Next steps:"
    echo "  1. Ensure DNS records point to: $tailscale_ip"
    echo "  2. Configure SSL certificates for HTTPS"
    echo "  3. Test all service endpoints"
    echo "  4. Update firewall rules if needed"
}

# Handle script arguments
case "${1:-}" in
    "ip")
        get_primary_tailscale_ip
        ;;
    "status")
        check_tailscale_status >/dev/null
        ;;
    "dns")
        if [[ -n "${2:-}" ]]; then
            tailscale_ip=$(get_primary_tailscale_ip)
            test_dns_resolution "$2" "$tailscale_ip"
        else
            echo "Usage: $0 dns <domain>"
        fi
        ;;
    *)
        main "$@"
        ;;
esac
