#!/bin/bash
# scripts/health-check.sh
# Health check script for nginx with SSL support

set -euo pipefail

# Configuration
DOMAIN_NAME="${DOMAIN_NAME:-nginx.7gram.xyz}"
TIMEOUT="${HEALTH_CHECK_TIMEOUT:-10}"
MAX_RETRIES="${MAX_RETRIES:-3}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}ℹ️  $*${NC}"; }
log_success() { echo -e "${GREEN}✅ $*${NC}"; }
log_warn() { echo -e "${YELLOW}⚠️  $*${NC}"; }
log_error() { echo -e "${RED}❌ $*${NC}"; }

# Test function with retries
test_endpoint() {
    local url="$1"
    local description="$2"
    local allow_self_signed="${3:-false}"
    
    local curl_opts="-f -s -m $TIMEOUT"
    if [[ "$allow_self_signed" == "true" ]]; then
        curl_opts="$curl_opts -k"
    fi
    
    log_info "Testing $description: $url"
    
    for attempt in $(seq 1 $MAX_RETRIES); do
        if curl $curl_opts "$url" >/dev/null 2>&1; then
            log_success "$description is healthy"
            return 0
        else
            if [[ $attempt -lt $MAX_RETRIES ]]; then
                log_warn "Attempt $attempt failed, retrying in 5 seconds..."
                sleep 5
            fi
        fi
    done
    
    log_error "$description failed after $MAX_RETRIES attempts"
    return 1
}

# Check if nginx container is running
check_container() {
    log_info "Checking nginx container status..."
    
    if docker ps --format "table {{.Names}}\t{{.Status}}" | grep -q "nginx-proxy.*Up"; then
        log_success "Nginx container is running"
        return 0
    else
        log_error "Nginx container is not running"
        docker ps --format "table {{.Names}}\t{{.Status}}" | grep nginx || true
        return 1
    fi
}

# Check nginx configuration
check_config() {
    log_info "Checking nginx configuration..."
    
    if docker exec nginx-proxy nginx -t >/dev/null 2>&1; then
        log_success "Nginx configuration is valid"
        return 0
    else
        log_error "Nginx configuration has errors"
        docker exec nginx-proxy nginx -t 2>&1 || true
        return 1
    fi
}

# Check SSL certificate status
check_ssl_cert() {
    log_info "Checking SSL certificate..."
    
    local ssl_dir="./ssl"
    if [[ ! -f "$ssl_dir/server.crt" ]] || [[ ! -f "$ssl_dir/server.key" ]]; then
        log_error "SSL certificate files not found"
        return 1
    fi
    
    # Check certificate validity
    if openssl x509 -checkend 86400 -noout -in "$ssl_dir/server.crt" >/dev/null 2>&1; then
        log_success "SSL certificate is valid"
        
        # Show certificate details
        local issuer=$(openssl x509 -issuer -noout -in "$ssl_dir/server.crt" | sed 's/issuer=//')
        local subject=$(openssl x509 -subject -noout -in "$ssl_dir/server.crt" | sed 's/subject=//')
        local expiry=$(openssl x509 -enddate -noout -in "$ssl_dir/server.crt" | sed 's/notAfter=//')
        
        log_info "Certificate details:"
        echo "  Subject: $subject"
        echo "  Issuer: $issuer"
        echo "  Expires: $expiry"
        
        # Check certificate type
        if [[ -f "$ssl_dir/cert_type" ]]; then
            local cert_type=$(cat "$ssl_dir/cert_type")
            log_info "Certificate type: $cert_type"
        fi
        
        return 0
    else
        log_error "SSL certificate is invalid or expires within 24 hours"
        return 1
    fi
}

# Test service endpoints
test_endpoints() {
    log_info "Testing service endpoints..."
    
    local http_success=true
    local https_success=true
    
    # Test HTTP health endpoint
    if ! test_endpoint "http://localhost/health" "HTTP health endpoint"; then
        http_success=false
    fi
    
    # Test HTTPS health endpoint (allow self-signed)
    if ! test_endpoint "https://localhost/health" "HTTPS health endpoint" "true"; then
        https_success=false
    fi
    
    # Test domain endpoint if accessible
    if command -v dig >/dev/null 2>&1 && dig +short "$DOMAIN_NAME" >/dev/null 2>&1; then
        log_info "Testing domain endpoints..."
        test_endpoint "https://$DOMAIN_NAME/health" "Domain HTTPS endpoint" "true" || true
    fi
    
    if [[ "$http_success" == "true" && "$https_success" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

# Check proxy backend connectivity
check_backends() {
    log_info "Checking backend service connectivity..."
    
    # Define expected backend services based on nginx config
    local backends=(
        "fks_api:8000"
        "fks_web:3000"
        "ats-server:8080"
    )
    
    local backend_success=true
    
    for backend in "${backends[@]}"; do
        local host="${backend%:*}"
        local port="${backend#*:}"
        
        if timeout 5 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
            log_success "Backend $backend is reachable"
        else
            log_warn "Backend $backend is not reachable (this may be expected)"
        fi
    done
    
    return 0  # Don't fail on backend connectivity issues
}

# Main health check function
main() {
    local command="${1:-full}"
    local exit_code=0
    
    echo "🏥 Nginx Health Check - $(date)"
    echo "Domain: $DOMAIN_NAME"
    echo
    
    case "$command" in
        container)
            check_container || exit_code=1
            ;;
        config)
            check_config || exit_code=1
            ;;
        ssl)
            check_ssl_cert || exit_code=1
            ;;
        endpoints)
            test_endpoints || exit_code=1
            ;;
        backends)
            check_backends || exit_code=1
            ;;
        full)
            check_container || exit_code=1
            check_config || exit_code=1
            check_ssl_cert || exit_code=1
            test_endpoints || exit_code=1
            check_backends || exit_code=1
            ;;
        help|--help|-h)
            cat << EOF
Nginx Health Check Script

Usage: $0 [COMMAND]

Commands:
    container   Check if nginx container is running
    config      Check nginx configuration validity
    ssl         Check SSL certificate status
    endpoints   Test HTTP/HTTPS endpoints
    backends    Check backend service connectivity
    full        Run all checks (default)
    help        Show this help message

Environment Variables:
    DOMAIN_NAME              Domain name to test (default: nginx.7gram.xyz)
    HEALTH_CHECK_TIMEOUT     Timeout for HTTP requests (default: 10)
    MAX_RETRIES             Number of retry attempts (default: 3)

Examples:
    $0                      # Run full health check
    $0 ssl                  # Check only SSL certificate
    $0 endpoints            # Test only endpoints
EOF
            exit 0
            ;;
        *)
            log_error "Unknown command: $command"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
    
    echo
    if [[ $exit_code -eq 0 ]]; then
        log_success "Health check completed successfully"
    else
        log_error "Health check completed with failures"
    fi
    
    exit $exit_code
}

# Execute main function
main "$@"
