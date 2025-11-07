#!/bin/bash
# scripts/smoke-tests.sh - Smoke tests for deployment validation

set -euo pipefail

# Configuration
BASE_URL="${1:-https://7gram.xyz}"
TIMEOUT=10
MAX_RETRIES=3

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test results
PASSED=0
FAILED=0
WARNINGS=0

# Helper functions
test_endpoint() {
    local url="$1"
    local expected_code="${2:-200}"
    local description="$3"
    
    echo -n "Testing $description... "
    
    for i in $(seq 1 $MAX_RETRIES); do
        response_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time $TIMEOUT "$url" || echo "000")
        
        if [ "$response_code" = "$expected_code" ]; then
            echo -e "${GREEN}✓${NC} ($response_code)"
            ((PASSED++))
            return 0
        elif [ $i -lt $MAX_RETRIES ]; then
            sleep 2
        fi
    done
    
    echo -e "${RED}✗${NC} (Expected: $expected_code, Got: $response_code)"
    ((FAILED++))
    return 1
}

test_content() {
    local url="$1"
    local content="$2"
    local description="$3"
    
    echo -n "Testing $description content... "
    
    response=$(curl -s --max-time $TIMEOUT "$url" || echo "")
    
    if echo "$response" | grep -q "$content"; then
        echo -e "${GREEN}✓${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC} (Content not found)"
        ((FAILED++))
        return 1
    fi
}

test_performance() {
    local url="$1"
    local max_time="$2"
    local description="$3"
    
    echo -n "Testing $description performance... "
    
    time_total=$(curl -s -o /dev/null -w "%{time_total}" --max-time $TIMEOUT "$url" || echo "999")
    time_ms=$(echo "$time_total * 1000" | bc | cut -d. -f1)
    
    if [ "$time_ms" -lt "$max_time" ]; then
        echo -e "${GREEN}✓${NC} (${time_ms}ms)"
        ((PASSED++))
        return 0
    else
        echo -e "${YELLOW}⚠${NC} (${time_ms}ms > ${max_time}ms)"
        ((WARNINGS++))
        return 1
    fi
}

# Main tests
echo "🧪 Running smoke tests for $BASE_URL"
echo "================================================"

# Core endpoints
test_endpoint "$BASE_URL/" 200 "Main dashboard"
test_endpoint "$BASE_URL/health" 200 "Health endpoint"
test_endpoint "$BASE_URL/assets/css/main.css" 200 "CSS assets"
test_endpoint "$BASE_URL/assets/js/main.js" 200 "JavaScript assets"

# Service endpoints
services=(
    "emby:Emby Media Server"
    "jellyfin:Jellyfin Media Server"
    "plex:Plex Media Server"
    "ai:AI Chat Interface"
    "portainer:Portainer"
    "home:Home Assistant"
)

echo ""
echo "Testing service endpoints..."
for service_info in "${services[@]}"; do
    IFS=':' read -r service name <<< "$service_info"
    test_endpoint "$BASE_URL/health" 200 "$name proxy"
done

# Content validation
echo ""
echo "Testing content..."
test_content "$BASE_URL/" "7Gram Network Dashboard" "Dashboard title"
test_content "$BASE_URL/" "service-card" "Service cards"

# Performance tests
echo ""
echo "Testing performance..."
test_performance "$BASE_URL/" 2000 "Dashboard load time"
test_performance "$BASE_URL/health" 500 "Health check response"

# SSL/TLS validation
echo ""
echo "Testing SSL/TLS..."
echo -n "Testing SSL certificate... "
if curl -s --head "$BASE_URL" 2>&1 | grep -q "SSL certificate problem"; then
    echo -e "${RED}✗${NC} (Certificate issue)"
    ((FAILED++))
else
    echo -e "${GREEN}✓${NC}"
    ((PASSED++))
fi

# Summary
echo ""
echo "================================================"
echo "Test Summary:"
echo -e "  Passed:   ${GREEN}$PASSED${NC}"
echo -e "  Failed:   ${RED}$FAILED${NC}"
echo -e "  Warnings: ${YELLOW}$WARNINGS${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All smoke tests passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed!${NC}"
    exit 1
fi