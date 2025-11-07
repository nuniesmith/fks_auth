#!/bin/bash
# scripts/performance-baseline.sh - Establish performance baselines

set -euo pipefail

# Configuration
BASE_URL="${1:-https://7gram.xyz}"
OUTPUT_FILE="${2:-performance-baseline.json}"

# Test endpoints
declare -A endpoints=(
    ["dashboard"]="/"
    ["health"]="/health"
    ["css"]="/assets/css/main.css"
    ["js"]="/assets/js/main.js"
)

# Run performance tests
echo "📊 Establishing performance baselines for $BASE_URL"
echo "================================================"

results="{"

for name in "${!endpoints[@]}"; do
    url="$BASE_URL${endpoints[$name]}"
    echo -n "Testing $name... "
    
    # Perform multiple requests to get average
    total_time=0
    total_size=0
    success_count=0
    
    for i in {1..10}; do
        metrics=$(curl -s -o /dev/null -w '{"time_total":%{time_total},"size_download":%{size_download},"http_code":%{http_code}}' "$url" || echo '{"time_total":0,"size_download":0,"http_code":0}')
        
        time_total=$(echo "$metrics" | jq -r '.time_total')
        size_download=$(echo "$metrics" | jq -r '.size_download')
        http_code=$(echo "$metrics" | jq -r '.http_code')
        
        if [ "$http_code" = "200" ]; then
            total_time=$(echo "$total_time + $time_total" | bc)
            total_size=$(echo "$total_size + $size_download" | bc)
            ((success_count++))
        fi
        
        sleep 0.5
    done
    
    if [ $success_count -gt 0 ]; then
        avg_time=$(echo "scale=3; $total_time / $success_count" | bc)
        avg_size=$(echo "scale=0; $total_size / $success_count" | bc)
        echo "✓ (avg: ${avg_time}s, ${avg_size} bytes)"
        
        results+='"'$name'":{"avg_response_time":'$avg_time',"avg_size":'$avg_size',"success_rate":'$success_count'0},'
    else
        echo "✗ (all requests failed)"
        results+='"'$name'":{"avg_response_time":0,"avg_size":0,"success_rate":0},'
    fi
done

# Add timestamp
results+='"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}'

# Save results
echo "$results" | jq '.' > "$OUTPUT_FILE"

echo ""
echo "✅ Performance baseline saved to: $OUTPUT_FILE"
echo ""
echo "Summary:"
jq -r 'to_entries | map(select(.key != "timestamp")) | .[] | "\(.key): \(.value.avg_response_time)s (\(.value.avg_size) bytes)"' "$OUTPUT_FILE"