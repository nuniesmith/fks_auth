#!/bin/bash
# scripts/health-monitor.sh - Continuous health monitoring during deployment

set -euo pipefail

# Configuration
BASE_URL="${1:-https://7gram.xyz}"
DURATION="${2:-300}" # 5 minutes default
INTERVAL="${3:-5}"   # 5 seconds default
WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"

# Monitoring data
declare -A health_stats
health_stats[success]=0
health_stats[failure]=0
health_stats[total]=0

# Start monitoring
echo "🏥 Starting health monitoring for $BASE_URL"
echo "Duration: ${DURATION}s, Interval: ${INTERVAL}s"
echo "================================================"

start_time=$(date +%s)
end_time=$((start_time + DURATION))

while [ $(date +%s) -lt $end_time ]; do
    current_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Perform health check
    response_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$BASE_URL/health" || echo "000")
    response_time=$(curl -s -o /dev/null -w "%{time_total}" --max-time 10 "$BASE_URL/health" || echo "0")
    
    ((health_stats[total]++))
    
    if [ "$response_code" = "200" ]; then
        ((health_stats[success]++))
        echo "[$current_time] ✅ Health check passed (${response_time}s)"
    else
        ((health_stats[failure]++))
        echo "[$current_time] ❌ Health check failed (HTTP $response_code)"
        
        # Send alert if webhook configured
        if [ -n "$WEBHOOK_URL" ] && [ $((health_stats[failure] % 3)) -eq 0 ]; then
            curl -s -H "Content-Type: application/json" \
                -d "{\"content\":\"⚠️ Health check failures on $BASE_URL: ${health_stats[failure]} failures in ${health_stats[total]} checks\"}" \
                "$WEBHOOK_URL" || true
        fi
    fi
    
    # Calculate success rate
    success_rate=$(echo "scale=2; ${health_stats[success]} * 100 / ${health_stats[total]}" | bc)
    
    # Break if success rate drops below 50%
    if [ "${health_stats[total]}" -gt 10 ] && (( $(echo "$success_rate < 50" | bc -l) )); then
        echo "❌ Success rate dropped below 50% ($success_rate%), aborting!"
        exit 1
    fi
    
    sleep $INTERVAL
done

# Final report
echo ""
echo "================================================"
echo "Health Monitoring Summary:"
echo "  Total checks: ${health_stats[total]}"
echo "  Successful:   ${health_stats[success]}"
echo "  Failed:       ${health_stats[failure]}"
echo "  Success rate: $success_rate%"
echo ""

if (( $(echo "$success_rate >= 95" | bc -l) )); then
    echo "✅ Health monitoring passed!"
    exit 0
else
    echo "❌ Health monitoring failed (success rate: $success_rate%)"
    exit 1
fi