#!/bin/bash
# Monitor FKS Trading Systems services

clear
echo "📊 FKS Trading Systems Monitor"
echo "============================="
echo "Time: $(date)"

# Service health
echo -e "\n🏥 Service Health:"
docker-compose ps --format "table {{.Service}}\t{{.Status}}\t{{.Ports}}"

# Resource usage
echo -e "\n💻 Resource Usage:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Recent logs from any unhealthy services
UNHEALTHY=$(docker-compose ps --format json | jq -r 'select(.Health != "healthy" and .Health != null) | .Service' 2>/dev/null)
if [ -n "$UNHEALTHY" ]; then
    echo -e "\n⚠️  Unhealthy Services:"
    for service in $UNHEALTHY; do
        echo -e "\n--- $service logs (last 10 lines) ---"
        docker-compose logs --tail=10 $service 2>&1
    done
fi

# Disk usage
echo -e "\n💾 Disk Usage:"
df -h | grep -E "^/dev|Filesystem"

# GPU status (if available)
if command -v nvidia-smi &> /dev/null; then
    echo -e "\n🎮 GPU Status:"
    nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu,temperature.gpu --format=csv
fi

# Docker system info
echo -e "\n🐳 Docker System:"
docker system df
