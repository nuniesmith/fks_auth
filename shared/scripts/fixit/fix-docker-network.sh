#!/usr/bin/env bash
# (Relocated) Fix Docker networking issues - requires sudo
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log(){ local lvl=$1; shift; local msg=$*; case $lvl in INFO) echo -e "${GREEN}[INFO]${NC} $msg";; WARN) echo -e "${YELLOW}[WARN]${NC} $msg";; ERROR) echo -e "${RED}[ERROR]${NC} $msg";; esac; }

if [[ $EUID -ne 0 ]]; then log ERROR "Must run as root (sudo)"; exit 1; fi
log INFO "🔧 Fixing Docker networking issues..."
systemctl stop docker || true
docker stop $(docker ps -aq) 2>/dev/null || true
docker network prune -f >/dev/null 2>&1 || true
log INFO "Cleaning iptables rules"
for tbl in nat filter; do
  for chain in DOCKER DOCKER-FORWARD DOCKER-ISOLATION-STAGE-1 DOCKER-ISOLATION-STAGE-2 DOCKER-USER; do
    iptables -t $tbl -F $chain 2>/dev/null || true
    iptables -t $tbl -X $chain 2>/dev/null || true
  done
done
rm -rf /var/lib/docker/network/files/* 2>/dev/null || true
systemctl restart docker
log INFO "Waiting for docker..."
for i in {1..30}; do docker info >/dev/null 2>&1 && { log INFO "✅ Docker ready"; break; } || sleep 1; done
docker info >/dev/null 2>&1 || { log ERROR "Docker failed to start"; exit 1; }
if docker network create --driver bridge test-network-$$ >/dev/null 2>&1; then docker network rm test-network-$$ >/dev/null 2>&1; log INFO "✅ Networking fixed"; else log ERROR "Still broken"; exit 1; fi