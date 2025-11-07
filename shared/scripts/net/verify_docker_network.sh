#!/usr/bin/env bash
set -euo pipefail

# verify_docker_network.sh
# Verifies health & configuration of docker network(s) used by the stack.
# Focus network: fks_network (default in docker-compose.yml)
# Outputs diagnostics & exits non-zero on hard failures.

TARGET_NETWORK=${1:-fks_network}
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BOLD="\033[1m"; NC="\033[0m"
INFO(){ echo -e "${BOLD}==>${NC} $*"; }
PASS(){ echo -e "${GREEN}✔${NC} $*"; }
FAIL(){ echo -e "${RED}✖${NC} $*"; }
WARN(){ echo -e "${YELLOW}!${NC} $*"; }

FAILURES=0

INFO "Checking Docker availability..."
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  FAIL "Docker not available"
  exit 1
fi
PASS "Docker daemon reachable"

INFO "Inspecting target network: $TARGET_NETWORK"
if ! docker network inspect "$TARGET_NETWORK" >/dev/null 2>&1; then
  FAIL "Network $TARGET_NETWORK not found"
  exit 1
fi
PASS "Network exists"

SUBNET=$(docker network inspect "$TARGET_NETWORK" -f '{{ (index .IPAM.Config 0).Subnet }}')
GATEWAY=$(docker network inspect "$TARGET_NETWORK" -f '{{ (index .IPAM.Config 0).Gateway }}')
INFO "Subnet: $SUBNET | Gateway: $GATEWAY"

# List containers connected
CONTAINERS=$(docker network inspect "$TARGET_NETWORK" -f '{{ range $k,$v := .Containers }}{{$v.Name}} {{end}}')
if [[ -z "$CONTAINERS" ]]; then
  WARN "No containers attached to $TARGET_NETWORK"
else
  INFO "Attached containers: $CONTAINERS"
fi

# Basic connectivity test: pick two running containers with curl & ping installed (heuristic: api & web)
PRIMARY_CANDIDATES=( api web data worker nginx )
FOUND=()
for name in "${PRIMARY_CANDIDATES[@]}"; do
  if docker ps --format '{{.Names}}' | grep -q "${name}"; then
    # accept any match containing the name (compose prefix agnostic)
    docker ps --format '{{.Names}}' | grep "${name}" | head -n1 | while read -r cname; do FOUND+=("$cname"); done
  fi
  [[ ${#FOUND[@]} -ge 2 ]] && break
done

if [[ ${#FOUND[@]} -lt 2 ]]; then
  # Fallback: pick any two containers on network
  INFO "Falling back to ANY two containers on network $TARGET_NETWORK"
  mapfile -t NET_CONTAINERS < <(docker network inspect "$TARGET_NETWORK" -f '{{ range $k,$v := .Containers }}{{$v.Name}} {{end}}') || true
  for c in "${NET_CONTAINERS[@]}"; do
    [[ -n "$c" ]] && FOUND+=("$c")
    [[ ${#FOUND[@]} -ge 2 ]] && break
  done
fi

if [[ ${#FOUND[@]} -ge 2 ]]; then
  A=${FOUND[0]}
  B=${FOUND[1]}
  INFO "Testing intra-network DNS & HTTP: $A -> $B"
  if docker exec "$A" /bin/sh -c "command -v curl >/dev/null 2>&1 && (curl -fsS http://$B:3000/ >/dev/null 2>&1 || curl -fsS http://$B:8000/ >/dev/null 2>&1)"; then
    PASS "Intra-network HTTP reachability OK ($A -> $B)"
  else
    WARN "HTTP probe failed; attempting ping as fallback"
    if docker exec "$A" /bin/sh -c "ping -c1 -W1 $B >/dev/null 2>&1"; then
      PASS "Basic ICMP reachability OK ($A -> $B)"
    else
      FAIL "Intra-network reachability failed ($A -> $B)"
      FAILURES=1
    fi
  fi
else
  WARN "Could not find two containers to test connectivity"
fi

# Check for duplicate IPs (should be unique)
DUP_IPS=$(docker network inspect "$TARGET_NETWORK" -f '{{range $k,$v := .Containers}}{{$v.IPv4Address}} {{end}}' | awk -F/ '{print $1}' | sort | uniq -d || true)
if [[ -n "$DUP_IPS" ]]; then
  FAIL "Duplicate IP addresses detected: $DUP_IPS"
  FAILURES=1
else
  PASS "No duplicate IPs"
fi

# Detect host firewall rules possibly dropping bridge traffic (nftables presence heuristic)
if command -v nft >/dev/null 2>&1; then
  INFO "Scanning nftables for drop rules referencing docker bridge..."
  BRIDGE_IF=$(ip link | awk -F: '/docker0/ {print $2; exit}' | xargs || true)
  if [[ -n "$BRIDGE_IF" ]]; then
    if nft list ruleset 2>/dev/null | grep -i "$BRIDGE_IF" | grep -qi drop; then
      WARN "Potential drop rule referencing $BRIDGE_IF detected (review nft ruleset)"
    else
      PASS "No explicit drop rules referencing $BRIDGE_IF"
    fi
  else
    WARN "docker0 bridge interface not found (rootless or custom network driver?)"
  fi
fi

if [[ $FAILURES -ne 0 ]]; then
  echo -e "\n${RED}Network verification encountered failures.${NC}" >&2
  exit 1
fi

echo -e "\n${GREEN}Network verification passed.${NC}"
