#!/usr/bin/env bash
set -euo pipefail

# validate_env.sh
# Preflight validation for required tooling, environment variables, and resource quotas
# prior to provisioning or deployment steps. Fail fast with actionable messages.

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BOLD="\033[1m"; NC="\033[0m"
INFO(){ echo -e "${BOLD}==>${NC} $*"; }
PASS(){ echo -e "${GREEN}✔${NC} $*"; }
FAIL(){ echo -e "${RED}✖${NC} $*"; }
WARN(){ echo -e "${YELLOW}!${NC} $*"; }

MISSING=0

REQUIRED_CMDS=( git docker jq awk sed grep curl ssh )
INFO "Checking required CLI tools..."
for c in "${REQUIRED_CMDS[@]}"; do
  if ! command -v "$c" >/dev/null 2>&1; then
    FAIL "Missing command: $c"
    MISSING=1
  else
    PASS "$c present ($(command -v $c))"
  fi
done

# Optional but recommended
OPTIONAL_CMDS=( shellcheck node npm python3 )
INFO "Checking optional (recommended) CLI tools..."
for c in "${OPTIONAL_CMDS[@]}"; do
  if ! command -v "$c" >/dev/null 2>&1; then
    WARN "Optional tool missing: $c"
  else
    PASS "$c present"
  fi
done

# Secrets / env vars expected (extend as needed)
REQUIRED_ENV=( LINODE_TOKEN DOCKER_TOKEN DOCKER_USERNAME )
INFO "Validating required environment variables..."
for v in "${REQUIRED_ENV[@]}"; do
  val="${!v:-}"
  if [[ -z "$val" ]]; then
    FAIL "Env var not set: $v"
    MISSING=1
  elif [[ "$val" == "placeholder" ]]; then
    WARN "$v set to placeholder (real secret not available in this context)"
  else
    PASS "$v present (length ${#val})"
  fi
done

# Network / outbound check (lightweight)
INFO "Testing outbound network (HTTPS to api.github.com)..."
if curl -fsS --max-time 5 https://api.github.com/rate_limit >/dev/null; then
  PASS "Outbound network OK"
else
  FAIL "Outbound HTTPS failed"
  MISSING=1
fi

# Docker daemon health
INFO "Checking Docker daemon..."
if docker info >/dev/null 2>&1; then
  PASS "Docker daemon reachable"
else
  FAIL "Docker daemon not reachable (is the service running?)"
  MISSING=1
fi

# Disk space check (root + docker data dir if default)
INFO "Checking disk space (need > 5G free) ..."
ROOT_FREE_GB=$(df -PB1G / | awk 'NR==2 {print $4}')
if [[ ${ROOT_FREE_GB:-0} -lt 5 ]]; then
  FAIL "Low root disk space: ${ROOT_FREE_GB}G (<5G)"
  MISSING=1
else
  PASS "Root disk space: ${ROOT_FREE_GB}G"
fi

# If linode-cli installed, optionally verify account (non-fatal if absent)
if command -v linode-cli >/dev/null 2>&1; then
  INFO "Checking Linode CLI authentication..."
  if linode-cli account view >/dev/null 2>&1; then
    PASS "Linode CLI authenticated"
  else
    WARN "Linode CLI not authenticated"
  fi
fi

if [[ $MISSING -ne 0 ]]; then
  echo -e "\n${RED}Preflight validation failed. Resolve issues above and retry.${NC}" >&2
  exit 1
fi

echo -e "\n${GREEN}Preflight validation passed.${NC}"
