#!/bin/bash
# Relocated exchange node management script.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_PROJECT_NAME="fks"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.exchange-nodes.yml"
cd "$PROJECT_ROOT"

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
print_info(){ echo -e "${BLUE}[INFO]${NC} $1"; }
print_success(){ echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error(){ echo -e "${RED}[ERROR]${NC} $1"; }

check_prereq(){
  if ! command -v docker >/dev/null 2>&1; then print_error "Docker missing"; exit 1; fi
  if docker compose version >/dev/null 2>&1; then COMPOSE_CMD="docker compose"; elif command -v docker-compose >/dev/null 2>&1; then COMPOSE_CMD="docker-compose"; else print_error "Compose missing"; exit 1; fi
}

start_all(){ print_info "Starting all exchange nodes"; $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" $COMPOSE_FILES up -d; print_success "Started"; }
stop_all(){ print_info "Stopping exchange nodes"; $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" $COMPOSE_FILES down; print_success "Stopped"; }
status(){ print_info "Node status"; $COMPOSE_CMD -p "$COMPOSE_PROJECT_NAME" $COMPOSE_FILES ps || true; }

case ${1:-} in
  start) check_prereq; start_all;;
  stop) check_prereq; stop_all;;
  status|"" ) check_prereq; status;;
  *) echo "Usage: $0 [start|stop|status]"; exit 1;;
esac
