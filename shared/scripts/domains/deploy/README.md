# Deploy Domain

Purpose: Owns deployment pipeline orchestration (Docker Compose, staged, multi-server, SSL-aware workflows).

## Responsibilities

- Normalize stage scripts (stage-0, stage-1, etc.)
- Environment preparation (.env management, secrets validation)
- Strategy selection (single-server, multi-server, gpu)
- Rollback helpers
- Integration with infra (DNS, tailscale) via `../infra` modules

## Non-Goals

- Direct SSL issuance (see `../ssl`)
- Container build logic (see `../docker`)

## Directory Layout (Target)

```text
deploy/
  pipeline/
    stage-0-create.sh        # Provision base server / prerequisites
    stage-1-prepare.sh       # Install dependencies, configure runtime
    stage-2-finalize.sh      # Start services + post validation
    deploy.sh                # High-level composition (idempotent)
  strategies/
    single.sh                # All services on one host
    multi.sh                 # Split roles across nodes
    gpu.sh                   # Adds GPU preparation hooks
  env/
    init.sh                  # Generate or patch .env variants
    validate.sh              # Ensure required vars are present
  rollback/
    rollback.sh              # Generic rollback dispatcher
```

## Function Naming

| Pattern | Purpose |
|---------|---------|
| `deploy_stage_<n>()` | Individual pipeline stage units |
| `deploy_strategy_<name>()` | Strategy implementations |
| `deploy_env_*()` | Environment file helpers |
| `deploy_rollback_*()` | Rollback primitives |

All public functions should return (not exit) and use `die` only at the CLI entrypoint layer.

## Script Skeleton

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "$ROOT/lib/log.sh"
source "$ROOT/lib/error.sh"
source "$ROOT/lib/env.sh"

deploy_stage_1() { log_info "Stage 1 placeholder"; }

main() {
  deploy_stage_1
  log_success "Deploy completed"
}
main "$@"
```

## Conventions

- Entrypoints: shebang + strict mode (`set -euo pipefail`)
- Always source libs with absolute paths derived from `ROOT`
- No mutable globals without `deploy_` prefix
- Stages idempotent: safe to re-run

## Migration Notes

Map legacy paths like `deployment/staged/stage-1-initial-setup.sh` -> `pipeline/stage-1-prepare.sh` (keep git history via `git mv`). Add a temporary stub at the old location for one release cycle.

