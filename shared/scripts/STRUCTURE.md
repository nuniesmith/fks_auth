# FKS Shared Scripts Structure (v1)

This document defines the canonical layout + conventions for the reorganized script system.

## High-Level Layout

```text
bin/                # End-user & CI entrypoints (thin wrappers only)
lib/                # Reusable sourced modules (no side effects)
domains/            # Business / operational domains
  deploy/
  orchestration/
  ssl/
  infra/
  docker/
  migration/
  maintenance/
  gpu/
  ninja/
  k8s/
  dns/              # Domain & DNS management (placeholder)
qa/                 # Quality layers (tests + smoke)
devtools/           # Meta tooling (catalog, generators)
  analysis/         # Analysis outputs (inventory, summaries)
  sbom/             # SBOM and checksum manifests
fixit/              # Quarantined one-off remediation scripts
archive/            # Deprecated awaiting removal
shims (root)        # Transitional wrappers calling new domain paths
```

## Principles

1. Deterministic sourcing: libs never emit output unless LOG_LEVEL=DEBUG.
2. Absolute path resolution: derive `ROOT` from the executing script for safety.
3. Idempotency: rerunning deploy stages or env init should not corrupt state.
4. Namespacing: functions exported by a domain are prefixed (`deploy_`, `ssl_`, `orchestrate_`).
5. Clear exit boundaries: only `bin/` scripts call `exit`; lower layers return codes (temporary root shims exit after exec).
6. Single logging system: `lib/log.sh` only; no ad-hoc echoes in domains (except user-facing final summaries).

## Library Modules (Initial Set)

| File             | Responsibility | Key Exports |
|------------------|---------------|-------------|
| `lib/log.sh`     | Logging       | `log_info`, `log_warn`, `log_error`, `log_debug`, `log_success` |
| `lib/env.sh`     | Mode/env load | `detect_mode`, `load_dotenv`, `require_cmd` |
| `lib/validate.sh`| Validation    | `assert_file`, `assert_dir`, `assert_cmd`, `assert_port_free` |
| `lib/error.sh`   | Error control | `die`, `with_temp_dir` |
| domains/ssl/manager.sh | SSL lifecycle (TODO restore) | (planned: ssl_issue, ssl_renew) |
| domains/ssl/systemd-install.sh | Install systemd units (TODO restore) | (planned: none) |

Add new modules with focused scope; avoid god-modules.

## Domain Conventions

Each domain `README.md` MUST include:

* Purpose
* Responsibilities / Non-goals
* Layout
* Naming conventions
* Migration notes (if transitional)

## Adding a New Command

1. Implement logic in an appropriate domain file exporting `feature_do_xyz`.
2. Create `bin/fks_xyz`:

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/lib/log.sh"
source "$ROOT/domains/feature/xyz.sh"  # example
feature_do_xyz "$@"
```

1. (Optional) Add alias dispatch inside `bin/fks` main multiplexer.

## Deprecation Policy

1. Move with `git mv` to retain history.
2. Leave a stub at the old path for one release cycle:

```bash
#!/usr/bin/env bash
echo "[DEPRECATED] Use bin/fks deploy instead" >&2
exec "$(dirname "$0")/../bin/fks" deploy "$@"
```

1. Remove stubs after release tag.

## Catalog Generation

Run:

```bash
bin/fks catalog
```
Outputs: `devtools/scripts-meta/catalog.md` (scans for `# Purpose:` lines).

## Testing & Linting (Planned)

Add a CI job:

```bash
shellcheck $(git ls-files '*.sh')
```
Future: Bats tests under `qa/tests/` for libs + smoke tests gated (optional) by env var.

## Roadmap

* [ ] Migrate legacy `deployment/` into `domains/deploy/`
* [ ] Centralize SSL logic
* [ ] Introduce `bin/fks_env` for env management
* [ ] Add Bats harness
* [ ] Enforce formatting via pre-commit

---
Generated on: $(date -u +'%Y-%m-%dT%H:%M:%SZ')
