# FKS Monorepo → Microrepos Migration

This directory contains automation and documentation for executing the repo split.

## Files

- `run-extraction.sh` – History-preserving extraction + scaffolding.
- `verify-split.sh` – Rich verification (build/test/schema/submodules/security/LOC) with parallel mode.
- `dry-run-extraction.sh` – Safe preview of a single target extraction.
- `full-migration-pipeline.sh` – One-shot extraction → verification → (optional) push.
- `post-cutover-checklist.md` – Manual validation steps after switching pipelines.
- `project-tracking-template.md` – Kanban/project board structure.

See `../extraction-map.yml` for path and submodule mapping.

## Quick Start

```bash
# Dry run single service
./migration/dry-run-extraction.sh . /tmp/fks_dry fks_api

# Extract all (exclude shared) into /tmp/extracted
./migration/run-extraction.sh --skip-shared . /tmp/extracted yourorg

# Verify with 4-way parallelism and size threshold
./migration/verify-split.sh /tmp/extracted --parallel 4 --max-files 1200 --table

# Full pipeline limited to api & engine and push
./migration/full-migration-pipeline.sh --mono . --out /tmp/pipeline --org yourorg \
	--only fks_api,fks_engine --parallel 4 --push
```

## Exit Codes (verify-split.sh)

- 0: All OK / warnings only
- 2: Failure detected (with --fail-on-fail)

## Optional Tools Needed

- `git-filter-repo`, `jq`, `cloc` (for LOC), language toolchains (cargo, python, node)
