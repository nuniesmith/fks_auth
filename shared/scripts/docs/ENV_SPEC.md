# Environment Variable Specification (Draft)

This spec defines a portable baseline set of environment variables for orchestrating multi-language (Python / Rust / Node / Shell) services using the shared_* assets. Consumers should treat all variables as OPTIONAL unless marked Required.

| Name | Required | Default | Purpose |
|------|----------|---------|---------|
| PROJECT_NS | No | fks | Logical project namespace used for tagging images, network names, volumes, logs. |
| SERVICE_FAMILY | No | trading | High-level grouping (e.g. trading, analytics, web). |
| SERVICE_NAME | Contextual | (derived) | Specific service id when executing service-scoped scripts. |
| STAGE | No | dev | Deployment stage: dev\|staging\|prod\|test. |
| IMAGE_TAG | No | latest or git sha | Tag used when building/publishing container images. |
| REGISTRY | No | (unset) | OCI registry base (e.g. ghcr.io/org). |
| CONFIG_PATH | No | ./config | Override path for configuration directory. |
| LOG_LEVEL | No | INFO | Logging verbosity (DEBUG\|INFO\|WARN\|ERROR). |
| LOG_FORMAT | No | plain | plain or json structured logs for shell tooling. |
| FKS_MODE | Deprecated | development | Backward compatibility; prefer STAGE. |
| OVERRIDE_ROOT | No | (auto-detect) | Force project root resolution for scripts. |
| ENABLE_METRICS | No | false | Toggle metrics exporters (language-specific adapters). |
| ENABLE_TRACING | No | false | Toggle tracing instrumentation. |
| PY_ENV | No | system | python environment selector (system\|venv\|conda). |
| RUST_LOG | No | info | Standard Rust logging override (maps to env_logger). |
| NODE_ENV | No | development | Node/React build/runtime environment. |
| DOCKER_BUILDKIT | Recommended | 1 | Enable modern Docker build features. |
| COMPOSE_PROFILES | Contextual | (unset) | Compose profile activation for partial stacks. |

## Discovery & Defaults

Scripts attempt to auto-detect PROJECT_ROOT by traversing upward for a `config` and `scripts` directory or `.project-root` sentinel file. You can explicitly set `OVERRIDE_ROOT` to bypass discovery.

## Namespacing Rules

- Container names should be formatted: `${PROJECT_NS}-${SERVICE_NAME}`
- Networks: `${PROJECT_NS}_internal`
- Volumes: `${PROJECT_NS}_${SERVICE_NAME}_data`

## Backward Compatibility

Legacy variables (FKS_MODE) are mapped to new canonical ones during the transition window. A deprecation warning may be emitted after v0.4.0.

## Extensibility

Projects may define additional vars under the prefix `${PROJECT_NS^^}_` to avoid collision (e.g. FKS_CUSTOM_FLAG). Such vars should be documented in a project-local extension file: `docs/ENV_SPEC_EXT.md`.

## Validation

A future `bin/env-verify` command will:

1. Load `.env` (if present)
2. Validate required set per execution context (build, run, deploy)
3. Emit JSON summary when `LOG_FORMAT=json`

---
Generated: 2025-08-31
