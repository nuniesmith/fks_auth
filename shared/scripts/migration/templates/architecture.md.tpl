# Architecture

## Overview
Brief description of the service/library purpose.

## Responsibilities
- Core responsibility 1
- Core responsibility 2

## Dependencies
- Internal: {{INTERNAL_DEPS}}
- External Services: (list URLs / protocols)
- Shared Components: {{SHARED_MODULES}}

## Runtime Diagram
```
(Service) ---> (Dependency)
```

## Data Flows
Describe key inputs/outputs. Reference schema versions.

## Configuration
| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| EXAMPLE_VAR | Example | none | yes |

## Observability
- Logging: structure / levels
- Metrics: list counters, histograms
- Healthchecks: /health, /version

## Security
- AuthN/AuthZ approach
- Secrets required

## Failure Modes & Mitigations
| Scenario | Impact | Mitigation |
|----------|--------|------------|
| Example  | Medium | Retry/backoff |

## Local Development
```
make deps
make verify
```

## Release & Versioning
- Semantic versioning
- Schema compatibility check automated via schema_assert.py

