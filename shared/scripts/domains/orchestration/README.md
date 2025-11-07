# Orchestration Domain

Controls runtime lifecycle: start, stop, restart, status, health checks.

## Planned Files

```text
run.sh
start.sh
stop.sh
restart.sh
status.sh
health-check.sh
```

## Guidelines

- Stateless wrappers; business state handled by services.
- Use `orchestrate_` prefix for functions.
