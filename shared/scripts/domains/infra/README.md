# Infra Domain

Covers DNS, tailscale, server provisioning, cloud provider helpers.

## Subareas

```text
dns/
servers/
network/
```

## Principles

- Idempotent: running twice shouldn't break.
- External calls guarded with confirmation flags.
