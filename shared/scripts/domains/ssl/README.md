# SSL Domain

Manages certificate issuance (Let's Encrypt / self-signed), renewal, installation and systemd integration.

## Components

```text
manager.sh         # High-level operations dispatch
issue.sh           # Obtain/renew certs
systemd-install.sh # Install/enable systemd timer/service
renew.sh           # Forced/manual renewal
```

## Notes

- Use staging ACME for tests.
- Avoid embedding secrets; rely on env vars.
