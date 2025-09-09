# FKS Auth (Dev Rust Service)

Lightweight Axum-based auth stub for development. Provides a single hardcoded dev user.

## Endpoints

- `GET /health` -> `ok`
- `POST /login` {"username":"jordan","password":"567326"} -> token
- `POST /refresh` {"refresh_token": "..."}
- `GET /me` (requires Bearer access token)

## Quick Start (Host)

```bash
cargo run --release
```

## Quick Start (Docker)

```bash
docker build -t fks_auth:dev .
docker run --rm -p 4100:4100 fks_auth:dev
```

## Response Examples

```bash
curl -s localhost:4100/health
LOGIN=$(curl -s -X POST localhost:4100/login -H 'Content-Type: application/json' \
	-d '{"username":"jordan","password":"567326"}')
echo "$LOGIN" | jq '.'
REFRESH=$(echo "$LOGIN" | jq -r '.refresh_token')
curl -s -X POST localhost:4100/refresh -H 'Content-Type: application/json' -d '{"refresh_token":"'$REFRESH'"}' | jq '.'
ACCESS=$(echo "$LOGIN" | jq -r '.access_token')
curl -s -H "Authorization: Bearer $ACCESS" localhost:4100/me | jq '.'
```

## Environment

Port fixed to 4100 (override by rebuilding image with code change or using docker-compose mapping).

## Notes

- Security intentionally minimal for local integration.
- Replace with real auth (JWT, sessions, DB) later.
