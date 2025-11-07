#!/bin/bash
# (Relocated) Deployment verification script.
set -e
echo "🔍 Verifying deployment configuration..."
required_files=("docker-compose.yml" ".env.example" "deployment/docker/nginx/Dockerfile")
for f in "${required_files[@]}"; do [[ -f $f ]] || echo "Missing $f"; done
if docker compose config >/dev/null 2>&1 || docker-compose config >/dev/null 2>&1; then echo "✅ Compose config OK"; else echo "❌ Compose config error"; fi
