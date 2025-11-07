#!/bin/bash
# (Relocated) Setup verification (trimmed).
echo "🔍 Verifying FKS Setup Configuration (minimal)"
grep -q "ACTIONS_USER_PASSWORD" .github/workflows/00-complete.yml 2>/dev/null && echo "✅ ACTIONS_USER_PASSWORD present" || echo "❌ Missing ACTIONS_USER_PASSWORD"
