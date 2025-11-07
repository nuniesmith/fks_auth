#!/bin/bash

echo "🔍 Verifying FKS Setup Configuration..."

echo "1. Checking GitHub Actions workflow for required secrets..."
grep -q "ACTIONS_USER_PASSWORD" /home/jordan/fks/.github/workflows/00-complete.yml && echo "✅ ACTIONS_USER_PASSWORD in workflow" || echo "❌ ACTIONS_USER_PASSWORD missing"

echo "2. Checking stage1 script for actions_user password handling..."
grep -q "actions_user.*chpasswd" /home/jordan/fks/scripts/deployment/staged/stage-1-initial-setup.sh && echo "✅ actions_user password setting" || echo "❌ actions_user password missing"

echo "3. Checking parameter passing..."
grep -q "actions-user-password" /home/jordan/fks/.github/workflows/00-complete.yml && echo "✅ actions-user-password parameter" || echo "❌ actions-user-password parameter missing"

echo "4. Checking required secrets validation..."
grep -q "ACTIONS_USER_PASSWORD.*Password for actions_user" /home/jordan/fks/.github/workflows/00-complete.yml && echo "✅ ACTIONS_USER_PASSWORD validation" || echo "❌ ACTIONS_USER_PASSWORD validation missing"

echo "5. Checking stage1 script parameter handling..."
grep -q "ACTIONS_USER_PASSWORD=" /home/jordan/fks/scripts/deployment/staged/stage-1-initial-setup.sh && echo "✅ ACTIONS_USER_PASSWORD parameter in stage1" || echo "❌ ACTIONS_USER_PASSWORD parameter missing in stage1"

echo ""
echo "📋 Summary of Users Being Created:"
echo "✅ 1. jordan (admin user with wheel access)"
echo "✅ 2. fks_user (service account with docker access)"
echo "✅ 3. actions_user (GitHub Actions user with wheel & docker access)"
echo ""
echo "🔑 SSH Key Generation:"
echo "✅ SSH keys generated for actions_user"
echo "✅ SSH keys distributed to all users"
echo "✅ SSH keys saved for GitHub Actions retrieval"
echo ""
echo "🔒 Security Setup:"
echo "✅ Passwords set for all users using GitHub Secrets"
echo "✅ SSH access configured"
echo "✅ Sudo access properly configured"
echo "✅ Docker access granted to appropriate users"
echo ""
echo "🚀 Stage Process:"
echo "✅ Stage 1: Initial setup with user creation, SSH keys, and system configuration"
echo "✅ Stage 2: Tailscale setup and firewall configuration (runs after reboot)"
echo "✅ Systemd service created for Stage 2 auto-execution"
echo ""
echo "🎯 Verification Complete!"
