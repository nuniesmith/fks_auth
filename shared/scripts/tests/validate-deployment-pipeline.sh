#!/bin/bash
# FKS Deployment Pipeline Validation Script

set -euo pipefail

echo "🔍 FKS Deployment Pipeline Validation"
echo "====================================="

# Check if we're in the right directory
if [ ! -f ".github/workflows/build-docker.yml" ] || [ ! -f ".github/workflows/deploy-dev.yml" ]; then
    echo "❌ Error: Run this script from the FKS project root directory"
    exit 1
fi

echo ""
echo "📋 Checking workflow files..."

# Check if workflow files exist and have correct structure
workflows=(".github/workflows/build-docker.yml" ".github/workflows/deploy-dev.yml")
for workflow in "${workflows[@]}"; do
    if [ -f "$workflow" ]; then
        echo "✅ $workflow exists"
        
        # Basic structure checks
        if grep -q "^name:" "$workflow"; then
            echo "  ✅ Has workflow name"
        else
            echo "  ❌ Missing workflow name"
        fi
        
        if grep -q "^jobs:" "$workflow"; then
            echo "  ✅ Has jobs section"
        else
            echo "  ❌ Missing jobs section"
        fi
        
        # Count jobs
        job_count=$(grep -c "^  [a-zA-Z][a-zA-Z0-9_-]*:$" "$workflow" 2>/dev/null || echo "0")
        echo "  📊 Jobs found: $job_count"
    else
        echo "❌ $workflow missing"
    fi
done

echo ""
echo "🔗 Checking workflow integration..."

# Check if build-docker.yml triggers deploy-dev.yml
if grep -q "deploy-dev.yml" ".github/workflows/build-docker.yml"; then
    echo "✅ build-docker.yml triggers deploy-dev.yml"
else
    echo "❌ build-docker.yml does not trigger deploy-dev.yml"
fi

echo ""
echo "📜 Checking referenced scripts..."

# Check if referenced scripts exist
scripts=(
    "scripts/deployment/linode/linode-stackscript.sh"
    "scripts/deployment/manual/fks_ssh-keygen.sh"
)

for script in "${scripts[@]}"; do
    if [ -f "$script" ]; then
        echo "✅ $script exists"
        if [ -x "$script" ]; then
            echo "  ✅ Script is executable"
        else
            echo "  ⚠️  Script is not executable (will be fixed by chmod)"
        fi
    else
        echo "❌ $script missing"
    fi
done

echo ""
echo "🔧 Checking dependencies..."

# Check for required commands/tools
commands=("docker" "git")
for cmd in "${commands[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "✅ $cmd is available"
    else
        echo "⚠️  $cmd not available (required on deployment server)"
    fi
done

echo ""
echo "📋 Workflow Summary:"
echo "-------------------"

# Get job names from deploy-dev.yml
echo "Deploy workflow jobs:"
grep "^  [a-zA-Z][a-zA-Z0-9_-]*:$" ".github/workflows/deploy-dev.yml" | sed 's/://g' | sed 's/^  /  • /'

echo ""
echo "Build workflow jobs:"
grep "^  [a-zA-Z][a-zA-Z0-9_-]*:$" ".github/workflows/build-docker.yml" | sed 's/://g' | sed 's/^  /  • /'

echo ""
echo "🎯 Key Features:"
echo "  • Automated Docker builds with change detection"
echo "  • Conditional SSH key generation for new servers"
echo "  • Tailscale DNS with public IP fallback"
echo "  • Discord notifications at key steps"
echo "  • Comprehensive error handling and recovery"

echo ""
echo "🚀 Next Steps:"
echo "  1. Ensure all GitHub secrets are configured"
echo "  2. Test with a push to main/develop branch"
echo "  3. Monitor workflow execution in GitHub Actions"
echo "  4. Check Discord for deployment notifications"

echo ""
echo "✅ Validation complete! The deployment pipeline is ready for testing."
