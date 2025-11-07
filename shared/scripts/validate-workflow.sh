#!/bin/bash
# GitHub Actions Workflow Validation Script

echo "🔍 Validating GitHub Actions workflow..."

# Check if required files exist
required_files=(".github/workflows/00-complete.yml" "deployment/docker/Dockerfile" "deployment/docker/nginx/Dockerfile")
for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file exists"
    else
        echo "❌ $file missing"
        exit 1
    fi
done

# Check if workflow syntax is valid
echo ""
echo "🔍 Checking GitHub Actions workflow syntax..."
if command -v act >/dev/null 2>&1; then
    echo "Using 'act' to validate workflow..."
    if act --list > /dev/null 2>&1; then
        echo "✅ Workflow syntax is valid"
    else
        echo "❌ Workflow syntax has errors"
        exit 1
    fi
else
    echo "⚠️  'act' not installed - skipping syntax validation"
    echo "Install with: curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash"
fi

# Check if required secrets are documented
echo ""
echo "🔍 Checking required secrets..."
required_secrets=("DOCKER_USERNAME" "DOCKER_TOKEN" "LINODE_CLI_TOKEN" "FKS_DEV_ROOT_PASSWORD")
for secret in "${required_secrets[@]}"; do
    if grep -q "$secret" .github/workflows/00-complete.yml; then
        echo "✅ $secret is referenced in workflow"
    else
        echo "❌ $secret not found in workflow"
    fi
done

# Check Docker compose configuration
echo ""
echo "🔍 Checking Docker compose configuration compatibility..."
if docker-compose config > /dev/null 2>&1; then
    echo "✅ Docker compose configuration is valid"
else
    echo "❌ Docker compose configuration has errors"
fi

# Check if build arguments match
echo ""
echo "🔍 Checking build arguments compatibility..."
if grep -q "SERVICE_TYPE" deployment/docker/Dockerfile; then
    echo "✅ SERVICE_TYPE build argument found in Dockerfile"
else
    echo "⚠️  SERVICE_TYPE build argument not found in Dockerfile"
fi

if grep -q "APP_ENV" deployment/docker/Dockerfile; then
    echo "✅ APP_ENV build argument found in Dockerfile"
else
    echo "⚠️  APP_ENV build argument not found in Dockerfile"
fi

echo ""
echo "🎯 Workflow validation complete!"
echo ""
echo "💡 Next steps:"
echo "1. Set up required GitHub secrets:"
echo "   - DOCKER_USERNAME: Your Docker Hub username"
echo "   - DOCKER_TOKEN: Your Docker Hub access token"
echo "   - LINODE_CLI_TOKEN: Your Linode API token"
echo "   - FKS_DEV_ROOT_PASSWORD: Root password for new servers"
echo "2. Test workflow with 'test-builds' mode first"
echo "3. Run full deployment with 'full-deploy' mode"
