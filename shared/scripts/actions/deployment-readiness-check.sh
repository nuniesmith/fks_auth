#!/bin/bash
# Deployment Status Check Script
# Use this to verify if all fixes are working

echo "🔍 Checking deployment readiness across all projects..."
echo "=================================================="

# Function to check if Docker Compose works in a directory
check_docker_compose() {
    local project_dir="$1"
    local project_name="$2"
    
    echo ""
    echo "🔍 Checking $project_name ($project_dir)..."
    
    if [[ ! -d "$project_dir" ]]; then
        echo "❌ Directory not found: $project_dir"
        return 1
    fi
    
    cd "$project_dir"
    
    # Check if docker-compose.yml exists
    if [[ ! -f "docker-compose.yml" ]]; then
        echo "⚠️ No docker-compose.yml found in $project_name"
        return 1
    fi
    
    # Detect compose command
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD="docker-compose"
    else
        echo "❌ No Docker Compose available"
        return 1
    fi
    
    echo "✅ Docker Compose available: $COMPOSE_CMD"
    
    # Test compose file syntax
    if $COMPOSE_CMD config >/dev/null 2>&1; then
        echo "✅ docker-compose.yml syntax is valid"
    else
        echo "❌ docker-compose.yml has syntax errors:"
        $COMPOSE_CMD config 2>&1 | head -5
        return 1
    fi
    
    # Check for .env file or create one
    if [[ ! -f ".env" ]]; then
        echo "⚠️ No .env file found, this may cause warnings"
        if [[ -f ".env.template" ]]; then
            echo "📋 .env.template found - copy this to .env and configure"
        fi
    else
        echo "✅ .env file exists"
    fi
    
    return 0
}

# Check all three projects
PROJECTS=(
    "/home/jordan/oryx/code/repos/nginx:nginx"
    "/home/jordan/oryx/code/repos/fks:fks"
    "/home/jordan/oryx/code/repos/ats:ats"
)

SUCCESS_COUNT=0
TOTAL_COUNT=0

for project_info in "${PROJECTS[@]}"; do
    IFS=':' read -r project_dir project_name <<< "$project_info"
    ((TOTAL_COUNT++))
    
    if check_docker_compose "$project_dir" "$project_name"; then
        ((SUCCESS_COUNT++))
    fi
done

echo ""
echo "=================================================="
echo "📊 Summary: $SUCCESS_COUNT/$TOTAL_COUNT projects ready"

if [[ $SUCCESS_COUNT -eq $TOTAL_COUNT ]]; then
    echo "🎉 All projects are ready for deployment!"
    exit 0
else
    echo "⚠️ Some projects need attention before deployment"
    exit 1
fi
