#!/bin/bash
# Quick Permission Fix for Dev Server
# Run this as fks_user to immediately fix permission issues

echo "🔧 Quick Permission Fix for Docker Containers"
echo "============================================"

# Create docker-compose.override.yml with correct user mapping
cat > docker-compose.override.yml << 'EOF'



services:
  # Override all services to use fks_user UID/GID
  web:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
    volumes:
      - ./src/web/react:/app/src/web/react:rw
      
  api:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
      
  worker:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
      
  data:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
      
  ninja-api:
    user: "1001:1001"
    environment:
      USER_ID: 1001
      GROUP_ID: 1001
EOF

echo "✅ Created docker-compose.override.yml"

# Fix permissions on key directories
echo "🔧 Fixing directory permissions..."
chmod -R 775 src/web/react 2>/dev/null || true
chmod -R 775 data 2>/dev/null || true
chmod -R 775 logs 2>/dev/null || true

# Ensure node_modules is writable
if [ -d "src/web/react/node_modules" ]; then
    chmod -R 775 src/web/react/node_modules 2>/dev/null || true
fi

echo "✅ Permissions fixed"

# Restart affected containers
echo "🔄 Restarting containers..."
docker compose stop web api worker data ninja-api
docker compose rm -f web api worker data ninja-api
docker compose up -d web api worker data ninja-api

echo "✅ Containers restarted"
echo ""
echo "📋 Check status with: docker compose ps"
echo "📋 View logs with: docker compose logs -f web"
echo ""
echo "🎯 The web service should now be able to write to the React directory!"
