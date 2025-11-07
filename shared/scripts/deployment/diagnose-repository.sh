#!/bin/bash

# Repository location diagnostic script
# This script helps diagnose where the repository is located

echo "🔍 FKS Repository Location Diagnostic"
echo "====================================="

echo ""
echo "📍 Checking expected locations:"
echo "------------------------------"

# Check main location
if [ -d "/home/fks_user/fks" ]; then
    echo "✅ /home/fks_user/fks EXISTS"
    echo "   Size: $(du -sh /home/fks_user/fks 2>/dev/null | cut -f1)"
    echo "   Owner: $(stat -c '%U:%G' /home/fks_user/fks 2>/dev/null)"
    echo "   Contents (first 10 items):"
    ls -la /home/fks_user/fks/ 2>/dev/null | head -11
else
    echo "❌ /home/fks_user/fks NOT FOUND"
fi

echo ""

# Check temp location
if [ -d "/home/actions_user/fks_temp" ]; then
    echo "⚠️ /home/actions_user/fks_temp EXISTS (should not exist after successful deployment)"
    echo "   Size: $(du -sh /home/actions_user/fks_temp 2>/dev/null | cut -f1)"
    echo "   Owner: $(stat -c '%U:%G' /home/actions_user/fks_temp 2>/dev/null)"
    echo "   Contents (first 10 items):"
    ls -la /home/actions_user/fks_temp/ 2>/dev/null | head -11
else
    echo "✅ /home/actions_user/fks_temp NOT FOUND (good - means it was moved)"
fi

echo ""
echo "🔍 Searching for any fks directories:"
echo "------------------------------------"
find /home -name "*fks*" -type d 2>/dev/null | sort

echo ""
echo "🔍 User directory structure:"
echo "----------------------------"
echo "actions_user home:"
ls -la /home/actions_user/ 2>/dev/null | head -10

echo ""
echo "fks_user home:"
ls -la /home/fks_user/ 2>/dev/null | head -10

echo ""
echo "👤 User information:"
echo "-------------------"
echo "Current user: $(whoami)"
echo "fks_user exists: $(id fks_user 2>/dev/null && echo 'YES' || echo 'NO')"
echo "actions_user exists: $(id actions_user 2>/dev/null && echo 'YES' || echo 'NO')"

echo ""
echo "🐳 Docker container status:"
echo "---------------------------"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | grep -E "(fks|NAME)" || echo "No FKS containers found"

echo ""
echo "📊 System resources:"
echo "-------------------"
echo "Disk usage:"
df -h /home 2>/dev/null || echo "Cannot check disk usage"
echo ""
echo "Memory usage:"
free -h 2>/dev/null || echo "Cannot check memory usage"

echo ""
echo "🔍 Repository diagnostic complete!"
echo "====================================="
