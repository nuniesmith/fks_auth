#!/bin/bash

# Status check script for auto-update process
# Usage: ./check_auto_update.sh

LOG_FILE="/home/jordan/fks/logs/auto_update.log"
LOCK_FILE="/tmp/auto_update.lock"

echo "=== Auto-Update Status Check ==="
echo "Date: $(date)"
echo

# Check if cron service is running
if systemctl is-active --quiet cronie; then
    echo "✓ Cron service is running"
else
    echo "✗ Cron service is NOT running"
fi

# Check if lock file exists (script is running)
if [ -f "$LOCK_FILE" ]; then
    echo "✓ Auto-update script is currently running"
else
    echo "✓ Auto-update script is not running (normal)"
fi

# Check cron job
if crontab -l | grep -q "auto_update.sh"; then
    echo "✓ Cron job is configured"
    echo "  Schedule: $(crontab -l | grep auto_update.sh | cut -d' ' -f1-5)"
else
    echo "✗ Cron job is NOT configured"
fi

# Show last few log entries
echo
echo "=== Last 10 Log Entries ==="
if [ -f "$LOG_FILE" ]; then
    tail -n 10 "$LOG_FILE"
else
    echo "Log file not found: $LOG_FILE"
fi

# Check repository status
echo
echo "=== Repository Status ==="
cd /home/jordan/fks || exit 1
echo "Current branch: $(git branch --show-current)"
echo "Last commit: $(git log -1 --oneline)"
echo "Remote status: $(git status -uno --porcelain)"

# Check if start.sh is running
echo
echo "=== Application Status ==="
if pgrep -f "start.sh" > /dev/null; then
    echo "✓ start.sh process is running"
    echo "  PID: $(pgrep -f start.sh)"
else
    echo "✗ start.sh process is NOT running"
fi
