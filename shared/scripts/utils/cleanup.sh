#!/bin/bash
# Emergency temp cleanup script
echo "🧹 Starting emergency cleanup..."

# Safe temp cleanup
echo "Cleaning system temp files..."
sudo find /tmp -type f -mtime +1 -delete 2>/dev/null
sudo find /var/tmp -type f -mtime +1 -delete 2>/dev/null

# User cache cleanup  
echo "Cleaning user caches..."
rm -rf ~/.cache/thumbnails/* 2>/dev/null
rm -rf ~/.cache/*/tmp 2>/dev/null
rm -rf ~/.cache/pip/* 2>/dev/null

# Browser cache (comment out if you want to keep)
# rm -rf ~/.cache/google-chrome/* 2>/dev/null
# rm -rf ~/.cache/chromium/* 2>/dev/null

# Package manager cleanup
echo "Cleaning package cache..."
sudo pacman -Sc --noconfirm

# Docker cleanup (MAJOR space saver)
if command -v docker > /dev/null; then
    echo "Cleaning Docker (this will free ~155GB)..."
    sudo docker system prune -f
fi

echo "✅ Cleanup complete!"
df -h /