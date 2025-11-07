#!/bin/bash

# Disk Space Analysis Script for Manjaro
# This script provides comprehensive disk usage information

echo "🔍 DISK SPACE ANALYSIS REPORT"
echo "=============================="
echo "Generated on: $(date)"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display section headers
print_header() {
    echo -e "\n${BLUE}📊 $1${NC}"
    echo "----------------------------------------"
}

# 1. Overall filesystem usage
print_header "FILESYSTEM OVERVIEW"
df -h --exclude-type=tmpfs --exclude-type=devtmpfs --exclude-type=squashfs

# 2. Find largest directories in root filesystem
print_header "TOP 10 LARGEST DIRECTORIES (Root Level)"
echo "Scanning root directories... (this may take a moment)"
sudo du -h --max-depth=1 / 2>/dev/null | sort -hr | head -10

# 3. Home directory analysis
print_header "HOME DIRECTORY ANALYSIS (~$(basename $HOME))"
if [ -d "$HOME" ]; then
    du -h --max-depth=1 "$HOME" 2>/dev/null | sort -hr | head -10
fi

# 4. System-specific large directories
print_header "SYSTEM DIRECTORIES CHECK"
echo "Checking common space consumers..."

# Check various system directories
check_dir() {
    local dir="$1"
    local desc="$2"
    if [ -d "$dir" ]; then
        local size=$(sudo du -sh "$dir" 2>/dev/null | cut -f1)
        printf "%-20s: %s\n" "$desc" "$size"
    fi
}

check_dir "/var/log" "System logs"
check_dir "/var/cache" "Package cache"
check_dir "/tmp" "Temporary files"
check_dir "/usr/share" "Shared data"
check_dir "/opt" "Optional packages"
check_dir "/var/lib/docker" "Docker data"
check_dir "/home/.snapshots" "Snapper snapshots"
check_dir "/var/cache/pacman/pkg" "Pacman cache"

# 5. Package cache analysis (Manjaro/Arch specific)
print_header "PACKAGE MANAGER CACHE"
if [ -d "/var/cache/pacman/pkg" ]; then
    cache_size=$(sudo du -sh /var/cache/pacman/pkg 2>/dev/null | cut -f1)
    cache_count=$(sudo find /var/cache/pacman/pkg -name "*.pkg.tar.*" 2>/dev/null | wc -l)
    echo "Pacman cache size: $cache_size"
    echo "Cached packages: $cache_count"
    echo "💡 To clean: sudo pacman -Sc (keep current) or sudo pacman -Scc (remove all)"
fi

# Check for AUR helpers cache
if [ -d "$HOME/.cache/yay" ]; then
    yay_size=$(du -sh "$HOME/.cache/yay" 2>/dev/null | cut -f1)
    echo "Yay cache size: $yay_size"
fi

if [ -d "$HOME/.cache/paru" ]; then
    paru_size=$(du -sh "$HOME/.cache/paru" 2>/dev/null | cut -f1)
    echo "Paru cache size: $paru_size"
fi

# 6. Log files analysis
print_header "LOG FILES ANALYSIS"
if [ -d "/var/log" ]; then
    echo "Largest log files:"
    sudo find /var/log -type f -name "*.log*" -exec du -h {} + 2>/dev/null | sort -hr | head -5
    
    # Check journal size
    if command -v journalctl > /dev/null; then
        journal_size=$(sudo journalctl --disk-usage 2>/dev/null | grep -o '[0-9.]*[A-Z]*' | head -1)
        echo "Systemd journal size: $journal_size"
        echo "💡 To clean: sudo journalctl --vacuum-time=30d (keep 30 days)"
    fi
fi

# 7. User-specific large files and directories
print_header "LARGE FILES IN HOME DIRECTORY"
echo "Finding files larger than 100MB in your home directory..."
find "$HOME" -type f -size +100M -exec du -h {} + 2>/dev/null | sort -hr | head -10

# 8. Hidden directories in home (often cache/config)
print_header "HIDDEN DIRECTORIES IN HOME"
du -sh "$HOME"/.[^.]* 2>/dev/null | sort -hr | head -10

# 9. Trash/Recycle bin
print_header "TRASH/RECYCLE BIN"
trash_dirs=("$HOME/.local/share/Trash" "$HOME/.Trash")
for trash_dir in "${trash_dirs[@]}"; do
    if [ -d "$trash_dir" ]; then
        trash_size=$(du -sh "$trash_dir" 2>/dev/null | cut -f1)
        echo "Trash size ($trash_dir): $trash_size"
        echo "💡 To empty: rm -rf $trash_dir/* $trash_dir/.*"
    fi
done

# 10. Docker containers and images (if Docker is installed)
if command -v docker > /dev/null 2>&1; then
    print_header "DOCKER USAGE"
    echo "Docker system usage:"
    sudo docker system df 2>/dev/null || echo "Docker not running or no permission"
    echo "💡 To clean Docker: sudo docker system prune -a"
fi

# 11. Snap packages (if installed)
if command -v snap > /dev/null 2>&1; then
    print_header "SNAP PACKAGES"
    snap_size=$(sudo du -sh /var/lib/snapd 2>/dev/null | cut -f1)
    echo "Snap packages size: $snap_size"
    echo "💡 To clean old revisions: sudo snap set system refresh.retain=2"
fi

# 12. Flatpak (if installed)
if command -v flatpak > /dev/null 2>&1; then
    print_header "FLATPAK PACKAGES"
    flatpak_size=$(du -sh "$HOME/.var/app" 2>/dev/null | cut -f1)
    echo "Flatpak user data: $flatpak_size"
    system_flatpak=$(sudo du -sh /var/lib/flatpak 2>/dev/null | cut -f1)
    echo "System Flatpak data: $system_flatpak"
    echo "💡 To clean: flatpak uninstall --unused"
fi

# 13. Temporary files and cache cleanup analysis
print_header "TEMPORARY FILES & CACHE ANALYSIS"
echo "Analyzing temporary and cache locations..."

# System temp directories
temp_locations=(
    "/tmp"
    "/var/tmp"
    "/var/cache"
    "$HOME/.cache"
    "$HOME/.tmp"
    "$HOME/tmp"
)

for temp_dir in "${temp_locations[@]}"; do
    if [ -d "$temp_dir" ]; then
        temp_size=$(du -sh "$temp_dir" 2>/dev/null | cut -f1)
        printf "%-20s: %s\n" "$(basename $temp_dir)" "$temp_size"
    fi
done

# Browser caches
echo ""
echo "Browser cache analysis:"
browser_caches=(
    "$HOME/.cache/google-chrome"
    "$HOME/.cache/chromium" 
    "$HOME/.cache/firefox"
    "$HOME/.mozilla/firefox/*/storage"
    "$HOME/.config/google-chrome/Default/Service Worker"
    "$HOME/.var/app/com.google.Chrome/cache"
    "$HOME/.var/app/org.mozilla.firefox/.cache"
)

for cache_dir in "${browser_caches[@]}"; do
    if [ -d "$cache_dir" ] 2>/dev/null; then
        cache_size=$(du -sh "$cache_dir" 2>/dev/null | cut -f1)
        printf "%-25s: %s\n" "$(basename $(dirname $cache_dir))/$(basename $cache_dir)" "$cache_size"
    fi
done

# Development/build caches
echo ""
echo "Development cache analysis:"
dev_caches=(
    "$HOME/.npm"
    "$HOME/.yarn"
    "$HOME/.cargo"
    "$HOME/.gradle"
    "$HOME/.m2"
    "$HOME/.nuget"
    "$HOME/.dotnet"
    "$HOME/go/pkg"
    "$HOME/.local/share/virtualenvs"
    "$HOME/.conda/pkgs"
    "$HOME/miniconda3/pkgs"
)

for dev_cache in "${dev_caches[@]}"; do
    if [ -d "$dev_cache" ]; then
        dev_size=$(du -sh "$dev_cache" 2>/dev/null | cut -f1)
        printf "%-25s: %s\n" "$(basename $dev_cache)" "$dev_size"
    fi
done

print_header "EMERGENCY TEMP CLEANUP COMMANDS"
echo -e "${RED}⚠️  CRITICAL: Your disk is 98% full!${NC}"
echo -e "${YELLOW}Immediate cleanup suggestions (in order of safety):${NC}"
echo ""
echo "1. 🧹 SAFE TEMP CLEANUP:"
echo "   sudo find /tmp -type f -mtime +7 -delete"
echo "   sudo find /var/tmp -type f -mtime +7 -delete"
echo "   rm -rf ~/.cache/thumbnails/*"
echo "   rm -rf ~/.cache/*/tmp"
echo ""
echo "2. 📦 PACKAGE CLEANUP:"
echo "   sudo pacman -Sc                    # Clean package cache (safe)"
echo "   sudo pacman -Scc                   # Remove ALL cached packages"
echo "   pacman -Qtdq | sudo pacman -Rns -  # Remove orphaned packages"
echo ""
echo "3. 🐳 DOCKER CLEANUP (MAJOR SPACE SAVER - 155GB!):"
echo "   sudo docker system prune -a --volumes  # Remove everything unused"
echo "   sudo docker image prune -a             # Remove all unused images"
echo ""
echo "4. 🗂️  BROWSER CACHE:"
echo "   rm -rf ~/.cache/google-chrome/"
echo "   rm -rf ~/.cache/chromium/"
echo "   rm -rf ~/.mozilla/firefox/*/storage/default/*"
echo ""
echo "5. 🎮 GAME FILES (Consider moving large games):"
echo "   # Your Steam games are using ~100GB+ in ~/.local/share/Steam/"
echo "   # Consider uninstalling games you don't play or moving to external drive"
echo ""
echo "6. 🔧 DEVELOPMENT CLEANUP:"
echo "   npm cache clean --force"
echo "   yarn cache clean"
echo "   conda clean --all"
echo "   rm -rf ~/.npm ~/.yarn/cache"

print_header "AUTOMATED TEMP CLEANUP SCRIPT"
echo -e "${BLUE}Run this for immediate temp cleanup:${NC}"
echo ""
cat << 'EOF'
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
EOF

print_header "REGULAR CLEANUP SUGGESTIONS"
echo -e "${YELLOW}For ongoing maintenance:${NC}"
echo "• Clean package cache: sudo pacman -Sc"
echo "• Clean journal logs: sudo journalctl --vacuum-time=30d"
echo "• Clean user cache: rm -rf ~/.cache/*"
echo "• Find and remove large files: find / -size +1G -type f 2>/dev/null"
echo "• Check for orphaned packages: pacman -Qtdq"
echo "• Docker cleanup: sudo docker system prune -f (weekly)"
echo ""
echo -e "${GREEN}For interactive exploration, install and use: sudo pacman -S ncdu${NC}"
echo -e "${GREEN}Then run: ncdu / (for system) or ncdu ~ (for home)${NC}"

echo ""
echo "Analysis complete! 🎉"