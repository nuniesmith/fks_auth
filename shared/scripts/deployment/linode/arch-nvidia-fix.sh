#!/bin/bash

# Arch Linux NVIDIA Firmware Conflict Fix
# Run this script if you're getting nvidia firmware conflicts

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Arch Linux NVIDIA Firmware Conflict Fix${NC}"
echo "========================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${YELLOW}Method 1: Force overwrite specific files${NC}"
pacman -Syu --noconfirm --overwrite '/usr/lib/firmware/nvidia/ad103,/usr/lib/firmware/nvidia/ad104,/usr/lib/firmware/nvidia/ad106,/usr/lib/firmware/nvidia/ad107' || {
    echo -e "${YELLOW}Method 1 failed, trying Method 2${NC}"
    
    echo -e "${YELLOW}Method 2: Remove conflicting files manually${NC}"
    rm -f /usr/lib/firmware/nvidia/ad103
    rm -f /usr/lib/firmware/nvidia/ad104
    rm -f /usr/lib/firmware/nvidia/ad106
    rm -f /usr/lib/firmware/nvidia/ad107
    
    # Try update again
    pacman -Syu --noconfirm || {
        echo -e "${YELLOW}Method 2 failed, trying Method 3${NC}"
        
        echo -e "${YELLOW}Method 3: Update excluding firmware, then force firmware${NC}"
        # Update everything except firmware
        pacman -Syu --noconfirm --ignore linux-firmware-nvidia --ignore linux-firmware
        
        # Force install firmware
        pacman -S --noconfirm --overwrite '*' linux-firmware linux-firmware-nvidia || {
            echo -e "${YELLOW}Method 3 failed, trying Method 4${NC}"
            
            echo -e "${YELLOW}Method 4: Remove and reinstall firmware packages${NC}"
            # Remove firmware packages without dependency check
            pacman -Rdd --noconfirm linux-firmware-nvidia linux-firmware 2>/dev/null || true
            
            # Reinstall firmware packages
            pacman -S --noconfirm linux-firmware linux-firmware-nvidia
        }
    }
}

echo -e "${GREEN}Fix completed! Your system should now be updated.${NC}"
echo -e "${GREEN}Run 'pacman -Syu' to verify everything is up to date.${NC}"