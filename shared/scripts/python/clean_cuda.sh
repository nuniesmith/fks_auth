#!/bin/bash
echo "Cleaning up existing CUDA installations..."

# Remove conda environment
conda env remove -n fks_env -y 2>/dev/null || echo "No fks_env found"

# Remove system CUDA packages (if any)
sudo pacman -Rns $(pacman -Qq | grep -E '^(cuda|cudnn)') 2>/dev/null || echo "No system CUDA packages found"

# Remove manual installations
sudo rm -rf /usr/local/cuda*
sudo rm -rf /opt/cuda*

# Clean bashrc
cp ~/.bashrc ~/.bashrc.backup
sed -i '/cuda/Id' ~/.bashrc
sed -i '/CUDA/Id' ~/.bashrc

# Clean conda cache
conda clean --all -y

# Remove any virtual environments
rm -rf .venv venv

echo "✅ Cleanup complete!"
echo "Now run: ./env.sh"