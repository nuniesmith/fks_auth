#!/bin/bash

# Test GPU functionality for FKS Trading Systems
# This script verifies GPU availability and Docker GPU integration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
    esac
}

echo "🎮 FKS GPU Test Suite"
echo "======================"
echo ""

# Test 1: Check if NVIDIA drivers are installed
log "INFO" "Testing NVIDIA driver installation..."
if command -v nvidia-smi &> /dev/null; then
    log "INFO" "✅ nvidia-smi found"
    
    if nvidia-smi &> /dev/null; then
        log "INFO" "✅ NVIDIA drivers working"
        
        # Get GPU information
        GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader,nounits | head -1)
        GPU_MEMORY=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1)
        DRIVER_VERSION=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader,nounits | head -1)
        
        echo ""
        log "INFO" "GPU Information:"
        echo "  📱 GPU: $GPU_NAME"
        echo "  💾 Memory: ${GPU_MEMORY}MB"
        echo "  🔧 Driver: $DRIVER_VERSION"
        echo ""
    else
        log "ERROR" "❌ NVIDIA drivers not working properly"
        log "ERROR" "Run 'nvidia-smi' to see detailed error information"
        exit 1
    fi
else
    log "ERROR" "❌ nvidia-smi not found"
    log "ERROR" "Please install NVIDIA drivers:"
    log "ERROR" "  sudo apt update"
    log "ERROR" "  sudo apt install nvidia-driver-535"
    log "ERROR" "  sudo reboot"
    exit 1
fi

# Test 2: Check Docker installation
log "INFO" "Testing Docker installation..."
if command -v docker &> /dev/null; then
    log "INFO" "✅ Docker found"
    
    if docker info &> /dev/null; then
        log "INFO" "✅ Docker daemon running"
    else
        log "ERROR" "❌ Docker daemon not running"
        log "ERROR" "Start Docker with: sudo systemctl start docker"
        exit 1
    fi
else
    log "ERROR" "❌ Docker not found"
    log "ERROR" "Please install Docker first"
    exit 1
fi

# Test 3: Check NVIDIA Docker runtime
log "INFO" "Testing NVIDIA Docker runtime..."
if docker info 2> /dev/null | grep -i nvidia > /dev/null; then
    log "INFO" "✅ NVIDIA Docker runtime available"
else
    log "ERROR" "❌ NVIDIA Docker runtime not found"
    log "ERROR" "Install nvidia-docker2:"
    log "ERROR" "  distribution=\$(. /etc/os-release;echo \$ID\$VERSION_ID)"
    log "ERROR" "  curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -"
    log "ERROR" "  curl -s -L https://nvidia.github.io/nvidia-docker/\$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list"
    log "ERROR" "  sudo apt-get update"
    log "ERROR" "  sudo apt-get install -y nvidia-docker2"
    log "ERROR" "  sudo systemctl restart docker"
    exit 1
fi

# Test 4: Test GPU access in Docker
log "INFO" "Testing GPU access in Docker container..."
if docker run --rm --gpus all nvidia/cuda:12.0-base-ubuntu20.04 nvidia-smi &> /dev/null; then
    log "INFO" "✅ GPU accessible from Docker containers"
else
    log "ERROR" "❌ GPU not accessible from Docker containers"
    log "ERROR" "Try restarting Docker: sudo systemctl restart docker"
    exit 1
fi

# Test 5: Run a simple CUDA test
log "INFO" "Running CUDA capability test..."
CUDA_OUTPUT=$(docker run --rm --gpus all nvidia/cuda:12.0-base-ubuntu20.04 nvidia-smi --query-gpu=name,compute_cap --format=csv,noheader,nounits 2>/dev/null || echo "Failed")

if [[ "$CUDA_OUTPUT" != "Failed" ]]; then
    log "INFO" "✅ CUDA capabilities:"
    echo "$CUDA_OUTPUT" | while read line; do
        echo "    $line"
    done
else
    log "WARN" "⚠️ Could not retrieve CUDA capabilities"
fi

# Test 6: Check PyTorch GPU support (if available)
log "INFO" "Testing PyTorch GPU support..."
PYTORCH_TEST=$(docker run --rm --gpus all python:3.11-slim bash -c "
    pip install torch --index-url https://download.pytorch.org/whl/cu121 --quiet && 
    python -c 'import torch; print(f\"PyTorch GPU available: {torch.cuda.is_available()}\"); print(f\"GPU count: {torch.cuda.device_count()}\"); print(f\"GPU name: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"N/A\"}\")'
" 2>/dev/null || echo "PyTorch test failed")

if [[ "$PYTORCH_TEST" != "PyTorch test failed" ]]; then
    log "INFO" "✅ PyTorch GPU test results:"
    echo "$PYTORCH_TEST" | while read line; do
        echo "    $line"
    done
else
    log "WARN" "⚠️ PyTorch GPU test failed (this is normal if PyTorch isn't installed)"
fi

echo ""
echo "🎉 GPU Test Results Summary:"
echo "=============================="
log "INFO" "✅ NVIDIA drivers: Working"
log "INFO" "✅ Docker: Working"
log "INFO" "✅ NVIDIA Docker runtime: Available"
log "INFO" "✅ GPU access in containers: Working"
echo ""
log "INFO" "🚀 Your system is ready for GPU-accelerated FKS services!"
log "INFO" "Start with GPU support using: ./start.sh --gpu"
echo ""
