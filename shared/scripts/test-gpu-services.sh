#!/bin/bash

# =================================================================
# GPU Services Test Script
# =================================================================
# This script tests the GPU services setup and functionality

set -e

echo "🧪 FKS GPU Services Test Script"
echo "================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO")
            echo -e "${BLUE}ℹ️  $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}❌ $message${NC}"
            ;;
    esac
}

# Function to check command availability
check_command() {
    local cmd=$1
    if command -v $cmd >/dev/null 2>&1; then
        print_status "SUCCESS" "$cmd is available"
        return 0
    else
        print_status "ERROR" "$cmd is not available"
        return 1
    fi
}

# Function to test service health
test_service_health() {
    local service_name=$1
    local port=$2
    local endpoint=${3:-/health}
    
    print_status "INFO" "Testing $service_name service on port $port..."
    
    if curl -f -s "http://localhost:$port$endpoint" >/dev/null 2>&1; then
        print_status "SUCCESS" "$service_name service is healthy"
        return 0
    else
        print_status "ERROR" "$service_name service is not responding"
        return 1
    fi
}

# Function to test GPU availability
test_gpu_availability() {
    print_status "INFO" "Testing GPU availability..."
    
    if command -v nvidia-smi >/dev/null 2>&1; then
        print_status "SUCCESS" "NVIDIA drivers are installed"
        
        # Check GPU status
        if nvidia-smi >/dev/null 2>&1; then
            print_status "SUCCESS" "GPU is accessible"
            echo ""
            nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader,nounits
            echo ""
        else
            print_status "ERROR" "GPU is not accessible"
            return 1
        fi
    else
        print_status "WARNING" "NVIDIA drivers not found (CPU-only mode)"
    fi
}

# Function to test Docker GPU support
test_docker_gpu() {
    print_status "INFO" "Testing Docker GPU support..."
    
    if docker run --rm --gpus all nvidia/cuda:12.8-base-ubuntu24.04 nvidia-smi >/dev/null 2>&1; then
        print_status "SUCCESS" "Docker GPU support is working"
    else
        print_status "WARNING" "Docker GPU support not available"
        print_status "INFO" "GPU services will not work without GPU support"
    fi
}

# Function to check compose profiles
test_compose_profiles() {
    print_status "INFO" "Testing Docker Compose profiles..."
    
    # Check if GPU services are defined
    if docker-compose config --profile gpu >/dev/null 2>&1; then
        print_status "SUCCESS" "GPU profile is valid"
    else
        print_status "ERROR" "GPU profile configuration error"
        return 1
    fi
    
    # List available profiles
    print_status "INFO" "Available profiles:"
    echo "  - default (CPU services)"
    echo "  - gpu (GPU services)"
    echo "  - training (training service only)"
    echo "  - transformer (transformer service only)"
    echo "  - ml (both ML services)"
    echo "  - home (all services)"
}

# Function to test environment files
test_environment_files() {
    print_status "INFO" "Checking environment files..."
    
    local env_files=(".env.development" ".env.cloud" ".env.gpu")
    
    for env_file in "${env_files[@]}"; do
        if [[ -f "$env_file" ]]; then
            print_status "SUCCESS" "$env_file exists"
        else
            print_status "ERROR" "$env_file not found"
        fi
    done
}

# Function to display usage examples
show_usage_examples() {
    print_status "INFO" "Usage Examples:"
    echo ""
    echo "🏠 Home Development (All services):"
    echo "   cp .env.gpu .env"
    echo "   docker-compose --profile gpu up -d"
    echo ""
    echo "☁️  Cloud Deployment (CPU only):"
    echo "   cp .env.cloud .env"
    echo "   docker-compose up -d"
    echo ""
    echo "🔬 Training Service Only:"
    echo "   docker-compose --profile training up -d"
    echo ""
    echo "🤖 Transformer Service Only:"
    echo "   docker-compose --profile transformer up -d"
    echo ""
    echo "🏗️  Build GPU Services Locally:"
    echo "   docker-compose -f docker-compose.yml -f docker-compose.gpu.yml --profile gpu up -d"
    echo ""
}

# Main test execution
main() {
    print_status "INFO" "Starting GPU services compatibility test..."
    echo ""
    
    # Test basic requirements
    print_status "INFO" "=== BASIC REQUIREMENTS ==="
    check_command "docker" || exit 1
    check_command "docker-compose" || exit 1
    
    # Test GPU availability
    echo ""
    print_status "INFO" "=== GPU AVAILABILITY ==="
    test_gpu_availability
    
    # Test Docker GPU support
    echo ""
    print_status "INFO" "=== DOCKER GPU SUPPORT ==="
    test_docker_gpu
    
    # Test environment files
    echo ""
    print_status "INFO" "=== ENVIRONMENT FILES ==="
    test_environment_files
    
    # Test compose configuration
    echo ""
    print_status "INFO" "=== DOCKER COMPOSE ==="
    test_compose_profiles
    
    # Test running services (if any)
    echo ""
    print_status "INFO" "=== RUNNING SERVICES ==="
    
    # Check if any services are running
    if docker-compose ps --services --filter "status=running" | grep -q .; then
        print_status "INFO" "Testing running services..."
        
        # Test standard services
        test_service_health "API" 8000 || true
        test_service_health "Data" 9001 || true
        test_service_health "Worker" 8001 || true
        test_service_health "App" 9000 || true
        
        # Test GPU services if running
        test_service_health "Training" 8088 || true
        test_service_health "Transformer" 8089 || true
    else
        print_status "INFO" "No services currently running"
    fi
    
    # Show usage examples
    echo ""
    print_status "INFO" "=== USAGE EXAMPLES ==="
    show_usage_examples
    
    print_status "SUCCESS" "GPU services test completed!"
    echo ""
    print_status "INFO" "Next steps:"
    echo "  1. Review the test results above"
    echo "  2. Install missing dependencies if needed"
    echo "  3. Choose your deployment scenario"
    echo "  4. Start the appropriate services"
    echo "  5. Check the GPU Services Guide: docs/GPU_SERVICES_GUIDE.md"
}

# Run the main function
main "$@"
