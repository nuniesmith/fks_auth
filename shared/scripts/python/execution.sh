#!/bin/bash
# filepath: scripts/python/execution.sh
# FKS Trading Systems - Python Application Execution

# Prevent multiple sourcing
[[ -n "${FKS_PYTHON_EXECUTION_LOADED:-}" ]] && return 0
readonly FKS_PYTHON_EXECUTION_LOADED=1

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../core/logging.sh"
source "$SCRIPT_DIR/environment.sh"

# Configuration paths
readonly CONFIG_PATH="${CONFIG_PATH:-./config/app_config.yaml}"
readonly DATA_PATH="${DATA_PATH:-./data/raw_gc_data.csv}"

# Main Python application execution
run_python_application() {
    log_info "🐍 Running Python application..."
    
    # Pre-flight validation
    validate_python_requirements
    
    # Setup and activate environment
    setup_and_activate_environment
    
    # Verify environment
    verify_execution_environment
    
    # Setup project structure
    setup_execution_project_structure
    
    # Run the main application
    execute_main_application
    
    # Cleanup
    cleanup_execution_environment
}

# Validate Python requirements
validate_python_requirements() {
    log_info "🔍 Validating Python requirements..."
    
    # Check if data file exists
    if [[ ! -f "$DATA_PATH" ]]; then
        log_warn "⚠️  Data file not found: $DATA_PATH"
        log_info "Please ensure your time series data is available"
        echo "Continue without data file? (y/N): "
        read -r REPLY
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    else
        log_success "✅ Data file found: $DATA_PATH"
        show_data_file_info
    fi
    
    # Check if config file exists
    if [[ ! -f "$CONFIG_PATH" ]]; then
        log_warn "⚠️  Config file not found: $CONFIG_PATH"
        create_default_python_config
    else
        log_success "✅ Config file found: $CONFIG_PATH"
    fi
}

# Show data file information
show_data_file_info() {
    local file_size
    file_size=$(du -h "$DATA_PATH" | cut -f1)
    local line_count
    line_count=$(wc -l < "$DATA_PATH" 2>/dev/null || echo "unknown")
    echo "   Size: $file_size, Lines: $line_count"
    
    # Show first few lines if it's a CSV
    if [[ "$DATA_PATH" == *.csv ]]; then
        echo "   Preview:"
        head -3 "$DATA_PATH" | while IFS= read -r line; do
            echo "     $line"
        done
    fi
}

# Create default Python configuration
create_default_python_config() {
    log_info "⚙️  Creating default Python configuration..."
    
    local config_dir
    config_dir="$(dirname "$CONFIG_PATH")"
    mkdir -p "$config_dir"
    
    cat > "$CONFIG_PATH" << 'EOF'
# FKS Trading Systems - Python Configuration
app:
  name: "FKS Trading Systems"
  version: "1.0.0"
  environment: "development"

model:
  type: "transformer"
  d_model: 64
  n_head: 8
  n_layers: 3
  dropout: 0.1
  learning_rate: 0.001
  weight_decay: 0.0001

data:
  seq_length: 60
  pred_length: 1
  batch_size: 32
  num_workers: 4
  test_split: 0.15
  val_split: 0.15

training:
  epochs: 100
  early_stopping_patience: 10
  gradient_clip_val: 1.0
  lr_scheduler:
    type: "cosine"
    min_lr: 0.00001
    warmup_steps: 500

features:
  use_technical_indicators: true
  use_advanced_sentiment: true
  use_fks_features: true
  
  fks_features:
    use_base_indicators: true
    use_market_structure: true
    use_order_blocks: true
    use_liquidity_zones: true
    use_signal_engine: true

paths:
  data_path: "./data"
  model_path: "./models"
  log_path: "./logs"
  results_path: "./results"
EOF
    
    log_success "✅ Default configuration created: $CONFIG_PATH"
}

# Setup and activate Python environment
setup_and_activate_environment() {
    log_info "🔧 Setting up Python environment for execution..."
    
    # Detect and setup environment
    if ! check_python_environments; then
        log_error "❌ No suitable Python environment found"
        exit 1
    fi
    
    # Setup the environment
    setup_python_environment
    
    # Activate the environment
    activate_python_environment
    
    log_success "✅ Python environment activated"
}

# Verify execution environment
verify_execution_environment() {
    log_info "🧪 Verifying execution environment..."
    
    # Show environment details
    local env_name
    case "$PYTHON_ENV_TYPE" in
        "conda")
            env_name="${CONDA_DEFAULT_ENV:-unknown}"
            ;;
        "venv")
            env_name="$(basename "${VIRTUAL_ENV:-$VENV_DIR}")"
            ;;
        "system")
            env_name="system"
            ;;
    esac
    
    echo "Environment: $env_name"
    echo "Python: $(python --version) at $(which python)"
    echo "Working Directory: $(pwd)"
    
    # Check critical imports
    check_critical_imports_for_execution
    
    # Check GPU availability
    check_gpu_availability
    
    # Check system resources
    check_execution_resources
}

# Check critical imports for execution
check_critical_imports_for_execution() {
    log_info "🔬 Checking critical imports..."
    
    local critical_imports=("numpy" "pandas" "torch" "sklearn" "yaml" "pydantic")
    local failed_imports=()
    
    for import_name in "${critical_imports[@]}"; do
        if python -c "import $import_name" 2>/dev/null; then
            echo "✅ $import_name"
        else
            echo "❌ $import_name"
            failed_imports+=("$import_name")
        fi
    done
    
    if [[ ${#failed_imports[@]} -gt 0 ]]; then
        log_error "❌ Critical imports failed: ${failed_imports[*]}"
        log_info "Installing missing packages..."
        install_missing_packages "${failed_imports[@]}"
        
        # Re-check after installation
        local still_failed=()
        for import_name in "${failed_imports[@]}"; do
            if ! python -c "import $import_name" 2>/dev/null; then
                still_failed+=("$import_name")
            fi
        done
        
        if [[ ${#still_failed[@]} -gt 0 ]]; then
            log_error "❌ Still failed after installation: ${still_failed[*]}"
            exit 1
        fi
    fi
    
    log_success "✅ All critical imports successful"
}

# Check execution resources
check_execution_resources() {
    log_info "💾 Checking execution resources..."
    
    # Memory check
    if command -v free >/dev/null 2>&1; then
        local total_mem_kb
        total_mem_kb=$(free | awk '/^Mem:/ {print $2}')
        local total_mem_gb=$((total_mem_kb / 1024 / 1024))
        
        if [[ $total_mem_gb -lt 4 ]]; then
            log_warn "⚠️  Low system memory: ${total_mem_gb}GB (recommended: 8GB+)"
        else
            echo "Memory: ${total_mem_gb}GB available"
        fi
    fi
    
    # Disk space check
    local available_space
    available_space=$(df . | awk 'NR==2 {print $4}')
    local available_gb=$((available_space / 1024 / 1024))
    
    if [[ $available_gb -lt 2 ]]; then
        log_warn "⚠️  Low disk space: ${available_gb}GB"
        echo "Continue anyway? (y/N): "
        read -r REPLY
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    else
        echo "Disk space: ${available_gb}GB available"
    fi
}

# Setup project structure for execution
setup_execution_project_structure() {
    log_info "📁 Setting up project structure for execution..."
    
    local required_dirs=("models" "data" "logs" "results" "config" "outputs")
    
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_debug "Created directory: $dir"
        fi
    done
    
    # Create subdirectories
    mkdir -p data/processed data/raw
    mkdir -p models/checkpoints models/saved
    mkdir -p logs/training logs/application
    mkdir -p results/experiments results/plots
    mkdir -p outputs/predictions outputs/analysis
    
    log_success "✅ Project structure ready"
}

# Execute main application
execute_main_application() {
    log_info "🚀 Starting main application execution..."
    
    # Export environment variables
    export_execution_environment_variables
    
    # Find and execute main script
    local main_script
    main_script=$(find_main_script)
    
    if [[ -n "$main_script" ]]; then
        log_info "📍 Found main script: $main_script"
        execute_python_script "$main_script"
    else
        log_error "❌ No main script found"
        show_main_script_options
        return 1
    fi
}

# Export environment variables for execution
export_execution_environment_variables() {
    # Export configuration paths
    export CONFIG_PATH="$CONFIG_PATH"
    export DATA_PATH="$DATA_PATH"
    export PYTHONPATH="${PYTHONPATH:-./src}"
    
    # Export application configuration if available
    if [[ -f "$CONFIG_PATH" ]] && command -v yq >/dev/null 2>&1; then
        export APP_MODEL_TYPE=$(yq eval '.model.type // "transformer"' "$CONFIG_PATH")
        export APP_BATCH_SIZE=$(yq eval '.data.batch_size // 32' "$CONFIG_PATH")
        export APP_EPOCHS=$(yq eval '.training.epochs // 100' "$CONFIG_PATH")
        export APP_USE_FKS_FEATURES=$(yq eval '.features.use_fks_features // true' "$CONFIG_PATH")
        export APP_ENVIRONMENT=$(yq eval '.app.environment // "development"' "$CONFIG_PATH")
    fi
    
    # Export system information
    export FKS_PYTHON_ENV_TYPE="$PYTHON_ENV_TYPE"
    export FKS_EXECUTION_TIME=$(date '+%Y-%m-%d_%H-%M-%S')
    
    log_debug "Environment variables exported"
}

# Find main script
find_main_script() {
    local main_scripts=(
        "./src/main.py"
        "./src/python/main.py"
        "./src/python/transformer/main.py"
        "./main.py"
        "./app.py"
        "./run_model.py"
        "./train.py"
    )
    
    for script in "${main_scripts[@]}"; do
        if [[ -f "$script" ]]; then
            echo "$script"
            return 0
        fi
    done
    
    return 1
}

# Execute Python script with monitoring
execute_python_script() {
    local script="$1"
    local start_time
    start_time=$(date +%s)
    
    log_info "🚀 Executing: python $script --config '$CONFIG_PATH' --data '$DATA_PATH'"
    
    # Create execution log
    local log_file="logs/execution_${FKS_EXECUTION_TIME}.log"
    
    # Execute with comprehensive error handling and logging
    {
        echo "FKS Trading Systems Execution Log"
        echo "Started: $(date)"
        echo "Script: $script"
        echo "Config: $CONFIG_PATH"
        echo "Data: $DATA_PATH"
        echo "Environment: $PYTHON_ENV_TYPE"
        echo "================================"
        echo ""
    } > "$log_file"
    
    # Execute the script
    if python "$script" --config "$CONFIG_PATH" --data "$DATA_PATH" 2>&1 | tee -a "$log_file"; then
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        log_success "🎉 Application completed successfully!"
        log_info "Execution time: ${duration} seconds"
        
        # Show execution summary
        show_execution_summary "$log_file" "$duration"
        
        return 0
    else
        local exit_code=$?
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        log_error "❌ Application failed with exit code $exit_code"
        log_info "Execution time: ${duration} seconds"
        
        # Show error analysis
        show_execution_error_analysis "$log_file" "$exit_code"
        
        return $exit_code
    fi
}

# Show execution summary
show_execution_summary() {
    local log_file="$1"
    local duration="$2"
    
    echo ""
    log_info "📊 Execution Summary"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Duration: ${duration} seconds"
    echo "Log file: $log_file"
    
    # Check for output files
    check_generated_outputs
    
    # Show resource usage if available
    show_resource_usage_summary
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Check generated outputs
check_generated_outputs() {
    echo ""
    echo "Generated outputs:"
    
    # Check for model files
    if [[ -d "models" ]]; then
        local model_files
        model_files=$(find models -name "*.pt" -o -name "*.pth" -o -name "*.pkl" 2>/dev/null | wc -l)
        echo "  Models: $model_files files"
    fi
    
    # Check for results
    if [[ -d "results" ]]; then
        local result_files
        result_files=$(find results -type f 2>/dev/null | wc -l)
        echo "  Results: $result_files files"
    fi
    
    # Check for plots
    if [[ -d "outputs" ]]; then
        local plot_files
        plot_files=$(find outputs -name "*.png" -o -name "*.jpg" -o -name "*.pdf" 2>/dev/null | wc -l)
        echo "  Plots: $plot_files files"
    fi
    
    # Check for predictions
    local prediction_files
    prediction_files=$(find . -name "*prediction*" -o -name "*forecast*" 2>/dev/null | wc -l)
    echo "  Predictions: $prediction_files files"
}

# Show resource usage summary
show_resource_usage_summary() {
    echo ""
    echo "Resource usage:"
    
    # Memory usage (if available in logs)
    if command -v ps >/dev/null 2>&1; then
        echo "  Peak memory: $(ps -o rss= -p $ | awk '{print $1/1024 " MB"}' 2>/dev/null || echo "unknown")"
    fi
    
    # GPU usage (if available)
    if command -v nvidia-smi >/dev/null 2>&1; then
        echo "  GPU status: Available"
    else
        echo "  GPU status: Not available/used"
    fi
    
    # Disk usage change
    local final_size
    final_size=$(du -sh . 2>/dev/null | cut -f1)
    echo "  Final project size: $final_size"
}

# Show execution error analysis
show_execution_error_analysis() {
    local log_file="$1"
    local exit_code="$2"
    
    echo ""
    log_error "❌ Execution Error Analysis"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Exit code: $exit_code"
    echo "Log file: $log_file"
    
    # Extract error information from log
    if [[ -f "$log_file" ]]; then
        echo ""
        echo "Recent errors from log:"
        grep -i "error\|exception\|traceback\|failed" "$log_file" | tail -10 || echo "No obvious errors found in log"
        
        echo ""
        echo "Last 10 lines of log:"
        tail -10 "$log_file"
    fi
    
    # Common error suggestions
    suggest_error_solutions "$exit_code"
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Suggest error solutions
suggest_error_solutions() {
    local exit_code="$1"
    
    echo ""
    echo "Suggested solutions:"
    
    case $exit_code in
        1)
            echo "  - Check configuration file syntax"
            echo "  - Verify data file exists and is readable"
            echo "  - Check Python dependencies"
            ;;
        2)
            echo "  - Check command line arguments"
            echo "  - Verify file paths are correct"
            ;;
        126)
            echo "  - Check file permissions"
            echo "  - Ensure script is executable"
            ;;
        127)
            echo "  - Check if Python is in PATH"
            echo "  - Verify script exists"
            ;;
        137)
            echo "  - Process was killed (out of memory?)"
            echo "  - Check system resources"
            ;;
        *)
            echo "  - Check the log file for detailed error information"
            echo "  - Verify all dependencies are installed"
            echo "  - Check system resources (memory, disk space)"
            ;;
    esac
}

# Show main script options when none found
show_main_script_options() {
    echo ""
    log_info "📝 No main script found. Available options:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "1) Create a basic main script"
    echo "2) Run interactive Python session"
    echo "3) Run Jupyter notebook"
    echo "4) Exit"
    echo ""
    
    echo "Select option (1-4): "
    read -r REPLY
    
    case $REPLY in
        1)
            create_basic_main_script
            ;;
        2)
            run_interactive_python
            ;;
        3)
            run_jupyter_notebook
            ;;
        4|*)
            log_info "Exiting..."
            return 1
            ;;
    esac
}

# Create basic main script
create_basic_main_script() {
    local main_script="./main.py"
    
    log_info "📝 Creating basic main script: $main_script"
    
    cat > "$main_script" << 'EOF'
#!/usr/bin/env python3
"""
FKS Trading Systems - Main Application
Auto-generated main script
"""

import argparse
import logging
import sys
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description='FKS Trading Systems')
    parser.add_argument('--config', type=str, default='./config/app_config.yaml',
                       help='Configuration file path')
    parser.add_argument('--data', type=str, default='./data/raw_gc_data.csv',
                       help='Data file path')
    
    args = parser.parse_args()
    
    logger.info("Starting FKS Trading Systems")
    logger.info(f"Config: {args.config}")
    logger.info(f"Data: {args.data}")
    
    # Check if files exist
    config_path = Path(args.config)
    data_path = Path(args.data)
    
    if not config_path.exists():
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)
    
    if not data_path.exists():
        logger.warning(f"Data file not found: {data_path}")
    
    try:
        # Import required modules
        import pandas as pd
        import numpy as np
        
        logger.info("Loading data...")
        if data_path.exists():
            data = pd.read_csv(data_path)
            logger.info(f"Data shape: {data.shape}")
            logger.info(f"Columns: {list(data.columns)}")
        
        logger.info("Loading configuration...")
        # Add your configuration loading logic here
        
        logger.info("Initializing model...")
        # Add your model initialization logic here
        
        logger.info("Training/Running model...")
        # Add your main processing logic here
        
        logger.info("Saving results...")
        # Add your results saving logic here
        
        logger.info("FKS Trading Systems completed successfully!")
        
    except ImportError as e:
        logger.error(f"Missing dependency: {e}")
        logger.error("Please install required packages")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF
    
    chmod +x "$main_script"
    log_success "✅ Basic main script created: $main_script"
    
    echo "Run the script now? (y/N): "
    read -r REPLY
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        execute_python_script "$main_script"
    fi
}

# Run interactive Python session
run_interactive_python() {
    log_info "🐍 Starting interactive Python session..."
    
    # Setup environment variables
    export_execution_environment_variables
    
    # Start Python with useful imports
    python -c "
import sys
import os
import pandas as pd
import numpy as np

print('FKS Trading Systems - Interactive Python Session')
print('===============================================')
print(f'Python: {sys.version}')
print(f'Working directory: {os.getcwd()}')
print(f'Config: {os.environ.get(\"CONFIG_PATH\", \"Not set\")}')
print(f'Data: {os.environ.get(\"DATA_PATH\", \"Not set\")}')
print('')
print('Available imports: pandas as pd, numpy as np')
print('Type exit() to quit')
print('')
" && python -i
}

# Run Jupyter notebook
run_jupyter_notebook() {
    log_info "📓 Starting Jupyter notebook..."
    
    # Check if Jupyter is installed
    if ! python -c "import jupyter" 2>/dev/null; then
        log_info "Installing Jupyter..."
        pip install jupyter notebook
    fi
    
    # Create notebooks directory
    mkdir -p notebooks
    
    # Create a sample notebook if none exists
    if [[ ! -f "notebooks/fks_analysis.ipynb" ]]; then
        create_sample_notebook
    fi
    
    # Setup environment variables
    export_execution_environment_variables
    
    # Start Jupyter
    log_info "Starting Jupyter notebook server..."
    echo "Open your browser to the URL shown below"
    cd notebooks && jupyter notebook --ip=0.0.0.0 --port=8888 --no-browser --allow-root
}

# Create sample notebook
create_sample_notebook() {
    local notebook_file="notebooks/fks_analysis.ipynb"
    
    cat > "$notebook_file" << 'EOF'
{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# FKS Trading Systems Analysis\n",
    "\n",
    "This notebook provides a starting point for analyzing your trading data and testing the FKS system."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "source": [
    "# Import required libraries\n",
    "import pandas as pd\n",
    "import numpy as np\n",
    "import matplotlib.pyplot as plt\n",
    "import os\n",
    "\n",
    "# Configuration\n",
    "config_path = os.environ.get('CONFIG_PATH', '../config/app_config.yaml')\n",
    "data_path = os.environ.get('DATA_PATH', '../data/raw_gc_data.csv')\n",
    "\n",
    "print(f'Config: {config_path}')\n",
    "print(f'Data: {data_path}')"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "source": [
    "# Load and explore data\n",
    "if os.path.exists(data_path):\n",
    "    data = pd.read_csv(data_path)\n",
    "    print(f'Data shape: {data.shape}')\n",
    "    print(f'Columns: {list(data.columns)}')\n",
    "    data.head()\n",
    "else:\n",
    "    print(f'Data file not found: {data_path}')"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "source": [
    "# Basic data analysis\n",
    "if 'data' in locals():\n",
    "    # Plot basic statistics\n",
    "    plt.figure(figsize=(12, 8))\n",
    "    \n",
    "    # Subplot 1: Data overview\n",
    "    plt.subplot(2, 2, 1)\n",
    "    data.describe()\n",
    "    \n",
    "    # Add your analysis here\n",
    "    plt.show()"
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.8.0"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 4
}
EOF
    
    log_success "✅ Sample notebook created: $notebook_file"
}

# Cleanup execution environment
cleanup_execution_environment() {
    log_info "🧹 Cleaning up execution environment..."
    
    # Deactivate Python environment
    deactivate_python_environment
    
    # Clean up temporary files
    find /tmp -name "*fks*" -user "$(whoami)" -delete 2>/dev/null || true
    
    log_info "📴 Python environment deactivated"
}

# Advanced execution options
advanced_execution_menu() {
    while true; do
        echo ""
        log_info "🔬 Advanced Execution Options"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "1) 🧪 Run with profiling"
        echo "2) 🐛 Run with debugging"
        echo "3) 📊 Run with monitoring"
        echo "4) 🔄 Run with auto-restart"
        echo "5) 📈 Benchmark execution"
        echo "6) 🧮 Parameter sweep"
        echo "7) 📋 Generate execution report"
        echo "8) ⬅️  Back to main execution"
        echo ""
        
        echo "Select advanced option (1-8): "
        read -r REPLY
        
        case $REPLY in
            1) run_with_profiling ;;
            2) run_with_debugging ;;
            3) run_with_monitoring ;;
            4) run_with_auto_restart ;;
            5) benchmark_execution ;;
            6) parameter_sweep ;;
            7) generate_execution_report ;;
            8|*) break ;;
        esac
        
        echo ""
        echo "Press Enter to continue..."
        read -r
    done
}

# Run with profiling
run_with_profiling() {
    log_info "🧪 Running with performance profiling..."
    
    local main_script
    main_script=$(find_main_script)
    
    if [[ -n "$main_script" ]]; then
        export_execution_environment_variables
        
        # Run with cProfile
        python -m cProfile -o "logs/profile_${FKS_EXECUTION_TIME}.prof" \
               "$main_script" --config "$CONFIG_PATH" --data "$DATA_PATH"
        
        log_success "✅ Profile saved to logs/profile_${FKS_EXECUTION_TIME}.prof"
        
        # Generate human-readable profile report
        python -c "
import pstats
p = pstats.Stats('logs/profile_${FKS_EXECUTION_TIME}.prof')
p.sort_stats('cumulative').print_stats(20)
" > "logs/profile_report_${FKS_EXECUTION_TIME}.txt"
        
        log_success "✅ Profile report saved to logs/profile_report_${FKS_EXECUTION_TIME}.txt"
    else
        log_error "No main script found for profiling"
    fi
}

# Run with debugging
run_with_debugging() {
    log_info "🐛 Running with debugging enabled..."
    
    local main_script
    main_script=$(find_main_script)
    
    if [[ -n "$main_script" ]]; then
        export_execution_environment_variables
        export PYTHONPATH="${PYTHONPATH:-./src}"
        
        # Run with pdb
        python -m pdb "$main_script" --config "$CONFIG_PATH" --data "$DATA_PATH"
    else
        log_error "No main script found for debugging"
    fi
}

# Run with monitoring
run_with_monitoring() {
    log_info "📊 Running with system monitoring..."
    
    local main_script
    main_script=$(find_main_script)
    
    if [[ -n "$main_script" ]]; then
        export_execution_environment_variables
        
        # Start monitoring in background
        {
            while true; do
                echo "$(date): $(ps -o pid,%cpu,%mem,command -p $)" >> "logs/monitoring_${FKS_EXECUTION_TIME}.log"
                sleep 10
            done
        } &
        local monitor_pid=$!
        
        # Run main script
        python "$main_script" --config "$CONFIG_PATH" --data "$DATA_PATH"
        
        # Stop monitoring
        kill $monitor_pid 2>/dev/null || true
        
        log_success "✅ Monitoring log saved to logs/monitoring_${FKS_EXECUTION_TIME}.log"
    else
        log_error "No main script found for monitoring"
    fi
}

# Placeholder functions for remaining advanced options
run_with_auto_restart() {
    echo "🔄 Auto-restart execution not yet implemented"
}

benchmark_execution() {
    echo "📈 Execution benchmarking not yet implemented"
}

parameter_sweep() {
    echo "🧮 Parameter sweep not yet implemented"
}

generate_execution_report() {
    echo "📋 Execution report generation not yet implemented"
}

# Export functions
export -f run_python_application execute_main_application
export -f advanced_execution_menu run_with_profiling run_with_debugging
export -f run_interactive_python run_jupyter_notebook
export -f create_basic_main_script