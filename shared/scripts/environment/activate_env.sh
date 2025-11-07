#!/bin/bash
# Activate the fks_env conda environment

# Initialize conda
eval "$(conda shell.bash hook)" 2>/dev/null || {
    if [ -f "$HOME/miniconda3/etc/profile.d/conda.sh" ]; then
        source "$HOME/miniconda3/etc/profile.d/conda.sh"
    elif [ -f "$HOME/anaconda3/etc/profile.d/conda.sh" ]; then
        source "$HOME/anaconda3/etc/profile.d/conda.sh"
    elif [ -f "/opt/conda/etc/profile.d/conda.sh" ]; then
        source "/opt/conda/etc/profile.d/conda.sh"
    fi
}

conda activate fks_env

if [ "$CONDA_DEFAULT_ENV" = "fks_env" ]; then
    echo "🚀 Conda environment 'fks_env' activated"
    echo "Python: $(which python)"
    echo "Pip: $(which pip)"
    
    python -c "
import torch
print(f'PyTorch: {torch.__version__}')
print(f'CUDA available: {torch.cuda.is_available()}')
if torch.cuda.is_available():
    print(f'GPU: {torch.cuda.get_device_name(0)}')
else:
    print('Running on CPU')
"
else
    echo "❌ Failed to activate environment"
fi
