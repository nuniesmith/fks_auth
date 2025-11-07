#!/bin/bash
# (Relocated) Basic GPU availability test.
set -e
echo "🎮 GPU Test"; if command -v nvidia-smi >/dev/null 2>&1; then nvidia-smi || true; else echo "No GPU detected"; fi
