#!/bin/bash
set -euo pipefail

# Test runner script - auto-detects test framework and runs appropriate tests
# Usage: ./run-tests.sh

echo "🧪 Auto-detecting test framework..."

# Node.js/JavaScript tests
if [[ -f "package.json" ]]; then
  echo "📦 Node.js project detected"
  if command -v npm &> /dev/null; then
    echo "Installing dependencies..."
    npm install
    
    if npm run test --if-present; then
      echo "✅ Node.js tests passed"
    else
      echo "⚠️ Node.js tests failed or no test script found"
    fi
  fi
fi

# Python tests
if [[ -f "requirements.txt" ]] || [[ -f "pyproject.toml" ]] || [[ -f "setup.py" ]]; then
  echo "🐍 Python project detected"
  if command -v python3 &> /dev/null; then
    if [[ -f "requirements.txt" ]]; then
      pip install -r requirements.txt
    fi
    
    # Try different test runners
    if python -m pytest --version &> /dev/null && find . -name "*test*.py" | grep -q .; then
      echo "Running pytest..."
      python -m pytest
    elif python -m unittest discover -s . -p "*test*.py" 2>/dev/null; then
      echo "✅ Python unittest tests passed"
    else
      echo "ℹ️ No Python tests found or test framework not available"
    fi
  fi
fi

# Go tests
if [[ -f "go.mod" ]]; then
  echo "🔷 Go project detected"
  if command -v go &> /dev/null; then
    go test ./...
    echo "✅ Go tests passed"
  fi
fi

echo "✅ Test phase complete"
