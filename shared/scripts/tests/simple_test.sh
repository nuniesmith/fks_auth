#!/bin/bash
# Simple test to find the exact line causing the issue

echo "🔍 Testing .env file line by line..."

# First, test if the file can be sourced at all
echo "1. Testing basic source:"
if source .env 2>/dev/null; then
    echo "✅ .env sources successfully"
else
    echo "❌ .env has issues, testing line by line..."
    
    # Test each line individually
    line_num=0
    while IFS= read -r line || [ -n "$line" ]; do
        ((line_num++))
        
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Test if this line can be evaluated
        if ! echo "$line" | bash -n 2>/dev/null; then
            echo "❌ Syntax error on line $line_num: $line"
            continue
        fi
        
        # Test if this line can be sourced
        if ! bash -c "$line" 2>/dev/null; then
            echo "❌ Execution error on line $line_num: $line"
            
            # Show the exact error
            echo "   Error details:"
            bash -c "$line" 2>&1 | head -3 | sed 's/^/   /'
        fi
        
    done < .env
fi

echo ""
echo "2. Testing with set -e (strict mode like the main script):"
if bash -c "set -e; source .env" 2>/dev/null; then
    echo "✅ .env works with strict mode"
else
    echo "❌ .env fails with strict mode"
    echo "   Error:"
    bash -c "set -e; source .env" 2>&1 | head -5 | sed 's/^/   /'
fi

echo ""
echo "3. Looking for problematic patterns:"

# Check for unescaped special characters
echo "Checking for unescaped special characters..."
grep -n '[;&|<>()]' .env | head -5 | sed 's/^/   Line /'

# Check for variables that might look like commands
echo "Checking for potential command-like variables..."
grep -n '^[A-Z_]*=.*[[:space:]]' .env | head -5 | sed 's/^/   Line /'

echo ""
echo "4. Manual line-by-line source test:"
line_num=0
while IFS= read -r line || [ -n "$line" ]; do
    ((line_num++))
    
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    
    # Try to source just this line
    if ! (set -e; eval "$line") 2>/dev/null; then
        echo "❌ Problem line $line_num: $line"
        echo "   Error:"
        (set -e; eval "$line") 2>&1 | sed 's/^/   /'
        break
    else
        echo "✅ Line $line_num OK"
    fi
    
done < .env