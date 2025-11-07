#!/bin/bash

# Directory Tree to Markdown Script - Fixed Version
# Usage: ./dir_tree_fixed.sh [directory_path] [output_file] [max_depth]
# Example: ./dir_tree_fixed.sh /path/to/dir output.md 3

# Default values
DEFAULT_DIR="."
DEFAULT_OUTPUT="dir_tree.md"
DEFAULT_DEPTH=3

# Get arguments or use defaults
TARGET_DIR="${1:-$DEFAULT_DIR}"
OUTPUT_FILE="${2:-$DEFAULT_OUTPUT}"
MAX_DEPTH="${3:-$DEFAULT_DEPTH}"

# Function to print usage
usage() {
    echo "Usage: $0 [directory_path] [output_file] [max_depth]"
    echo "  directory_path: Path to the directory to scan (default: current directory)"
    echo "  output_file: Output markdown file (default: dir_tree.md)"
    echo "  max_depth: Maximum depth to scan (default: 3)"
    echo ""
    echo "Examples:"
    echo "  $0                              # Scan current dir, output to dir_tree.md, depth 3"
    echo "  $0 /home/user/project           # Scan specific dir"
    echo "  $0 . structure.md 5             # Custom output file and depth"
}

# Check if help is requested
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
    exit 0
fi

# Validate target directory
if [[ ! -d "$TARGET_DIR" ]]; then
    echo "Error: Directory '$TARGET_DIR' does not exist."
    exit 1
fi

# Convert to absolute path
TARGET_DIR=$(realpath "$TARGET_DIR")

# Start generating the markdown file
echo "Generating directory tree for: $TARGET_DIR"
echo "Output file: $OUTPUT_FILE"
echo "Max depth: $MAX_DEPTH"
echo ""

# Create the markdown file
cat > "$OUTPUT_FILE" << EOF
# Directory Tree

**Path:** \`$TARGET_DIR\`  
**Generated:** $(date)  
**Max Depth:** $MAX_DEPTH  

\`\`\`
EOF

# Check if tree command is available
if command -v tree >/dev/null 2>&1; then
    echo "Using tree command..."
    # Use tree command with proper options
    if [[ "$SHOW_HIDDEN" == "true" ]]; then
        tree -a -L "$MAX_DEPTH" --charset=ascii "$TARGET_DIR" >> "$OUTPUT_FILE"
    else
        tree -L "$MAX_DEPTH" --charset=ascii "$TARGET_DIR" >> "$OUTPUT_FILE"
    fi
else
    echo "Tree command not found, using find-based approach..."
    
    # Add the root directory
    echo "$(basename "$TARGET_DIR")/" >> "$OUTPUT_FILE"
    
    # Create a temporary file to store the structure
    TEMP_FILE=$(mktemp)
    
    # Find all items up to max depth
    find "$TARGET_DIR" -maxdepth "$MAX_DEPTH" | \
    grep -v "^$TARGET_DIR$" | \
    sort > "$TEMP_FILE"
    
    # Process each item
    while IFS= read -r item; do
        # Skip hidden files unless requested
        if [[ "$(basename "$item")" == .* ]] && [[ "$SHOW_HIDDEN" != "true" ]]; then
            continue
        fi
        
        # Calculate relative path
        rel_path="${item#$TARGET_DIR/}"
        
        # Count the depth (number of slashes)
        depth=$(echo "$rel_path" | tr -cd '/' | wc -c)
        
        # Skip if beyond max depth
        if [[ $depth -ge $MAX_DEPTH ]]; then
            continue
        fi
        
        # Create indentation
        indent=""
        for ((i=0; i<depth; i++)); do
            indent="$indent    "
        done
        
        # Get the item name
        item_name=$(basename "$item")
        
        # Add directory indicator
        if [[ -d "$item" ]]; then
            echo "${indent}├── ${item_name}/" >> "$OUTPUT_FILE"
        else
            echo "${indent}├── ${item_name}" >> "$OUTPUT_FILE"
        fi
        
    done < "$TEMP_FILE"
    
    # Clean up temp file
    rm -f "$TEMP_FILE"
fi

# Close the code block
echo '```' >> "$OUTPUT_FILE"

echo ""
echo "Directory tree has been saved to: $OUTPUT_FILE"
echo ""
echo "To view the file:"
echo "  cat $OUTPUT_FILE"
echo ""
echo "To include hidden files, run:"
echo "  SHOW_HIDDEN=true $0 \"$TARGET_DIR\" \"$OUTPUT_FILE\" $MAX_DEPTH"
