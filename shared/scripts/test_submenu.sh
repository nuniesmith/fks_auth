#!/bin/bash
# Test script for show_docker_hub_submenu

# Source the main script to get the functions
source /home/jordan/code/repos/fks/run.sh

echo "Testing show_docker_hub_submenu function..."
echo ""

# Test with automated input (select back)
echo "b" | show_docker_hub_submenu

echo ""
echo "Test completed."
