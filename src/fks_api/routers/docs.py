"""
Documentation API Router
Serves markdown documentation files from the docs directory
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
import os
from pathlib import Path

router = APIRouter(prefix="/docs", tags=["documentation"])

# Base path for documentation
# In Docker, docs are mounted at /app/docs
DOCS_BASE_PATH = Path("/app/docs")

@router.get("/{file_path:path}", response_class=PlainTextResponse)
async def get_documentation(file_path: str):
    """
    Get documentation file content
    
    Args:
        file_path: Path to the documentation file relative to docs directory
        
    Returns:
        Plain text content of the markdown file
    """
    # Default to README.md if no path specified
    if not file_path:
        file_path = "README.md"
    
    # Construct full path
    full_path = DOCS_BASE_PATH / file_path
    
    # Security check - ensure path is within docs directory
    try:
        full_path = full_path.resolve()
        DOCS_BASE_PATH.resolve()
        if not str(full_path).startswith(str(DOCS_BASE_PATH)):
            raise HTTPException(status_code=403, detail="Access denied")
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid path")
    
    # Check if file exists
    if not full_path.exists() or not full_path.is_file():
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Read and return file content
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return content
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")
