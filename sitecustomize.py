"""Simplified sys.path bootstrap (shared removed).

Adds only service local `src/` for imports.
"""
from __future__ import annotations
import sys, pathlib
root = pathlib.Path(__file__).resolve().parent
src = root/"src"
if src.is_dir():
    sp = str(src)
    if sp not in sys.path:
        sys.path.insert(0, sp)
