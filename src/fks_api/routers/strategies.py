"""
Strategies listing and assignment persistence for UI wiring.

This is a lightweight, file-backed implementation. Replace with DB-backed
storage when the engine is ready.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Body

router = APIRouter(tags=["strategies"])  # we'll set explicit paths below


def _data_dir() -> Path:
    base = os.getenv("DATA_DIR", "/app/data")
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _assignments_file() -> Path:
    return _data_dir() / "strategy_assignments.json"


def _strategies_file() -> Path:
    return _data_dir() / "strategies.json"


# Seed with a few demo strategies if none exist
_DEMO_STRATEGIES: List[Dict[str, Any]] = [
    {"id": "ma_cross", "name": "MA Cross", "type": "entry", "status": "active"},
    {"id": "rsi_filter", "name": "RSI Filter", "type": "filter", "status": "testing"},
    {"id": "atr_trail", "name": "ATR Trailing Stop", "type": "exit", "status": "active"},
]


@router.get("/strategies")
async def list_strategies() -> Dict[str, Any]:
    try:
        if _strategies_file().exists():
            items = json.loads(_strategies_file().read_text())
        else:
            items = _DEMO_STRATEGIES
            _strategies_file().write_text(json.dumps(items, indent=2))
        return {"items": items, "count": len(items)}
    except Exception as e:
        return {"items": [], "count": 0, "error": str(e)}


@router.get("/strategy/assignments")
async def get_assignments() -> Dict[str, Any]:
    try:
        if _assignments_file().exists():
            data = json.loads(_assignments_file().read_text())
        else:
            data = {}
        return {"assignments": data}
    except Exception as e:
        return {"assignments": {}, "error": str(e)}


@router.post("/strategy/assignments")
async def save_assignments(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    try:
        assignments = payload.get("assignments") or {}
        if not isinstance(assignments, dict):
            return {"ok": False, "error": "Invalid assignments object"}
        _assignments_file().write_text(json.dumps(assignments, indent=2))
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}
