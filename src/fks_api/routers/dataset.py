"""
Dataset management endpoints used by the web UI for split and verification.

These are intentionally lightweight and file-backed so the UI can function
in development without the full data stack. Replace with TimescaleDB logic
when available.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Body

router = APIRouter(prefix="/data/dataset", tags=["dataset"])


def _data_dir() -> Path:
    base = os.getenv("DATA_DIR", "/app/data")
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _split_file() -> Path:
    return _data_dir() / "dataset_split.json"


@router.post("/split")
async def set_split(payload: Dict[str, int] = Body(...)) -> Dict[str, Any]:
    train = int(payload.get("train", 0))
    val = int(payload.get("val", 0))
    test = int(payload.get("test", 0))
    if train < 0 or val < 0 or test < 0 or train + val + test != 100:
        return {"ok": False, "error": "Split must be non-negative and sum to 100"}
    data = {"train": train, "val": val, "test": test}
    _split_file().write_text(json.dumps(data, indent=2))
    return {"ok": True, "split": data}


@router.post("/verify")
async def verify_split() -> Dict[str, Any]:
    try:
        if not _split_file().exists():
            return {"ok": False, "message": "No split configured"}
        data = json.loads(_split_file().read_text())
        ok = int(data.get("train", 0)) == 80 and int(data.get("val", 0)) == 10 and int(data.get("test", 0)) == 10
        return {"ok": ok, "split": data}
    except Exception as e:
        return {"ok": False, "error": str(e)}
