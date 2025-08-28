"""
Trading session control endpoints used by the UI to start/pause/stop sessions.

These are no-op stubs that record timestamps in-memory. Replace with actual
engine integration when available.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Query

router = APIRouter(prefix="/trading/sessions", tags=["trading-sessions"])

_state: Dict[str, Dict[str, Any]] = {
    "simulation": {"status": "idle"},
    "live": {"status": "idle"},
}


def _now() -> str:
    return datetime.utcnow().isoformat()


@router.post("/start")
async def start_session(mode: str = Query("simulation")) -> Dict[str, Any]:
    if mode not in ("simulation", "live"):
        return {"ok": False, "error": "invalid mode"}
    _state[mode].update({"status": "active", "startedAt": _now()})
    return {"ok": True, **_state[mode]}


@router.post("/pause")
async def pause_session(mode: str = Query("simulation")) -> Dict[str, Any]:
    if mode not in ("simulation", "live"):
        return {"ok": False, "error": "invalid mode"}
    _state[mode].update({"status": "paused", "pausedAt": _now()})
    return {"ok": True, **_state[mode]}


@router.post("/stop")
async def stop_session(mode: str = Query("simulation")) -> Dict[str, Any]:
    if mode not in ("simulation", "live"):
        return {"ok": False, "error": "invalid mode"}
    _state[mode].update({"status": "stopped", "stoppedAt": _now()})
    return {"ok": True, **_state[mode]}
