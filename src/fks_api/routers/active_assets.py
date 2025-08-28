"""
Active Assets API router

Endpoints under /api/active-assets to manage tracked symbols and backfill progress.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from loguru import logger

from services.api.services.data_service import DataService
from services.data.active_assets import (
    ActiveAsset,
    ActiveAssetStore,
    BackfillScheduler,
)
from framework.middleware.auth import get_auth_token, authenticate_user


router = APIRouter(prefix="/active-assets", tags=["active-assets"])

_store = ActiveAssetStore()
_datasvc: Optional[DataService] = None
_scheduler: Optional[BackfillScheduler] = None


def _get_datasvc() -> DataService:
    global _datasvc
    if _datasvc is None:
        _datasvc = DataService()
    return _datasvc


def _ensure_scheduler() -> BackfillScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackfillScheduler(store=_store)
        # Start scheduler with a fetcher callback that uses DataService
        datasvc = _get_datasvc()

        def fetcher_cb(source: str, symbol: str, interval: str, start_date: Optional[datetime], end_date: Optional[datetime]):
            import asyncio

            # Use run loop if inside event loop, else create a new one
            async def _run():
                df = await datasvc.get_data(
                    source=source,
                    symbol=symbol,
                    start_date=start_date,
                    end_date=end_date,
                    interval=interval,
                    limit=None,
                )
                return df

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Run blocking
                    return asyncio.run(_run())
                return loop.run_until_complete(_run())
            except Exception:
                # Fallback simple run
                return asyncio.run(_run())

        _scheduler.start(fetcher_cb)
    return _scheduler


def _assignments_map() -> dict:
    try:
        p = Path(os.getenv("DATA_DIR", "/app/data")) / "strategy_assignments.json"
        if p.exists():
            return json.loads(p.read_text())
    except Exception:
        pass
    return {}


@router.get("")
async def list_assets(token: str = Depends(get_auth_token)) -> Dict[str, Any]:
    authenticate_user(token)
    assets = _store.list_assets()
    assigns = _assignments_map()
    for a in assets:
        aid = str(a.get("id"))
        a["assigned_strategies"] = len(assigns.get(aid, []))
    return {"items": assets, "count": len(assets)}


@router.post("")
async def add_asset(payload: Dict[str, Any], token: str = Depends(get_auth_token)) -> Dict[str, Any]:
    authenticate_user(token)
    try:
        source = str(payload.get("source") or "auto").strip()
        symbol = str(payload.get("symbol") or "").strip()
        intervals = payload.get("intervals") or ["1d"]
        asset_type = payload.get("asset_type")
        exchange = payload.get("exchange")
        years = payload.get("years")
        full_history = bool(payload.get("full_history", False))
        if not source or not symbol:
            raise HTTPException(status_code=400, detail="source and symbol are required")
        asset = ActiveAsset(
            id=None,
            source=source,
            symbol=symbol,
            asset_type=asset_type,
            exchange=exchange,
            intervals=list(intervals),
            years=int(years) if years is not None else None,
            full_history=full_history,
            enabled=True,
        )
        asset_id = _store.add_asset(asset)
        # Ensure scheduler is running
        _ensure_scheduler()
        return {"id": asset_id, "ok": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"add_asset error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{asset_id}")
async def remove_asset(asset_id: int, token: str = Depends(get_auth_token)) -> Dict[str, Any]:
    authenticate_user(token)
    ok = _store.remove_asset(asset_id)
    if not ok:
        raise HTTPException(status_code=404, detail="asset not found")
    return {"ok": True}


@router.post("/{asset_id}/enable")
async def enable_asset(asset_id: int, enable: bool = True, token: str = Depends(get_auth_token)) -> Dict[str, Any]:
    authenticate_user(token)
    _store.set_enabled(asset_id, enable)
    return {"ok": True}


@router.post("/scheduler/start")
async def start_scheduler(token: str = Depends(get_auth_token)) -> Dict[str, Any]:
    authenticate_user(token)
    _ensure_scheduler()
    return {"ok": True}


@router.post("/scheduler/stop")
async def stop_scheduler(token: str = Depends(get_auth_token)) -> Dict[str, Any]:
    authenticate_user(token)
    global _scheduler
    if _scheduler:
        _scheduler.stop()
        _scheduler = None
    return {"ok": True}
