"""
Signals API: scan simple signals and send notifications for live/manual trading.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import requests
from fastapi import APIRouter, Depends
from loguru import logger

from framework.middleware.auth import get_auth_token, authenticate_user
from services.api.services.data_service import DataService


router = APIRouter(prefix="/signals", tags=["signals"])


def _svc() -> DataService:
    return DataService()


def _find_dt_col(df: pd.DataFrame) -> Optional[str]:
    for c in df.columns:
        cl = str(c).lower()
        if "date" in cl or "time" in cl:
            return c
    return None


@router.post("/scan")
async def scan_signals(
    source: str,
    symbol: str,
    interval: str = "1h",
    z_threshold: float = 3.0,
    lookback: int = 500,
    token: str = Depends(get_auth_token),
) -> Dict[str, Any]:
    """Scan for simple return z-score breakout signals (BUY/SELL)."""
    authenticate_user(token)
    svc = _svc()
    now = datetime.utcnow()
    df = await svc.get_data(source=source, symbol=symbol, interval=interval, end_date=now)
    if df is None or df.empty:
        return {"ok": True, "events": []}
    dtc = _find_dt_col(df)
    if dtc is None or "close" not in df.columns:
        return {"ok": True, "events": []}
    df[dtc] = pd.to_datetime(df[dtc])
    df = df.sort_values(dtc).tail(max(100, lookback))
    r = df["close"].pct_change().fillna(0.0)
    if len(r) < 10:
        return {"ok": True, "events": []}
    z = (r - r.rolling(100, min_periods=10).mean()) / (r.rolling(100, min_periods=10).std(ddof=0) + 1e-9)
    z = z.fillna(0.0)
    last_z = float(z.iloc[-1])
    ts = df[dtc].iloc[-1].isoformat()
    events: List[Dict[str, Any]] = []
    if last_z >= z_threshold:
        events.append({"type": "BUY", "symbol": symbol, "interval": interval, "ts": ts, "z": last_z})
    elif last_z <= -z_threshold:
        events.append({"type": "SELL", "symbol": symbol, "interval": interval, "ts": ts, "z": last_z})
    return {"ok": True, "events": events, "last_z": last_z}


@router.post("/notify")
async def notify(
    content: str,
    webhook_url: Optional[str] = None,
    token: str = Depends(get_auth_token),
) -> Dict[str, Any]:
    authenticate_user(token)
    url = webhook_url or os.getenv("DISCORD_WEBHOOK_URL")
    if not url:
        return {"ok": False, "error": "No webhook_url provided and DISCORD_WEBHOOK_URL not set"}
    if not url.startswith("https://discord.com/api/webhooks/"):
        return {"ok": False, "error": "Invalid webhook domain"}
    try:
        r = requests.post(url, json={"content": content}, timeout=10)
        r.raise_for_status()
        return {"ok": True}
    except Exception as e:
        logger.warning(f"notify error: {e}")
        return {"ok": False, "error": str(e)}
