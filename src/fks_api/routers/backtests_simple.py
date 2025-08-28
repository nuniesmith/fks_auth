"""
Simple Backtests API to support UI flow quickly.

This endpoint accepts code/language/parameters and returns computed
summary metrics synchronously (mock). Replace with real engine when ready.
"""
from __future__ import annotations

import hashlib
import time
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from loguru import logger

from framework.middleware.auth import get_auth_token, authenticate_user

router = APIRouter(prefix="/backtests", tags=["backtests"])


class BacktestInput(BaseModel):
    code: str
    language: str
    parameters: Dict[str, Any]
    asset: Optional[str] = None
    exchange: Optional[str] = None
    reducedParams: Optional[bool] = None


class BacktestResult(BaseModel):
    winRate: float
    totalReturn: float
    maxDrawdown: float
    sharpeRatio: float
    startedAt: str
    finishedAt: str


def _hash_str(s: str) -> int:
    return int(hashlib.sha256(s.encode("utf-8")).hexdigest(), 16) & 0xFFFFFFFF


@router.post("")
async def run_backtest(input: BacktestInput, token: str = Depends(get_auth_token)) -> BacktestResult:
    authenticate_user(token)
    try:
        started = datetime.utcnow().isoformat()
        seed_str = (
            input.code
            + input.language
            + (input.asset or "")
            + (input.exchange or "")
            + str(sorted(input.parameters.items()))
            + str(bool(input.reducedParams))
        )
        seed = _hash_str(seed_str)

        # Very light pseudo-random based on seed
        def rnd(n: int) -> float:
            h = (seed ^ (n * 0x9E3779B1)) & 0xFFFFFFFF
            h ^= (h << 13) & 0xFFFFFFFF
            h ^= (h >> 17) & 0xFFFFFFFF
            h ^= (h << 5) & 0xFFFFFFFF
            return (h % 10000) / 10000.0

        # Simulate compute time
        time.sleep(0.05)

        win_rate = 50 + round(rnd(1) * 30, 1)
        total_return = round((rnd(2) - 0.2) * 40, 1)
        max_dd = -round(5 + rnd(3) * 15, 1)
        sharpe = round(0.8 + rnd(4) * 2.0 + (0.2 if input.reducedParams else 0.0), 2)

        finished = datetime.utcnow().isoformat()
        return BacktestResult(
            winRate=win_rate,
            totalReturn=total_return,
            maxDrawdown=max_dd,
            sharpeRatio=sharpe,
            startedAt=started,
            finishedAt=finished,
        )
    except Exception as e:
        logger.error(f"Backtest error: {e}")
        raise HTTPException(status_code=500, detail=f"Backtest failed: {e}")
