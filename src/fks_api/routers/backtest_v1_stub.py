"""
Lightweight stub for v1 backtest endpoints.

Purpose: Provide a minimal, dependency-free implementation of the v1 backtest
API so the frontend can function even when heavy internal modules are missing.

Endpoints (under /api/v1/backtest):
 - POST /create
 - GET  /list
 - GET  /{backtest_id}/status
 - GET  /{backtest_id}/results
 - POST /{backtest_id}/cancel
 - GET  /stats
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Path, Query, status
from pydantic import BaseModel, Field


router = APIRouter(prefix="/backtest", tags=["backtest-v1-stub"])  # will be mounted under /api/v1


# -----------------------------
# Models (mirroring frontend)
# -----------------------------


class V1BacktestDataConfig(BaseModel):
    source: str
    symbols: List[str]
    start_date: str
    end_date: str
    interval: Optional[str] = "1d"


class V1BacktestStrategyConfig(BaseModel):
    type: str
    params: Dict[str, Any] = Field(default_factory=dict)


class V1BacktestRiskConfig(BaseModel):
    risk_per_trade: Optional[float] = None
    max_daily_loss_pct: Optional[float] = None
    max_position_size_pct: Optional[float] = None
    sizing_mode: Optional[str] = None
    atr_period: Optional[int] = None
    atr_mult: Optional[float] = None


class V1BacktestCreateConfig(BaseModel):
    name: str
    description: Optional[str] = None
    initial_capital: float = 100000.0
    commission: float = 0.001
    slippage: float = 0.0
    data: V1BacktestDataConfig
    strategy: V1BacktestStrategyConfig
    risk: Optional[V1BacktestRiskConfig] = None


class V1BacktestCreateResponse(BaseModel):
    backtest_id: str
    status: str
    message: str
    url: Optional[str] = None


class V1BacktestStatus(BaseModel):
    backtest_id: str
    name: str
    status: str
    progress: float
    message: str
    created_at: datetime
    updated_at: datetime
    estimated_completion: Optional[datetime] = None


class V1BacktestResultsResponse(BaseModel):
    backtest_id: str
    name: str
    description: Optional[str] = None
    summary: Dict[str, Any]
    metrics: Dict[str, Any]
    charts: Optional[List[Any]] = None
    trades: Optional[List[Any]] = None
    trades_count: Optional[int] = None
    trades_truncated: Optional[bool] = None


# -----------------------------
# In-memory state
# -----------------------------


_active: Dict[str, Dict[str, Any]] = {}
_results: Dict[str, Dict[str, Any]] = {}


def _now() -> datetime:
    return datetime.utcnow()


def _new_id() -> str:
    return f"bt_{uuid.uuid4().hex[:12]}"


def _simulate_results(symbols: List[str]) -> Dict[str, Any]:
    # Minimal deterministic-ish numbers
    total_return = 12.3
    win_rate = 0.56
    sharpe = 1.12
    mdd = -8.4
    return {
        "summary": {
            "total_return": total_return,
            "win_rate": win_rate,
            "max_drawdown": mdd,
            "sharpe_ratio": sharpe,
            "trades": 123,
            "symbols": symbols,
        },
        "metrics": {
            "total_return": total_return,
            "win_rate": win_rate,
            "max_drawdown": mdd,
            "sharpe_ratio": sharpe,
        },
        "sample_data": [
            {"time": int(_now().timestamp()), "equity": 100000.0},
            {"time": int((_now() + timedelta(minutes=1)).timestamp()), "equity": 100500.0},
            {"time": int((_now() + timedelta(minutes=2)).timestamp()), "equity": 112300.0},
        ],
        "charts": [],
    }


def _complete(backtest_id: str) -> None:
    bt = _active.get(backtest_id)
    if not bt:
        return
    res = _simulate_results(bt["config"]["data"]["symbols"])
    _results[backtest_id] = res
    bt.update(
        status="completed",
        progress=100.0,
        message="Backtest completed successfully",
        updated_at=_now(),
    )


def _advance(backtest_id: str, target: float, msg: str) -> None:
    bt = _active.get(backtest_id)
    if not bt:
        return
    bt.update(progress=target, message=msg, updated_at=_now())


def _run_simulation(backtest_id: str) -> None:
    # Lightweight, fast simulation; sleeps small amounts to allow UI polling
    try:
        _advance(backtest_id, 10.0, "Loading market data...")
        time.sleep(0.2)
        _advance(backtest_id, 35.0, "Preparing strategy...")
        time.sleep(0.2)
        _advance(backtest_id, 65.0, "Running backtest simulation...")
        time.sleep(0.4)
        _advance(backtest_id, 90.0, "Analyzing results...")
        time.sleep(0.2)
        _complete(backtest_id)
    except Exception as e:  # pragma: no cover - defensive
        bt = _active.get(backtest_id)
        if bt:
            bt.update(status="error", message=str(e), updated_at=_now())


# -----------------------------
# Routes
# -----------------------------


@router.post("/create", response_model=V1BacktestCreateResponse, status_code=status.HTTP_201_CREATED)
def create_backtest(config: V1BacktestCreateConfig, background_tasks: BackgroundTasks):
    bt_id = _new_id()
    _active[bt_id] = {
        "id": bt_id,
        "name": config.name,
        "description": config.description,
        "config": config.dict(),
        "status": "initialized",
        "progress": 0.0,
        "message": "Backtest created",
        "created_at": _now(),
        "updated_at": _now(),
        "estimated_completion": _now() + timedelta(seconds=2),
    }

    # Kick off background simulation
    background_tasks.add_task(_run_simulation, bt_id)

    return V1BacktestCreateResponse(
        backtest_id=bt_id,
        status="initialized",
        message="Backtest created and scheduled to run",
        url=f"/api/v1/backtest/{bt_id}/status",
    )


@router.get("/list", response_model=List[V1BacktestStatus])
def list_backtests() -> List[V1BacktestStatus]:
    out: List[V1BacktestStatus] = []
    for bt in _active.values():
        out.append(
            V1BacktestStatus(
                backtest_id=bt["id"],
                name=bt["name"],
                status=bt["status"],
                progress=float(bt.get("progress", 0.0)),
                message=bt.get("message", ""),
                created_at=bt["created_at"],
                updated_at=bt["updated_at"],
                estimated_completion=bt.get("estimated_completion"),
            )
        )
    return out


@router.get("/{backtest_id}/status", response_model=V1BacktestStatus)
def get_backtest_status(backtest_id: str = Path(...)) -> V1BacktestStatus:
    bt = _active.get(backtest_id)
    if not bt:
        raise HTTPException(status_code=404, detail="Backtest not found")
    return V1BacktestStatus(
        backtest_id=bt["id"],
        name=bt["name"],
        status=bt["status"],
        progress=float(bt.get("progress", 0.0)),
        message=bt.get("message", ""),
        created_at=bt["created_at"],
        updated_at=bt["updated_at"],
        estimated_completion=bt.get("estimated_completion"),
    )


@router.get("/{backtest_id}/results", response_model=V1BacktestResultsResponse)
def get_backtest_results(
    backtest_id: str = Path(...),
    include_trades: bool = Query(False),
    max_trades: int = Query(1000, ge=1, le=10000),
):
    if backtest_id not in _active:
        raise HTTPException(status_code=404, detail="Backtest not found")
    bt = _active[backtest_id]
    if bt["status"] != "completed":
        raise HTTPException(status_code=400, detail="Backtest not completed yet")
    res = _results.get(backtest_id) or {}
    trades = res.get("sample_data", []) if include_trades else None
    if trades is not None and len(trades) > max_trades:
        trades = trades[:max_trades]
        truncated = True
    else:
        truncated = False
    return V1BacktestResultsResponse(
        backtest_id=backtest_id,
        name=bt["name"],
        description=bt.get("description"),
        summary=res.get("summary", {}),
        metrics=res.get("metrics", {}),
        charts=res.get("charts", []),
        trades=trades,
        trades_count=(len(trades) if trades is not None else None),
        trades_truncated=(truncated if trades is not None else None),
    )


@router.post("/{backtest_id}/cancel")
def cancel_backtest(backtest_id: str = Path(...)) -> Dict[str, Any]:
    bt = _active.get(backtest_id)
    if not bt:
        raise HTTPException(status_code=404, detail="Backtest not found")
    if bt["status"] in {"completed", "cancelled"}:
        return {"backtest_id": backtest_id, "status": bt["status"], "message": "No action"}
    bt.update(status="cancelled", message="Backtest cancelled", updated_at=_now())
    return {"backtest_id": backtest_id, "status": "cancelled", "message": "Cancellation requested"}


@router.get("/stats")
def get_stats() -> Dict[str, Any]:
    by_status: Dict[str, int] = {}
    for bt in _active.values():
        s = bt["status"]
        by_status[s] = by_status.get(s, 0) + 1
    return {
        "counts": {
            "total": len(_active),
            "by_status": by_status,
        }
    }
