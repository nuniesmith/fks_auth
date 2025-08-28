"""
API endpoints for data quality reports, cross-validation, and dataset splitting.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger

from framework.middleware.auth import get_auth_token, authenticate_user
from services.api.services.data_service import DataService
from services.data.validation import validate_ohlcv, cross_validate, compute_time_splits
from services.data.splitting import split_managed_csv


router = APIRouter(prefix="/data-quality", tags=["data-quality"])


def _svc() -> DataService:
    return DataService()


@router.get("/quality")
async def quality(
    source: str,
    symbol: str,
    interval: str = "1d",
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    token: str = Depends(get_auth_token),
) -> Dict[str, Any]:
    authenticate_user(token)
    svc = _svc()
    df = await svc.get_data(source=source, symbol=symbol, interval=interval, start_date=start, end_date=end)
    rep = validate_ohlcv(df).to_dict()
    return {"ok": True, "report": rep}


@router.get("/cross-validate")
async def cross_validate_endpoint(
    source_a: str,
    symbol_a: str,
    source_b: str,
    symbol_b: str,
    interval: str = "1d",
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    token: str = Depends(get_auth_token),
) -> Dict[str, Any]:
    authenticate_user(token)
    svc = _svc()
    df_a = await svc.get_data(source=source_a, symbol=symbol_a, interval=interval, start_date=start, end_date=end)
    df_b = await svc.get_data(source=source_b, symbol=symbol_b, interval=interval, start_date=start, end_date=end)
    out = cross_validate(df_a, df_b)
    return {"ok": True, **out}


@router.post("/split")
async def make_splits(
    source: str,
    symbol: str,
    interval: str = "1d",
    token: str = Depends(get_auth_token),
) -> Dict[str, Any]:
    authenticate_user(token)
    paths = split_managed_csv(source, symbol, interval)
    return {"ok": True, "files": [str(p) for p in paths]}
