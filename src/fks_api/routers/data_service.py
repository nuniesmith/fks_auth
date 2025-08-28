"""
Lightweight Data API router to support the FKS Data page quickly.

This avoids heavy v1 dependencies and provides pragmatic endpoints under /api/data.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from loguru import logger

from services.api.services.data_service import DataService
from framework.middleware.auth import get_auth_token, authenticate_user

router = APIRouter(prefix="/data", tags=["data"])

_data_service: Optional[DataService] = None

def get_data_service() -> DataService:
    global _data_service
    if _data_service is None:
        _data_service = DataService()
    return _data_service


@router.get("/sources")
async def list_sources(token: str = Depends(get_auth_token)) -> Dict[str, Any]:
    authenticate_user(token)
    svc = get_data_service()
    sources = await svc.list_sources()
    return {"sources": sources, "count": len(sources)}


@router.get("/sources/{source_id}")
async def source_info(source_id: str, token: str = Depends(get_auth_token)) -> Dict[str, Any]:
    authenticate_user(token)
    svc = get_data_service()
    if not await svc.has_source(source_id):
        raise HTTPException(status_code=404, detail=f"Unknown source: {source_id}")
    info = await svc.get_source_info(source_id)
    return info


@router.get("/sources/{source_id}/symbols")
async def symbols(
    source_id: str,
    query: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    token: str = Depends(get_auth_token),
) -> Dict[str, Any]:
    authenticate_user(token)
    svc = get_data_service()
    if not await svc.has_source(source_id):
        raise HTTPException(status_code=404, detail=f"Unknown source: {source_id}")
    items, total = await svc.get_symbols(source_id, query=query, limit=limit)
    return {"symbols": items, "count": len(items), "total": total}


@router.get("/sources/{source_id}/data/{symbol}", response_model=None)
async def market_data(
    source_id: str,
    symbol: str,
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    interval: str = Query("1d"),
    limit: int = Query(1000, ge=1, le=10000),
    page_token: Optional[str] = Query(None, description="Opaque pagination token from previous response"),
    format: str = Query("json", pattern="^(json|csv)$"),
    token: str = Depends(get_auth_token),
):
    authenticate_user(token)
    svc = get_data_service()
    if not await svc.has_source(source_id):
        raise HTTPException(status_code=404, detail=f"Unknown source: {source_id}")

    sd = datetime.fromisoformat(start_date) if start_date else None
    ed = datetime.fromisoformat(end_date) if end_date else None

    page_df, total, next_token = await svc.get_data_page(
        source=source_id,
        symbol=symbol,
        start_date=sd,
        end_date=ed,
        interval=interval,
        limit=limit,
        page_token=page_token,
    )

    if format == "csv":
        csv_bytes = page_df.to_csv(index=False).encode("utf-8")
        return StreamingResponse(
            iter([csv_bytes]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={symbol}_{interval}.csv",
                "X-Total-Count": str(total),
                "X-Next-Page-Token": next_token or "",
            },
        )

    return {
        "symbol": symbol,
        "source": source_id,
        "interval": interval,
        "count": len(page_df),
        "total": total,
        "next_page_token": next_token,
        "columns": list(page_df.columns),
        "data": page_df.to_dict(orient="records"),
    }


@router.get("/sources/{source_id}/availability/{symbol}")
async def availability(
    source_id: str,
    symbol: str,
    token: str = Depends(get_auth_token),
) -> Dict[str, Any]:
    authenticate_user(token)
    svc = get_data_service()
    if not await svc.has_source(source_id):
        raise HTTPException(status_code=404, detail=f"Unknown source: {source_id}")
    info = await svc.get_symbol_availability(source_id, symbol)
    return {"source": source_id, "symbol": symbol, **info}
