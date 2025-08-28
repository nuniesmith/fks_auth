"""
Minimal ingestion endpoint for transformer service.

Accepts market/news payloads and returns 202 Accepted with an echo. In the
future, this can enqueue to Redis or call the transformer service directly.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from framework.middleware.auth import get_auth_token, authenticate_user


router = APIRouter(prefix="/transformer", tags=["transformer"])


class IngestPayload(BaseModel):
    kind: str = Field(..., description="Type of payload, e.g., 'market', 'news'")
    source: Optional[str] = Field(None, description="Source identifier")
    symbol: Optional[str] = Field(None, description="Market symbol if applicable")
    data: Dict[str, Any] = Field(default_factory=dict, description="Payload body")


@router.post("/ingest", status_code=202)
async def ingest(payload: IngestPayload, token: str = Depends(get_auth_token)) -> Dict[str, Any]:
    user = authenticate_user(token)
    # For now, just acknowledge receipt; hook up to queue/bus in future
    return {
        "status": "accepted",
        "received_at": datetime.utcnow().isoformat(),
        "user": user.get("sub"),
        "kind": payload.kind,
        "source": payload.source,
        "symbol": payload.symbol,
        "size": len(payload.data) if isinstance(payload.data, dict) else 0,
    }
