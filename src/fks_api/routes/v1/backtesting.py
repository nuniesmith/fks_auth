"""Backtesting routes (placeholder)."""

from fastapi import APIRouter


router = APIRouter(prefix="/backtesting", tags=["backtesting"])


@router.get("/status")
def status() -> dict[str, str]:  # pragma: no cover
	return {"status": "idle"}


__all__ = ["router"]

"""Backtesting endpoints"""
