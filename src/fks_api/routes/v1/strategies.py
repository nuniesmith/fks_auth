"""Strategies routes (placeholder)."""

from fastapi import APIRouter


router = APIRouter(prefix="/strategies", tags=["strategies"])


@router.get("/names")
def list_strategy_names() -> list[str]:  # pragma: no cover
	return []


__all__ = ["router"]

"""Strategy management endpoints"""
