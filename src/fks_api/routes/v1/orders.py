"""Order routes (placeholder)."""

from fastapi import APIRouter


router = APIRouter(prefix="/orders", tags=["orders"])


@router.get("/")
def list_orders() -> list[dict[str, str]]:  # pragma: no cover
	return []


__all__ = ["router"]

"""Order management endpoints"""
