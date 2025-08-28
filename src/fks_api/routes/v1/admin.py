"""Admin routes (placeholder)."""

from fastapi import APIRouter


router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/ping")
def ping() -> dict[str, str]:  # pragma: no cover
	return {"pong": "admin"}


__all__ = ["router"]

"""Admin endpoints"""
