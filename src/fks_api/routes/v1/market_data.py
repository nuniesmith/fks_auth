"""Market data endpoints (placeholder)."""

from fastapi import APIRouter


router = APIRouter(prefix="/market", tags=["market"])


@router.get("/ping")
def ping() -> dict[str, str]:  # pragma: no cover
	return {"pong": "market"}


__all__ = ["router"]

