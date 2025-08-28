"""Authentication dependencies (placeholders)."""

from fastapi import Depends, HTTPException, status


def get_current_user(token: str | None = None):  # pragma: no cover - placeholder
	if not token:
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
	return {"sub": "anonymous"}


__all__ = ["get_current_user"]

