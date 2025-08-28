"""Service dependencies (placeholders)."""

from typing import Any


def get_service(name: str) -> Any:  # pragma: no cover - placeholder
	return {"name": name}


__all__ = ["get_service"]

