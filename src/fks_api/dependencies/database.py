"""Database dependencies (placeholders)."""

from contextlib import contextmanager
from typing import Iterator


@contextmanager
def get_db() -> Iterator[object]:  # pragma: no cover - placeholder
	db = object()
	try:
		yield db
	finally:
		pass


__all__ = ["get_db"]

