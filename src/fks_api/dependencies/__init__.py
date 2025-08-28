"""FastAPI dependency utilities (placeholders)."""

from .auth import get_current_user  # noqa: F401
from .database import get_db  # noqa: F401

__all__ = ["get_current_user", "get_db"]

