"""
API Monitoring Module

This module provides endpoints for monitoring the health and performance of the API.
It includes health checks, metrics collection, circuit breaker status, and alert management.

Usage:
    from api.routes.monitoring import router as monitoring_router
    app.include_router(monitoring_router, prefix="/api")

Or use the setup module:
    from api.routes.monitoring.setup import setup_monitoring
    setup_monitoring(app, prefix="/api")
"""

from fastapi import APIRouter

from . import models

# Import main components
from .routes import router
from .setup import setup_monitoring

# Re-export the main components for easy importing
__all__ = ["router", "setup_monitoring", "models"]
