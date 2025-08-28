"""
Monitoring Setup Module

This module provides functions to set up the monitoring routes in a FastAPI application.
"""

from fastapi import FastAPI
from loguru import logger

from .routes import router


def setup_monitoring(app: FastAPI, prefix: str = "/api") -> None:
    """
    Set up monitoring routes in a FastAPI application.

    Args:
        app: The FastAPI application
        prefix: URL prefix for the monitoring routes (default: "/api")
    """
    app.include_router(router, prefix=prefix)
    logger.info(f"Monitoring routes registered with prefix: {prefix}")
