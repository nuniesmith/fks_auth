"""
API Routes v1

This package contains all version 1 API routes.
"""

from typing import Dict, List, Optional

from fastapi import APIRouter, FastAPI
from loguru import logger


# Import all routers with error handling
def _import_router(module_name: str) -> Optional[APIRouter]:
    """Import a router with error handling."""
    try:
        module_path = f".{module_name}"
        module = __import__(module_path, globals(), locals(), ["router"], 1)
        return module.router
    except ImportError as e:
        logger.warning(f"Could not import {module_name} router: {str(e)}")
        return None
    except AttributeError as e:
        logger.warning(f"Router not found in {module_name} module: {str(e)}")
        return None


# Import all routers explicitly for direct use
auth_router = _import_router("auth")
backtest_router = _import_router("backtest")
data_router = _import_router("data")
health_router = _import_router("health")
sentiment_router = _import_router("sentiment")
status_router = _import_router("status")
strategy_router = _import_router("strategy")
trading_router = _import_router("trading")
visualization_router = _import_router("visualization")

# Special handling for CLI that has additional functions
try:
    from .cli import cli_router, initialize_cli_routes
except ImportError as e:
    logger.warning(f"Could not import CLI router: {str(e)}")
    cli_router = None

    def initialize_cli_routes(app: FastAPI, prefix: str) -> None:
        logger.warning("CLI routes not available")
        pass


# Dictionary for reference if needed
routers_dict: Dict[str, Optional[APIRouter]] = {
    "auth": auth_router,
    "backtest": backtest_router,
    "data": data_router,
    "health": health_router,
    "sentiment": sentiment_router,
    "status": status_router,
    "strategy": strategy_router,
    "trading": trading_router,
    "visualization": visualization_router,
    "cli_commands": cli_router,
}

# List of routers for easy inclusion in the main app
# Filter out None values from potentially failed imports
routers: List[APIRouter] = [
    router
    for router in [
        health_router,
        sentiment_router,
        status_router,
        visualization_router,
        cli_router,
    ]
    if router is not None
]


def setup_v1_routes(app: FastAPI, prefix: str = "/api/v1") -> None:
    """
    Initialize all v1 API routes.

    Args:
        app: The FastAPI application
        prefix: URL prefix for all v1 routes
    """
    # Register core routers explicitly
    for name, router in routers_dict.items():
        try:
            # Skip CLI router as it's handled separately
            if name == "cli_commands" or router is None:
                continue

            app.include_router(router, prefix=prefix, tags=[name])
            logger.info(f"Loaded v1 router: {name}")
        except Exception as e:
            logger.error(f"Failed to load v1 router {name}: {str(e)}")

    # Initialize CLI routes separately to handle sub-components
    if cli_router is not None:
        try:
            cli_prefix = f"{prefix}/cli"
            initialize_cli_routes(app, cli_prefix)
            logger.info(f"Initialized CLI routes with prefix: {cli_prefix}")
        except Exception as e:
            logger.error(f"Failed to initialize CLI routes: {str(e)}")

    logger.info(f"All v1 routes initialized with prefix: {prefix}")


# Aliases for compatibility with different naming conventions
initialize_routes = setup_v1_routes
setup_routes = setup_v1_routes

# Export everything for easy importing
__all__ = [
    "auth_router",
    "backtest_router",
    "data_router",
    "health_router",
    "sentiment_router",
    "status_router",
    "strategy_router",
    "trading_router",
    "visualization_router",
    "cli_router",
    "routers_dict",
    "routers",
    "setup_v1_routes",
    "initialize_routes",
    "setup_routes",
]
