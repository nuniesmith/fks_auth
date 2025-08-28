"""
API Routes Package

This package contains all API routes organized by version and purpose.
"""

import importlib
import os
from typing import Callable, Dict, Optional

from fastapi import FastAPI
from loguru import logger

# Import setup functions
try:
    from .monitoring.setup import setup_monitoring
except ImportError:
    logger.warning(
        "Monitoring setup not found, monitoring routes will not be available"
    )

    # Define a dummy function if monitoring setup is not available
    def setup_monitoring(app: FastAPI, prefix: str = "/api"):
        logger.warning("Monitoring setup not available, skipping")
        pass


# Import v1 routes setup
try:
    # Try to import the setup_v1_routes function from v1 package
    from .v1 import setup_v1_routes
except ImportError:
    logger.warning("V1 setup_v1_routes not found, trying initialize_routes")
    try:
        # Try the older naming convention as fallback
        from .v1 import initialize_routes as setup_v1_routes
    except ImportError:
        logger.error(
            "No v1 route setup function found, v1 routes will not be available"
        )

        # Define a dummy function if v1 setup is not available
        def setup_v1_routes(app: FastAPI, prefix: str = "/api/v1"):
            logger.warning("V1 routes setup not available, skipping")
            pass


def _discover_version_modules() -> Dict[str, Callable]:
    """
    Dynamically discover all available version modules.

    Returns:
        Dict mapping version names to their setup functions
    """
    version_setups = {}
    # Look for version directories (v1, v2, etc.)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    for item in os.listdir(current_dir):
        if not os.path.isdir(os.path.join(current_dir, item)):
            continue

        if not item.startswith("v") or not item[1:].isdigit():
            continue

        version = item  # e.g., "v1", "v2"
        try:
            # Try to dynamically import the setup function
            module = importlib.import_module(f".{version}", package="api.routes")

            # Look for the setup function with different possible names
            setup_func = None
            for func_name in [
                f"setup_{version}_routes",
                "setup_routes",
                "initialize_routes",
            ]:
                if hasattr(module, func_name):
                    setup_func = getattr(module, func_name)
                    break

            if setup_func:
                version_setups[version] = setup_func
                logger.info(f"Discovered {version} routes")
            else:
                logger.warning(f"No setup function found in {version} module")
        except ImportError as e:
            logger.warning(f"Could not import {version} module: {str(e)}")

    return version_setups


def initialize_routes(app: FastAPI, base_prefix: str = "/api") -> None:
    """
    Initialize all API routes.

    This function sets up all API routes, both version-specific (like v1)
    and version-independent (like monitoring).

    Args:
        app: The FastAPI application
        base_prefix: Base prefix for all API routes
    """
    # Set up monitoring routes (version-independent)
    logger.info("Setting up monitoring routes...")
    try:
        setup_monitoring(app, prefix=base_prefix)
        logger.info("Monitoring routes setup completed")
    except Exception as e:
        logger.error(f"Failed to setup monitoring routes: {str(e)}")

    # Try to discover version modules dynamically
    version_setups = _discover_version_modules()

    if not version_setups:
        # Fall back to hardcoded v1 setup if dynamic discovery fails
        logger.info("No version modules discovered dynamically, using hardcoded v1")
        version_setups = {"v1": setup_v1_routes}

    # Set up all discovered version routes
    for version, setup_func in version_setups.items():
        logger.info(f"Setting up {version} routes...")
        try:
            version_prefix = f"{base_prefix}/{version}"
            setup_func(app, prefix=version_prefix)
            logger.info(
                f"{version} routes setup completed with prefix: {version_prefix}"
            )
        except Exception as e:
            logger.error(f"Failed to setup {version} routes: {str(e)}")

    logger.info(f"All routes initialized with base prefix: {base_prefix}")


# Alias for backward compatibility with factory.py
register_routes = initialize_routes

__all__ = ["initialize_routes", "register_routes"]
