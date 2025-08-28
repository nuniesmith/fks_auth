import asyncio
import json
import os
import platform
import socket
import sys
import threading
import time
from datetime import datetime, timedelta
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Literal, Optional

import psutil
from core.telemetry.telemetry import telemetry
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from framework.infrastructure.monitoring.metrics.request_metrics import HealthResponse
from framework.middleware.auth import (
    authenticate_user,
    check_permission,
    get_auth_token,
)
from loguru import logger
from pydantic import BaseModel, Field

# Configure logger
logger = logger.opt(colors=True).getLogger("health_api")

# Constants
CHECK_INTERVAL_SECONDS = 30  # How often to refresh the detailed health info

# Start time of the application
start_time = datetime.now()

# Cache for health check data to avoid running expensive checks on every request
last_check_time = datetime.min
health_cache = {}
health_cache_lock = threading.Lock()


# Enum for health status
class HealthStatus(str, Enum):
    """Possible health statuses for the application and its components."""

    OK = "ok"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    STARTING = "starting"
    UNKNOWN = "unknown"


# Models
class ComponentHealth(BaseModel):
    """Health information for a single component."""

    status: HealthStatus
    message: Optional[str] = None
    last_check: Optional[datetime] = None
    latency_ms: Optional[float] = None
    details: Optional[Dict[str, Any]] = None


class SystemInfo(BaseModel):
    """System information."""

    hostname: str
    cpu_percent: float
    cpu_count: int
    memory_total_mb: float
    memory_available_mb: float
    memory_percent: float
    disk_usage_percent: float
    python_version: str
    platform: str
    process_id: int
    uptime_seconds: float
    load_average: List[float] = Field(default_factory=list)
    network_connections: int


class DependencyHealth(BaseModel):
    """Health information for a dependency."""

    status: HealthStatus
    name: str
    type: str
    latency_ms: Optional[float] = None
    message: Optional[str] = None
    last_check: datetime


class DetailedHealthResponse(BaseModel):
    """Detailed health response including all components."""

    status: HealthStatus
    version: str
    environment: str
    timestamp: datetime
    uptime_seconds: float
    components: Dict[str, ComponentHealth]
    system: SystemInfo
    dependencies: List[DependencyHealth]
    checks_age_seconds: float


# Create router
router = APIRouter(tags=["health"])


# Helper functions
def get_version() -> str:
    """Get the application version from environment or default to unknown."""
    return os.environ.get("APP_VERSION", "unknown")


def get_environment() -> str:
    """Get the deployment environment from environment variable."""
    return os.environ.get("APP_ENVIRONMENT", "development")


@lru_cache(maxsize=1)
def get_hostname() -> str:
    """Get the hostname of the server."""
    return socket.gethostname()


async def check_database_health() -> ComponentHealth:
    """Check the health of the database connection."""
    try:
        # This would be replaced with your actual database check logic
        # For example: await db.execute("SELECT 1")
        start_time = time.time()
        # Simulate a database check with a small delay
        await asyncio.sleep(0.05)
        elapsed_ms = (time.time() - start_time) * 1000

        return ComponentHealth(
            status=HealthStatus.OK,
            message="Database connection successful",
            last_check=datetime.now(),
            latency_ms=elapsed_ms,
            details={
                "connection_pool_size": 10,
                "active_connections": 2,
            },  # Example values
        )
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        return ComponentHealth(
            status=HealthStatus.UNHEALTHY,
            message=f"Database connection failed: {str(e)}",
            last_check=datetime.now(),
        )


async def check_cache_health() -> ComponentHealth:
    """Check the health of the cache service."""
    try:
        # This would be replaced with your actual cache check logic
        # For example: await redis_client.ping()
        start_time = time.time()
        # Simulate a cache check with a small delay
        await asyncio.sleep(0.02)
        elapsed_ms = (time.time() - start_time) * 1000

        return ComponentHealth(
            status=HealthStatus.OK,
            message="Cache service responding",
            last_check=datetime.now(),
            latency_ms=elapsed_ms,
            details={"cached_items": 1245, "memory_usage_mb": 42.5},  # Example values
        )
    except Exception as e:
        logger.error(f"Cache health check failed: {str(e)}")
        return ComponentHealth(
            status=HealthStatus.UNHEALTHY,
            message=f"Cache service check failed: {str(e)}",
            last_check=datetime.now(),
        )


async def check_external_apis() -> Dict[str, ComponentHealth]:
    """Check health of external APIs."""
    results = {}

    # Example APIs to check - replace with your actual dependencies
    apis = {
        "market_data_api": "https://api.market-data.example.com/health",
        "auth_service": "https://auth.example.com/health",
    }

    for name, url in apis.items():
        try:
            # This would be replaced with your actual API check logic
            # For example: async with httpx.AsyncClient() as client: await client.get(url)
            start_time = time.time()
            # Simulate an API check with a small delay
            await asyncio.sleep(0.1)
            elapsed_ms = (time.time() - start_time) * 1000

            results[name] = ComponentHealth(
                status=HealthStatus.OK,
                message=f"API responding",
                last_check=datetime.now(),
                latency_ms=elapsed_ms,
            )
        except Exception as e:
            logger.error(f"API health check failed for {name}: {str(e)}")
            results[name] = ComponentHealth(
                status=HealthStatus.UNHEALTHY,
                message=f"API check failed: {str(e)}",
                last_check=datetime.now(),
            )

    return results


def get_system_info() -> SystemInfo:
    """Get detailed system information."""
    mem = psutil.virtual_memory()

    try:
        load_avg = [round(x, 2) for x in os.getloadavg()]
    except (AttributeError, OSError):
        # Windows doesn't support getloadavg
        load_avg = []

    current_time = datetime.now()
    uptime_seconds = (current_time - start_time).total_seconds()

    return SystemInfo(
        hostname=get_hostname(),
        cpu_percent=psutil.cpu_percent(interval=0.5),
        cpu_count=psutil.cpu_count(),
        memory_total_mb=mem.total / (1024 * 1024),
        memory_available_mb=mem.available / (1024 * 1024),
        memory_percent=mem.percent,
        disk_usage_percent=psutil.disk_usage("/").percent,
        python_version=platform.python_version(),
        platform=platform.platform(),
        process_id=os.getpid(),
        uptime_seconds=uptime_seconds,
        load_average=load_avg,
        network_connections=len(psutil.net_connections()),
    )


async def get_detailed_health() -> DetailedHealthResponse:
    """
    Get detailed health information for all components.
    This is an expensive operation, so results are cached.
    """
    global last_check_time, health_cache

    current_time = datetime.now()

    # Check if we need to refresh the cache
    with health_cache_lock:
        cache_age = (current_time - last_check_time).total_seconds()
        if cache_age < CHECK_INTERVAL_SECONDS and health_cache:
            # Update the age of checks in the cached response
            if "checks_age_seconds" in health_cache:
                health_cache["checks_age_seconds"] = cache_age
            return DetailedHealthResponse(**health_cache)

    # Perform all health checks
    db_health = await check_database_health()
    cache_health = await check_cache_health()
    external_apis_health = await check_external_apis()
    system_info = get_system_info()

    # Collect all component health information
    components = {"database": db_health, "cache": cache_health, **external_apis_health}

    # Collect all dependency health information
    dependencies = [
        DependencyHealth(
            status=(
                HealthStatus.OK
                if db_health.status == HealthStatus.OK
                else HealthStatus.UNHEALTHY
            ),
            name="database",
            type="postgresql",  # Example - replace with your actual database type
            latency_ms=db_health.latency_ms,
            message=db_health.message,
            last_check=db_health.last_check or current_time,
        ),
        DependencyHealth(
            status=(
                HealthStatus.OK
                if cache_health.status == HealthStatus.OK
                else HealthStatus.UNHEALTHY
            ),
            name="cache",
            type="redis",  # Example - replace with your actual cache type
            latency_ms=cache_health.latency_ms,
            message=cache_health.message,
            last_check=cache_health.last_check or current_time,
        ),
    ]

    # Add external API dependencies
    for name, health in external_apis_health.items():
        dependencies.append(
            DependencyHealth(
                status=(
                    HealthStatus.OK
                    if health.status == HealthStatus.OK
                    else HealthStatus.UNHEALTHY
                ),
                name=name,
                type="external_api",
                latency_ms=health.latency_ms,
                message=health.message,
                last_check=health.last_check or current_time,
            )
        )

    # Determine overall status
    status = HealthStatus.OK
    if any(c.status == HealthStatus.UNHEALTHY for c in components.values()):
        status = HealthStatus.UNHEALTHY
    elif any(c.status == HealthStatus.DEGRADED for c in components.values()):
        status = HealthStatus.DEGRADED

    # Create the response
    response = DetailedHealthResponse(
        status=status,
        version=get_version(),
        environment=get_environment(),
        timestamp=current_time,
        uptime_seconds=system_info.uptime_seconds,
        components=components,
        system=system_info,
        dependencies=dependencies,
        checks_age_seconds=0,  # Fresh check
    )

    # Update the cache
    with health_cache_lock:
        last_check_time = current_time
        health_cache = response.dict()

    return response


def determine_status_code(health_status: HealthStatus) -> int:
    """Determine the HTTP status code based on health status."""
    if health_status == HealthStatus.OK:
        return status.HTTP_200_OK
    elif health_status == HealthStatus.DEGRADED:
        return status.HTTP_200_OK  # Still operational but degraded
    elif health_status == HealthStatus.STARTING:
        return status.HTTP_503_SERVICE_UNAVAILABLE
    else:  # UNHEALTHY or UNKNOWN
        return status.HTTP_503_SERVICE_UNAVAILABLE


# Routes
@router.get("/health", response_model=HealthResponse)
async def basic_health_check():
    """
    Basic health check endpoint for quick status checks.
    This is a lightweight endpoint suitable for frequent health monitoring.
    """
    current_time = datetime.now()
    uptime_seconds = (current_time - start_time).total_seconds()

    # Get CPU and memory usage with minimal overhead
    cpu_percent = psutil.cpu_percent(interval=None)  # Non-blocking call
    memory_info = psutil.virtual_memory()

    # Get system information
    system_info = {
        "cpu_percent": cpu_percent,
        "memory_percent": memory_info.percent,
        "disk_usage_percent": psutil.disk_usage("/").percent,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "process_id": os.getpid(),
    }

    # Determine status based on simple thresholds
    system_status = HealthStatus.OK
    if cpu_percent > 90 or memory_info.percent > 90:
        system_status = HealthStatus.DEGRADED

    return HealthResponse(
        status=system_status,
        timestamp=current_time.isoformat(),
        uptime=uptime_seconds,
        system_info=system_info,
    )


@router.get("/health/detailed", response_model=DetailedHealthResponse)
async def detailed_health_check(
    response: Response,
    refresh: bool = Query(False, description="Force refresh of health checks"),
    level: str = Query("basic", description="Level of detail for system info"),
    token: Optional[str] = Depends(get_auth_token),
):
    """
    Detailed health check endpoint that performs comprehensive checks on all components.
    This endpoint is more expensive to call and should be used less frequently.

    Args:
        response: FastAPI response object
        refresh: Whether to force a refresh of cached health data
        level: Level of detail for system info (basic, detailed)
        token: Optional authentication token for additional information

    Returns:
        Detailed health information for all components
    """
    # Check if token is provided and authenticate for additional access
    try:
        if token:
            user = authenticate_user(token)
            # Additional check for admin role if needed
            is_admin = "admin" in user.get("roles", [])
        else:
            is_admin = False
    except Exception:
        is_admin = False

    # If refresh is requested and user is admin, invalidate the cache
    if refresh and is_admin:
        with health_cache_lock:
            global last_check_time
            last_check_time = datetime.min

    # Get detailed health info
    health_info = await get_detailed_health()

    # Set appropriate status code
    response.status_code = determine_status_code(health_info.status)

    # Add custom headers
    response.headers["X-Health-Status"] = health_info.status
    response.headers["X-Uptime-Seconds"] = str(int(health_info.uptime_seconds))

    # If not admin and level is not detailed, remove sensitive information
    if not is_admin and level != "detailed":
        # Remove detailed system info and simplify the response
        simplified_system = {
            "status": health_info.status,
            "uptime_seconds": health_info.uptime_seconds,
            "environment": health_info.environment,
            "version": health_info.version,
        }
        return JSONResponse(content=simplified_system)

    return health_info


@router.get("/health/readiness")
async def readiness_probe():
    """
    Readiness probe endpoint for Kubernetes and other orchestrators.
    Reports if the application is ready to receive traffic.
    """
    # Check if the application is ready to serve requests
    if (datetime.now() - start_time).total_seconds() < 10:
        # Application still starting up
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "starting", "ready": False},
        )

    # For a more accurate check, you could verify dependencies
    try:
        # Example dependency check - minimal version
        db_health = await check_database_health()
        cache_health = await check_cache_health()

        if db_health.status == HealthStatus.UNHEALTHY:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "status": "not_ready",
                    "ready": False,
                    "reason": "Database connection failed",
                },
            )

        if cache_health.status == HealthStatus.UNHEALTHY:
            # We might still be ready even if cache is down
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "status": "ready_degraded",
                    "ready": True,
                    "warning": "Cache service unavailable",
                },
            )

        return JSONResponse(content={"status": "ready", "ready": True})

    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "error", "ready": False, "reason": str(e)},
        )


@router.get("/health/liveness")
async def liveness_probe():
    """
    Liveness probe endpoint for Kubernetes and other orchestrators.
    Reports if the application is alive and not deadlocked.
    """
    # This is a minimal check - the fact that we can respond means we're alive
    return {"status": "alive"}


@router.get("/health/metrics")
async def health_metrics(token: str = Depends(get_auth_token)):
    """
    Health metrics endpoint for monitoring systems.
    Returns metrics in a format suitable for monitoring systems.

    Args:
        token: Authentication token (required)

    Returns:
        Health metrics
    """
    # Authenticate and verify permissions
    user = authenticate_user(token)
    check_permission(user, "metrics:read")

    # Get system metrics
    try:
        metrics = {
            "uptime_seconds": (datetime.now() - start_time).total_seconds(),
            "cpu": {
                "percent": psutil.cpu_percent(interval=0.5),
                "count": psutil.cpu_count(),
                "per_cpu": psutil.cpu_percent(interval=0.5, percpu=True),
            },
            "memory": {
                "total_mb": psutil.virtual_memory().total / (1024 * 1024),
                "available_mb": psutil.virtual_memory().available / (1024 * 1024),
                "percent": psutil.virtual_memory().percent,
                "swap_percent": psutil.swap_memory().percent,
            },
            "disk": {
                "usage_percent": psutil.disk_usage("/").percent,
                "total_gb": psutil.disk_usage("/").total / (1024 * 1024 * 1024),
                "free_gb": psutil.disk_usage("/").free / (1024 * 1024 * 1024),
            },
            "network": {
                "connections": len(psutil.net_connections()),
                # Add more network stats if needed
            },
            "process": {
                "pid": os.getpid(),
                "threads": threading.active_count(),
                "open_files": len(psutil.Process(os.getpid()).open_files()),
            },
        }

        return metrics

    except Exception as e:
        logger.error(f"Error collecting metrics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error collecting metrics: {str(e)}",
        )
