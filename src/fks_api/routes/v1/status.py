import json
import os
import platform
import time
from datetime import datetime, timedelta
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Literal, Optional

import psutil
from core.telemetry.telemetry import telemetry
from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from framework.infrastructure.monitoring.metrics.request_metrics import StatusResponse
from framework.middleware.auth import (
    authenticate_user,
    cache_response,
    check_permission,
    get_auth_token,
    get_cached_response,
)
from loguru import logger
from pydantic import BaseModel, Field

# Configure logger
logger = logger.opt(colors=True).getLogger("status_api")

# Application start time
start_time = datetime.now()


# Status constants
class ComponentStatus(str, Enum):
    """Status values for system components."""

    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    OUTAGE = "outage"
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"


class ServiceTier(str, Enum):
    """Service tier levels."""

    FREE = "free"
    BASIC = "basic"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"


# models
class ComponentStatusInfo(BaseModel):
    """Status information for a system component."""

    status: ComponentStatus
    message: Optional[str] = None
    last_updated: Optional[datetime] = None
    metrics: Optional[Dict[str, Any]] = None


class DataSourceStatus(BaseModel):
    """Status information for a data source."""

    name: str
    status: ComponentStatus
    last_update: Optional[datetime] = None
    record_count: Optional[int] = None
    latency_ms: Optional[float] = None


class SystemResource(BaseModel):
    """System resource utilization information."""

    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    load_average: List[float]
    network_connections: int


class CacheStatus(BaseModel):
    """Cache status information."""

    enabled: bool
    hit_rate: Optional[float] = None
    item_count: Optional[int] = None
    size_mb: Optional[float] = None
    oldest_item: Optional[datetime] = None


class DetailedStatusResponse(BaseModel):
    """Detailed system status response."""

    status: str
    version: str
    environment: str
    timestamp: str
    uptime_seconds: float
    uptime_formatted: str
    components: Dict[str, ComponentStatusInfo]
    data_sources: List[DataSourceStatus]
    system_resources: SystemResource
    cache: Optional[CacheStatus] = None
    user_count: Optional[int] = None
    service_tier: Optional[ServiceTier] = None
    maintenance_mode: bool = False
    maintenance_message: Optional[str] = None
    rate_limits: Optional[Dict[str, Any]] = None


# Create router
router = APIRouter()


# Helper functions
def get_version() -> str:
    """Get the application version."""
    return os.environ.get("APP_VERSION", "1.0.0")


def get_environment() -> str:
    """Get the deployment environment."""
    return os.environ.get("APP_ENVIRONMENT", "production")


def format_uptime(seconds: float) -> str:
    """Format uptime in human-readable format."""
    delta = timedelta(seconds=seconds)
    days = delta.days
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if seconds > 0 or not parts:
        parts.append(f"{seconds}s")

    return " ".join(parts)


def get_system_resources() -> SystemResource:
    """Get current system resource utilization."""
    try:
        # Get load average or provide empty list if not available (e.g., on Windows)
        try:
            load_avg = [round(x, 2) for x in os.getloadavg()]
        except (AttributeError, OSError):
            load_avg = []

        return SystemResource(
            cpu_percent=psutil.cpu_percent(interval=0.1),
            memory_percent=psutil.virtual_memory().percent,
            disk_usage_percent=psutil.disk_usage("/").percent,
            load_average=load_avg,
            network_connections=len(psutil.net_connections()),
        )
    except Exception as e:
        logger.error(f"Error getting system resources: {str(e)}")
        # Return default values on error
        return SystemResource(
            cpu_percent=0.0,
            memory_percent=0.0,
            disk_usage_percent=0.0,
            load_average=[],
            network_connections=0,
        )


def check_data_sources(tracker) -> List[DataSourceStatus]:
    """Check status of all data sources."""
    data_sources = []

    try:
        # Check if tracker is available
        if tracker is None:
            return [
                DataSourceStatus(
                    name="tracker",
                    status=ComponentStatus.OUTAGE,
                    last_update=None,
                    record_count=0,
                    latency_ms=0,
                )
            ]

        # Check crypto data
        crypto_status = ComponentStatus.OPERATIONAL
        crypto_last_update = None
        crypto_count = 0

        try:
            if (
                hasattr(tracker, "prev_crypto_data")
                and tracker.prev_crypto_data is not None
            ):
                crypto_status = ComponentStatus.OPERATIONAL
                crypto_count = (
                    len(tracker.prev_crypto_data)
                    if hasattr(tracker.prev_crypto_data, "__len__")
                    else 1
                )

                # Get last update time if available
                if hasattr(tracker.prev_crypto_data, "get") and isinstance(
                    tracker.prev_crypto_data, dict
                ):
                    timestamp = tracker.prev_crypto_data.get("timestamp")
                    if timestamp:
                        try:
                            if isinstance(timestamp, str):
                                crypto_last_update = datetime.fromisoformat(
                                    timestamp.replace("Z", "+00:00")
                                )
                            elif isinstance(timestamp, (int, float)):
                                crypto_last_update = datetime.fromtimestamp(timestamp)
                        except (ValueError, TypeError):
                            pass
            else:
                crypto_status = ComponentStatus.UNKNOWN
        except Exception as e:
            logger.error(f"Error checking crypto data: {str(e)}")
            crypto_status = ComponentStatus.OUTAGE

        data_sources.append(
            DataSourceStatus(
                name="crypto",
                status=crypto_status,
                last_update=crypto_last_update,
                record_count=crypto_count,
                latency_ms=None,
            )
        )

        # Check forex data
        forex_status = ComponentStatus.OPERATIONAL
        forex_last_update = None
        forex_count = 0

        try:
            if (
                hasattr(tracker, "prev_forex_data")
                and tracker.prev_forex_data is not None
            ):
                forex_status = ComponentStatus.OPERATIONAL
                forex_count = (
                    len(tracker.prev_forex_data)
                    if hasattr(tracker.prev_forex_data, "__len__")
                    else 1
                )

                # Get last update time if available
                if hasattr(tracker.prev_forex_data, "get") and isinstance(
                    tracker.prev_forex_data, dict
                ):
                    timestamp = tracker.prev_forex_data.get("timestamp")
                    if timestamp:
                        try:
                            if isinstance(timestamp, str):
                                forex_last_update = datetime.fromisoformat(
                                    timestamp.replace("Z", "+00:00")
                                )
                            elif isinstance(timestamp, (int, float)):
                                forex_last_update = datetime.fromtimestamp(timestamp)
                        except (ValueError, TypeError):
                            pass
            else:
                forex_status = ComponentStatus.UNKNOWN
        except Exception as e:
            logger.error(f"Error checking forex data: {str(e)}")
            forex_status = ComponentStatus.OUTAGE

        data_sources.append(
            DataSourceStatus(
                name="forex",
                status=forex_status,
                last_update=forex_last_update,
                record_count=forex_count,
                latency_ms=None,
            )
        )

        # Check any other data sources
        # ...

        return data_sources

    except Exception as e:
        logger.error(f"Error checking data sources: {str(e)}")
        return [
            DataSourceStatus(
                name="unknown",
                status=ComponentStatus.UNKNOWN,
                last_update=None,
                record_count=0,
                latency_ms=0,
            )
        ]


def check_components(request: Request) -> Dict[str, ComponentStatusInfo]:
    """Check status of all system components."""
    components = {}

    # API status
    components["api"] = ComponentStatusInfo(
        status=ComponentStatus.OPERATIONAL,
        message="API is responding normally",
        last_updated=datetime.now(),
    )

    # Database status (if applicable)
    try:
        # Example: Check database status
        # This would be replaced with your actual database check
        db_status = ComponentStatus.OPERATIONAL
        db_message = "Database connection is healthy"

        # Add database metrics if available
        db_metrics = {
            "connection_pool_size": 10,  # Example value
            "active_connections": 5,  # Example value
            "query_latency_ms": 12.5,  # Example value
        }

        components["database"] = ComponentStatusInfo(
            status=db_status,
            message=db_message,
            last_updated=datetime.now(),
            metrics=db_metrics,
        )
    except Exception as e:
        logger.error(f"Error checking database status: {str(e)}")
        components["database"] = ComponentStatusInfo(
            status=ComponentStatus.UNKNOWN,
            message=f"Error checking database status: {str(e)}",
            last_updated=datetime.now(),
        )

    # Check tracker status
    try:
        tracker = request.app.state.tracker

        tracker_status = (
            ComponentStatus.OPERATIONAL
            if tracker is not None
            else ComponentStatus.OUTAGE
        )
        tracker_message = (
            "Tracker is operational"
            if tracker is not None
            else "Tracker is not initialized"
        )

        # Add tracker metrics if available
        tracker_metrics = {}

        if tracker is not None:
            # Check if tracker has combined_report
            if (
                hasattr(tracker, "combined_report")
                and tracker.combined_report is not None
            ):
                # Get timestamp if available
                timestamp = tracker.combined_report.get("timestamp")
                if timestamp:
                    try:
                        if isinstance(timestamp, str):
                            last_report_time = datetime.fromisoformat(
                                timestamp.replace("Z", "+00:00")
                            )
                        elif isinstance(timestamp, (int, float)):
                            last_report_time = datetime.fromtimestamp(timestamp)

                        # Check if report is stale (e.g., older than 1 hour)
                        if (datetime.now() - last_report_time).total_seconds() > 3600:
                            tracker_status = ComponentStatus.DEGRADED
                            tracker_message = "Tracker report is stale"
                    except (ValueError, TypeError):
                        pass

                # Add other metrics if available
                for key in ["total_symbols", "processed_records", "alerts_count"]:
                    if key in tracker.combined_report:
                        tracker_metrics[key] = tracker.combined_report.get(key)

        components["tracker"] = ComponentStatusInfo(
            status=tracker_status,
            message=tracker_message,
            last_updated=datetime.now(),
            metrics=tracker_metrics,
        )
    except Exception as e:
        logger.error(f"Error checking tracker status: {str(e)}")
        components["tracker"] = ComponentStatusInfo(
            status=ComponentStatus.UNKNOWN,
            message=f"Error checking tracker status: {str(e)}",
            last_updated=datetime.now(),
        )

    # Check other components...

    return components


def get_cache_status() -> CacheStatus:
    """Get cache status information."""
    # This is a placeholder - replace with actual cache metrics from your system
    return CacheStatus(
        enabled=True,
        hit_rate=85.5,  # Example value: 85.5%
        item_count=1250,  # Example value
        size_mb=42.7,  # Example value
        oldest_item=datetime.now() - timedelta(hours=3),  # Example value
    )


def determine_overall_status(components: Dict[str, ComponentStatusInfo]) -> str:
    """Determine overall system status based on component statuses."""
    # Count components by status
    status_counts = {status: 0 for status in ComponentStatus}

    for component in components.values():
        status_counts[component.status] += 1

    # Determine overall status
    if status_counts[ComponentStatus.OUTAGE] > 0:
        return "system_issues"
    elif status_counts[ComponentStatus.DEGRADED] > 0:
        return "degraded_performance"
    elif status_counts[ComponentStatus.MAINTENANCE] > 0:
        return "maintenance"
    else:
        return "operational"


# Routes
@router.get("/status", response_model=StatusResponse)
async def get_status(request: Request):
    """
    Get the current status of the API and tracker.

    This endpoint provides a quick overview of the system status
    including basic information about the tracker and data availability.

    Returns:
        Basic status information
    """
    # Start telemetry span
    with telemetry.start_span("get_status"):
        try:
            # Get tracker from request state
            tracker = request.app.state.tracker

            # Calculate uptime
            current_time = datetime.now()
            uptime_seconds = (current_time - start_time).total_seconds()

            # Check if tracker is initialized
            tracker_initialized = tracker is not None

            # Safely check crypto and forex data
            crypto_data_available = False
            forex_data_available = False
            last_report_timestamp = None

            if tracker_initialized:
                try:
                    crypto_data_available = (
                        hasattr(tracker, "prev_crypto_data")
                        and tracker.prev_crypto_data is not None
                    )
                except Exception:
                    pass

                try:
                    forex_data_available = (
                        hasattr(tracker, "prev_forex_data")
                        and tracker.prev_forex_data is not None
                    )
                except Exception:
                    pass

                try:
                    if (
                        hasattr(tracker, "combined_report")
                        and tracker.combined_report is not None
                    ):
                        last_report_timestamp = tracker.combined_report.get("timestamp")
                except Exception:
                    pass

            # Get system info
            system_info = {
                "tracker_initialized": tracker_initialized,
                "crypto_data_available": crypto_data_available,
                "forex_data_available": forex_data_available,
                "last_report_timestamp": last_report_timestamp,
                "app_version": get_version(),
                "environment": get_environment(),
            }

            return StatusResponse(
                status="running",
                timestamp=current_time.strftime("%Y-%m-%d %H:%M:%S"),
                uptime=uptime_seconds,
                system_info=system_info,
            )

        except Exception as e:
            logger.error(f"Error in status endpoint: {str(e)}")
            return StatusResponse(
                status="error",
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                uptime=(datetime.now() - start_time).total_seconds(),
                system_info={"error": str(e)},
            )


@router.get("/status/detailed", response_model=DetailedStatusResponse)
async def get_detailed_status(
    request: Request,
    response: Response,
    include_system_resources: bool = Query(
        True, description="Include system resource metrics"
    ),
    include_cache_status: bool = Query(
        True, description="Include cache status information"
    ),
    token: Optional[str] = Depends(get_auth_token),
):
    """
    Get detailed status information about all system components.

    This endpoint provides comprehensive information about the status of
    the system, including all components, data sources, and system resources.

    Args:
        include_system_resources: Whether to include system resource metrics
        include_cache_status: Whether to include cache status information
        token: Optional authentication token for additional information

    Returns:
        Detailed status information
    """
    # Start telemetry span
    with telemetry.start_span("get_detailed_status"):
        # Check if token is provided and authenticate for additional access
        is_admin = False
        try:
            if token:
                user = authenticate_user(token)
                # Check for admin role
                is_admin = "admin" in user.get("roles", [])
        except Exception:
            pass

        try:
            # Get tracker from request state
            tracker = request.app.state.tracker

            # Check component statuses
            components = check_components(request)

            # Check data sources
            data_sources = check_data_sources(tracker)

            # Get system resources if requested
            system_resources = (
                get_system_resources() if include_system_resources else None
            )

            # Get cache status if requested
            cache_status = get_cache_status() if include_cache_status else None

            # Calculate uptime
            current_time = datetime.now()
            uptime_seconds = (current_time - start_time).total_seconds()
            uptime_formatted = format_uptime(uptime_seconds)

            # Determine overall status
            overall_status = determine_overall_status(components)

            # Create response
            response_data = DetailedStatusResponse(
                status=overall_status,
                version=get_version(),
                environment=get_environment(),
                timestamp=current_time.strftime("%Y-%m-%d %H:%M:%S"),
                uptime_seconds=uptime_seconds,
                uptime_formatted=uptime_formatted,
                components=components,
                data_sources=data_sources,
                system_resources=system_resources,
                cache=cache_status,
                maintenance_mode=False,  # Set to True during maintenance
            )

            # Add additional info for admins
            if is_admin:
                # Example: Add user count and service tier
                response_data.user_count = 1250  # Example value
                response_data.service_tier = ServiceTier.PREMIUM  # Example value

                # Example: Add rate limit info
                response_data.rate_limits = {
                    "current_rate": 15,  # Example value: requests per second
                    "limit": 100,  # Example value: max requests per second
                    "reset_at": (current_time + timedelta(minutes=5)).isoformat(),
                }

            # Set custom headers
            response.headers["X-System-Status"] = overall_status
            response.headers["X-Uptime"] = uptime_formatted

            return response_data

        except Exception as e:
            logger.error(f"Error in detailed status endpoint: {str(e)}")

            # Return error response
            return DetailedStatusResponse(
                status="error",
                version=get_version(),
                environment=get_environment(),
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                uptime_seconds=(datetime.now() - start_time).total_seconds(),
                uptime_formatted=format_uptime(
                    (datetime.now() - start_time).total_seconds()
                ),
                components={
                    "api": ComponentStatusInfo(
                        status=ComponentStatus.DEGRADED,
                        message=f"Error retrieving status: {str(e)}",
                        last_updated=datetime.now(),
                    )
                },
                data_sources=[],
                system_resources=(
                    get_system_resources()
                    if include_system_resources
                    else SystemResource(
                        cpu_percent=0.0,
                        memory_percent=0.0,
                        disk_usage_percent=0.0,
                        load_average=[],
                        network_connections=0,
                    )
                ),
                maintenance_mode=False,
            )


@router.get("/status/health", status_code=status.HTTP_200_OK)
async def health_check(request: Request):
    """
    Basic health check endpoint for monitoring systems.

    This endpoint returns a simple health status that can be used
    by monitoring systems to check if the API is alive.

    Returns:
        Simple health status
    """
    try:
        # Simple check if tracker is available
        tracker = request.app.state.tracker

        return {
            "status": "healthy" if tracker is not None else "degraded",
            "timestamp": datetime.now().isoformat(),
        }
    except Exception:
        # Return unhealthy status
        response = JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "timestamp": datetime.now().isoformat()},
        )
        return response


@router.get("/status/data", response_model=List[DataSourceStatus])
async def get_data_status(request: Request):
    """
    Get status of all data sources.

    This endpoint provides detailed information about the status
    of all data sources used by the system.

    Returns:
        Status of all data sources
    """
    try:
        # Get tracker from request state
        tracker = request.app.state.tracker

        # Check data sources
        data_sources = check_data_sources(tracker)

        return data_sources
    except Exception as e:
        logger.error(f"Error in data status endpoint: {str(e)}")

        # Return error response
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving data source status: {str(e)}",
        )
