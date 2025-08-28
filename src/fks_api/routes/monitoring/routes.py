"""
API Monitoring Routes

This module defines all the monitoring routes for the API.
"""

import time
from typing import Any, Dict, List, Literal, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse
from framework.infrastructure.persistence.cache.backends import memory, redis
from framework.infrastructure.persistence.cache.decorators import cached
from framework.middleware.protection.circuit_breaker.core import CircuitBreaker

# Models
from .models import (
    Alert,
    AlertAcknowledgementResponse,
    DeepHealthResponse,
    EndpointMetrics,
    ErrorDistribution,
    HealthResponse,
    HealthStatus,
    MetricsSummary,
    Percentiles,
    SlowRequest,
)

# Create a router for monitoring endpoints
router = APIRouter(tags=["monitoring"])


@router.get(
    "/health",
    dependencies=[Depends(health_check_limiter())],
    response_model=HealthResponse,
)
async def health_check() -> HealthResponse:
    """
    Basic health check endpoint.

    Returns:
        HealthResponse: Basic health status with timestamp
    """
    return HealthResponse(status=HealthStatus.HEALTHY, timestamp=time.time())


@router.get(
    "/deep_health",
    dependencies=[Depends(get_api_key)],
    response_model=DeepHealthResponse,
)
@cached(storage="memory", expiry_seconds=30)
async def deep_health_check(request: Request) -> DeepHealthResponse:
    """
    Advanced health check that verifies all components.

    Returns:
        DeepHealthResponse: Detailed health status of all system components
    """
    health_status = {
        "status": HealthStatus.HEALTHY,
        "timestamp": time.time(),
        "components": {
            "api": {"status": HealthStatus.HEALTHY},
            "database": {"status": "unknown"},
            "sentiment_tracker": {"status": "unknown"},
            "circuit_breakers": {},
        },
    }

    # Check database health if available
    try:
        if hasattr(request.app.state, "db"):
            # Execute a simple query to check database connectivity
            await request.app.state.db.execute("SELECT 1")
            health_status["components"]["database"] = {"status": HealthStatus.HEALTHY}
    except Exception as e:
        health_status["components"]["database"] = {
            "status": HealthStatus.UNHEALTHY,
            "error": str(e),
        }
        health_status["status"] = HealthStatus.DEGRADED

    # Check circuit breakers
    for name in CircuitBreaker.get_all_names():
        circuit = CircuitBreaker.get_instance(name)
        circuit_status = (
            HealthStatus.HEALTHY
            if circuit.state.name == "CLOSED"
            else HealthStatus.DEGRADED
        )

        health_status["components"]["circuit_breakers"][name] = {
            "status": circuit_status,
            "state": circuit.state.name,
        }

        # Update overall status if any circuit is not healthy
        if circuit_status != HealthStatus.HEALTHY:
            health_status["status"] = HealthStatus.DEGRADED

    # Check tracker health if available
    try:
        if hasattr(request.app.state, "tracker") and hasattr(
            request.app.state.tracker, "health_check"
        ):
            tracker_health = await request.app.state.tracker.health_check()
            health_status["components"]["sentiment_tracker"] = tracker_health

            # Update overall status if tracker is not healthy
            if tracker_health.get("status") != HealthStatus.HEALTHY:
                health_status["status"] = HealthStatus.DEGRADED
    except Exception as e:
        health_status["components"]["sentiment_tracker"] = {
            "status": HealthStatus.UNHEALTHY,
            "error": str(e),
        }
        health_status["status"] = HealthStatus.DEGRADED

    return DeepHealthResponse(**health_status)


@router.get(
    "/circuits", dependencies=[Depends(get_api_key)], response_model=Dict[str, Any]
)
@cached(storage="memory", expiry_seconds=15)
async def get_circuit_status() -> Dict[str, Any]:
    """
    Get status of all circuit breakers.

    Returns:
        Dict[str, Any]: Status and metrics for all circuit breakers
    """
    circuits = {}
    for name in CircuitBreaker.get_all_names():
        circuit = CircuitBreaker.get_instance(name)
        circuits[name] = {"state": circuit.state.name, "metrics": circuit.get_metrics()}
    return circuits


@router.get(
    "/metrics", dependencies=[Depends(get_api_key)], response_model=MetricsSummary
)
@cached(storage="redis", expiry_seconds=60)
async def get_metrics(
    request: Request,
    timeframe_seconds: Optional[int] = Query(
        None, ge=1, description="Time window in seconds"
    ),
) -> MetricsSummary:
    """
    Get API metrics summary.

    Args:
        timeframe_seconds: Optional time window in seconds

    Returns:
        MetricsSummary: API metrics summary
    """
    metrics_analyzer = request.app.state.metrics_analyzer
    result = metrics_analyzer.get_summary(timeframe_seconds=timeframe_seconds)
    return MetricsSummary(**result)


@router.get(
    "/metrics/slow_requests",
    dependencies=[Depends(get_api_key)],
    response_model=List[SlowRequest],
)
@cached(storage="memory", expiry_seconds=30)
async def get_slow_requests(
    request: Request,
    threshold_ms: int = Query(
        1000, ge=100, le=10000, description="Threshold in milliseconds"
    ),
    timeframe_seconds: Optional[int] = Query(
        None, ge=1, description="Time window in seconds"
    ),
    endpoint: Optional[str] = Query(None, description="Filter by specific endpoint"),
) -> List[SlowRequest]:
    """
    Get slow API requests exceeding threshold.

    Args:
        threshold_ms: Response time threshold in milliseconds
        timeframe_seconds: Optional time window in seconds
        endpoint: Optional endpoint filter

    Returns:
        List[SlowRequest]: Slow requests exceeding the threshold
    """
    metrics_analyzer = request.app.state.metrics_analyzer
    slow_requests = metrics_analyzer.get_slow_requests(
        threshold_ms=threshold_ms,
        timeframe_seconds=timeframe_seconds,
        endpoint=endpoint,
    )
    return [SlowRequest(**req) for req in slow_requests]


@router.get(
    "/metrics/errors",
    dependencies=[Depends(get_api_key)],
    response_model=ErrorDistribution,
)
@cached(storage="memory", expiry_seconds=45)
async def get_error_distribution(
    request: Request,
    timeframe_seconds: Optional[int] = Query(
        None, ge=1, description="Time window in seconds"
    ),
) -> ErrorDistribution:
    """
    Get distribution of API errors.

    Args:
        timeframe_seconds: Optional time window in seconds

    Returns:
        ErrorDistribution: Error distribution by status code and endpoint
    """
    metrics_analyzer = request.app.state.metrics_analyzer
    error_dist = metrics_analyzer.get_error_distribution(
        timeframe_seconds=timeframe_seconds
    )
    return ErrorDistribution(**error_dist)


@router.get(
    "/metrics/percentiles",
    dependencies=[Depends(get_api_key)],
    response_model=Percentiles,
)
@cached(storage="memory", expiry_seconds=30)
async def get_response_percentiles(
    request: Request,
    endpoint: Optional[str] = Query(None, description="Filter by specific endpoint"),
    method: Optional[str] = Query(None, description="Filter by HTTP method"),
    timeframe_seconds: Optional[int] = Query(
        None, ge=1, description="Time window in seconds"
    ),
) -> Percentiles:
    """
    Get response time percentiles.

    Args:
        endpoint: Optional endpoint filter
        method: Optional HTTP method filter
        timeframe_seconds: Optional time window in seconds

    Returns:
        Percentiles: Response time percentiles (p50, p90, p95, p99)
    """
    metrics_analyzer = request.app.state.metrics_analyzer
    percentiles = metrics_analyzer.get_percentiles(
        endpoint=endpoint, method=method, timeframe_seconds=timeframe_seconds
    )
    return Percentiles(**percentiles)


@router.get(
    "/metrics/top_endpoints",
    dependencies=[Depends(get_api_key)],
    response_model=List[EndpointMetrics],
)
@cached(storage="memory", expiry_seconds=60)
async def get_top_endpoints(
    request: Request,
    limit: int = Query(10, ge=1, le=100, description="Number of endpoints to return"),
    by_metric: str = Query(
        "avg_time",
        description="Metric to sort by",
        regex="^(avg_time|p95_time|error_rate|request_count)$",
    ),
    timeframe_seconds: Optional[int] = Query(
        None, ge=1, description="Time window in seconds"
    ),
) -> List[EndpointMetrics]:
    """
    Get top endpoints by various metrics.

    Args:
        limit: Number of endpoints to return
        by_metric: Metric to sort by (avg_time, p95_time, error_rate, request_count)
        timeframe_seconds: Optional time window in seconds

    Returns:
        List[EndpointMetrics]: Top endpoints ranked by the specified metric
    """
    metrics_analyzer = request.app.state.metrics_analyzer
    top_endpoints = metrics_analyzer.get_top_endpoints(
        limit=limit, by_metric=by_metric, timeframe_seconds=timeframe_seconds
    )
    return [EndpointMetrics(**endpoint) for endpoint in top_endpoints]


@router.get(
    "/metrics/alerts", dependencies=[Depends(get_api_key)], response_model=List[Alert]
)
@cached(storage="memory", expiry_seconds=10)
async def get_alerts(
    level: Optional[str] = Query(
        None, description="Filter by alert level", regex="^(critical|warning|info)$"
    ),
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    max_age: Optional[int] = Query(None, ge=1, description="Maximum age in seconds"),
    acknowledged: Optional[bool] = Query(
        None, description="Filter by acknowledgment status"
    ),
    limit: int = Query(
        100, ge=1, le=1000, description="Maximum number of alerts to return"
    ),
) -> List[Alert]:
    """
    Get system alerts.

    Args:
        level: Optional alert level filter (critical, warning, info)
        alert_type: Optional alert type filter
        max_age: Optional maximum age in seconds
        acknowledged: Optional acknowledgment status filter
        limit: Maximum number of alerts to return

    Returns:
        List[Alert]: Matching alerts
    """
    return [
        Alert(**alert.to_dict())
        for alert in alert_system.get_alerts(
            level=level,
            alert_type=alert_type,
            max_age=max_age,
            acknowledged=acknowledged,
            limit=limit,
        )
    ]


@router.post(
    "/metrics/alerts/{alert_id}/acknowledge",
    dependencies=[Depends(get_api_key)],
    response_model=AlertAcknowledgementResponse,
)
async def acknowledge_alert(alert_id: str) -> AlertAcknowledgementResponse:
    """
    Acknowledge an alert.

    Args:
        alert_id: ID of the alert to acknowledge

    Returns:
        AlertAcknowledgementResponse: Acknowledgment status

    Raises:
        HTTPException: If the alert is not found (status 404)
    """
    result = alert_system.acknowledge_alert(alert_id)
    if result:
        # Invalidate relevant caches after state change
        memory.cache.invalidate("get_alerts")
        return AlertAcknowledgementResponse(
            status="success", message=f"Alert {alert_id} acknowledged successfully"
        )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Alert with ID {alert_id} not found",
    )


@router.get(
    "/metrics/prometheus",
    response_class=PlainTextResponse,
)
@cached(storage="redis", expiry_seconds=30)
async def get_prometheus_metrics(
    request: Request, token: str = Depends(get_api_key)
) -> PlainTextResponse:
    """
    Get metrics in Prometheus format for scraping.

    Returns:
        PlainTextResponse: Metrics in Prometheus format
    """
    metrics_analyzer = request.app.state.metrics_analyzer
    metrics_text = metrics_analyzer.export_to_prometheus_format()
    return PlainTextResponse(content=metrics_text)


@router.post("/cache/clear", dependencies=[Depends(get_api_key)])
async def clear_cache(
    cache_type: str = Query("all", regex="^(all|memory|redis)$")
) -> Dict[str, str]:
    """
    Clear cache data.

    Args:
        cache_type: Type of cache to clear (all, memory, redis)

    Returns:
        Dict[str, str]: Result message
    """
    cleared = []

    if cache_type in ["all", "memory"]:
        await memory.cache.clear_all_async()
        cleared.append("memory")

    if cache_type in ["all", "redis"]:
        await redis.cache.clear_all_async()
        cleared.append("redis")

    return {
        "status": "success",
        "message": f"Successfully cleared cache: {', '.join(cleared)}",
        "timestamp": time.time(),
    }
