"""
Monitoring Data Models

This module defines Pydantic models for standardizing the request and response schemas
of the monitoring endpoints.
"""

import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, validator


class HealthStatus(str, Enum):
    """Health status enum for components and overall system"""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class CircuitState(str, Enum):
    """Circuit breaker state enum"""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class AlertLevel(str, Enum):
    """Alert severity level enum"""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class ComponentHealth(BaseModel):
    """Health status of an individual component"""

    status: HealthStatus
    error: Optional[str] = None

    class Config:
        schema_extra = {"example": {"status": "healthy"}}


class CircuitMetrics(BaseModel):
    """Circuit breaker metrics"""

    success: int = Field(..., description="Number of successful calls")
    failure: int = Field(..., description="Number of failed calls")
    rejection: int = Field(..., description="Number of rejected calls")
    success_rate: float = Field(..., description="Success rate (0.0-1.0)")
    last_failure: Optional[float] = Field(None, description="Timestamp of last failure")

    class Config:
        schema_extra = {
            "example": {
                "success": 95,
                "failure": 5,
                "rejection": 0,
                "success_rate": 0.95,
                "last_failure": 1634567890.123,
            }
        }


class CircuitStatus(BaseModel):
    """Circuit breaker status"""

    state: CircuitState
    metrics: CircuitMetrics

    class Config:
        schema_extra = {
            "example": {
                "state": "CLOSED",
                "metrics": {
                    "success": 95,
                    "failure": 5,
                    "rejection": 0,
                    "success_rate": 0.95,
                    "last_failure": 1634567890.123,
                },
            }
        }


class CircuitBreakerHealth(BaseModel):
    """Health status of a circuit breaker"""

    status: HealthStatus
    state: CircuitState

    class Config:
        schema_extra = {"example": {"status": "healthy", "state": "CLOSED"}}


class HealthResponse(BaseModel):
    """Basic health check response"""

    status: HealthStatus
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp")

    class Config:
        schema_extra = {"example": {"status": "healthy", "timestamp": 1634567890.123}}


class DeepHealthResponse(BaseModel):
    """Advanced health check response with component details"""

    status: HealthStatus
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp")
    components: Dict[str, Any] = Field(
        ..., description="Status of individual components"
    )

    class Config:
        schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": 1634567890.123,
                "components": {
                    "api": {"status": "healthy"},
                    "database": {"status": "healthy"},
                    "sentiment_tracker": {"status": "healthy"},
                    "circuit_breakers": {
                        "api_calls": {"status": "healthy", "state": "CLOSED"}
                    },
                },
            }
        }


class Alert(BaseModel):
    """System alert model"""

    id: str = Field(..., description="Unique alert identifier")
    timestamp: float = Field(..., description="Unix timestamp when alert was generated")
    level: AlertLevel
    alert_type: str = Field(..., description="Type of alert")
    message: str = Field(..., description="Alert message")
    source: str = Field(..., description="Component that generated the alert")
    acknowledged: bool = Field(
        False, description="Whether the alert has been acknowledged"
    )
    acknowledged_at: Optional[float] = Field(
        None, description="Timestamp when acknowledged"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional alert data"
    )

    @validator("timestamp", "acknowledged_at", pre=True)
    def validate_timestamp(cls, v):
        """Convert datetime to Unix timestamp if needed"""
        if isinstance(v, datetime):
            return v.timestamp()
        return v

    class Config:
        schema_extra = {
            "example": {
                "id": "alert-123",
                "timestamp": 1634567890.123,
                "level": "warning",
                "alert_type": "high_latency",
                "message": "API response time exceeds threshold",
                "source": "metrics_analyzer",
                "acknowledged": False,
                "acknowledged_at": None,
                "metadata": {
                    "endpoint": "/api/v1/data",
                    "response_time_ms": 1500,
                    "threshold_ms": 1000,
                },
            }
        }


class AlertAcknowledgementResponse(BaseModel):
    """Response for alert acknowledgement"""

    status: Literal["success", "error"]
    message: str

    class Config:
        schema_extra = {
            "example": {"status": "success", "message": "Alert acknowledged"}
        }


class SlowRequest(BaseModel):
    """Information about a slow request"""

    timestamp: float
    endpoint: str
    method: str
    response_time_ms: float
    status_code: int
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "timestamp": 1634567890.123,
                "endpoint": "/api/v1/data",
                "method": "GET",
                "response_time_ms": 1500,
                "status_code": 200,
                "client_ip": "192.168.1.1",
                "user_agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                ),
            }
        }


class ErrorDistribution(BaseModel):
    """Distribution of errors by status code and endpoint"""

    by_status_code: Dict[str, int] = Field(
        ..., description="Count of errors by status code"
    )
    by_endpoint: Dict[str, int] = Field(..., description="Count of errors by endpoint")
    top_errors: List[Dict[str, Any]] = Field(
        ..., description="Details of most frequent errors"
    )

    class Config:
        schema_extra = {
            "example": {
                "by_status_code": {"404": 50, "500": 10, "403": 5},
                "by_endpoint": {
                    "/api/v1/user": 30,
                    "/api/v1/data": 25,
                    "/api/v1/auth": 10,
                },
                "top_errors": [
                    {
                        "status_code": 404,
                        "endpoint": "/api/v1/user",
                        "count": 25,
                        "sample_message": "User not found",
                    }
                ],
            }
        }


class Percentiles(BaseModel):
    """Response time percentiles"""

    p50: float = Field(..., description="50th percentile (median)")
    p90: float = Field(..., description="90th percentile")
    p95: float = Field(..., description="95th percentile")
    p99: float = Field(..., description="99th percentile")
    min: float = Field(..., description="Minimum value")
    max: float = Field(..., description="Maximum value")
    avg: float = Field(..., description="Average (mean) value")
    sample_size: int = Field(..., description="Number of data points")

    class Config:
        schema_extra = {
            "example": {
                "p50": 120.5,
                "p90": 350.2,
                "p95": 500.7,
                "p99": 1200.1,
                "min": 10.2,
                "max": 2500.0,
                "avg": 180.3,
                "sample_size": 10000,
            }
        }


class EndpointMetrics(BaseModel):
    """Metrics for a specific endpoint"""

    endpoint: str
    method: str
    request_count: int
    error_count: int
    error_rate: float
    avg_time: float
    p95_time: float
    p99_time: float
    min_time: float
    max_time: float

    class Config:
        schema_extra = {
            "example": {
                "endpoint": "/api/v1/data",
                "method": "GET",
                "request_count": 5000,
                "error_count": 50,
                "error_rate": 0.01,
                "avg_time": 120.5,
                "p95_time": 500.7,
                "p99_time": 1200.1,
                "min_time": 10.2,
                "max_time": 2500.0,
            }
        }


class MetricsSummary(BaseModel):
    """Summary of API metrics"""

    request_count: int
    error_count: int
    avg_response_time: float
    error_rate: float
    timeframe_seconds: Optional[int] = None
    start_time: Optional[float] = None
    end_time: float = Field(default_factory=time.time)
    percentiles: Percentiles

    class Config:
        schema_extra = {
            "example": {
                "request_count": 100000,
                "error_count": 1500,
                "avg_response_time": 150.3,
                "error_rate": 0.015,
                "timeframe_seconds": 3600,
                "start_time": 1634564290.123,
                "end_time": 1634567890.123,
                "percentiles": {
                    "p50": 120.5,
                    "p90": 350.2,
                    "p95": 500.7,
                    "p99": 1200.1,
                    "min": 10.2,
                    "max": 2500.0,
                    "avg": 150.3,
                    "sample_size": 100000,
                },
            }
        }
