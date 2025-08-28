import asyncio
import hashlib
import time
import traceback
import uuid
from datetime import datetime, timedelta
from functools import wraps
from threading import Lock
from typing import Any, Dict, List, Optional, Union

from core.telemetry.telemetry import telemetry
from core.types.market import MarketType
from data.service import DataService
from dependencies import get_auth_token, get_db
from domain.trading.strategies.backtest.engine import BacktestEngine
from domain.trading.strategies.registry import StrategyRegistry
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Path,
    Query,
    Security,
    status,
)
from fastapi.responses import JSONResponse
from framework.common.exceptions.validation import ValidationError
from loguru import logger
from middleware.auth import authenticate_user, check_permission
from pydantic import BaseModel, Field, root_validator, validator
from strategy.factory import StrategyFactory

# Configure logger
backtest_logger = logger.bind(module="backtest")


# Models for request/response
class DataConfig(BaseModel):
    """Data configuration for backtest."""

    source: str
    symbols: List[str]
    start_date: str
    end_date: str
    interval: str = "1d"

    @validator("symbols")
    def validate_symbols(cls, v):
        if not v:
            raise ValueError("At least one symbol must be provided")
        if len(v) > 20:
            raise ValueError("Maximum of 20 symbols allowed per backtest")
        return v

    @validator("start_date", "end_date")
    def validate_dates(cls, v):
        try:
            datetime.fromisoformat(v)
        except ValueError:
            raise ValueError(f"Invalid date format: {v}. Use ISO format (YYYY-MM-DD)")
        return v

    @root_validator
    def validate_date_range(cls, values):
        if "start_date" in values and "end_date" in values:
            start = datetime.fromisoformat(values["start_date"])
            end = datetime.fromisoformat(values["end_date"])

            if start >= end:
                raise ValueError("End date must be after start date")

            # Check if date range is too large
            if (end - start).days > 3650:  # 10 years
                raise ValueError("Date range cannot exceed 10 years")

        return values


class StrategyConfig(BaseModel):
    """Strategy configuration for backtest."""

    type: str
    params: Dict[str, Any] = Field(default_factory=dict)


class RiskConfig(BaseModel):
    """Optional risk configuration for backtests and strategies.

    These values are merged into the strategy params during creation so that
    strategies or the underlying engine can apply position sizing and limits.
    """

    # Fraction of equity to risk per trade (e.g., 0.01 = 1%)
    risk_per_trade: Optional[float] = Field(default=None, ge=0.0, le=0.1)
    # Max daily loss in percent of equity (e.g., 0.05 = 5%)
    max_daily_loss_pct: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    # Max position size as fraction of equity (e.g., 0.1 = 10%)
    max_position_size_pct: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    # Sizing mode: fixed quantity or volatility/ATR based
    sizing_mode: Optional[str] = Field(default=None, description="fixed|atr|volatility")
    # ATR settings when using ATR sizing
    atr_period: Optional[int] = Field(default=None, ge=1, le=365)
    atr_mult: Optional[float] = Field(default=None, ge=0.1, le=20.0)


class BacktestConfig(BaseModel):
    """Configuration for creating a backtest."""

    name: str
    description: Optional[str] = None
    initial_capital: float = 100000.0
    commission: float = 0.001
    slippage: float = 0.0
    data: DataConfig
    strategy: StrategyConfig
    risk: Optional[RiskConfig] = None

    @validator("name")
    def validate_name(cls, v):
        if len(v) < 3 or len(v) > 100:
            raise ValueError("Name must be between 3 and 100 characters")
        return v

    @validator("initial_capital")
    def validate_capital(cls, v):
        if v <= 0:
            raise ValueError("Initial capital must be positive")
        if v > 1_000_000_000:  # $1 billion
            raise ValueError("Initial capital too large")
        return v

    @validator("commission", "slippage")
    def validate_cost_parameters(cls, v):
        if v < 0:
            raise ValueError("Commission and slippage cannot be negative")
        if v > 0.1:  # 10%
            raise ValueError(
                "Commission and slippage values too large (max 0.1 or 10%)"
            )
        return v


class BacktestStatus(BaseModel):
    """Status of a backtest."""

    backtest_id: str
    name: str
    status: str
    progress: float
    message: str
    created_at: datetime
    updated_at: datetime
    estimated_completion: Optional[datetime] = None


class BacktestSummaryResponse(BaseModel):
    """Summary of backtest results."""

    backtest_id: str
    name: str
    description: Optional[str] = None
    initial_capital: float
    final_equity: float
    total_return: float
    total_trades: int
    win_rate: float
    sharpe_ratio: float
    max_drawdown: float
    start_date: datetime
    end_date: datetime
    duration: str  # Duration of the backtest


class ResultsFilterParams(BaseModel):
    """Parameters for filtering backtest results."""

    metric_gt: Optional[Dict[str, float]] = None
    metric_lt: Optional[Dict[str, float]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None


# Create router
router = APIRouter(
    prefix="/backtest",
    tags=["backtest"],
    dependencies=[Depends(get_auth_token)],
)

# Local accessors to avoid mypy/linters complaining about dynamic attributes on router
def _get_data_service() -> DataService:
    return getattr(router, "data_service")  # type: ignore[attr-defined]

def _get_strategy_registry() -> StrategyRegistry:
    return getattr(router, "strategy_registry")  # type: ignore[attr-defined]

# Thread synchronization
backtest_locks = {}
lock_mutex = Lock()

# Storage for active backtests (in a real app, this would be in a database)
active_backtests = {}
backtest_engines = {}
backtest_results = {}
cancellation_requests = set()

# Resource limits
MAX_CONCURRENT_BACKTESTS = 5
MAX_TOTAL_BACKTESTS = 50
CLEANUP_OLDER_THAN_DAYS = 30


# Helper functions
def get_user_backtests_count(user_id: str) -> int:
    """Get count of user's backtests."""
    return len([bt for bt in active_backtests.values() if bt["user_id"] == user_id])


def check_user_limits(user_id: str) -> None:
    """
    Check if user has reached resource limits.

    Args:
        user_id: User ID to check

    Raises:
        HTTPException: If user has reached limits
    """
    # Count active backtests for this user
    user_active_count = len(
        [
            bt
            for bt in active_backtests.values()
            if bt["user_id"] == user_id
            and bt["status"] in ["running", "loading_data", "preparing_strategy"]
        ]
    )

    if user_active_count >= MAX_CONCURRENT_BACKTESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Maximum of {MAX_CONCURRENT_BACKTESTS} concurrent backtests allowed. Please wait for some to complete.",
        )

    # Count total backtests for this user
    user_total_count = get_user_backtests_count(user_id)

    if user_total_count >= MAX_TOTAL_BACKTESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Maximum of {MAX_TOTAL_BACKTESTS} total backtests allowed. Please delete some old backtests.",
        )


def check_backtest_access(backtest_id: str, user_id: str) -> Dict[str, Any]:
    """
    Check if user has access to a backtest and return the backtest data.

    Args:
        backtest_id: ID of the backtest
        user_id: ID of the user

    Returns:
        Backtest data

    Raises:
        HTTPException: If backtest not found or user doesn't have access
    """
    # Check if backtest exists
    if backtest_id not in active_backtests:
        # Try to load from database
        try:
            # This would be replaced with actual database retrieval
            # backtest = await BacktestRepository.get_backtest(backtest_id)
            # if backtest:
            #     active_backtests[backtest_id] = backtest
            pass
        except Exception:
            pass

        if backtest_id not in active_backtests:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Backtest {backtest_id} not found",
            )

    # Check if user has access to this backtest
    backtest = active_backtests[backtest_id]
    if backtest["user_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to access this backtest",
        )

    return backtest


def create_backtest_id(user_id: str, config: Dict[str, Any]) -> str:
    """
    Create a unique backtest ID.

    Args:
        user_id: User ID
        config: Backtest configuration

    Returns:
        Unique backtest ID
    """
    # Create a unique ID based on user, time, and config hash
    config_hash = hashlib.md5(str(config).encode()).hexdigest()
    timestamp = int(time.time())
    unique_id = str(uuid.uuid4())[:8]

    return f"bt_{user_id}_{timestamp}_{config_hash[:8]}_{unique_id}"


async def cleanup_old_backtests() -> None:
    """
    Clean up old backtests to free resources.
    This would typically be called by a scheduled task.
    """
    cutoff_time = datetime.now() - timedelta(days=CLEANUP_OLDER_THAN_DAYS)

    backtests_to_remove = []
    for backtest_id, backtest in active_backtests.items():
        # Skip running backtests
        if backtest["status"] in ["running", "loading_data", "preparing_strategy"]:
            continue

        # Check if backtest is old enough to remove
        if backtest["updated_at"] < cutoff_time:
            backtests_to_remove.append(backtest_id)

    # Remove old backtests
    for backtest_id in backtests_to_remove:
        # In a real app, this would archive to database first
        # await BacktestRepository.archive_backtest(backtest_id)

        del active_backtests[backtest_id]

        if backtest_id in backtest_engines:
            del backtest_engines[backtest_id]

        if backtest_id in backtest_results:
            del backtest_results[backtest_id]

        logger.info(f"Cleaned up old backtest: {backtest_id}")


# Routes
@router.post(
    "/create", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED
)
async def create_backtest(
    config: BacktestConfig,
    background_tasks: BackgroundTasks,
    token: str = Depends(get_auth_token),
    data_service: DataService = Depends(_get_data_service),
    strategy_registry: StrategyRegistry = Depends(_get_strategy_registry),
):
    """
    Create a new backtest with the provided configuration.

    Args:
        config: Backtest configuration
        background_tasks: FastAPI background tasks
        token: Authentication token
        data_service: Data service dependency
        strategy_registry: Strategy registry dependency

    Returns:
        Dictionary with backtest ID and status
    """
    # Start telemetry span
    with telemetry.start_span("create_backtest"):
        # Authenticate user
        user = authenticate_user(token)

        # Check user permissions
        check_permission(user, "backtest:create")

        # Check resource limits
        check_user_limits(user["sub"])

        try:
            # Generate backtest ID
            backtest_id = create_backtest_id(user["sub"], config.dict())

            # Validate strategy type
            if not strategy_registry.has_strategy(config.strategy.type):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Strategy type '{config.strategy.type}' not found",
                )

            # Validate data source
            if not await data_service.has_source(config.data.source):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Data source '{config.data.source}' not found",
                )

            # Initialize backtest in database
            # (in a real application, you would store this in the database)
            active_backtests[backtest_id] = {
                "id": backtest_id,
                "name": config.name,
                "description": config.description,
                "user_id": user["sub"],
                "config": config.dict(),
                "status": "initialized",
                "progress": 0,
                "message": "Backtest created",
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
                "estimated_completion": None,
            }

            # Initialize lock for this backtest
            with lock_mutex:
                backtest_locks[backtest_id] = Lock()

            # Log backtest creation
            logger.info(f"Created backtest {backtest_id} for user {user['sub']}")

            # Start a background task to run the backtest
            background_tasks.add_task(
                run_backtest,
                backtest_id=backtest_id,
                user_id=user["sub"],
                config=config.dict(),
                data_service=data_service,
                strategy_registry=strategy_registry,
            )

            return {
                "backtest_id": backtest_id,
                "status": "initialized",
                "message": "Backtest created and scheduled to run",
                "url": (
                    f"/api/v1/backtest/{backtest_id}/status"  # URL for status endpoint
                ),
            }

        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except ValidationError as e:
            # Handle validation errors
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Validation error: {str(e)}",
            )
        except Exception as e:
            # Log unexpected errors
            logger.error(f"Error creating backtest: {str(e)}")
            logger.error(traceback.format_exc())

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error creating backtest: {str(e)}",
            )


@router.get("/list", response_model=Dict[str, Any])
async def list_backtests(
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    name: Optional[str] = Query(None, description="Filter by name"),
    strategy_type: Optional[str] = Query(None, description="Filter by strategy type"),
    date_from: Optional[str] = Query(
        None, description="Filter by creation date (from)"
    ),
    date_to: Optional[str] = Query(None, description="Filter by creation date (to)"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_desc: bool = Query(True, description="Sort descending"),
    limit: int = Query(10, ge=1, le=100, description="Number of backtests to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    token: str = Depends(get_auth_token),
):
    """
    List backtests for the authenticated user.

    Args:
        status: Optional status filter
        name: Optional name filter
        strategy_type: Optional strategy type filter
        date_from: Optional creation date filter (from)
        date_to: Optional creation date filter (to)
        sort_by: Field to sort by
        sort_desc: Sort in descending order
        limit: Number of results to return
        offset: Offset for pagination
        token: Authentication token

    Returns:
        Dictionary with backtest list and pagination info
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "backtest:list")

    # Filter backtests by user
    user_backtests = [
        bt for bt in active_backtests.values() if bt["user_id"] == user["sub"]
    ]

    # Apply filters
    filtered_backtests = user_backtests

    # Status filter
    if status_filter:
        filtered_backtests = [bt for bt in filtered_backtests if bt["status"] == status_filter]

    # Name filter
    if name:
        filtered_backtests = [
            bt for bt in filtered_backtests if name.lower() in bt["name"].lower()
        ]

    # Strategy type filter
    if strategy_type:
        filtered_backtests = [
            bt
            for bt in filtered_backtests
            if bt["config"]["strategy"]["type"] == strategy_type
        ]

    # Date range filter
    if date_from:
        try:
            from_date = datetime.fromisoformat(date_from)
            filtered_backtests = [
                bt for bt in filtered_backtests if bt["created_at"] >= from_date
            ]
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid date format for date_from: {date_from}. Use ISO format.",
            )

    if date_to:
        try:
            to_date = datetime.fromisoformat(date_to)
            filtered_backtests = [
                bt for bt in filtered_backtests if bt["created_at"] <= to_date
            ]
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid date format for date_to: {date_to}. Use ISO format.",
            )

    # Get total count before pagination
    total_count = len(filtered_backtests)

    # Sort backtests
    if sort_by == "created_at":
        filtered_backtests.sort(key=lambda bt: bt["created_at"], reverse=sort_desc)
    elif sort_by == "updated_at":
        filtered_backtests.sort(key=lambda bt: bt["updated_at"], reverse=sort_desc)
    elif sort_by == "name":
        filtered_backtests.sort(key=lambda bt: bt["name"].lower(), reverse=sort_desc)
    elif sort_by == "status":
        filtered_backtests.sort(key=lambda bt: bt["status"], reverse=sort_desc)
    else:
        # Default to created_at
        filtered_backtests.sort(key=lambda bt: bt["created_at"], reverse=sort_desc)

    # Apply pagination
    paginated_backtests = filtered_backtests[offset : offset + limit]

    # Format response
    results = [
        {
            "backtest_id": bt["id"],
            "name": bt["name"],
            "description": bt.get("description"),
            "status": bt["status"],
            "progress": bt["progress"],
            "created_at": bt["created_at"].isoformat(),
            "updated_at": bt["updated_at"].isoformat(),
            "strategy_type": bt["config"]["strategy"]["type"],
            "symbols": bt["config"]["data"]["symbols"],
        }
        for bt in paginated_backtests
    ]

    return {
        "results": results,
        "pagination": {
            "total": total_count,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < total_count,
        },
        "filters": {
            "status": status_filter,
            "name": name,
            "strategy_type": strategy_type,
            "date_from": date_from,
            "date_to": date_to,
        },
    }


@router.get("/{backtest_id}/status", response_model=BacktestStatus)
async def get_backtest_status(
    backtest_id: str = Path(..., description="ID of the backtest"),
    token: str = Depends(get_auth_token),
):
    """
    Get the status of a specific backtest.

    Args:
        backtest_id: ID of the backtest
        token: Authentication token

    Returns:
        Backtest status details
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "backtest:read")

    # Check backtest access
    backtest = check_backtest_access(backtest_id, user["sub"])

    return BacktestStatus(
        backtest_id=backtest["id"],
        name=backtest["name"],
        status=backtest["status"],
        progress=backtest["progress"],
        message=backtest["message"],
        created_at=backtest["created_at"],
        updated_at=backtest["updated_at"],
        estimated_completion=backtest.get("estimated_completion"),
    )


@router.get("/{backtest_id}/results", response_model=Dict[str, Any])
async def get_backtest_results(
    backtest_id: str = Path(..., description="ID of the backtest"),
    include_trades: bool = Query(False, description="Include sample trade data"),
    max_trades: int = Query(
        1000, ge=1, le=10000, description="Maximum number of trades to return"
    ),
    token: str = Depends(get_auth_token),
):
    """
    Get the results of a completed backtest.

    Args:
        backtest_id: ID of the backtest
        include_trades: Whether to include sample trade data
        max_trades: Maximum number of trades to return
        token: Authentication token

    Returns:
        Backtest results
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "backtest:read")

    # Check backtest access
    backtest = check_backtest_access(backtest_id, user["sub"])

    # Check if backtest is completed
    if backtest["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Backtest {backtest_id} is not completed yet (status: {backtest['status']})",
        )

    # Check if results exist
    if backtest_id not in backtest_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Results for backtest {backtest_id} not found",
        )

    # Get results
    results = backtest_results[backtest_id]

    # Prepare response
    response = {
        "backtest_id": backtest_id,
        "name": backtest["name"],
        "description": backtest.get("description"),
        "summary": results["summary"],
        "metrics": results["metrics"],
        "charts": results.get("charts", []),
    }

    # Include sample trade data if requested
    if include_trades:
        trade_data = results.get("sample_data", [])
        response["trades"] = trade_data[:max_trades]
        response["trades_count"] = len(trade_data)
        response["trades_truncated"] = len(trade_data) > max_trades

    return response


@router.post("/{backtest_id}/cancel", response_model=Dict[str, Any])
async def cancel_backtest(
    backtest_id: str = Path(..., description="ID of the backtest"),
    token: str = Depends(get_auth_token),
):
    """
    Cancel a running backtest.

    Args:
        backtest_id: ID of the backtest
        token: Authentication token

    Returns:
        Cancellation status
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "backtest:cancel")

    # Check backtest access
    backtest = check_backtest_access(backtest_id, user["sub"])

    # Check if backtest can be canceled
    if backtest["status"] not in [
        "initialized",
        "loading_data",
        "preparing_strategy",
        "running",
    ]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Backtest {backtest_id} cannot be canceled (status: {backtest['status']})",
        )

    # Add to cancellation requests
    cancellation_requests.add(backtest_id)

    # Update status
    with backtest_locks.get(backtest_id, Lock()):
        active_backtests[backtest_id]["status"] = "canceling"
        active_backtests[backtest_id]["message"] = "Cancellation requested"
        active_backtests[backtest_id]["updated_at"] = datetime.now()

    return {
        "backtest_id": backtest_id,
        "status": "canceling",
        "message": "Cancellation requested",
    }


@router.delete("/{backtest_id}", response_model=Dict[str, Any])
async def delete_backtest(
    backtest_id: str = Path(..., description="ID of the backtest"),
    token: str = Depends(get_auth_token),
):
    """
    Delete a backtest.

    Args:
        backtest_id: ID of the backtest
        token: Authentication token

    Returns:
        Deletion confirmation
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "backtest:delete")

    # Check backtest access
    backtest = check_backtest_access(backtest_id, user["sub"])

    # Check if backtest is running
    if backtest["status"] in ["running", "loading_data", "preparing_strategy"]:
        # Add to cancellation requests
        cancellation_requests.add(backtest_id)

        # Wait a bit for cancellation to take effect
        with backtest_locks.get(backtest_id, Lock()):
            active_backtests[backtest_id]["status"] = "canceling"
            active_backtests[backtest_id][
                "message"
            ] = "Cancellation requested for deletion"
            active_backtests[backtest_id]["updated_at"] = datetime.now()

        # In a real app, this would queue the deletion after cancellation
        return {
            "backtest_id": backtest_id,
            "status": "pending_deletion",
            "message": "Backtest will be deleted after cancellation completes",
        }

    # Delete backtest data
    with lock_mutex:
        if backtest_id in backtest_locks:
            del backtest_locks[backtest_id]

    if backtest_id in active_backtests:
        del active_backtests[backtest_id]

    if backtest_id in backtest_engines:
        del backtest_engines[backtest_id]

    if backtest_id in backtest_results:
        del backtest_results[backtest_id]

    if backtest_id in cancellation_requests:
        cancellation_requests.remove(backtest_id)

    logger.info(f"Deleted backtest {backtest_id}")

    return {
        "backtest_id": backtest_id,
        "status": "deleted",
        "message": "Backtest deleted successfully",
    }


@router.get("/stats", response_model=Dict[str, Any])
async def get_backtest_stats(token: str = Depends(get_auth_token)):
    """
    Get statistics about user's backtests.

    Args:
        token: Authentication token

    Returns:
        Backtest statistics
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "backtest:read")

    # Filter backtests by user
    user_backtests = [
        bt for bt in active_backtests.values() if bt["user_id"] == user["sub"]
    ]

    # Count by status
    status_counts = {}
    for backtest in user_backtests:
        status = backtest["status"]
        status_counts[status] = status_counts.get(status, 0) + 1

    # Count by strategy type
    strategy_counts = {}
    for backtest in user_backtests:
        strategy_type = backtest["config"]["strategy"]["type"]
        strategy_counts[strategy_type] = strategy_counts.get(strategy_type, 0) + 1

    # Get most recent backtests
    recent_backtests = sorted(
        user_backtests, key=lambda bt: bt["created_at"], reverse=True
    )[:5]
    recent = [
        {
            "backtest_id": bt["id"],
            "name": bt["name"],
            "status": bt["status"],
            "created_at": bt["created_at"].isoformat(),
        }
        for bt in recent_backtests
    ]

    # Resource usage
    usage = {
        "total": len(user_backtests),
        "limit": MAX_TOTAL_BACKTESTS,
        "active": len(
            [
                bt
                for bt in user_backtests
                if bt["status"] in ["running", "loading_data", "preparing_strategy"]
            ]
        ),
        "active_limit": MAX_CONCURRENT_BACKTESTS,
    }

    return {
        "counts": {
            "total": len(user_backtests),
            "by_status": status_counts,
            "by_strategy": strategy_counts,
        },
        "recent": recent,
        "resource_usage": usage,
    }


async def run_backtest(
    backtest_id: str,
    user_id: str,
    config: Dict[str, Any],
    data_service: DataService,
    strategy_registry: StrategyRegistry,
):
    """
    Run a backtest in the background.

    Args:
        backtest_id: ID of the backtest
        user_id: ID of the user
        config: Backtest configuration
        data_service: Data service instance
        strategy_registry: Strategy registry instance
    """
    backtest_logger = logger.opt(colors=True).bind(task="backtest")
    start_time = time.time()

    try:
        # Create a lock if it doesn't exist
        with lock_mutex:
            if backtest_id not in backtest_locks:
                backtest_locks[backtest_id] = Lock()

        # Update status
        with backtest_locks[backtest_id]:
            active_backtests[backtest_id]["status"] = "loading_data"
            active_backtests[backtest_id]["progress"] = 5
            active_backtests[backtest_id]["message"] = "Loading market data..."
            active_backtests[backtest_id]["updated_at"] = datetime.now()

        # Check for cancellation
        if backtest_id in cancellation_requests:
            logger.info(f"Backtest {backtest_id} cancelled during startup")
            with backtest_locks[backtest_id]:
                active_backtests[backtest_id]["status"] = "cancelled"
                active_backtests[backtest_id]["message"] = "Backtest cancelled"
                active_backtests[backtest_id]["updated_at"] = datetime.now()
            return

        # Extract configuration
        data_config = config["data"]
        strategy_config = config["strategy"]

        # Create strategy factory
        strategy_factory = StrategyFactory(strategy_registry)

        # Initialize backtest engine
        engine = BacktestEngine(
            initial_capital=config.get("initial_capital", 100000.0),
            commission=config.get("commission", 0.001),
            slippage=config.get("slippage", 0.0),
            name=f"backtest_engine_{backtest_id}",
        )

        # Store engine for later access
        backtest_engines[backtest_id] = engine

        # Load data
        data_dict = {}
        symbols = data_config["symbols"]
        source = data_config["source"]
        start_date = datetime.fromisoformat(data_config["start_date"])
        end_date = datetime.fromisoformat(data_config["end_date"])
        interval = data_config.get("interval", "1d")

        total_symbols = len(symbols)
        for i, symbol in enumerate(symbols):
            # Check for cancellation
            if backtest_id in cancellation_requests:
                logger.info(f"Backtest {backtest_id} cancelled during data loading")
                with backtest_locks[backtest_id]:
                    active_backtests[backtest_id]["status"] = "cancelled"
                    active_backtests[backtest_id]["message"] = "Backtest cancelled"
                    active_backtests[backtest_id]["updated_at"] = datetime.now()
                return

            # Update progress
            progress_percent = 5 + (
                i / total_symbols * 40
            )  # 5-45% progress for data loading
            with backtest_locks[backtest_id]:
                active_backtests[backtest_id]["progress"] = progress_percent
                active_backtests[backtest_id][
                    "message"
                ] = f"Loading data for {symbol}..."
                active_backtests[backtest_id]["updated_at"] = datetime.now()

            # Estimate completion time
            elapsed_time = time.time() - start_time
            if i > 0:  # Need at least one iteration to estimate
                estimated_total_time = elapsed_time * (total_symbols / i)
                estimated_completion = datetime.now() + timedelta(
                    seconds=estimated_total_time - elapsed_time
                )

                with backtest_locks[backtest_id]:
                    active_backtests[backtest_id][
                        "estimated_completion"
                    ] = estimated_completion

            try:
                # Load data for this symbol with timeout
                data = await asyncio.wait_for(
                    data_service.get_data(
                        source=source,
                        symbol=symbol,
                        start_date=start_date,
                        end_date=end_date,
                        interval=interval,
                    ),
                    timeout=60,  # 60-second timeout for data loading
                )
                data_dict[symbol] = data

            except asyncio.TimeoutError:
                logger.error(
                    f"Timeout loading data for {symbol} in backtest {backtest_id}"
                )
                with backtest_locks[backtest_id]:
                    active_backtests[backtest_id]["status"] = "error"
                    active_backtests[backtest_id][
                        "message"
                    ] = f"Timeout loading data for {symbol}"
                    active_backtests[backtest_id]["updated_at"] = datetime.now()
                return
            except Exception as e:
                logger.error(
                    f"Error loading data for {symbol} in backtest {backtest_id}: {str(e)}"
                )
                with backtest_locks[backtest_id]:
                    active_backtests[backtest_id]["status"] = "error"
                    active_backtests[backtest_id][
                        "message"
                    ] = f"Error loading data for {symbol}: {str(e)}"
                    active_backtests[backtest_id]["updated_at"] = datetime.now()
                return

        # Update status
        with backtest_locks[backtest_id]:
            active_backtests[backtest_id]["status"] = "preparing_strategy"
            active_backtests[backtest_id]["progress"] = 50
            active_backtests[backtest_id]["message"] = "Preparing strategy..."
            active_backtests[backtest_id]["updated_at"] = datetime.now()

        # Check for cancellation
        if backtest_id in cancellation_requests:
            logger.info(f"Backtest {backtest_id} cancelled during strategy preparation")
            with backtest_locks[backtest_id]:
                active_backtests[backtest_id]["status"] = "cancelled"
                active_backtests[backtest_id]["message"] = "Backtest cancelled"
                active_backtests[backtest_id]["updated_at"] = datetime.now()
            return

        try:
            # Create strategy
            # Merge optional risk config into params (flat merge + nested copy)
            params = dict(strategy_config.get("params", {}) or {})
            risk_cfg: Dict[str, Any] = (config.get("risk") or {})
            # Flat merge for broad compatibility
            for k, v in risk_cfg.items():
                if v is not None and k not in params:
                    params[k] = v
            # Preserve nested copy too if consumers expect a `risk` object
            if risk_cfg:
                params.setdefault("risk", {})
                for k, v in risk_cfg.items():
                    if v is not None and k not in params["risk"]:
                        params["risk"][k] = v

            strategy = strategy_factory.create_strategy(
                strategy_type=strategy_config["type"],
                **params,
            )

            # Set strategy and data
            engine.set_strategy(strategy)
            engine.set_data(data_dict)
        except Exception as e:
            logger.error(
                f"Error preparing strategy for backtest {backtest_id}: {str(e)}"
            )
            logger.error(traceback.format_exc())

            with backtest_locks[backtest_id]:
                active_backtests[backtest_id]["status"] = "error"
                active_backtests[backtest_id][
                    "message"
                ] = f"Error preparing strategy: {str(e)}"
                active_backtests[backtest_id]["updated_at"] = datetime.now()
            return

        # Update status
        with backtest_locks[backtest_id]:
            active_backtests[backtest_id]["status"] = "running"
            active_backtests[backtest_id]["progress"] = 60
            active_backtests[backtest_id]["message"] = "Running backtest simulation..."
            active_backtests[backtest_id]["updated_at"] = datetime.now()

        # Check for cancellation
        if backtest_id in cancellation_requests:
            logger.info(f"Backtest {backtest_id} cancelled before execution")
            with backtest_locks[backtest_id]:
                active_backtests[backtest_id]["status"] = "cancelled"
                active_backtests[backtest_id]["message"] = "Backtest cancelled"
                active_backtests[backtest_id]["updated_at"] = datetime.now()
            return

        # Register progress callback
        def progress_callback(progress, message):
            """Callback for progress updates from engine."""
            # Map engine progress (0-100) to our progress range (60-90)
            mapped_progress = 60 + (progress * 0.3)

            with backtest_locks[backtest_id]:
                active_backtests[backtest_id]["progress"] = mapped_progress
                if message:
                    active_backtests[backtest_id]["message"] = message
                active_backtests[backtest_id]["updated_at"] = datetime.now()

            # Check for cancellation requests
            if backtest_id in cancellation_requests:
                return False  # Signal to stop processing

            return True  # Continue processing

        # Register the callback
        engine.set_progress_callback(progress_callback)

        # Run backtest with cancellation check
        try:
            results = engine.run()
        except Exception as e:
            logger.error(f"Error running backtest {backtest_id}: {str(e)}")
            logger.error(traceback.format_exc())

            with backtest_locks[backtest_id]:
                active_backtests[backtest_id]["status"] = "error"
                active_backtests[backtest_id][
                    "message"
                ] = f"Error running backtest: {str(e)}"
                active_backtests[backtest_id]["updated_at"] = datetime.now()
            return

        # Check if cancelled during execution
        if backtest_id in cancellation_requests:
            logger.info(f"Backtest {backtest_id} was cancelled during execution")
            with backtest_locks[backtest_id]:
                active_backtests[backtest_id]["status"] = "cancelled"
                active_backtests[backtest_id]["message"] = "Backtest cancelled"
                active_backtests[backtest_id]["updated_at"] = datetime.now()

            # Clean up
            if backtest_id in cancellation_requests:
                cancellation_requests.remove(backtest_id)

            return

        # Update status
        with backtest_locks[backtest_id]:
            active_backtests[backtest_id]["status"] = "analyzing"
            active_backtests[backtest_id]["progress"] = 90
            active_backtests[backtest_id]["message"] = "Analyzing results..."
            active_backtests[backtest_id]["updated_at"] = datetime.now()

        # Get summary
        try:
            summary = engine.get_summary()

            # Calculate execution time
            execution_time = time.time() - start_time
            execution_time_str = str(timedelta(seconds=int(execution_time)))

            # Add execution time to summary
            summary["execution_time"] = execution_time_str

            # Generate charts if available
            charts = []
            if hasattr(engine, "generate_charts"):
                charts = engine.generate_charts()

            # Store results
            backtest_results[backtest_id] = {
                "summary": summary,
                "metrics": results.attrs.get("risk_metrics", {}),
                "sample_data": (
                    results.iloc[:5000].to_dict(orient="records")
                ),  # Store more data for API responses
                "charts": charts,
            }

            # In a real app, store results in database
            # await BacktestRepository.save_results(backtest_id, backtest_results[backtest_id])

            # Update status
            with backtest_locks[backtest_id]:
                active_backtests[backtest_id]["status"] = "completed"
                active_backtests[backtest_id]["progress"] = 100
                active_backtests[backtest_id][
                    "message"
                ] = "Backtest completed successfully"
                active_backtests[backtest_id]["updated_at"] = datetime.now()

            logger.info(
                f"Backtest {backtest_id} completed successfully in {execution_time_str}"
            )

        except Exception as e:
            logger.error(
                f"Error analyzing results for backtest {backtest_id}: {str(e)}"
            )
            logger.error(traceback.format_exc())

            with backtest_locks[backtest_id]:
                active_backtests[backtest_id]["status"] = "error"
                active_backtests[backtest_id][
                    "message"
                ] = f"Error analyzing results: {str(e)}"
                active_backtests[backtest_id]["updated_at"] = datetime.now()

    except Exception as e:
        logger.error(f"Unexpected error in backtest {backtest_id}: {str(e)}")
        logger.error(traceback.format_exc())

        # Update status to error
        with backtest_locks.get(backtest_id, Lock()):
            active_backtests[backtest_id]["status"] = "error"
            active_backtests[backtest_id]["message"] = f"Unexpected error: {str(e)}"
            active_backtests[backtest_id]["updated_at"] = datetime.now()

    finally:
        # Clean up cancellation request if exists
        if backtest_id in cancellation_requests:
            cancellation_requests.remove(backtest_id)


def register_dependencies(
    data_service: DataService, strategy_registry: StrategyRegistry
) -> None:
    """
    Register dependencies for the router.

    Args:
        data_service: Data service instance
        strategy_registry: Strategy registry instance
    """
    setattr(router, "data_service", data_service)
    setattr(router, "strategy_registry", strategy_registry)

    # Schedule cleanup task
    # In a real app, this would be a scheduled task
    # app.on_event("startup")(cleanup_old_backtests)
