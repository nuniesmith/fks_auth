import asyncio
import hashlib
import json
import time
from datetime import datetime, timedelta
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from core.models.pagination import PaginatedResponse, PaginationParams
from core.telemetry.telemetry import telemetry
from domain.trading.strategies.registry import StrategyRegistry
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from framework.common.exceptions import (
    StrategyExecutionError,
    StrategyNotFoundError,
    StrategyParameterError,
    StrategyValidationError,
)
from framework.middleware.auth import (
    authenticate_user,
    cache_response,
    check_permission,
    get_auth_token,
    get_cached_response,
    get_db,
)
from loguru import logger
from pydantic import BaseModel, Field, ValidationError, root_validator, validator
from strategy.factory import StrategyFactory

# Configure logger
logger = logger.opt(colors=True).getLogger("strategy_api")

# Constants
CACHE_TTL_SECONDS = 3600  # 1 hour cache for strategy listings
MAX_VALIDATION_TIME_SECONDS = 10  # Maximum time for parameter validation
DEFAULT_PAGE_SIZE = 20


# Enums
class StrategyType(str, Enum):
    """Types of trading strategies."""

    TREND_FOLLOWING = "trend_following"
    MEAN_REVERSION = "mean_reversion"
    BREAKOUT = "breakout"
    MOMENTUM = "momentum"
    STATISTICAL_ARBITRAGE = "statistical_arbitrage"
    MACHINE_LEARNING = "machine_learning"
    CUSTOM = "custom"


class ParameterType(str, Enum):
    """Types of strategy parameters."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    ENUM = "enum"
    DATE = "date"


class SortOrder(str, Enum):
    """Sort order options."""

    ASC = "asc"
    DESC = "desc"


# Models for request/response
class StrategyInfo(BaseModel):
    """Information about a strategy."""

    id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    type: Optional[StrategyType] = None
    version: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    author: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)
    popularity: Optional[int] = None
    performance_metrics: Optional[Dict[str, Any]] = None


class StrategyParameter(BaseModel):
    """Parameter definition for a strategy."""

    name: str
    type: ParameterType
    description: Optional[str] = None
    default: Optional[Any] = None
    required: bool = False
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    options: Optional[List[Any]] = None
    pattern: Optional[str] = None
    multiple_of: Optional[float] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    nullable: bool = False
    deprecated: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ValidationResult(BaseModel):
    """Result of parameter validation."""

    valid: bool
    message: str
    error: Optional[str] = None
    errors: Dict[str, List[str]] = Field(default_factory=dict)
    warnings: Dict[str, List[str]] = Field(default_factory=dict)
    suggested_values: Dict[str, Any] = Field(default_factory=dict)
    execution_time_ms: Optional[float] = None


class StrategyComparison(BaseModel):
    """Comparison between two strategies."""

    base_strategy_id: str
    compared_strategy_id: str
    parameter_diff: Dict[str, Dict[str, Any]]
    performance_diff: Optional[Dict[str, float]] = None
    recommendation: Optional[str] = None


class StrategyListParams(BaseModel):
    """Parameters for listing strategies."""

    category: Optional[str] = None
    type: Optional[StrategyType] = None
    tags: Optional[List[str]] = None
    author: Optional[str] = None
    search: Optional[str] = None
    min_popularity: Optional[int] = None
    created_after: Optional[datetime] = None
    page: int = Field(1, ge=1)
    page_size: int = Field(DEFAULT_PAGE_SIZE, ge=1, le=100)
    sort_by: str = "name"
    sort_order: SortOrder = SortOrder.ASC


class ParameterValidationConfig(BaseModel):
    """Configuration for parameter validation."""

    mode: str = "strict"  # strict, lenient
    timeout_ms: int = Field(5000, ge=100, le=30000)
    validate_defaults: bool = True
    suggest_fixes: bool = True


class StrategyUpdate(BaseModel):
    """Updates to a strategy."""

    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None

    @validator("name")
    def validate_name(cls, v):
        if v is not None and (len(v) < 3 or len(v) > 100):
            raise ValueError("Name must be between 3 and 100 characters")
        return v

    @validator("tags")
    def validate_tags(cls, v):
        if v is not None:
            if len(v) > 10:
                raise ValueError("Maximum of 10 tags allowed")

            for tag in v:
                if not isinstance(tag, str) or len(tag) < 2 or len(tag) > 30:
                    raise ValueError("Tags must be strings between 2 and 30 characters")
        return v


class StrategyStats(BaseModel):
    """Usage statistics for strategies."""

    total_count: int
    by_category: Dict[str, int]
    by_type: Dict[str, int]
    most_popular: List[StrategyInfo]
    recently_updated: List[StrategyInfo]


# Custom exceptions
class StrategyRateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""

    def __init__(self, message: str, retry_after: int):
        self.message = message
        self.retry_after = retry_after
        super().__init__(message)


# Create router
router = APIRouter(
    prefix="/strategies",
    tags=["strategies"],
    dependencies=[Depends(get_auth_token)],
)


# Helper functions
def create_cache_key(prefix: str, user_id: str, **params) -> str:
    """Create a cache key based on prefix, user ID and parameters."""
    # Create a deterministic representation of parameters
    param_str = json.dumps(params, sort_keys=True)

    # Create hash for parameters to keep key length manageable
    param_hash = hashlib.md5(param_str.encode()).hexdigest()

    return f"{prefix}_{user_id}_{param_hash}"


async def validate_parameters_async(
    strategy_class, parameters: Dict[str, Any], config: ParameterValidationConfig
) -> ValidationResult:
    """
    Validate parameters asynchronously with timeout.

    Args:
        strategy_class: The strategy class to validate against
        parameters: The parameters to validate
        config: Validation configuration

    Returns:
        Validation result
    """
    start_time = time.time()

    try:
        # Get parameter definitions
        if not hasattr(strategy_class, "get_parameters"):
            return ValidationResult(
                valid=True,
                message="Strategy does not define parameter validation",
                execution_time_ms=round((time.time() - start_time) * 1000, 2),
            )

        param_definitions = strategy_class.get_parameters()

        # Validate required parameters
        errors = {}
        warnings = {}
        suggested_values = {}

        # Check for required parameters
        for param_name, param_info in param_definitions.items():
            if isinstance(param_info, dict) and param_info.get("required", False):
                if param_name not in parameters:
                    errors[param_name] = ["Required parameter is missing"]

        if errors:
            return ValidationResult(
                valid=False,
                message="Missing required parameters",
                errors=errors,
                execution_time_ms=round((time.time() - start_time) * 1000, 2),
            )

        # Validate parameter types and constraints
        for param_name, param_value in parameters.items():
            if param_name not in param_definitions:
                if config.mode == "strict":
                    errors[param_name] = ["Unknown parameter"]
                else:
                    warnings[param_name] = ["Unknown parameter, will be ignored"]
                continue

            param_info = param_definitions[param_name]

            # Handle simple parameter definitions
            if not isinstance(param_info, dict):
                continue

            # Validate based on type
            param_type = param_info.get("type", "string")

            try:
                # Validate type
                if param_type == "integer" and not isinstance(param_value, int):
                    raise ValueError(
                        f"Must be an integer, got {type(param_value).__name__}"
                    )

                elif param_type == "float" and not isinstance(
                    param_value, (int, float)
                ):
                    raise ValueError(
                        f"Must be a number, got {type(param_value).__name__}"
                    )

                elif param_type == "boolean" and not isinstance(param_value, bool):
                    raise ValueError(
                        f"Must be a boolean, got {type(param_value).__name__}"
                    )

                elif param_type == "array" and not isinstance(param_value, list):
                    raise ValueError(
                        f"Must be an array, got {type(param_value).__name__}"
                    )

                elif param_type == "object" and not isinstance(param_value, dict):
                    raise ValueError(
                        f"Must be an object, got {type(param_value).__name__}"
                    )

                # Validate ranges
                if param_type in ["integer", "float"]:
                    if (
                        "min_value" in param_info
                        and param_value < param_info["min_value"]
                    ):
                        raise ValueError(f"Must be at least {param_info['min_value']}")

                    if (
                        "max_value" in param_info
                        and param_value > param_info["max_value"]
                    ):
                        raise ValueError(f"Must be at most {param_info['max_value']}")

                    if (
                        "multiple_of" in param_info
                        and param_value % param_info["multiple_of"] != 0
                    ):
                        raise ValueError(
                            f"Must be a multiple of {param_info['multiple_of']}"
                        )

                # Validate enum options
                if "options" in param_info and param_value not in param_info["options"]:
                    raise ValueError(
                        f"Must be one of: {', '.join(str(o) for o in param_info['options'])}"
                    )

                # Validate string length
                if param_type == "string" and isinstance(param_value, str):
                    if (
                        "min_length" in param_info
                        and len(param_value) < param_info["min_length"]
                    ):
                        raise ValueError(
                            f"Must be at least {param_info['min_length']} characters"
                        )

                    if (
                        "max_length" in param_info
                        and len(param_value) > param_info["max_length"]
                    ):
                        raise ValueError(
                            f"Must be at most {param_info['max_length']} characters"
                        )

                    if "pattern" in param_info:
                        import re

                        if not re.match(param_info["pattern"], param_value):
                            raise ValueError(
                                f"Must match pattern: {param_info['pattern']}"
                            )

                # Validate array length
                if param_type == "array" and isinstance(param_value, list):
                    if (
                        "min_length" in param_info
                        and len(param_value) < param_info["min_length"]
                    ):
                        raise ValueError(
                            f"Must have at least {param_info['min_length']} items"
                        )

                    if (
                        "max_length" in param_info
                        and len(param_value) > param_info["max_length"]
                    ):
                        raise ValueError(
                            f"Must have at most {param_info['max_length']} items"
                        )

            except ValueError as e:
                errors[param_name] = [str(e)]

        # Check for success
        if errors:
            return ValidationResult(
                valid=False,
                message="Parameter validation failed",
                errors=errors,
                warnings=warnings,
                suggested_values=suggested_values,
                execution_time_ms=round((time.time() - start_time) * 1000, 2),
            )

        # If we get here, basic validation passed - now try creating an instance
        try:
            # Try to create a strategy instance
            factory = StrategyFactory(None)  # We don't need registry for validation
            strategy_instance = factory.create_strategy_instance(
                strategy_class=strategy_class, **parameters
            )

            # If the strategy has a validate method, call it
            if hasattr(strategy_instance, "validate"):
                validation_issues = strategy_instance.validate()

                if validation_issues:
                    for issue in validation_issues:
                        param = issue.get("parameter", "general")
                        message = issue.get("message", "Validation failed")
                        is_error = issue.get("is_error", True)

                        if is_error:
                            if param not in errors:
                                errors[param] = []
                            errors[param].append(message)
                        else:
                            if param not in warnings:
                                warnings[param] = []
                            warnings[param].append(message)

                    if errors:
                        return ValidationResult(
                            valid=False,
                            message="Strategy validation failed",
                            errors=errors,
                            warnings=warnings,
                            suggested_values=suggested_values,
                            execution_time_ms=round(
                                (time.time() - start_time) * 1000, 2
                            ),
                        )

            return ValidationResult(
                valid=True,
                message="Parameters are valid",
                warnings=warnings,
                suggested_values=suggested_values,
                execution_time_ms=round((time.time() - start_time) * 1000, 2),
            )

        except Exception as e:
            return ValidationResult(
                valid=False,
                message=f"Error creating strategy instance: {str(e)}",
                error=str(e),
                execution_time_ms=round((time.time() - start_time) * 1000, 2),
            )

    except asyncio.TimeoutError:
        return ValidationResult(
            valid=False,
            message="Validation timed out",
            error="Validation took too long to complete",
            execution_time_ms=config.timeout_ms,
        )

    except Exception as e:
        return ValidationResult(
            valid=False,
            message=f"Error during validation: {str(e)}",
            error=str(e),
            execution_time_ms=round((time.time() - start_time) * 1000, 2),
        )


def filter_strategies(
    strategies: List[Dict],
    category: Optional[str] = None,
    type: Optional[StrategyType] = None,
    tags: Optional[List[str]] = None,
    author: Optional[str] = None,
    search: Optional[str] = None,
    min_popularity: Optional[int] = None,
    created_after: Optional[datetime] = None,
) -> List[Dict]:
    """
    Filter strategies based on criteria.

    Args:
        strategies: List of strategy dictionaries
        category: Optional category filter
        type: Optional strategy type filter
        tags: Optional tags filter (strategies must have at least one)
        author: Optional author filter
        search: Optional search term (matched against name and description)
        min_popularity: Optional minimum popularity filter
        created_after: Optional creation date filter

    Returns:
        Filtered list of strategies
    """
    filtered = strategies

    # Filter by category
    if category:
        filtered = [s for s in filtered if s.get("category") == category]

    # Filter by type
    if type:
        filtered = [s for s in filtered if s.get("type") == type]

    # Filter by tags
    if tags:
        filtered = [
            s for s in filtered if any(tag in s.get("tags", []) for tag in tags)
        ]

    # Filter by author
    if author:
        filtered = [s for s in filtered if s.get("author") == author]

    # Filter by search term
    if search:
        search_lower = search.lower()
        filtered = [
            s
            for s in filtered
            if (
                search_lower in s.get("name", "").lower()
                or search_lower in s.get("description", "").lower()
                or any(search_lower in tag.lower() for tag in s.get("tags", []))
            )
        ]

    # Filter by popularity
    if min_popularity is not None:
        filtered = [s for s in filtered if s.get("popularity", 0) >= min_popularity]

    # Filter by creation date
    if created_after:
        filtered = [
            s
            for s in filtered
            if s.get("created_at") and s.get("created_at") >= created_after
        ]

    return filtered


def sort_strategies(
    strategies: List[Dict], sort_by: str = "name", sort_order: SortOrder = SortOrder.ASC
) -> List[Dict]:
    """
    Sort strategies based on field and order.

    Args:
        strategies: List of strategy dictionaries
        sort_by: Field to sort by
        sort_order: Sort order (asc or desc)

    Returns:
        Sorted list of strategies
    """

    # Default sort key function for missing values
    def get_sort_key(s, key):
        if key == "name":
            return s.get(key, "").lower()  # Sort names case-insensitive
        return s.get(key)

    reverse = sort_order == SortOrder.DESC

    # Handle special sort fields
    if sort_by == "popularity":
        return sorted(
            strategies,
            key=lambda s: (s.get("popularity", 0), s.get("name", "").lower()),
            reverse=reverse,
        )
    elif sort_by == "created_at" or sort_by == "updated_at":
        # Ensure datetime objects are compared (assume string ISO format if not datetime)
        def get_date(s, field):
            value = s.get(field)
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    return datetime.min
            return value or datetime.min

        return sorted(strategies, key=lambda s: get_date(s, sort_by), reverse=reverse)
    else:
        # General sorting
        return sorted(
            strategies, key=lambda s: get_sort_key(s, sort_by), reverse=reverse
        )


def paginate_strategies(
    strategies: List[Dict], page: int, page_size: int
) -> Tuple[List[Dict], int, int, bool]:
    """
    Paginate strategies.

    Args:
        strategies: List of strategy dictionaries
        page: Page number (1-based)
        page_size: Page size

    Returns:
        Tuple of (paginated strategies, total count, total pages, has more)
    """
    total_count = len(strategies)
    total_pages = (total_count + page_size - 1) // page_size

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size

    paginated = strategies[start_idx:end_idx]

    has_more = page < total_pages

    return paginated, total_count, total_pages, has_more


# Routes
@router.get("/", response_model=PaginatedResponse[StrategyInfo])
async def list_strategies(
    request: Request,
    response: Response,
    category: Optional[str] = Query(None, description="Filter by category"),
    type: Optional[StrategyType] = Query(None, description="Filter by strategy type"),
    tags: Optional[str] = Query(None, description="Comma-separated list of tags"),
    author: Optional[str] = Query(None, description="Filter by author"),
    search: Optional[str] = Query(None, description="Search term"),
    min_popularity: Optional[int] = Query(None, description="Minimum popularity score"),
    created_after: Optional[datetime] = Query(
        None, description="Filter by creation date"
    ),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=100, description="Page size"),
    sort_by: str = Query("name", description="Field to sort by"),
    sort_order: SortOrder = Query(SortOrder.ASC, description="Sort order"),
    refresh_cache: bool = Query(False, description="Force refresh cache"),
    token: str = Depends(get_auth_token),
    strategy_registry: StrategyRegistry = Depends(lambda: router.strategy_registry),
):
    """
    List available strategy types with filtering, sorting, and pagination.

    This endpoint retrieves strategies from the registry and allows filtering
    by various criteria, sorting, and pagination.

    Args:
        category: Optional category filter
        type: Optional strategy type filter
        tags: Optional comma-separated list of tags
        author: Optional author filter
        search: Optional search term (matched against name and description)
        min_popularity: Optional minimum popularity filter
        created_after: Optional creation date filter
        page: Page number (1-based)
        page_size: Number of items per page
        sort_by: Field to sort by
        sort_order: Sort order (asc or desc)
        refresh_cache: Force refresh cache
        token: Authentication token
        strategy_registry: Strategy registry dependency

    Returns:
        Paginated list of strategies
    """
    # Start telemetry span
    with telemetry.start_span("list_strategies"):
        # Authenticate user
        user = authenticate_user(token)

        # Check user permissions
        check_permission(user, "strategy:list")

        # Parse tags if provided
        parsed_tags = None
        if tags:
            parsed_tags = [tag.strip() for tag in tags.split(",") if tag.strip()]

        # Create cache key
        cache_key = create_cache_key(
            prefix="strategies_list",
            user_id=user["sub"],
            category=category,
            type=type,
            tags=parsed_tags,
            author=author,
            search=search,
            min_popularity=min_popularity,
            created_after=created_after.isoformat() if created_after else None,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        # Check cache unless refresh requested
        if not refresh_cache:
            cached_response = get_cached_response(cache_key)
            if cached_response:
                # Set cache hit header
                response.headers["X-Cache"] = "HIT"
                return PaginatedResponse[StrategyInfo](**cached_response)

        try:
            # Get strategies from registry
            strategies = strategy_registry.list_strategies()

            # Apply filters
            filtered_strategies = filter_strategies(
                strategies=strategies,
                category=category,
                type=type,
                tags=parsed_tags,
                author=author,
                search=search,
                min_popularity=min_popularity,
                created_after=created_after,
            )

            # Sort strategies
            sorted_strategies = sort_strategies(
                strategies=filtered_strategies, sort_by=sort_by, sort_order=sort_order
            )

            # Paginate strategies
            paginated_strategies, total_count, total_pages, has_more = (
                paginate_strategies(
                    strategies=sorted_strategies, page=page, page_size=page_size
                )
            )

            # Convert to response model
            response_items = []
            for strategy in paginated_strategies:
                # Convert dates if they're strings
                created_at = strategy.get("created_at")
                if isinstance(created_at, str):
                    try:
                        created_at = datetime.fromisoformat(
                            created_at.replace("Z", "+00:00")
                        )
                    except ValueError:
                        created_at = None

                updated_at = strategy.get("updated_at")
                if isinstance(updated_at, str):
                    try:
                        updated_at = datetime.fromisoformat(
                            updated_at.replace("Z", "+00:00")
                        )
                    except ValueError:
                        updated_at = None

                response_items.append(
                    StrategyInfo(
                        id=strategy["id"],
                        name=strategy["name"],
                        description=strategy.get("description"),
                        category=strategy.get("category"),
                        type=strategy.get("type"),
                        version=strategy.get("version"),
                        parameters=strategy.get("parameters", {}),
                        author=strategy.get("author"),
                        created_at=created_at,
                        updated_at=updated_at,
                        tags=strategy.get("tags", []),
                        popularity=strategy.get("popularity"),
                        performance_metrics=strategy.get("performance_metrics"),
                    )
                )

            # Create response
            result = PaginatedResponse[StrategyInfo](
                items=response_items,
                page=page,
                page_size=page_size,
                total_count=total_count,
                total_pages=total_pages,
                has_more=has_more,
            )

            # Cache response
            cache_response(cache_key, result.dict(), ttl_seconds=CACHE_TTL_SECONDS)

            # Set cache miss header
            response.headers["X-Cache"] = "MISS"

            return result

        except Exception as e:
            logger.error(f"Error listing strategies: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error listing strategies: {str(e)}",
            )


@router.get("/{strategy_id}", response_model=StrategyInfo)
async def get_strategy(
    request: Request,
    response: Response,
    strategy_id: str = Path(..., description="ID of the strategy"),
    include_metrics: bool = Query(False, description="Include performance metrics"),
    refresh_cache: bool = Query(False, description="Force refresh cache"),
    token: str = Depends(get_auth_token),
    strategy_registry: StrategyRegistry = Depends(lambda: router.strategy_registry),
):
    """
    Get details about a specific strategy.

    This endpoint retrieves detailed information about a specific strategy,
    including its parameters and optionally performance metrics.

    Args:
        strategy_id: ID of the strategy
        include_metrics: Whether to include performance metrics
        refresh_cache: Force refresh cache
        token: Authentication token
        strategy_registry: Strategy registry dependency

    Returns:
        Strategy details
    """
    # Start telemetry span
    with telemetry.start_span("get_strategy"):
        # Authenticate user
        user = authenticate_user(token)

        # Check user permissions
        check_permission(user, "strategy:read")

        # Create cache key
        cache_key = create_cache_key(
            prefix="strategy_detail",
            user_id=user["sub"],
            strategy_id=strategy_id,
            include_metrics=include_metrics,
        )

        # Check cache unless refresh requested
        if not refresh_cache:
            cached_response = get_cached_response(cache_key)
            if cached_response:
                # Set cache hit header
                response.headers["X-Cache"] = "HIT"
                return StrategyInfo(**cached_response)

        try:
            # Get strategy from registry
            strategy_class = strategy_registry.get_strategy(strategy_id)

            if not strategy_class:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Strategy {strategy_id} not found",
                )

            # Get strategy metadata
            name = getattr(strategy_class, "name", strategy_id)
            description = strategy_class.__doc__ or ""
            category = getattr(strategy_class, "category", None)
            type_value = getattr(strategy_class, "type", None)
            version = getattr(strategy_class, "version", "1.0.0")
            author = getattr(strategy_class, "author", None)
            created_at = getattr(strategy_class, "created_at", None)
            updated_at = getattr(strategy_class, "updated_at", None)
            tags = getattr(strategy_class, "tags", [])
            popularity = getattr(strategy_class, "popularity", 0)

            # Get parameters
            parameters = {}
            if hasattr(strategy_class, "get_parameters"):
                parameters = strategy_class.get_parameters()

            # Get performance metrics if requested
            performance_metrics = None
            if include_metrics and hasattr(strategy_class, "get_performance_metrics"):
                try:
                    performance_metrics = strategy_class.get_performance_metrics()
                except Exception as e:
                    logger.warning(
                        f"Error getting performance metrics for {strategy_id}: {str(e)}"
                    )

            # Create response
            result = StrategyInfo(
                id=strategy_id,
                name=name,
                description=description,
                category=category,
                type=type_value,
                version=version,
                parameters=parameters,
                author=author,
                created_at=created_at,
                updated_at=updated_at,
                tags=tags,
                popularity=popularity,
                performance_metrics=performance_metrics,
            )

            # Cache response
            cache_response(cache_key, result.dict(), ttl_seconds=CACHE_TTL_SECONDS)

            # Set cache miss header
            response.headers["X-Cache"] = "MISS"

            return result

        except HTTPException:
            raise
        except StrategyNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Strategy {strategy_id} not found",
            )
        except Exception as e:
            logger.error(f"Error getting strategy {strategy_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error getting strategy: {str(e)}",
            )


@router.get("/{strategy_id}/parameters", response_model=List[StrategyParameter])
async def get_strategy_parameters(
    strategy_id: str = Path(..., description="ID of the strategy"),
    include_metadata: bool = Query(False, description="Include additional metadata"),
    token: str = Depends(get_auth_token),
    strategy_registry: StrategyRegistry = Depends(lambda: router.strategy_registry),
):
    """
    Get parameter definitions for a specific strategy.

    This endpoint retrieves detailed parameter definitions for a specific strategy,
    including type information, constraints, and optionally additional metadata.

    Args:
        strategy_id: ID of the strategy
        include_metadata: Whether to include additional metadata
        token: Authentication token
        strategy_registry: Strategy registry dependency

    Returns:
        List of parameter definitions
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "strategy:read")

    try:
        # Get strategy from registry
        strategy_class = strategy_registry.get_strategy(strategy_id)

        if not strategy_class:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Strategy {strategy_id} not found",
            )

        # Get parameters
        if not hasattr(strategy_class, "get_parameters"):
            return []

        params_dict = strategy_class.get_parameters()

        # Convert to response model
        response = []
        for param_name, param_info in params_dict.items():
            if isinstance(param_info, dict):
                # Get parameter type
                param_type = param_info.get("type", "string")

                # Try to convert to enum
                try:
                    param_type = ParameterType(param_type)
                except ValueError:
                    param_type = ParameterType.STRING

                # Create parameter object
                parameter = StrategyParameter(
                    name=param_name,
                    type=param_type,
                    description=param_info.get("description"),
                    default=param_info.get("default"),
                    required=param_info.get("required", False),
                    min_value=param_info.get("min_value"),
                    max_value=param_info.get("max_value"),
                    options=param_info.get("options"),
                    pattern=param_info.get("pattern"),
                    multiple_of=param_info.get("multiple_of"),
                    min_length=param_info.get("min_length"),
                    max_length=param_info.get("max_length"),
                    nullable=param_info.get("nullable", False),
                    deprecated=param_info.get("deprecated", False),
                )

                # Add metadata if requested
                if include_metadata:
                    # Extract metadata fields (any fields not in the StrategyParameter model)
                    base_fields = {
                        "name",
                        "type",
                        "description",
                        "default",
                        "required",
                        "min_value",
                        "max_value",
                        "options",
                        "pattern",
                        "multiple_of",
                        "min_length",
                        "max_length",
                        "nullable",
                        "deprecated",
                    }

                    metadata = {
                        k: v for k, v in param_info.items() if k not in base_fields
                    }

                    parameter.metadata = metadata

                response.append(parameter)
            else:
                # Handle simple parameter definitions
                response.append(
                    StrategyParameter(
                        name=param_name, type=ParameterType.STRING, default=param_info
                    )
                )

        return response

    except HTTPException:
        raise
    except StrategyNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Strategy {strategy_id} not found",
        )
    except Exception as e:
        logger.error(f"Error getting strategy parameters for {strategy_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting strategy parameters: {str(e)}",
        )


@router.post("/{strategy_id}/validate", response_model=ValidationResult)
async def validate_strategy_parameters(
    strategy_id: str = Path(..., description="ID of the strategy"),
    parameters: Dict[str, Any] = Body(..., description="Parameters to validate"),
    config: ParameterValidationConfig = Body(
        ParameterValidationConfig(), description="Validation configuration"
    ),
    token: str = Depends(get_auth_token),
    strategy_registry: StrategyRegistry = Depends(lambda: router.strategy_registry),
):
    """
    Validate parameters for a strategy.

    This endpoint validates provided parameters against a strategy's requirements
    and returns validation results including errors and warnings.

    Args:
        strategy_id: ID of the strategy
        parameters: Parameters to validate
        config: Validation configuration
        token: Authentication token
        strategy_registry: Strategy registry dependency

    Returns:
        Validation result
    """
    # Start telemetry span
    with telemetry.start_span("validate_strategy_parameters"):
        # Authenticate user
        user = authenticate_user(token)

        # Check user permissions
        check_permission(user, "strategy:validate")

        try:
            # Get strategy from registry
            strategy_class = strategy_registry.get_strategy(strategy_id)

            if not strategy_class:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Strategy {strategy_id} not found",
                )

            # Run validation with timeout
            try:
                timeout_seconds = config.timeout_ms / 1000
                validation_task = asyncio.create_task(
                    validate_parameters_async(strategy_class, parameters, config)
                )
                result = await asyncio.wait_for(
                    validation_task, timeout=timeout_seconds
                )
                return result

            except asyncio.TimeoutError:
                return ValidationResult(
                    valid=False,
                    message="Validation timed out",
                    error=f"Validation exceeded the {config.timeout_ms}ms timeout",
                    execution_time_ms=config.timeout_ms,
                )

        except HTTPException:
            raise
        except StrategyNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Strategy {strategy_id} not found",
            )
        except Exception as e:
            logger.error(
                f"Error validating strategy parameters for {strategy_id}: {str(e)}"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error validating strategy parameters: {str(e)}",
            )


@router.get("/categories", response_model=List[str])
async def get_strategy_categories(
    response: Response,
    token: str = Depends(get_auth_token),
    strategy_registry: StrategyRegistry = Depends(lambda: router.strategy_registry),
    refresh_cache: bool = Query(False, description="Force refresh cache"),
):
    """
    Get available strategy categories.

    This endpoint retrieves all unique categories used by registered strategies.

    Args:
        token: Authentication token
        strategy_registry: Strategy registry dependency
        refresh_cache: Force refresh cache

    Returns:
        List of category names
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "strategy:list")

    # Create cache key
    cache_key = create_cache_key(prefix="strategy_categories", user_id=user["sub"])

    # Check cache unless refresh requested
    if not refresh_cache:
        cached_response = get_cached_response(cache_key)
        if cached_response:
            # Set cache hit header
            response.headers["X-Cache"] = "HIT"
            return cached_response

    try:
        # Get strategies from registry
        strategies = strategy_registry.list_strategies()

        # Extract categories
        categories = set()
        for strategy in strategies:
            if "category" in strategy and strategy["category"]:
                categories.add(strategy["category"])

        result = sorted(list(categories))

        # Cache response
        cache_response(cache_key, result, ttl_seconds=CACHE_TTL_SECONDS)

        # Set cache miss header
        response.headers["X-Cache"] = "MISS"

        return result

    except Exception as e:
        logger.error(f"Error getting strategy categories: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting strategy categories: {str(e)}",
        )


@router.get("/types", response_model=List[str])
async def get_strategy_types(
    response: Response,
    token: str = Depends(get_auth_token),
    refresh_cache: bool = Query(False, description="Force refresh cache"),
):
    """
    Get available strategy types.

    This endpoint retrieves all defined strategy types that can be used
    for filtering strategies.

    Args:
        token: Authentication token
        refresh_cache: Force refresh cache

    Returns:
        List of strategy types
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "strategy:list")

    # Create cache key
    cache_key = create_cache_key(prefix="strategy_types", user_id=user["sub"])

    # Check cache unless refresh requested
    if not refresh_cache:
        cached_response = get_cached_response(cache_key)
        if cached_response:
            # Set cache hit header
            response.headers["X-Cache"] = "HIT"
            return cached_response

    try:
        # Get all strategy types from enum
        result = [t.value for t in StrategyType]

        # Cache response
        cache_response(
            cache_key, result, ttl_seconds=CACHE_TTL_SECONDS * 24
        )  # Cache for 24x longer, rarely changes

        # Set cache miss header
        response.headers["X-Cache"] = "MISS"

        return result

    except Exception as e:
        logger.error(f"Error getting strategy types: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting strategy types: {str(e)}",
        )


@router.get("/parameter-types", response_model=List[str])
async def get_parameter_types(
    response: Response,
    token: str = Depends(get_auth_token),
    refresh_cache: bool = Query(False, description="Force refresh cache"),
):
    """
    Get available parameter types.

    This endpoint retrieves all defined parameter types that can be used
    for strategy parameters.

    Args:
        token: Authentication token
        refresh_cache: Force refresh cache

    Returns:
        List of parameter types
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "strategy:list")

    # Create cache key
    cache_key = create_cache_key(prefix="parameter_types", user_id=user["sub"])

    # Check cache unless refresh requested
    if not refresh_cache:
        cached_response = get_cached_response(cache_key)
        if cached_response:
            # Set cache hit header
            response.headers["X-Cache"] = "HIT"
            return cached_response

    try:
        # Get all parameter types from enum
        result = [t.value for t in ParameterType]

        # Cache response
        cache_response(
            cache_key, result, ttl_seconds=CACHE_TTL_SECONDS * 24
        )  # Cache for 24x longer, rarely changes

        # Set cache miss header
        response.headers["X-Cache"] = "MISS"

        return result

    except Exception as e:
        logger.error(f"Error getting parameter types: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting parameter types: {str(e)}",
        )


@router.get("/stats", response_model=StrategyStats)
async def get_strategy_stats(
    response: Response,
    token: str = Depends(get_auth_token),
    strategy_registry: StrategyRegistry = Depends(lambda: router.strategy_registry),
    refresh_cache: bool = Query(False, description="Force refresh cache"),
):
    """
    Get usage statistics for strategies.

    This endpoint retrieves aggregated statistics about strategies,
    including counts by category and type, most popular strategies,
    and recently updated strategies.

    Args:
        token: Authentication token
        strategy_registry: Strategy registry dependency
        refresh_cache: Force refresh cache

    Returns:
        Strategy statistics
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "strategy:read")

    # Create cache key
    cache_key = create_cache_key(prefix="strategy_stats", user_id=user["sub"])

    # Check cache unless refresh requested
    if not refresh_cache:
        cached_response = get_cached_response(cache_key)
        if cached_response:
            # Set cache hit header
            response.headers["X-Cache"] = "HIT"
            return StrategyStats(**cached_response)

    try:
        # Get strategies from registry
        strategies = strategy_registry.list_strategies()

        # Calculate stats

        # Total count
        total_count = len(strategies)

        # Count by category
        by_category = {}
        for strategy in strategies:
            category = strategy.get("category", "uncategorized")
            by_category[category] = by_category.get(category, 0) + 1

        # Count by type
        by_type = {}
        for strategy in strategies:
            type_value = strategy.get("type", "unknown")
            by_type[type_value] = by_type.get(type_value, 0) + 1

        # Get most popular strategies
        sorted_by_popularity = sorted(
            strategies, key=lambda s: s.get("popularity", 0), reverse=True
        )[
            :5
        ]  # Top 5

        # Get recently updated strategies
        sorted_by_updated = sorted(
            [s for s in strategies if s.get("updated_at")],
            key=lambda s: s.get("updated_at"),
            reverse=True,
        )[
            :5
        ]  # Top 5

        # Convert strategies to StrategyInfo model
        most_popular = [
            StrategyInfo(
                id=s["id"],
                name=s["name"],
                description=s.get("description"),
                category=s.get("category"),
                type=s.get("type"),
                parameters=s.get("parameters", {}),
                popularity=s.get("popularity", 0),
            )
            for s in sorted_by_popularity
        ]

        recently_updated = [
            StrategyInfo(
                id=s["id"],
                name=s["name"],
                description=s.get("description"),
                category=s.get("category"),
                type=s.get("type"),
                parameters=s.get("parameters", {}),
                updated_at=s.get("updated_at"),
            )
            for s in sorted_by_updated
        ]

        # Create result
        result = StrategyStats(
            total_count=total_count,
            by_category=by_category,
            by_type=by_type,
            most_popular=most_popular,
            recently_updated=recently_updated,
        )

        # Cache response
        cache_response(cache_key, result.dict(), ttl_seconds=CACHE_TTL_SECONDS)

        # Set cache miss header
        response.headers["X-Cache"] = "MISS"

        return result

    except Exception as e:
        logger.error(f"Error getting strategy stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting strategy stats: {str(e)}",
        )


@router.post("/compare", response_model=StrategyComparison)
async def compare_strategies(
    base_strategy_id: str = Body(..., description="Base strategy ID"),
    compared_strategy_id: str = Body(..., description="Strategy to compare with"),
    base_params: Optional[Dict[str, Any]] = Body(
        None, description="Parameters for base strategy"
    ),
    compared_params: Optional[Dict[str, Any]] = Body(
        None, description="Parameters for compared strategy"
    ),
    token: str = Depends(get_auth_token),
    strategy_registry: StrategyRegistry = Depends(lambda: router.strategy_registry),
):
    """
    Compare two strategies.

    This endpoint compares two strategies, including their parameters
    and optionally their performance with different parameters.

    Args:
        base_strategy_id: Base strategy ID
        compared_strategy_id: Strategy to compare with
        base_params: Optional parameters for base strategy
        compared_params: Optional parameters for compared strategy
        token: Authentication token
        strategy_registry: Strategy registry dependency

    Returns:
        Comparison results
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "strategy:read")

    try:
        # Get strategies from registry
        base_strategy_class = strategy_registry.get_strategy(base_strategy_id)
        compared_strategy_class = strategy_registry.get_strategy(compared_strategy_id)

        if not base_strategy_class:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Base strategy {base_strategy_id} not found",
            )

        if not compared_strategy_class:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Compared strategy {compared_strategy_id} not found",
            )

        # Get parameters
        base_strategy_params = {}
        if hasattr(base_strategy_class, "get_parameters"):
            base_strategy_params = base_strategy_class.get_parameters()

        compared_strategy_params = {}
        if hasattr(compared_strategy_class, "get_parameters"):
            compared_strategy_params = compared_strategy_class.get_parameters()

        # Find parameter differences
        parameter_diff = {}

        # Compare parameters that exist in both strategies
        for param_name in set(base_strategy_params.keys()) | set(
            compared_strategy_params.keys()
        ):
            # Parameter only in base strategy
            if param_name not in compared_strategy_params:
                parameter_diff[param_name] = {
                    "only_in_base": True,
                    "base_value": base_strategy_params[param_name],
                }
                continue

            # Parameter only in compared strategy
            if param_name not in base_strategy_params:
                parameter_diff[param_name] = {
                    "only_in_compared": True,
                    "compared_value": compared_strategy_params[param_name],
                }
                continue

            # Parameter in both strategies
            base_param = base_strategy_params[param_name]
            compared_param = compared_strategy_params[param_name]

            # Simple comparison for non-dict parameters
            if not isinstance(base_param, dict) or not isinstance(compared_param, dict):
                if base_param != compared_param:
                    parameter_diff[param_name] = {
                        "base_value": base_param,
                        "compared_value": compared_param,
                    }
                continue

            # Compare dict parameters
            differences = {}

            # Compare all fields from both parameters
            for field in set(base_param.keys()) | set(compared_param.keys()):
                # Field only in base param
                if field not in compared_param:
                    differences[field] = {
                        "only_in_base": True,
                        "base_value": base_param[field],
                    }
                    continue

                # Field only in compared param
                if field not in base_param:
                    differences[field] = {
                        "only_in_compared": True,
                        "compared_value": compared_param[field],
                    }
                    continue

                # Field in both params but with different values
                if base_param[field] != compared_param[field]:
                    differences[field] = {
                        "base_value": base_param[field],
                        "compared_value": compared_param[field],
                    }

            # Add param diff if there are differences
            if differences:
                parameter_diff[param_name] = differences

        # Compare performance if provided with parameters
        performance_diff = None
        recommendation = None

        if base_params and compared_params:
            # Create strategy instances with provided parameters
            factory = StrategyFactory(strategy_registry)

            try:
                # Try to create strategy instances
                base_strategy = factory.create_strategy(
                    strategy_type=base_strategy_id, **base_params
                )

                compared_strategy = factory.create_strategy(
                    strategy_type=compared_strategy_id, **compared_params
                )

                # Get performance metrics for both strategies if available
                base_metrics = None
                compared_metrics = None

                if hasattr(base_strategy, "get_performance_metrics"):
                    base_metrics = base_strategy.get_performance_metrics()

                if hasattr(compared_strategy, "get_performance_metrics"):
                    compared_metrics = compared_strategy.get_performance_metrics()

                # Calculate performance differences if metrics available
                if base_metrics and compared_metrics:
                    performance_diff = {}

                    # Compare metrics that exist in both strategies
                    for metric_name in set(base_metrics.keys()) & set(
                        compared_metrics.keys()
                    ):
                        if isinstance(
                            base_metrics[metric_name], (int, float)
                        ) and isinstance(compared_metrics[metric_name], (int, float)):
                            diff = (
                                compared_metrics[metric_name]
                                - base_metrics[metric_name]
                            )
                            performance_diff[metric_name] = diff

                    # Generate recommendation based on performance diff
                    if performance_diff:
                        if sum(performance_diff.values()) > 0:
                            recommendation = f"The compared strategy ({compared_strategy_id}) appears to perform better overall."
                        else:
                            recommendation = f"The base strategy ({base_strategy_id}) appears to perform better overall."

            except Exception as e:
                logger.warning(f"Error comparing strategy performance: {str(e)}")

        # Create response
        return StrategyComparison(
            base_strategy_id=base_strategy_id,
            compared_strategy_id=compared_strategy_id,
            parameter_diff=parameter_diff,
            performance_diff=performance_diff,
            recommendation=recommendation,
        )

    except HTTPException:
        raise
    except StrategyNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.error(f"Error comparing strategies: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error comparing strategies: {str(e)}",
        )


def register_dependencies(strategy_registry: StrategyRegistry) -> None:
    """
    Register dependencies for the router.

    Args:
        strategy_registry: Strategy registry instance
    """
    router.strategy_registry = strategy_registry
