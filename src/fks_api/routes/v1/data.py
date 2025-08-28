import asyncio
import csv
import io
import json
import time
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd
from core.data.service import DataService
from core.telemetry import telemetry
from core.validation.validators import validate
from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Response,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from framework.common.exceptions import (
    DataSourceNotFoundError,
    InvalidDateRangeError,
    SymbolNotFoundError,
)
from framework.middleware.auth import (
    authenticate_user,
    cache_response,
    get_auth_token,
    get_cached_response,
    invalidate_cache,
)
from loguru import logger
from pydantic import BaseModel, Field, root_validator, validator

# Configure logger
logger = logger.opt(colors=True).getLogger("data_api")


# Enums for standard options
class DataFormat(str, Enum):
    """Available data export formats."""

    JSON = "json"
    CSV = "csv"
    EXCEL = "excel"


class DataInterval(str, Enum):
    """Standard time intervals for market data."""

    MINUTE_1 = "1m"
    MINUTE_5 = "5m"
    MINUTE_15 = "15m"
    MINUTE_30 = "30m"
    HOUR_1 = "1h"
    HOUR_4 = "4h"
    DAY_1 = "1d"
    WEEK_1 = "1w"
    MONTH_1 = "1M"


# Models for request/response
class DataSourceInfo(BaseModel):
    """Information about a data source."""

    id: str
    name: str
    type: str
    description: Optional[str] = None
    requires_auth: bool = False
    supports_live: bool = False
    intervals: List[str] = Field(default_factory=list)
    asset_types: List[str] = Field(default_factory=list)
    max_history_days: Optional[int] = None
    rate_limit: Optional[Dict[str, Any]] = None


class SymbolInfo(BaseModel):
    """Information about a symbol."""

    symbol: str
    name: Optional[str] = None
    exchange: Optional[str] = None
    asset_type: Optional[str] = None
    currency: Optional[str] = None
    sector: Optional[str] = None
    industry: Optional[str] = None
    first_date: Optional[str] = None
    last_date: Optional[str] = None


class MarketDataResponse(BaseModel):
    """Response model for market data."""

    symbol: str
    source: str
    interval: str
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    points_count: int
    columns: List[str]
    data: List[Dict[str, Any]]
    has_more: bool = False
    next_page_token: Optional[str] = None


class DataSourceListResponse(BaseModel):
    """Response model for data source listing."""

    sources: List[DataSourceInfo]
    count: int


class SymbolListResponse(BaseModel):
    """Response model for symbol listing."""

    symbols: List[SymbolInfo]
    count: int
    total_count: int
    has_more: bool = False
    next_page: Optional[str] = None


class DataAvailabilityResponse(BaseModel):
    """Response model for data availability."""

    source: str
    symbol: str
    available_intervals: List[str]
    first_date: Optional[str] = None
    last_date: Optional[str] = None
    data_points: Optional[int] = None
    data_complete: bool = True


class BulkDataRequest(BaseModel):
    """Request model for bulk data retrieval."""

    symbols: List[str]
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    interval: str = "1d"

    @validator("symbols")
    def validate_symbols(cls, v):
        if not v:
            raise ValueError("At least one symbol must be provided")
        if len(v) > 50:
            raise ValueError("Maximum of 50 symbols allowed per request")
        return v

    @validator("interval")
    def validate_interval(cls, v):
        valid_intervals = [interval.value for interval in DataInterval]
        if v not in valid_intervals:
            raise ValueError(
                f"Invalid interval: {v}. Valid options: {', '.join(valid_intervals)}"
            )
        return v

    @validator("start_date", "end_date")
    def validate_dates(cls, v):
        if v is None:
            return v
        try:
            datetime.fromisoformat(v)
        except ValueError:
            raise ValueError(f"Invalid date format: {v}. Use ISO format (YYYY-MM-DD)")
        return v


# Helper functions
def get_date_range(
    start_date: Optional[str], end_date: Optional[str], default_days: int = 30
) -> Tuple[datetime, datetime]:
    """
    Get validated date range with defaults.

    Args:
        start_date: Optional start date string
        end_date: Optional end date string
        default_days: Default number of days if no start date

    Returns:
        Tuple of (start_date, end_date) as datetime objects

    Raises:
        ValueError: For invalid date formats or ranges
    """
    now = datetime.now()

    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date)
        except ValueError:
            raise ValueError(f"Invalid end date format: {end_date}")
    else:
        end_dt = now

    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date)
        except ValueError:
            raise ValueError(f"Invalid start date format: {start_date}")
    else:
        start_dt = end_dt - timedelta(days=default_days)

    # Validate range
    if start_dt > end_dt:
        raise ValueError("Start date must be before end date")

    if start_dt > now:
        raise ValueError("Start date cannot be in the future")

    # Limit range to reasonable values
    if (end_dt - start_dt).days > 3650:  # 10 years
        raise ValueError("Date range cannot exceed 10 years")

    return start_dt, end_dt


def dataframe_to_format(
    df: pd.DataFrame, format_type: DataFormat, filename: Optional[str] = None
) -> Tuple[bytes, str, str]:
    """
    Convert DataFrame to specified format.

    Args:
        df: Pandas DataFrame
        format_type: Output format
        filename: Optional filename base

    Returns:
        Tuple of (bytes_data, content_type, suggested_filename)
    """
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"market_data_{timestamp}"

    if format_type == DataFormat.CSV:
        # Convert to CSV
        buffer = io.StringIO()
        df.to_csv(buffer, index=False)
        data = buffer.getvalue().encode()
        content_type = "text/csv"
        filename = f"{filename}.csv"

    elif format_type == DataFormat.EXCEL:
        # Convert to Excel
        buffer = io.BytesIO()
        df.to_excel(buffer, index=False)
        data = buffer.getvalue()
        content_type = (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        filename = f"{filename}.xlsx"

    else:  # Default to JSON
        # Convert to JSON
        data = df.to_json(orient="records", date_format="iso").encode()
        content_type = "application/json"
        filename = f"{filename}.json"

    return data, content_type, filename


def rate_limit_middleware(rate_limit_per_min: int = 100):
    """
    Rate limiting decorator for endpoints.

    Args:
        rate_limit_per_min: Requests allowed per minute

    Returns:
        Decorated function
    """

    def decorator(func):
        # Store request timestamps for each user
        request_history = {}

        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get user ID from kwargs
            token = kwargs.get("token")
            if token:
                user = authenticate_user(token)
                user_id = user["sub"]
            else:
                user_id = "anonymous"

            # Get current time
            now = time.time()

            # Initialize user history if needed
            if user_id not in request_history:
                request_history[user_id] = []

            # Remove requests older than 1 minute
            request_history[user_id] = [
                t for t in request_history[user_id] if now - t < 60
            ]

            # Check rate limit
            if len(request_history[user_id]) >= rate_limit_per_min:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded: {rate_limit_per_min} requests per minute",
                )

            # Add current request
            request_history[user_id].append(now)

            # Call original function
            return await func(*args, **kwargs)

        return wrapper

    return decorator


# Create router
router = APIRouter(
    prefix="/data",
    tags=["data"],
    dependencies=[Depends(get_auth_token)],
)


# Routes
@router.get("/sources", response_model=DataSourceListResponse)
@rate_limit_middleware(rate_limit_per_min=20)
async def get_data_sources(
    token: str = Depends(get_auth_token),
    data_service: DataService = Depends(lambda: router.data_service),
    source_type: Optional[str] = Query(None, description="Filter by source type"),
    refresh_cache: bool = Query(False, description="Force refresh of cached data"),
):
    """
    Get available data sources.

    Args:
        token: Authentication token
        data_service: Data service dependency
        source_type: Optional filter by source type
        refresh_cache: Force refresh of cached data

    Returns:
        Data source information
    """
    # Start telemetry span
    with telemetry.start_span("get_data_sources"):
        # Authenticate user
        user = authenticate_user(token)

        # Check user permissions
        check_permission(user, "data:read")

        # Cache key based on user and filter
        cache_key = f"data_sources_{user['sub']}_{source_type or 'all'}"

        # Check cache unless refresh requested
        if not refresh_cache:
            cached_response = get_cached_response(
                cache_key, max_age_seconds=3600
            )  # Cache for 1 hour
            if cached_response:
                return cached_response

        # Get sources from service
        try:
            sources = await data_service.list_sources()

            # Apply type filter if provided
            if source_type:
                sources = {
                    id: info
                    for id, info in sources.items()
                    if info.get("type") == source_type
                }

            # Convert to response model
            response_sources = []
            for source_id, source_info in sources.items():
                response_sources.append(
                    DataSourceInfo(
                        id=source_id,
                        name=source_info.get("name", source_id),
                        type=source_info.get("type", "unknown"),
                        description=source_info.get("description"),
                        requires_auth=source_info.get("requires_auth", False),
                        supports_live=source_info.get("supports_live", False),
                        intervals=source_info.get("intervals", []),
                        asset_types=source_info.get("asset_types", []),
                        max_history_days=source_info.get("max_history_days"),
                        rate_limit=source_info.get("rate_limit"),
                    )
                )

            # Prepare response
            response = DataSourceListResponse(
                sources=response_sources, count=len(response_sources)
            )

            # Cache response
            cache_response(cache_key, response.dict())

            return response

        except Exception as e:
            logger.error(f"Error getting data sources: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error getting data sources: {str(e)}",
            )


@router.get("/sources/{source_id}", response_model=DataSourceInfo)
async def get_data_source(
    source_id: str = Path(..., description="ID of the data source"),
    token: str = Depends(get_auth_token),
    data_service: DataService = Depends(lambda: router.data_service),
):
    """
    Get details about a specific data source.

    Args:
        source_id: ID of the data source
        token: Authentication token
        data_service: Data service dependency

    Returns:
        Data source details
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "data:read")

    try:
        # Check if source exists
        if not await data_service.has_source(source_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Data source '{source_id}' not found",
            )

        # Get source info
        source_info = await data_service.get_source_info(source_id)

        return DataSourceInfo(
            id=source_id,
            name=source_info.get("name", source_id),
            type=source_info.get("type", "unknown"),
            description=source_info.get("description"),
            requires_auth=source_info.get("requires_auth", False),
            supports_live=source_info.get("supports_live", False),
            intervals=source_info.get("intervals", []),
            asset_types=source_info.get("asset_types", []),
            max_history_days=source_info.get("max_history_days"),
            rate_limit=source_info.get("rate_limit"),
        )

    except HTTPException:
        raise
    except DataSourceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Data source '{source_id}' not found",
        )
    except Exception as e:
        logger.error(f"Error getting data source {source_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting data source: {str(e)}",
        )


@router.get("/sources/{source_id}/symbols", response_model=SymbolListResponse)
@rate_limit_middleware(rate_limit_per_min=30)
async def get_symbols(
    source_id: str = Path(..., description="ID of the data source"),
    query: Optional[str] = Query(None, description="Search query"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    exchange: Optional[str] = Query(None, description="Filter by exchange"),
    limit: int = Query(100, ge=1, le=1000, description="Number of symbols to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    refresh_cache: bool = Query(False, description="Force refresh of cached data"),
    token: str = Depends(get_auth_token),
    data_service: DataService = Depends(lambda: router.data_service),
):
    """
    Get available symbols for a data source.

    Args:
        source_id: ID of the data source
        query: Optional search query
        asset_type: Filter by asset type
        exchange: Filter by exchange
        limit: Number of symbols to return
        offset: Offset for pagination
        refresh_cache: Force refresh of cached data
        token: Authentication token
        data_service: Data service dependency

    Returns:
        List of symbols
    """
    # Start telemetry span
    with telemetry.start_span("get_symbols"):
        # Authenticate user
        user = authenticate_user(token)

        # Check user permissions
        check_permission(user, "data:read")

        # Check if source exists
        if not await data_service.has_source(source_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Data source '{source_id}' not found",
            )

        # Check cache
        filters_key = f"_{query or ''}_{asset_type or ''}_{exchange or ''}"
        cache_key = f"symbols_{source_id}{filters_key}_{user['sub']}"

        # Check cache unless refresh requested
        if not refresh_cache:
            cached_response = get_cached_response(
                cache_key, max_age_seconds=3600
            )  # Cache for 1 hour
            if cached_response:
                # Apply pagination to cached data
                total_count = cached_response.get(
                    "total_count", len(cached_response.get("symbols", []))
                )
                symbols = cached_response.get("symbols", [])[offset : offset + limit]

                return SymbolListResponse(
                    symbols=symbols,
                    count=len(symbols),
                    total_count=total_count,
                    has_more=(offset + limit) < total_count,
                    next_page=(
                        f"/data/sources/{source_id}/symbols?offset={offset+limit}&limit={limit}"
                        if (offset + limit) < total_count
                        else None
                    ),
                )

        try:
            # Get symbols from service
            symbols, total_count = await data_service.get_symbols(
                source_id,
                query=query,
                asset_type=asset_type,
                exchange=exchange,
                limit=None,  # Get all for caching, we'll paginate below
            )

            # Convert to response model
            response_symbols = []
            for symbol_info in symbols:
                if isinstance(symbol_info, dict):
                    response_symbols.append(
                        SymbolInfo(
                            symbol=symbol_info.get("symbol"),
                            name=symbol_info.get("name"),
                            exchange=symbol_info.get("exchange"),
                            asset_type=symbol_info.get("asset_type"),
                            currency=symbol_info.get("currency"),
                            sector=symbol_info.get("sector"),
                            industry=symbol_info.get("industry"),
                            first_date=symbol_info.get("first_date"),
                            last_date=symbol_info.get("last_date"),
                        )
                    )
                else:
                    response_symbols.append(SymbolInfo(symbol=symbol_info))

            # Cache all symbols before pagination
            cache_response(
                cache_key,
                {
                    "symbols": [s.dict() for s in response_symbols],
                    "total_count": total_count or len(response_symbols),
                },
            )

            # Apply pagination
            paginated_symbols = response_symbols[offset : offset + limit]

            return SymbolListResponse(
                symbols=paginated_symbols,
                count=len(paginated_symbols),
                total_count=total_count or len(response_symbols),
                has_more=(offset + limit) < len(response_symbols),
                next_page=(
                    f"/data/sources/{source_id}/symbols?offset={offset+limit}&limit={limit}"
                    if (offset + limit) < len(response_symbols)
                    else None
                ),
            )

        except DataSourceNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Data source '{source_id}' not found",
            )
        except Exception as e:
            logger.error(f"Error getting symbols for {source_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Error getting symbols: {str(e)}",
            )


@router.get("/sources/{source_id}/data/{symbol}", response_model=MarketDataResponse)
@rate_limit_middleware(rate_limit_per_min=50)
async def get_market_data(
    response: Response,
    source_id: str = Path(..., description="ID of the data source"),
    symbol: str = Path(..., description="Symbol to get data for"),
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    interval: DataInterval = Query(DataInterval.DAY_1, description="Data interval"),
    limit: int = Query(
        1000, ge=1, le=10000, description="Maximum number of data points"
    ),
    page_token: Optional[str] = Query(None, description="Page token for pagination"),
    format: Optional[DataFormat] = Query(None, description="Response format"),
    columns: Optional[str] = Query(
        None, description="Comma-separated list of columns to include"
    ),
    include_metadata: bool = Query(True, description="Include metadata in response"),
    token: str = Depends(get_auth_token),
    user_agent: Optional[str] = Header(None),
    data_service: DataService = Depends(lambda: router.data_service),
):
    """
    Get market data for a symbol.

    Args:
        response: FastAPI response object
        source_id: ID of the data source
        symbol: Symbol to get data for
        start_date: Optional start date
        end_date: Optional end date
        interval: Data interval
        limit: Maximum number of data points
        page_token: Page token for pagination
        format: Response format
        columns: Comma-separated list of columns to include
        include_metadata: Include metadata in response
        token: Authentication token
        user_agent: User agent header
        data_service: Data service dependency

    Returns:
        Market data in requested format
    """
    # Start telemetry span
    with telemetry.start_span("get_market_data"):
        # Log request info
        logger.info(
            f"Market data request: {source_id}/{symbol} ({interval}) from {start_date} to {end_date}"
        )

        # Authenticate user
        user = authenticate_user(token)

        # Check user permissions
        check_permission(user, "data:read")

        # Request ID for logging and telemetry
        request_id = (
            telemetry.current_span().span_id if telemetry.current_span() else None
        )

        try:
            # Validate symbol
            if not validate_symbol(symbol):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid symbol format: {symbol}",
                )

            # Parse dates
            try:
                start_dt, end_dt = get_date_range(start_date, end_date, default_days=30)
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
                )

            # Parse pagination token if provided
            pagination_info = None
            if page_token:
                try:
                    import base64
                    import zlib

                    token_bytes = base64.urlsafe_b64decode(page_token)
                    token_data = zlib.decompress(token_bytes).decode("utf-8")
                    pagination_info = json.loads(token_data)
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid pagination token: {str(e)}",
                    )

            # Parse columns if provided
            included_columns = None
            if columns:
                included_columns = [col.strip() for col in columns.split(",")]

            # Get data from service
            data_df = await data_service.get_data(
                source=source_id,
                symbol=symbol,
                start_date=start_dt,
                end_date=end_dt,
                interval=interval,
                limit=limit + 1,  # Request one extra to check if there's more
                page_info=pagination_info,
                columns=included_columns,
                request_id=request_id,
            )

            # Check if we got more than requested (for pagination)
            has_more = len(data_df) > limit
            if has_more:
                data_df = data_df.iloc[:limit]  # Trim to requested limit

            # Generate next page token if needed
            next_page_token = None
            if has_more and len(data_df) > 0:
                # Get the last timestamp to use as a marker
                last_row = data_df.iloc[-1]
                last_timestamp = None

                # Try to find a timestamp column
                timestamp_cols = [
                    col
                    for col in data_df.columns
                    if "time" in col.lower() or "date" in col.lower()
                ]
                if timestamp_cols:
                    last_timestamp = last_row[timestamp_cols[0]]

                # Create pagination info
                token_data = {
                    "symbol": symbol,
                    "start": (
                        last_timestamp.isoformat()
                        if hasattr(last_timestamp, "isoformat")
                        else str(last_timestamp)
                    ),
                    "end": end_dt.isoformat(),
                    "last_id": len(data_df),
                }

                # Compress and encode token
                token_json = json.dumps(token_data)
                token_bytes = zlib.compress(token_json.encode("utf-8"))
                next_page_token = base64.urlsafe_b64encode(token_bytes).decode("utf-8")

            # Handle format-specific responses
            if format and format != DataFormat.JSON:
                # Get filename base
                filename_base = f"{symbol}_{interval.value}_{start_dt.strftime('%Y%m%d')}_{end_dt.strftime('%Y%m%d')}"

                # Convert to requested format
                data_bytes, content_type, filename = dataframe_to_format(
                    data_df, format, filename_base
                )

                # Return formatted response
                return StreamingResponse(
                    io.BytesIO(data_bytes),
                    media_type=content_type,
                    headers={
                        "Content-Disposition": f"attachment; filename={filename}",
                        "X-Total-Count": str(len(data_df)),
                        "X-Has-More": str(has_more).lower(),
                    },
                )

            # Default JSON response
            # Convert DataFrame to dict for JSON serialization
            data_dict = data_df.to_dict(orient="records")

            response_data = {
                "symbol": symbol,
                "source": source_id,
                "interval": interval,
                "points_count": len(data_df),
                "columns": list(data_df.columns),
                "has_more": has_more,
                "next_page_token": next_page_token,
                "data": data_dict,
            }

            # Add date info if requested
            if include_metadata:
                response_data["start_date"] = start_date
                response_data["end_date"] = end_date

            # Set response headers for pagination
            response.headers["X-Total-Count"] = str(len(data_df))
            response.headers["X-Has-More"] = str(has_more).lower()
            if next_page_token:
                response.headers["X-Next-Page"] = next_page_token

            return response_data

        except DataSourceNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Data source '{source_id}' not found",
            )
        except SymbolNotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Symbol '{symbol}' not found in data source '{source_id}'",
            )
        except InvalidDateRangeError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            logger.error(f"Error getting market data: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error getting market data: {str(e)}",
            )


@router.post("/sources/{source_id}/bulk-data", response_model=Dict[str, Any])
async def get_bulk_market_data(
    source_id: str,
    request: BulkDataRequest,
    format: Optional[DataFormat] = Query(None, description="Response format"),
    token: str = Depends(get_auth_token),
    data_service: DataService = Depends(lambda: router.data_service),
):
    """
    Get market data for multiple symbols in a single request.

    Args:
        source_id: ID of the data source
        request: Bulk data request
        format: Response format
        token: Authentication token
        data_service: Data service dependency

    Returns:
        Market data for multiple symbols
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "data:read")

    try:
        # Parse dates
        try:
            start_dt, end_dt = get_date_range(
                request.start_date, request.end_date, default_days=30
            )
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

        # Get data for each symbol
        results = {}
        errors = {}

        for symbol in request.symbols:
            try:
                # Validate symbol
                if not validate_symbol(symbol):
                    errors[symbol] = "Invalid symbol format"
                    continue

                # Get data from service
                data_df = await data_service.get_data(
                    source=source_id,
                    symbol=symbol,
                    start_date=start_dt,
                    end_date=end_dt,
                    interval=request.interval,
                )

                # Store result
                results[symbol] = {
                    "points_count": len(data_df),
                    "columns": list(data_df.columns),
                    "data": data_df.to_dict(orient="records"),
                }

            except Exception as e:
                errors[symbol] = str(e)

        # Handle format-specific responses for all data
        if format and format != DataFormat.JSON and results:
            # Combine all DataFrames
            all_dfs = {}
            for symbol, data in results.items():
                df = pd.DataFrame(data["data"])
                if not df.empty:
                    # Add symbol column if not already present
                    if "symbol" not in df.columns:
                        df["symbol"] = symbol
                    all_dfs[symbol] = df

            if all_dfs:
                # Concatenate DataFrames
                combined_df = pd.concat(all_dfs.values(), axis=0)

                # Get filename base
                filename_base = f"bulk_data_{source_id}_{len(request.symbols)}_symbols"

                # Convert to requested format
                data_bytes, content_type, filename = dataframe_to_format(
                    combined_df, format, filename_base
                )

                # Return formatted response
                return StreamingResponse(
                    io.BytesIO(data_bytes),
                    media_type=content_type,
                    headers={
                        "Content-Disposition": f"attachment; filename={filename}",
                        "X-Success-Count": str(len(results)),
                        "X-Error-Count": str(len(errors)),
                    },
                )

        # Default response
        return {
            "source": source_id,
            "symbols_requested": len(request.symbols),
            "symbols_success": len(results),
            "symbols_failed": len(errors),
            "interval": request.interval,
            "start_date": start_dt.isoformat(),
            "end_date": end_dt.isoformat(),
            "data": results,
            "errors": errors,
        }

    except DataSourceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Data source '{source_id}' not found",
        )
    except Exception as e:
        logger.error(f"Error getting bulk market data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting bulk market data: {str(e)}",
        )


@router.get(
    "/sources/{source_id}/availability/{symbol}",
    response_model=DataAvailabilityResponse,
)
async def get_data_availability(
    source_id: str = Path(..., description="ID of the data source"),
    symbol: str = Path(..., description="Symbol to check"),
    token: str = Depends(get_auth_token),
    data_service: DataService = Depends(lambda: router.data_service),
):
    """
    Check data availability for a symbol.

    Args:
        source_id: ID of the data source
        symbol: Symbol to check
        token: Authentication token
        data_service: Data service dependency

    Returns:
        Data availability information
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "data:read")

    try:
        # Get availability info
        availability = await data_service.get_symbol_availability(source_id, symbol)

        return DataAvailabilityResponse(
            source=source_id,
            symbol=symbol,
            available_intervals=availability.get("intervals", []),
            first_date=availability.get("first_date"),
            last_date=availability.get("last_date"),
            data_points=availability.get("data_points"),
            data_complete=availability.get("data_complete", True),
        )

    except DataSourceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Data source '{source_id}' not found",
        )
    except SymbolNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Symbol '{symbol}' not found in data source '{source_id}'",
        )
    except Exception as e:
        logger.error(f"Error checking data availability: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error checking data availability: {str(e)}",
        )


@router.post("/cache/invalidate", status_code=status.HTTP_204_NO_CONTENT)
async def invalidate_data_cache(
    source_id: Optional[str] = Query(
        None, description="Data source to invalidate cache for"
    ),
    symbol: Optional[str] = Query(None, description="Symbol to invalidate cache for"),
    token: str = Depends(get_auth_token),
):
    """
    Invalidate data cache.

    Args:
        source_id: Optional data source to invalidate cache for
        symbol: Optional symbol to invalidate cache for
        token: Authentication token
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions - require admin for cache invalidation
    check_permission(user, "admin:cache")

    # Build cache pattern
    pattern = None
    if source_id and symbol:
        pattern = f"*{source_id}*{symbol}*"
    elif source_id:
        pattern = f"*{source_id}*"

    # Invalidate matching cache entries
    count = invalidate_cache(pattern)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


def register_dependencies(data_service: DataService) -> None:
    """
    Register dependencies for the router.

    Args:
        data_service: Data service instance
    """
    router.data_service = data_service
