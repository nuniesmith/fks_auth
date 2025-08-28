import asyncio
import hashlib
import json
import time
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from app.trading.service import TradingService
from core.models.pagination import PaginatedResponse, PaginationParams, get_pagination
from core.telemetry.telemetry import telemetry
from data.service import DataService
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
from trading.models import (
    OrderSide,
    OrderStatus,
    OrderSubmitResult,
    OrderType,
    Position,
    PositionSide,
    TimeInForce,
    TradeError,
    TradeExecution,
)

# Configure logger
logger = logger.opt(colors=True).getLogger("trading_api")


# Constants
DEFAULT_ORDER_TTL_SECONDS = 60 * 60 * 24  # 24 hours
MAX_ORDERS_PER_REQUEST = 10

# Rate limit state - in production, use Redis or other distributed store
rate_limit_data = {}


# Models
class OrderRequest(BaseModel):
    """Request model for submitting a new trade order."""

    symbol: str = Field(..., description="Trading symbol (e.g., 'BTCUSD')")
    side: OrderSide
    type: OrderType
    quantity: float = Field(..., gt=0, description="Order quantity")
    price: Optional[float] = Field(
        None, gt=0, description="Order price (required for limit orders)"
    )
    time_in_force: TimeInForce = Field(
        TimeInForce.GOOD_TILL_CANCELLED, description="Time in force"
    )
    stop_price: Optional[float] = Field(
        None, gt=0, description="Stop price for stop orders"
    )
    take_profit: Optional[float] = Field(None, gt=0, description="Take profit price")
    stop_loss: Optional[float] = Field(None, gt=0, description="Stop loss price")
    client_order_id: Optional[str] = Field(None, description="Client-side order ID")
    reduce_only: bool = Field(
        False, description="Whether the order should only reduce position"
    )
    strategy_id: Optional[str] = Field(None, description="Associated strategy ID")
    strategy_params: Dict[str, Any] = Field(
        default_factory=dict, description="Strategy parameters"
    )

    @root_validator
    def validate_order_type(cls, values):
        """Validate that required fields for specific order types are provided."""
        order_type = values.get("type")
        price = values.get("price")
        stop_price = values.get("stop_price")

        if order_type == OrderType.LIMIT and price is None:
            raise ValueError("Price is required for limit orders")

        if order_type == OrderType.STOP_MARKET and stop_price is None:
            raise ValueError("Stop price is required for stop market orders")

        if order_type == OrderType.STOP_LIMIT and (stop_price is None or price is None):
            raise ValueError(
                "Both stop price and limit price are required for stop limit orders"
            )

        return values


class OrderResponse(BaseModel):
    """Response model for order submission."""

    order_id: str
    client_order_id: Optional[str] = None
    symbol: str
    side: OrderSide
    type: OrderType
    quantity: float
    price: Optional[float] = None
    status: OrderStatus
    created_at: datetime
    message: Optional[str] = None


class BulkOrderRequest(BaseModel):
    """Request model for submitting multiple trade orders."""

    orders: List[OrderRequest] = Field(..., max_items=MAX_ORDERS_PER_REQUEST)


class BulkOrderResponse(BaseModel):
    """Response model for bulk order submission."""

    orders: List[OrderResponse]
    success_count: int
    failed_count: int
    errors: Dict[str, str] = Field(default_factory=dict)


class OrderDetail(BaseModel):
    """Detailed information about an order."""

    order_id: str
    client_order_id: Optional[str] = None
    symbol: str
    side: OrderSide
    type: OrderType
    quantity: float
    executed_quantity: float = 0
    price: Optional[float] = None
    stop_price: Optional[float] = None
    take_profit: Optional[float] = None
    stop_loss: Optional[float] = None
    status: OrderStatus
    time_in_force: TimeInForce
    created_at: datetime
    updated_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    reduce_only: bool = False
    executions: List[TradeExecution] = Field(default_factory=list)
    strategy_id: Optional[str] = None
    average_price: Optional[float] = None
    message: Optional[str] = None


class OrderUpdateRequest(BaseModel):
    """Request model for updating an existing order."""

    price: Optional[float] = Field(None, gt=0, description="New order price")
    quantity: Optional[float] = Field(None, gt=0, description="New order quantity")
    stop_price: Optional[float] = Field(None, gt=0, description="New stop price")
    take_profit: Optional[float] = Field(
        None, gt=0, description="New take profit price"
    )
    stop_loss: Optional[float] = Field(None, gt=0, description="New stop loss price")
    time_in_force: Optional[TimeInForce] = None


class PositionDetail(BaseModel):
    """Detailed information about a position."""

    symbol: str
    side: PositionSide
    quantity: float
    entry_price: float
    liquidation_price: Optional[float] = None
    mark_price: float
    unrealized_pnl: float
    realized_pnl: float
    margin: Optional[float] = None
    leverage: Optional[float] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    stop_loss: Optional[float] = None
    take_profit: Optional[float] = None
    aggregated_orders: List[OrderDetail] = Field(default_factory=list)


class AccountBalance(BaseModel):
    """Account balance information."""

    asset: str
    free: float
    locked: float
    total: float


class AccountInfo(BaseModel):
    """Trading account information."""

    account_id: str
    account_type: str
    balances: List[AccountBalance]
    positions: List[PositionDetail]
    margin_level: Optional[float] = None
    margin_used: Optional[float] = None
    margin_available: Optional[float] = None
    unrealized_pnl: float = 0
    realized_pnl: float = 0
    equity: float
    update_time: datetime


class PositionUpdateRequest(BaseModel):
    """Request model for updating a position."""

    stop_loss: Optional[float] = Field(None, description="New stop loss price")
    take_profit: Optional[float] = Field(None, description="New take profit price")
    leverage: Optional[float] = Field(None, gt=0, le=100, description="New leverage")


class TradeEvent(BaseModel):
    """Model for trade events."""

    event_type: str
    timestamp: datetime
    symbol: str
    order_id: Optional[str] = None
    client_order_id: Optional[str] = None
    execution_id: Optional[str] = None
    price: Optional[float] = None
    quantity: Optional[float] = None
    side: Optional[OrderSide] = None
    order_type: Optional[OrderType] = None
    order_status: Optional[OrderStatus] = None
    message: Optional[str] = None
    reason: Optional[str] = None


class TradeHistoryItem(BaseModel):
    """Historical trade item."""

    id: str
    order_id: str
    symbol: str
    side: OrderSide
    price: float
    quantity: float
    commission: float
    commission_asset: str
    executed_at: datetime
    order_type: OrderType
    realized_pnl: Optional[float] = None
    counter_party_id: Optional[str] = None


class TradingPerformance(BaseModel):
    """Trading performance metrics."""

    total_trades: int
    winning_trades: int
    losing_trades: int
    win_rate: float
    avg_profit: float
    avg_loss: float
    profit_factor: float
    total_profit: float
    total_loss: float
    max_drawdown: float
    max_drawdown_percentage: float
    sharpe_ratio: Optional[float] = None
    sortino_ratio: Optional[float] = None
    time_period: str


class StrategyTradeRequest(BaseModel):
    """Request model for executing trades based on a strategy."""

    strategy_id: str
    symbols: List[str]
    parameters: Dict[str, Any] = Field(default_factory=dict)
    initial_capital: float = 10000.0
    risk_percentage: Optional[float] = Field(
        None, ge=0.1, le=10, description="Risk per trade (percentage)"
    )
    max_positions: int = Field(5, ge=1, le=20, description="Maximum open positions")
    mode: str = "real"  # 'real', 'paper', 'backtest'
    backtest_start: Optional[datetime] = None
    backtest_end: Optional[datetime] = None


class StrategyTradeResponse(BaseModel):
    """Response model for strategy trade execution."""

    strategy_id: str
    job_id: str
    status: str
    orders_placed: int
    orders_failed: int
    message: Optional[str] = None


class OrderListQueryParams(BaseModel):
    """Query parameters for listing orders."""

    symbol: Optional[str] = None
    status: Optional[List[OrderStatus]] = None
    side: Optional[OrderSide] = None
    order_type: Optional[OrderType] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    strategy_id: Optional[str] = None


# Create router
router = APIRouter(
    prefix="/trading",
    tags=["trading"],
    dependencies=[Depends(get_auth_token)],
)


# Helper functions
def check_rate_limit(
    user_id: str, action: str, limit: int = 10, window: int = 60
) -> bool:
    """
    Check if user has exceeded rate limit for an action.

    Args:
        user_id: User ID to check
        action: Action identifier (e.g., 'order_create')
        limit: Maximum number of actions allowed in the window
        window: Time window in seconds

    Returns:
        True if within rate limit, False if exceeded
    """
    now = time.time()
    key = f"{user_id}:{action}"

    if key not in rate_limit_data:
        rate_limit_data[key] = []

    # Remove timestamps older than the window
    rate_limit_data[key] = [ts for ts in rate_limit_data[key] if now - ts < window]

    # Check if rate limit is exceeded
    if len(rate_limit_data[key]) >= limit:
        return False

    # Add current timestamp
    rate_limit_data[key].append(now)
    return True


async def validate_order(
    order: OrderRequest, trading_service: TradingService, user_id: str
) -> Dict[str, Any]:
    """
    Validate an order before submission.

    Args:
        order: Order request
        trading_service: Trading service
        user_id: User ID

    Returns:
        Dictionary with validation results
    """
    try:
        # Check symbol
        symbol_info = await trading_service.get_symbol_info(order.symbol)
        if not symbol_info:
            return {
                "valid": False,
                "field": "symbol",
                "message": (
                    f"Symbol {order.symbol} not found or not supported for trading"
                ),
            }

        # Check quantity meets minimum
        min_qty = symbol_info.get("min_qty", 0)
        if order.quantity < min_qty:
            return {
                "valid": False,
                "field": "quantity",
                "message": f"Quantity {order.quantity} is below minimum {min_qty}",
            }

        # Check quantity precision
        qty_precision = symbol_info.get("qty_precision", 8)
        formatted_qty = round(order.quantity, qty_precision)
        if formatted_qty != order.quantity:
            order.quantity = formatted_qty

        # Check price for limit orders
        if (
            order.type in [OrderType.LIMIT, OrderType.STOP_LIMIT]
            and order.price is not None
        ):
            price_precision = symbol_info.get("price_precision", 8)
            formatted_price = round(order.price, price_precision)
            if formatted_price != order.price:
                order.price = formatted_price

        # Check user has sufficient balance
        account_info = await trading_service.get_account_info(user_id)

        # For simplicity, we'll assume we're trading with the base currency
        # In a real application, you'd need to perform proper balance calculation
        base_currency = symbol_info.get("base_currency", "USD")
        available_balance = 0

        for balance in account_info.balances:
            if balance.asset == base_currency:
                available_balance = balance.free
                break

        required_amount = order.quantity
        if order.price:
            required_amount = order.quantity * order.price

        if required_amount > available_balance:
            return {
                "valid": False,
                "field": "quantity",
                "message": (
                    f"Insufficient balance. Required: {required_amount} {base_currency}, Available: {available_balance} {base_currency}"
                ),
            }

        # Additional validation based on order type
        if order.type == OrderType.STOP_MARKET and order.stop_price is None:
            return {
                "valid": False,
                "field": "stop_price",
                "message": "Stop price is required for stop market orders",
            }

        # Validate strategy if provided
        if order.strategy_id:
            # Perform strategy validation here
            pass

        return {"valid": True, "message": "Order validation passed", "order": order}

    except Exception as e:
        logger.error(f"Error validating order: {str(e)}")
        return {
            "valid": False,
            "field": "general",
            "message": f"Order validation error: {str(e)}",
        }


def generate_client_order_id(user_id: str, symbol: str) -> str:
    """
    Generate a unique client order ID.

    Args:
        user_id: User ID
        symbol: Trading symbol

    Returns:
        Client order ID
    """
    timestamp = int(time.time() * 1000)
    unique_id = str(uuid.uuid4())[:8]
    return f"{user_id}_{symbol}_{timestamp}_{unique_id}"


# Routes
@router.post("/orders", response_model=OrderResponse)
async def create_order(
    request: Request,
    order: OrderRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    Submit a new trading order.

    This endpoint allows creating various types of orders including
    market orders, limit orders, and stop orders.

    Args:
        order: Order request details
        background_tasks: FastAPI background tasks
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Order submission result
    """
    # Start telemetry span
    with telemetry.start_span("create_order"):
        # Authenticate user
        user = authenticate_user(token)

        # Check user permissions
        check_permission(user, "trading:order:create")

        # Check rate limit
        if not check_rate_limit(user["sub"], "order_create", limit=20, window=60):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for order creation",
            )

        try:
            # Generate client order ID if not provided
            client_order_id = order.client_order_id
            if not client_order_id:
                client_order_id = generate_client_order_id(user["sub"], order.symbol)
                order.client_order_id = client_order_id

            # Validate order
            validation_result = await validate_order(
                order, trading_service, user["sub"]
            )

            if not validation_result["valid"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=validation_result["message"],
                )

            # Submit order
            try:
                result = await trading_service.submit_order(
                    user_id=user["sub"],
                    symbol=order.symbol,
                    side=order.side,
                    order_type=order.type,
                    quantity=order.quantity,
                    price=order.price,
                    client_order_id=client_order_id,
                    time_in_force=order.time_in_force,
                    stop_price=order.stop_price,
                    take_profit=order.take_profit,
                    stop_loss=order.stop_loss,
                    reduce_only=order.reduce_only,
                    strategy_id=order.strategy_id,
                )

                # Log successful order creation
                logger.info(
                    f"Order created: {result.order_id} for user {user['sub']}, "
                    f"symbol {order.symbol}, side {order.side}, type {order.type}"
                )

                # Schedule notification in background if needed
                background_tasks.add_task(
                    trading_service.notify_order_status,
                    user_id=user["sub"],
                    order_id=result.order_id,
                    status=result.status,
                )

                # Return response
                return OrderResponse(
                    order_id=result.order_id,
                    client_order_id=result.client_order_id,
                    symbol=order.symbol,
                    side=order.side,
                    type=order.type,
                    quantity=order.quantity,
                    price=order.price,
                    status=result.status,
                    created_at=result.created_at,
                    message=result.message,
                )

            except TradeError as e:
                logger.error(f"Trade error for user {user['sub']}: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Trade error: {str(e)}",
                )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error creating order: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error creating order: {str(e)}",
            )


@router.post("/orders/bulk", response_model=BulkOrderResponse)
async def create_bulk_orders(
    request: Request,
    orders: BulkOrderRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    Submit multiple trading orders in a single request.

    This endpoint allows creating multiple orders in a single request
    for efficient order submission.

    Args:
        orders: Bulk order request
        background_tasks: FastAPI background tasks
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Bulk order submission results
    """
    # Start telemetry span
    with telemetry.start_span("create_bulk_orders"):
        # Authenticate user
        user = authenticate_user(token)

        # Check user permissions
        check_permission(user, "trading:order:create")

        # Check rate limit (bulk orders count as multiple)
        order_count = len(orders.orders)
        if not check_rate_limit(user["sub"], "order_bulk", limit=5, window=60):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for bulk order creation",
            )

        # Check maximum orders
        if order_count > MAX_ORDERS_PER_REQUEST:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Maximum of {MAX_ORDERS_PER_REQUEST} orders allowed per request",
            )

        try:
            # Process each order
            results = []
            errors = {}

            for i, order in enumerate(orders.orders):
                # Generate client order ID if not provided
                client_order_id = order.client_order_id
                if not client_order_id:
                    client_order_id = generate_client_order_id(
                        user["sub"], order.symbol
                    )
                    order.client_order_id = client_order_id

                # Validate order
                validation_result = await validate_order(
                    order, trading_service, user["sub"]
                )

                if not validation_result["valid"]:
                    # Add error and continue with next order
                    errors[f"order_{i}"] = validation_result["message"]
                    continue

                try:
                    # Submit order
                    result = await trading_service.submit_order(
                        user_id=user["sub"],
                        symbol=order.symbol,
                        side=order.side,
                        order_type=order.type,
                        quantity=order.quantity,
                        price=order.price,
                        client_order_id=client_order_id,
                        time_in_force=order.time_in_force,
                        stop_price=order.stop_price,
                        take_profit=order.take_profit,
                        stop_loss=order.stop_loss,
                        reduce_only=order.reduce_only,
                        strategy_id=order.strategy_id,
                    )

                    # Add to results
                    results.append(
                        OrderResponse(
                            order_id=result.order_id,
                            client_order_id=result.client_order_id,
                            symbol=order.symbol,
                            side=order.side,
                            type=order.type,
                            quantity=order.quantity,
                            price=order.price,
                            status=result.status,
                            created_at=result.created_at,
                            message=result.message,
                        )
                    )

                    # Schedule notification in background
                    background_tasks.add_task(
                        trading_service.notify_order_status,
                        user_id=user["sub"],
                        order_id=result.order_id,
                        status=result.status,
                    )

                except TradeError as e:
                    # Add error and continue with next order
                    errors[f"order_{i}"] = str(e)

            # Return response
            return BulkOrderResponse(
                orders=results,
                success_count=len(results),
                failed_count=len(errors),
                errors=errors,
            )

        except Exception as e:
            logger.error(f"Error creating bulk orders: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error creating bulk orders: {str(e)}",
            )


@router.get("/orders/{order_id}", response_model=OrderDetail)
async def get_order_details(
    order_id: str = Path(..., description="Order ID"),
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    Get detailed information about a specific order.

    This endpoint retrieves comprehensive information about an order
    including its status, executions, and other details.

    Args:
        order_id: Order ID
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Detailed order information
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "trading:order:read")

    try:
        # Get order details
        order = await trading_service.get_order(user["sub"], order_id)

        if not order:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Order {order_id} not found",
            )

        return order

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting order details: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting order details: {str(e)}",
        )


@router.delete("/orders/{order_id}", response_model=Dict[str, Any])
async def cancel_order(
    order_id: str = Path(..., description="Order ID"),
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    Cancel an existing order.

    This endpoint cancels an active order that hasn't been fully executed.

    Args:
        order_id: Order ID
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Cancellation result
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "trading:order:cancel")

    try:
        # Check if order exists and belongs to user
        order = await trading_service.get_order(user["sub"], order_id)

        if not order:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Order {order_id} not found",
            )

        # Check if order can be cancelled
        if order.status not in [OrderStatus.NEW, OrderStatus.PARTIALLY_FILLED]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Order {order_id} cannot be cancelled (status: {order.status})",
            )

        # Cancel order
        result = await trading_service.cancel_order(user["sub"], order_id)

        return {
            "order_id": order_id,
            "status": "cancelled",
            "message": result.get("message", "Order cancelled successfully"),
        }

    except HTTPException:
        raise
    except TradeError as e:
        logger.error(f"Trade error cancelling order: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Trade error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error cancelling order: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error cancelling order: {str(e)}",
        )


@router.put("/orders/{order_id}", response_model=OrderDetail)
async def update_order(
    order_id: str = Path(..., description="Order ID"),
    update_data: OrderUpdateRequest = Body(...),
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    Update an existing order.

    This endpoint allows modifying an active order's parameters
    such as price, quantity, or stop prices.

    Args:
        order_id: Order ID
        update_data: Order update data
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Updated order details
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "trading:order:update")

    try:
        # Check if order exists and belongs to user
        order = await trading_service.get_order(user["sub"], order_id)

        if not order:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Order {order_id} not found",
            )

        # Check if order can be updated
        if order.status not in [OrderStatus.NEW, OrderStatus.PARTIALLY_FILLED]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Order {order_id} cannot be updated (status: {order.status})",
            )

        # Update order
        updated_order = await trading_service.update_order(
            user_id=user["sub"],
            order_id=order_id,
            price=update_data.price,
            quantity=update_data.quantity,
            stop_price=update_data.stop_price,
            take_profit=update_data.take_profit,
            stop_loss=update_data.stop_loss,
            time_in_force=update_data.time_in_force,
        )

        return updated_order

    except HTTPException:
        raise
    except TradeError as e:
        logger.error(f"Trade error updating order: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Trade error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error updating order: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating order: {str(e)}",
        )


@router.get("/orders", response_model=PaginatedResponse[OrderDetail])
async def list_orders(
    symbol: Optional[str] = Query(None, description="Filter by symbol"),
    status: Optional[List[str]] = Query(
        None, description="Filter by status (comma-separated)"
    ),
    side: Optional[OrderSide] = Query(None, description="Filter by side"),
    order_type: Optional[OrderType] = Query(None, description="Filter by order type"),
    start_time: Optional[datetime] = Query(None, description="Filter by start time"),
    end_time: Optional[datetime] = Query(None, description="Filter by end time"),
    strategy_id: Optional[str] = Query(None, description="Filter by strategy ID"),
    pagination: PaginationParams = Depends(get_pagination),
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    List orders with filtering and pagination.

    This endpoint retrieves a list of orders with various filter options
    and pagination support.

    Args:
        symbol: Filter by symbol
        status: Filter by order status
        side: Filter by order side
        order_type: Filter by order type
        start_time: Filter by start time
        end_time: Filter by end time
        strategy_id: Filter by strategy ID
        pagination: Pagination parameters
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Paginated list of orders
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "trading:order:list")

    try:
        # Parse status from string if provided
        parsed_status = None
        if status:
            try:
                parsed_status = [OrderStatus(s.strip()) for s in status]
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid order status: {str(e)}",
                )

        # Create query parameters
        query_params = OrderListQueryParams(
            symbol=symbol,
            status=parsed_status,
            side=side,
            order_type=order_type,
            start_time=start_time,
            end_time=end_time,
            strategy_id=strategy_id,
        )

        # Query orders
        orders, total_count = await trading_service.list_orders(
            user_id=user["sub"],
            query_params=query_params,
            skip=pagination.get_skip(),
            limit=pagination.get_limit(),
            sort_by=pagination.sort_by,
            sort_dir=pagination.sort_dir,
        )

        # Create paginated response
        return PaginatedResponse(
            items=orders,
            page=pagination.page,
            page_size=pagination.page_size,
            total_count=total_count,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing orders: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing orders: {str(e)}",
        )


@router.get("/account", response_model=AccountInfo)
async def get_account_info(
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    Get trading account information.

    This endpoint retrieves comprehensive information about the user's
    trading account including balances, positions, and margin details.

    Args:
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Account information
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "trading:account:read")

    try:
        # Get account info
        account_info = await trading_service.get_account_info(user["sub"])

        return account_info

    except Exception as e:
        logger.error(f"Error getting account info: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting account info: {str(e)}",
        )


@router.get("/positions", response_model=List[PositionDetail])
async def list_positions(
    symbol: Optional[str] = Query(None, description="Filter by symbol"),
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    List open positions.

    This endpoint retrieves a list of currently open positions
    with optional filtering by symbol.

    Args:
        symbol: Filter by symbol
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        List of open positions
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "trading:position:read")

    try:
        # Get positions
        positions = await trading_service.get_positions(user["sub"], symbol)

        return positions

    except Exception as e:
        logger.error(f"Error listing positions: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing positions: {str(e)}",
        )


@router.put("/positions/{symbol}", response_model=PositionDetail)
async def update_position(
    symbol: str = Path(..., description="Symbol of the position"),
    update_data: PositionUpdateRequest = Body(...),
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    Update position settings.

    This endpoint allows updating a position's settings such as
    stop loss, take profit, or leverage.

    Args:
        symbol: Symbol of the position
        update_data: Position update data
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Updated position details
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "trading:position:update")

    try:
        # Check if position exists
        positions = await trading_service.get_positions(user["sub"], symbol)

        if not positions:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No open position found for {symbol}",
            )

        # Update position
        updated_position = await trading_service.update_position(
            user_id=user["sub"],
            symbol=symbol,
            stop_loss=update_data.stop_loss,
            take_profit=update_data.take_profit,
            leverage=update_data.leverage,
        )

        return updated_position

    except HTTPException:
        raise
    except TradeError as e:
        logger.error(f"Trade error updating position: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Trade error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error updating position: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating position: {str(e)}",
        )


@router.post("/positions/{symbol}/close", response_model=OrderResponse)
async def close_position(
    symbol: str = Path(..., description="Symbol of the position"),
    percentage: float = Query(
        100, ge=1, le=100, description="Percentage of position to close"
    ),
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    Close a position.

    This endpoint closes an open position, optionally specifying
    a percentage of the position to close.

    Args:
        symbol: Symbol of the position
        percentage: Percentage of position to close (1-100)
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Order details for the closing order
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "trading:position:close")

    try:
        # Check if position exists
        positions = await trading_service.get_positions(user["sub"], symbol)

        if not positions:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No open position found for {symbol}",
            )

        # Close position
        result = await trading_service.close_position(
            user_id=user["sub"], symbol=symbol, percentage=percentage
        )

        # Create response
        return OrderResponse(
            order_id=result.order_id,
            client_order_id=result.client_order_id,
            symbol=symbol,
            side=result.side,
            type=OrderType.MARKET,
            quantity=result.quantity,
            status=result.status,
            created_at=result.created_at,
            message=result.message,
        )

    except HTTPException:
        raise
    except TradeError as e:
        logger.error(f"Trade error closing position: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Trade error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error closing position: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error closing position: {str(e)}",
        )


@router.get("/history", response_model=PaginatedResponse[TradeHistoryItem])
async def get_trade_history(
    symbol: Optional[str] = Query(None, description="Filter by symbol"),
    start_time: Optional[datetime] = Query(None, description="Filter by start time"),
    end_time: Optional[datetime] = Query(None, description="Filter by end time"),
    pagination: PaginationParams = Depends(get_pagination),
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    Get trade execution history.

    This endpoint retrieves a history of trade executions
    with optional filtering by symbol and time range.

    Args:
        symbol: Filter by symbol
        start_time: Filter by start time
        end_time: Filter by end time
        pagination: Pagination parameters
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Paginated list of trade history items
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "trading:history:read")

    try:
        # Query trade history
        trades, total_count = await trading_service.get_trade_history(
            user_id=user["sub"],
            symbol=symbol,
            start_time=start_time,
            end_time=end_time,
            skip=pagination.get_skip(),
            limit=pagination.get_limit(),
            sort_by=pagination.sort_by or "executed_at",
            sort_dir=pagination.sort_dir,
        )

        # Create paginated response
        return PaginatedResponse(
            items=trades,
            page=pagination.page,
            page_size=pagination.page_size,
            total_count=total_count,
        )

    except Exception as e:
        logger.error(f"Error getting trade history: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting trade history: {str(e)}",
        )


@router.get("/performance", response_model=TradingPerformance)
async def get_trading_performance(
    symbol: Optional[str] = Query(None, description="Filter by symbol"),
    start_time: Optional[datetime] = Query(
        None, description="Start time for performance calculation"
    ),
    end_time: Optional[datetime] = Query(
        None, description="End time for performance calculation"
    ),
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    Get trading performance metrics.

    This endpoint retrieves performance metrics for the user's trading activity
    including win rate, profit factor, and drawdown statistics.

    Args:
        symbol: Filter by symbol
        start_time: Start time for performance calculation
        end_time: End time for performance calculation
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Trading performance metrics
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "trading:performance:read")

    try:
        # Get trading performance
        performance = await trading_service.get_performance(
            user_id=user["sub"], symbol=symbol, start_time=start_time, end_time=end_time
        )

        return performance

    except Exception as e:
        logger.error(f"Error getting trading performance: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting trading performance: {str(e)}",
        )


@router.post("/strategy", response_model=StrategyTradeResponse)
async def execute_strategy_trades(
    request: StrategyTradeRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
    strategy_registry: StrategyRegistry = Depends(lambda: router.strategy_registry),
):
    """
    Execute trades based on a strategy.

    This endpoint initiates trading based on a specified strategy,
    with options for real trading, paper trading, or backtesting.

    Args:
        request: Strategy trade request
        background_tasks: FastAPI background tasks
        token: Authentication token
        trading_service: Trading service dependency
        strategy_registry: Strategy registry dependency

    Returns:
        Strategy trade execution response
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions based on mode
    if request.mode == "real":
        check_permission(user, "trading:strategy:execute")
    elif request.mode == "paper":
        check_permission(user, "trading:strategy:paper")
    else:  # backtest
        check_permission(user, "trading:strategy:backtest")

    # Check rate limit
    if not check_rate_limit(
        user["sub"], f"strategy_{request.mode}", limit=5, window=600
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for strategy {request.mode} execution",
        )

    try:
        # Check if strategy exists
        strategy_class = strategy_registry.get_strategy(request.strategy_id)

        if not strategy_class:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Strategy {request.strategy_id} not found",
            )

        # Generate job ID
        job_id = str(uuid.uuid4())

        # Execute strategy in background
        background_tasks.add_task(
            trading_service.execute_strategy,
            job_id=job_id,
            user_id=user["sub"],
            strategy_id=request.strategy_id,
            symbols=request.symbols,
            parameters=request.parameters,
            initial_capital=request.initial_capital,
            risk_percentage=request.risk_percentage,
            max_positions=request.max_positions,
            mode=request.mode,
            backtest_start=request.backtest_start,
            backtest_end=request.backtest_end,
        )

        # Return initial response
        return StrategyTradeResponse(
            strategy_id=request.strategy_id,
            job_id=job_id,
            status="processing",
            orders_placed=0,
            orders_failed=0,
            message="Strategy execution started",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing strategy trades: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing strategy trades: {str(e)}",
        )


@router.get("/strategy/jobs/{job_id}", response_model=Dict[str, Any])
async def get_strategy_job_status(
    job_id: str = Path(..., description="Strategy job ID"),
    token: str = Depends(get_auth_token),
    trading_service: TradingService = Depends(lambda: router.trading_service),
):
    """
    Get status of a strategy execution job.

    This endpoint retrieves the current status of a strategy execution job
    including order placement status and results.

    Args:
        job_id: Strategy job ID
        token: Authentication token
        trading_service: Trading service dependency

    Returns:
        Strategy job status
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "trading:strategy:read")

    try:
        # Get job status
        job_status = await trading_service.get_strategy_job_status(user["sub"], job_id)

        if not job_status:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Strategy job {job_id} not found",
            )

        return job_status

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting strategy job status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting strategy job status: {str(e)}",
        )


def register_dependencies(
    trading_service: TradingService, strategy_registry: StrategyRegistry
) -> None:
    """
    Register dependencies for the router.

    Args:
        trading_service: Trading service instance
        strategy_registry: Strategy registry instance
    """
    router.trading_service = trading_service
    router.strategy_registry = strategy_registry
