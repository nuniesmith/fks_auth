from fastapi.responses import JSONResponse
from framework.middleware import BaseMiddleware
from framework.middleware.protection.rate_limiter import RateLimiter


class RateLimitMiddleware(BaseMiddleware):
    """
    Rate limiting middleware with multiple strategies
    """

    def __init__(self, config: dict):
        self.limiters = {
            "global": RateLimiter(
                rate=config.get("global_rate", 1000),
                period=config.get("global_period", 60),
            ),
            "per_user": RateLimiter(
                rate=config.get("user_rate", 100), period=config.get("user_period", 60)
            ),
            "per_endpoint": {},
        }

    async def __call__(self, request, call_next):
        """Apply rate limiting"""
        # Global rate limit
        client_ip = request.client.host
        if not await self.limiters["global"].allow(client_ip):
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded"},
                headers={"Retry-After": "60"},
            )

        # User-specific rate limit
        if hasattr(request.state, "user"):
            user_id = request.state.user.id
            if not await self.limiters["per_user"].allow(f"user:{user_id}"):
                return JSONResponse(
                    status_code=429, content={"error": "User rate limit exceeded"}
                )

        # Process request
        return await call_next(request)
