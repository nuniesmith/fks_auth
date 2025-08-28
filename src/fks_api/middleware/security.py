from framework.common.exceptions.classes import RateLimitExceeded, ServiceUnavailable
from framework.middleware import BaseMiddleware
from framework.middleware.protection import CircuitBreaker, RateLimiter


class SecurityMiddleware(BaseMiddleware):
    def __init__(self, config: dict):
        super().__init__("security", config)
        self.rate_limiter = RateLimiter(config["rate_limit"])
        self.circuit_breaker = CircuitBreaker(config["circuit_breaker"])

    async def process_request(self, request):
        """Process incoming request"""
        # Rate limiting
        client_id = self._get_client_id(request)
        if not await self.rate_limiter.allow(client_id):
            raise RateLimitExceeded()

        # Circuit breaker check
        if not self.circuit_breaker.is_closed():
            raise ServiceUnavailable()

        # JWT validation
        if self.config.get("jwt_required", True):
            await self._validate_jwt(request)

    def _get_client_id(self, request):
        """Extract client identifier"""
        # Try API key first
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"api_key:{api_key}"

        # Fall back to IP
        return f"ip:{request.client.host}"
