from datetime import datetime, timedelta
from typing import Dict

from fastapi.responses import JSONResponse
from framework.middleware import BaseMiddleware
from framework.middleware.protection.circuit_breaker import CircuitState


class CircuitBreakerMiddleware(BaseMiddleware):
    """
    Circuit breaker pattern for API protection
    """

    def __init__(
        self, failure_threshold: float = 0.5, timeout: int = 60, min_calls: int = 10
    ):
        self.failure_threshold = failure_threshold
        self.timeout = timedelta(seconds=timeout)
        self.min_calls = min_calls
        self.states: Dict[str, CircuitState] = {}

    async def __call__(self, request, call_next):
        """Process request through circuit breaker"""
        endpoint = f"{request.method}:{request.url.path}"
        state = self._get_state(endpoint)

        # Check if circuit is open
        if state.is_open:
            if datetime.utcnow() < state.open_until:
                return JSONResponse(
                    status_code=503,
                    content={"error": "Service temporarily unavailable"},
                )
            else:
                # Try half-open state
                state.to_half_open()
            # Process request
            try:
                response = await call_next(request)

                # Record success
                state.record_success()

                # Close circuit if in half-open state
                if state.is_half_open:
                    state.to_closed()

                return response

            except Exception as e:
                # Record failure
                state.record_failure()

                # Check if we should open the circuit
                if state.should_open():
                    state.to_open(self.timeout)

                raise

        def _get_state(self, endpoint: str) -> CircuitState:
            """Get or create circuit state for endpoint"""
            if endpoint not in self.states:
                self.states[endpoint] = CircuitState()
            return self.states[endpoint]
            raise
