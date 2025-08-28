"""
FKS Trading Systems API Service with FastAPI
"""

import os
import sys
from contextlib import asynccontextmanager
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
import math
import random

from fastapi import FastAPI
from fastapi import Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi import WebSocket, WebSocketDisconnect

# Add Python source paths to sys.path if not already there
for p in ("/app/src/python", "/app/src"):
    if p not in sys.path:
        sys.path.insert(0, p)

# Configure app metadata
APP_NAME = os.getenv("API_SERVICE_NAME", "FKS Trading API")
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
APP_ENV = os.getenv("APP_ENV", "development")
API_PORT = int(os.getenv("API_SERVICE_PORT", "8000"))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gpt-oss:20b")
OLLAMA_FAST_MODEL = os.getenv("OLLAMA_FAST_MODEL", "llama3.2:3b-instruct")
OLLAMA_AUTOPULL = os.getenv("OLLAMA_AUTOPULL", "1") in ("1", "true", "yes")
OLLAMA_AUTOPULL_FAST = os.getenv("OLLAMA_AUTOPULL_FAST", "0") in ("1", "true", "yes")

# Configure CORS origins
CORS_ORIGINS = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:8080",
    "http://localhost:8081",
    "http://fks_web:3000",  # Docker internal
    "http://web:3000",      # Docker internal
]

# Add additional origins from environment
additional_origins = os.getenv("CORS_ORIGINS", "").split(",")
CORS_ORIGINS.extend([origin.strip() for origin in additional_origins if origin.strip()])

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application lifespan events."""
    # Startup
    print(f"🚀 Starting {APP_NAME} v{APP_VERSION} in {APP_ENV} environment")
    print(f"📡 API listening on port {API_PORT}")
    print(f"🔗 CORS enabled for: {', '.join(CORS_ORIGINS)}")
    # In development, try to ensure Ollama models are available without blocking startup
    if APP_ENV.lower() == "development" and OLLAMA_AUTOPULL:
        async def _ensure_ollama_models():
            try:
                import httpx  # type: ignore

                # Helper creates its own client per pull to avoid using a closed client
                async def _pull_model(name: str) -> None:
                    try:
                        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as c:
                            await c.post(f"{OLLAMA_BASE_URL}/api/pull", json={"name": name})
                            print(f"[ollama] pull request issued for: {name}")
                    except Exception as e:
                        print(f"[ollama] pull failed for {name}: {e}")

                # Probe existing models
                async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0)) as probe:
                    try:
                        r = await probe.get(f"{OLLAMA_BASE_URL}/api/tags")
                        tags = r.json().get("models", []) if r.status_code < 400 else []
                    except Exception as e:
                        print(f"[ollama] tags probe failed: {e}")
                        tags = []

                have = {m.get("name") for m in tags if isinstance(m, dict)}
                to_pull = []
                if OLLAMA_MODEL and OLLAMA_MODEL not in have:
                    to_pull.append(OLLAMA_MODEL)
                if OLLAMA_AUTOPULL_FAST and OLLAMA_FAST_MODEL and OLLAMA_FAST_MODEL not in have:
                    to_pull.append(OLLAMA_FAST_MODEL)
                for name in to_pull:
                    try:
                        print(f"🧰 Ollama: starting background pull for model '{name}'...")
                        asyncio.create_task(_pull_model(name))
                    except Exception as e:
                        print(f"[ollama] pull start failed for {name}: {e}")
            except Exception as e:
                print(f"[ollama] ensure models error: {e}")
        asyncio.create_task(_ensure_ollama_models())
    yield
    # Shutdown
    print(f"🛑 Shutting down {APP_NAME}")

# Create FastAPI application
app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Health check endpoint
@app.get("/health")
@app.get("/api/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "environment": APP_ENV,
        "timestamp": datetime.utcnow().isoformat(),
        "details": {
            "api_port": API_PORT,
            "cors_enabled": True,
            "cors_origins": CORS_ORIGINS,
        }
    }

# Info endpoint
@app.get("/info")
@app.get("/api/info")
async def service_info() -> Dict[str, Any]:
    """Service information endpoint."""
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "environment": APP_ENV,
        "api": {
            "docs": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json",
        },
        "health": "/health",
    }

# Root endpoint
@app.get("/")
async def root() -> Dict[str, str]:
    """Root endpoint."""
    return {
        "message": f"Welcome to {APP_NAME}",
        "version": APP_VERSION,
        "docs": "/docs",
    }

# Example API endpoints for trading system
@app.get("/api/status")
async def system_status() -> Dict[str, Any]:
    """Get trading system status."""
    return {
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "api": "healthy",
            "data": "connecting",
            "worker": "idle",
        }
    }

# Add more API routes here as needed
# You can import route modules and include them:
# from .routes import trading, data, backtest
# app.include_router(trading.router, prefix="/api/trading", tags=["trading"])
# app.include_router(data.router, prefix="/api/data", tags=["data"])
# app.include_router(backtest.router, prefix="/api/backtest", tags=["backtest"])

# Import and add routers (optional, continue on failure to keep core up)
try:
    from .routers.docs import router as docs_router
    app.include_router(docs_router, prefix="/api")
except Exception as e:
    print(f"[router] docs not loaded: {e}")

DATA_SERVICE_AVAILABLE = True
try:
    from .routers.data_service import router as data_router
    app.include_router(data_router, prefix="/api")
except Exception as e:
    print(f"[router] data_service not loaded: {e}")
    DATA_SERVICE_AVAILABLE = False

try:
    from .routers.transformer_ingest import router as transformer_router
    app.include_router(transformer_router, prefix="/api")
except Exception as e:
    print(f"[router] transformer_ingest not loaded: {e}")

try:
    from .routers.active_assets import router as active_assets_router
    app.include_router(active_assets_router, prefix="/api")
except Exception as e:
    print(f"[router] active_assets not loaded: {e}")

# Data quality & splits
try:
    from .routers.data_quality import router as data_quality_router
    app.include_router(data_quality_router, prefix="/api")
except Exception as e:
    print(f"[router] data_quality not loaded: {e}")

# Dataset management (split/verify)
try:
    from .routers.dataset import router as dataset_router
    app.include_router(dataset_router, prefix="/api")
except Exception as e:
    print(f"[router] dataset not loaded: {e}")

# Signals
try:
    from .routers.signals import router as signals_router
    app.include_router(signals_router, prefix="/api")
except Exception as e:
    print(f"[router] signals not loaded: {e}")

# Strategies + assignments (file-backed)
try:
    from .routers.strategies import router as strategies_router
    app.include_router(strategies_router, prefix="/api")
except Exception as e:
    print(f"[router] strategies not loaded: {e}")

try:
    from services.api.routes.v1.backtest import router as backtest_v1_router
    app.include_router(backtest_v1_router, prefix="/api/v1")
except Exception as e:
    print(f"[router] v1 backtest not loaded: {e}")
    # Fallback to a lightweight stub so the UI can function
    try:
        from .routers.backtest_v1_stub import router as backtest_v1_stub_router
        app.include_router(backtest_v1_stub_router, prefix="/api/v1")
        print("[router] using v1 backtest stub router")
    except Exception as ee:
        print(f"[router] v1 backtest stub failed: {ee}")

try:
    from .routers.optimization import router as optimization_router
    app.include_router(optimization_router, prefix="/api")
except Exception as e:
    print(f"[router] optimization not loaded: {e}")

try:
    from .routers.backtests_simple import router as backtests_simple_router
    app.include_router(backtests_simple_router, prefix="/api")
except Exception as e:
    print(f"[router] backtests_simple not loaded: {e}")

# Trading sessions control (stubs)
try:
    from .routers.trading_sessions import router as sessions_router
    app.include_router(sessions_router, prefix="/api")
except Exception as e:
    print(f"[router] trading_sessions not loaded: {e}")

# Ollama AI proxy
try:
    from .routers.ollama_proxy import router as ollama_router
    app.include_router(ollama_router, prefix="/api")
except Exception as e:
    print(f"[router] ollama not loaded: {e}")

# If the heavy Data Service is unavailable, provide minimal fallbacks so the UI works
if not DATA_SERVICE_AVAILABLE:
    @app.get("/api/data/sources")
    async def fallback_list_sources() -> Dict[str, Any]:
        sources = {
            "yahoo": {
                "id": "yahoo",
                "name": "Yahoo Finance",
                "type": "yahoo",
                "supports_live": False,
                "intervals": ["1d", "1h", "5m"],
                "asset_types": ["stocks", "etf", "crypto"],
                "description": "Fallback source (demo)",
            },
            "binance": {
                "id": "binance",
                "name": "Binance Futures",
                "type": "binance",
                "supports_live": True,
                "intervals": ["1m", "5m", "15m", "1h", "4h", "1d"],
                "asset_types": ["crypto"],
                "description": "Fallback source (demo)",
            },
        }
        return {"sources": sources, "count": len(sources)}

    @app.get("/api/data/sources/{source_id}/symbols")
    async def fallback_symbols(source_id: str, query: Optional[str] = None, limit: int = 25) -> Dict[str, Any]:
        query = (query or "").strip().lower()
        if source_id.lower() == "binance":
            base = [
                {"symbol": "BTCUSDT", "name": "Bitcoin / Tether", "exchange": "BINANCE", "asset_type": "crypto"},
                {"symbol": "ETHUSDT", "name": "Ethereum / Tether", "exchange": "BINANCE", "asset_type": "crypto"},
                {"symbol": "SOLUSDT", "name": "Solana / Tether", "exchange": "BINANCE", "asset_type": "crypto"},
            ]
        else:
            base = [
                {"symbol": "AAPL", "name": "Apple Inc.", "exchange": "NASDAQ", "asset_type": "equity"},
                {"symbol": "MSFT", "name": "Microsoft Corp.", "exchange": "NASDAQ", "asset_type": "equity"},
                {"symbol": "BTC-USD", "name": "Bitcoin USD", "exchange": "CCC", "asset_type": "crypto"},
            ]
        items = [s for s in base if not query or query in s["symbol"].lower() or query in (s.get("name") or "").lower()]
        return {"symbols": items[: max(1, min(limit, 100))], "count": len(items), "total": len(base)}

# ---------------------------------------------------------------------------
# Lightweight endpoints used by the web client security/perf modules
# ---------------------------------------------------------------------------

@app.get("/api/network/status")
async def network_status() -> Dict[str, Any]:
    # Basic client IP echo and timestamp; in prod, add TS checks if available
    return {"ok": True, "clientIP": os.getenv("CLIENT_IP", "127.0.0.1"), "ts": datetime.utcnow().isoformat()}

@app.get("/api/security/validate-connection")
async def security_validate_connection() -> Dict[str, Any]:
    # Minimal validation hook used by PerformanceMonitor
    return {"ok": True, "ts": datetime.utcnow().isoformat()}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    try:
        # Simple heartbeat channel; echoes messages and responds to ping
        while True:
            data = await ws.receive_text()
            if data:
                if data == "ping" or '"ping"' in data:
                    await ws.send_text("pong")
                else:
                    await ws.send_text(data)
    except WebSocketDisconnect:
        pass

# ---------------------------------------------------------------------------
# Utility: Discord webhook proxy to bypass browser CORS
# ---------------------------------------------------------------------------

@app.post("/api/utils/discord-proxy")
async def discord_proxy(payload: Dict[str, Any] = Body(...)):
    """Post to a Discord webhook URL from the server side.
    Expected payload shape: { "webhook_url": str, "content": str, "username": Optional[str] }
    """
    try:
        webhook_url = str(payload.get("webhook_url") or "").strip()
        content = str(payload.get("content") or "").strip()
        username = payload.get("username")
        if not webhook_url or not content:
            return JSONResponse({"ok": False, "error": "Missing webhook_url or content"}, status_code=400)
        # Basic allowlist for Discord domains
        if not webhook_url.startswith("https://discord.com/api/webhooks/"):
            return JSONResponse({"ok": False, "error": "Invalid webhook domain"}, status_code=400)
        import requests  # type: ignore
        resp = requests.post(
            webhook_url,
            json={"content": content, **({"username": username} if username else {})},
            timeout=10,
        )
        if resp.status_code >= 400:
            return JSONResponse({"ok": False, "status": resp.status_code, "body": resp.text}, status_code=resp.status_code)
        return {"ok": True}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)

# ---------------------------------------------------------------------------
# Minimal chart data endpoints used by the UI when dataSource="internal"
# These provide synthetic candles/indicators for quick demos and wiring.
# ---------------------------------------------------------------------------

def _tf_to_seconds(tf: str) -> int:
    mapping = {
        "1m": 60,
        "3m": 180,
        "5m": 300,
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "2h": 7200,
        "4h": 14400,
        "6h": 21600,
        "8h": 28800,
        "12h": 43200,
        "1d": 86400,
        "1w": 604800,
    }
    return mapping.get(tf, 3600)


@app.get("/api/chart-data/{symbol}")
async def chart_data(symbol: str, timeframe: str = "1h", limit: int = 500) -> Dict[str, Any]:
    """Return synthetic OHLCV candles for the requested symbol/timeframe.
    This is for UI development; replace with real data service when available.
    """
    try:
        limit = max(10, min(int(limit), 2000))
    except Exception:
        limit = 500
    step = _tf_to_seconds(timeframe)
    now = int(datetime.utcnow().timestamp())
    start = now - step * (limit - 1)

    # Seed from symbol for consistent series shape across calls
    seeded = sum(ord(c) for c in symbol.upper()) % 997
    rng = random.Random(seeded)
    base = 100.0 + (seeded % 25)  # base price varies by symbol
    vol = 0.5 + (seeded % 7) * 0.1

    data: List[Dict[str, Any]] = []
    last_close = base
    for i in range(limit):
        t = start + i * step
        # simple random walk + sine wave modulation
        drift = (rng.random() - 0.5) * vol
        wave = math.sin(i / 15.0) * (vol * 0.6)
        open_p = last_close
        close_p = max(0.01, open_p + drift + wave)
        high_p = max(open_p, close_p) + abs(rng.random() * vol * 0.6)
        low_p = min(open_p, close_p) - abs(rng.random() * vol * 0.6)
        volume = abs(int(rng.gauss(1000, 250))) + 50
        data.append({
            "time": t,
            "open": round(open_p, 4),
            "high": round(high_p, 4),
            "low": round(low_p, 4),
            "close": round(close_p, 4),
            "volume": volume,
        })
        last_close = close_p

    return {"symbol": symbol, "timeframe": timeframe, "data": data}


@app.get("/api/chart-indicators/{symbol}")
async def chart_indicators(
    symbol: str,
    indicators: Optional[str] = None,
    timeframe: str = "1h",
    limit: int = 500,
) -> Dict[str, Any]:
    """Return simple indicator series for the provided symbol.
    Supports comma-separated indicators; known sample: SMA, EMA.
    """
    # Build a base series from the same generator to keep alignment
    candles = await chart_data(symbol, timeframe=timeframe, limit=limit)
    closes = [c["close"] for c in candles["data"]]
    times = [c["time"] for c in candles["data"]]

    def sma(period: int) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        s = 0.0
        for i, v in enumerate(closes):
            s += v
            if i >= period:
                s -= closes[i - period]
            if i >= period - 1:
                out.append({"time": times[i], "value": round(s / period, 4)})
        return out

    def ema(period: int) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        k = 2 / (period + 1)
        ema_v: Optional[float] = None
        for i, v in enumerate(closes):
            if ema_v is None:
                ema_v = float(v)
            else:
                ema_v = float(v) * k + float(ema_v) * (1 - k)
            if i >= period - 1 and ema_v is not None:
                out.append({"time": times[i], "value": round(float(ema_v), 4)})
        return out

    series: List[Dict[str, Any]] = []
    specs = (indicators or "SMA(20),EMA(50)").split(",")
    for spec in specs:
        name = spec.strip().upper()
        if name.startswith("SMA"):
            try:
                p = int(name.partition("(")[2].rstrip(")") or 20)
            except Exception:
                p = 20
            series.append({
                "name": f"SMA({p})",
                "data": sma(p),
                "options": {"color": "#22d3ee", "lineWidth": 2},
            })
        elif name.startswith("EMA"):
            try:
                p = int(name.partition("(")[2].rstrip(")") or 50)
            except Exception:
                p = 50
            series.append({
                "name": f"EMA({p})",
                "data": ema(p),
                "options": {"color": "#a78bfa", "lineWidth": 2},
            })

    return {"series": series}

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "fastapi_main:app",
        host="0.0.0.0",
        port=API_PORT,
        reload=APP_ENV == "development",
        log_level="info"
    )
