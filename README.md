# FKS API Service

Lightweight FastAPI service providing HTTP/WebSocket endpoints for the FKS platform.

## Features

- Health & info endpoints
- Synthetic chart + indicator data for UI development
- Optional background Ollama model pull (dev)
- Modular router loading with graceful degradation

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install .[websocket,security]
uvicorn fks_api.fastapi_main:app --reload --port 8000
```

Visit: <http://localhost:8000/docs>

## Smoke Test

```bash
pytest -q
```

## Environment Vars

- API_SERVICE_NAME, API_SERVICE_PORT
- APP_ENV (development|production)
- OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_FAST_MODEL

## Next Steps

- Replace synthetic data endpoints with real data service
- AuthN/Z middleware integration
- Metrics & tracing
