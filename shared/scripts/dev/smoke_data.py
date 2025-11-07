#!/usr/bin/env python3
"""
Quick, non-blocking smoke tests for the data service.
- Builds a tiny Flask app in-process with the data service custom endpoints
- Executes a few small queries (providers, keys, tiny OHLCV fetches)
- Prints a compact summary and exits (no long-running server)

Run:
  python scripts/dev/smoke_data.py

Environment:
  Optionally set POLYGON_API_KEY, ALPHA_VANTAGE_API_KEY, COINMARKETCAP_API_KEY
"""
from __future__ import annotations

import os
import sys
import traceback
from typing import Any, Dict

# Ensure src/python is on path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC_PY = os.path.join(ROOT, "src", "python")
if SRC_PY not in sys.path:
    sys.path.insert(0, SRC_PY)

from flask import Flask

summary: Dict[str, Any] = {"ok": True, "checks": []}

try:
    # Import data service endpoint factory
    from services.data.main import _custom_endpoints  # type: ignore
except Exception as e:
    print("[smoke] ERROR: couldn't import services.data.main:_custom_endpoints:", e)
    traceback.print_exc()
    sys.exit(2)

app = Flask("data-smoke")
# Wire endpoints like the template would do
for path, spec in _custom_endpoints().items():
    if callable(spec):
        app.add_url_rule(path, endpoint=path.replace('/', '_') or 'root', view_func=spec)
    elif isinstance(spec, (tuple, list)) and len(spec) >= 1:
        handler = spec[0]
        methods = spec[1] if len(spec) >= 2 else None
        app.add_url_rule(path, endpoint=path.replace('/', '_'), view_func=handler, methods=methods)
    elif isinstance(spec, dict):
        handler = spec.get("handler")
        methods = spec.get("methods")
        app.add_url_rule(path, endpoint=path.replace('/', '_'), view_func=handler, methods=methods)

client = app.test_client()

def check(name: str, fn):
    try:
        out = fn()
        summary["checks"].append({"name": name, "ok": True, **(out or {})})
    except Exception as e:
        summary["ok"] = False
        summary["checks"].append({"name": name, "ok": False, "error": str(e)})

# Checks

def providers():
    r = client.get("/providers")
    assert r.status_code == 200, r.data
    j = r.get_json() or {}
    return {"providers": j.get("count", 0)}


def keys():
    r = client.get("/providers/keys")
    assert r.status_code == 200, r.data
    j = r.get_json() or {}
    arr = j.get("keys")
    # arr is a list of {provider, exists}
    if isinstance(arr, dict):
        # Backward compat (map)
        exists_count = sum(1 for v in arr.values() if v)
    else:
        exists_count = sum(1 for k in (arr or []) if k.get("exists"))
    return {"keys_present": exists_count}


def yf_daily_small():
    r = client.get("/daily", query_string={"symbol": "AAPL", "period": "5d", "provider": "yfinance"})
    assert r.status_code == 200, r.data
    j = r.get_json() or {}
    return {"yf_daily_rows": j.get("count", 0)}


def binance_small():
    r = client.get("/crypto/binance/klines", query_string={"symbol": "BTCUSDT", "interval": "1m", "limit": 5})
    assert r.status_code == 200, r.data
    j = r.get_json() or {}
    return {"binance_rows": j.get("count", 0)}

# Optional: save provider keys from env and run provider-specific tiny checks
def save_key(provider: str, api_key: str):
    return client.post(f"/providers/{provider}/key", json={"api_key": api_key})

def polygon_small():
    r = client.get("/daily", query_string={"symbol": "AAPL", "period": "1mo", "provider": "polygon", "limit": 5})
    assert r.status_code == 200, r.data
    j = r.get_json() or {}
    return {"polygon_rows": j.get("count", 0)}

def alpha_small():
    r = client.get("/daily", query_string={"symbol": "AAPL", "period": "1mo", "provider": "alpha_vantage", "limit": 5})
    assert r.status_code == 200, r.data
    j = r.get_json() or {}
    return {"alpha_rows": j.get("count", 0)}

def alpha_news_small():
    r = client.get("/providers/alpha/news", query_string={"symbol": "AAPL", "limit": 3})
    assert r.status_code == 200, r.data
    j = r.get_json() or {}
    return {"alpha_news": j.get("count", 0)}

# Run
check("providers", providers)
check("keys", keys)
check("yf_daily_small", yf_daily_small)
check("binance_small", binance_small)

# If keys are available, save them and run extra checks
POLY = os.getenv("POLYGON_API_KEY")
ALPHA = os.getenv("ALPHA_VANTAGE_API_KEY") or os.getenv("ALPHAVANTAGE_API_KEY")
try:
    if POLY:
        rr = save_key("polygon", POLY)
        assert rr.status_code in (200, 201), rr.data
        check("polygon_small", polygon_small)
    if ALPHA:
        rr = save_key("alpha_vantage", ALPHA)
        assert rr.status_code in (200, 201), rr.data
        check("alpha_small", alpha_small)
        check("alpha_news_small", alpha_news_small)
except Exception as _:
    # Non-fatal for smoke
    pass

# Print compact result
ok = summary.get("ok")
print("[smoke] ok=", ok)
for c in summary["checks"]:
    status = "PASS" if c["ok"] else "FAIL"
    extra = {k: v for k, v in c.items() if k not in ("name", "ok", "error")}
    if c["ok"]:
        print(f" - {status} {c['name']} {extra}")
    else:
        print(f" - {status} {c['name']} error={c.get('error')}")

sys.exit(0 if ok else 1)
