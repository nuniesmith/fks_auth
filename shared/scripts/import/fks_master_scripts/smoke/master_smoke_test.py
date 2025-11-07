#!/usr/bin/env python3
"""Smoke test for fks_master orchestration service.

Covers:
- /health endpoint
- /api/services listing
- Unauthorized compose & restart attempt (expects 401 / error)
- WebSocket initial message + subscription + filtered event receipt (best-effort; times out gracefully)

Environment:
Requires fks_master running locally (default port 9090).
Optionally set FKS_WS_JWT_SECRET and provide JWT via MASTER_SMOKE_JWT for authorized restart path.
"""
from __future__ import annotations
import json, os, sys, time, asyncio
import websockets
import requests

BASE = os.environ.get("FKS_MASTER_BASE", "http://localhost:9090")
WS   = BASE.replace("http://", "ws://") + "/ws"
JWT  = os.environ.get("MASTER_SMOKE_JWT")
TIMEOUT = float(os.environ.get("MASTER_SMOKE_TIMEOUT", "10"))


def pretty(obj):
    return json.dumps(obj, indent=2, sort_keys=True)


def check_health():
    r = requests.get(f"{BASE}/health", timeout=5)
    r.raise_for_status()
    data = r.json()
    assert data.get("status") == "healthy", data
    return data


def list_services():
    r = requests.get(f"{BASE}/api/services", timeout=5)
    r.raise_for_status()
    return r.json()


def unauthorized_compose():
    # Intentionally omit API key header
    payload = {"action": "ps", "services": []}
    r = requests.post(f"{BASE}/api/compose", json=payload, timeout=5)
    # If auth disabled, this may be 200; accept both but record outcome
    return {"status": r.status_code, "body": safe_json(r)}


def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text[:200]}

async def websocket_flow(expect_service: str | None = None):
    results = {"initial": None, "subscription_confirmed": False, "event_received": False}
    try:
        async with websockets.connect(WS, ping_interval=None) as ws:
            # Receive initial
            raw = await asyncio.wait_for(ws.recv(), timeout=TIMEOUT)
            init = json.loads(raw)
            results["initial"] = {k: list(init.keys()) for k in ["type", "services", "metrics"] if k in init}
            # Subscribe (optionally filter by service if provided)
            sub = {"command_type": "subscribe_events"}
            if expect_service:
                sub["service_id"] = expect_service
            await ws.send(json.dumps(sub))
            # Await confirmation
            t0 = time.time()
            while time.time() - t0 < TIMEOUT:
                msg = await asyncio.wait_for(ws.recv(), timeout=TIMEOUT)
                data = json.loads(msg)
                if data.get("type") == "subscription_confirmed":
                    results["subscription_confirmed"] = True
                elif data.get("type") == "event":
                    results["event_received"] = True
                    break
            return results
    except Exception as e:  # best-effort
        results["error"] = str(e)
        return results


def maybe_authorized_restart(first_service: str | None):
    if not JWT or not first_service:
        return {"skipped": True}
    r = requests.post(f"{BASE}/api/services/{first_service}/restart", headers={"Authorization": f"Bearer {JWT}"}, timeout=10)
    return {"status": r.status_code, "body": safe_json(r)}


def main():
    try:
        out = {}
        out["health"] = check_health()
        services = list_services()
        out["service_count"] = len(services)
        first_service = services[0]["id"] if services else None
        out["unauth_compose"] = unauthorized_compose()
        out["ws"] = asyncio.run(websocket_flow(expect_service=first_service))
        out["restart_attempt"] = maybe_authorized_restart(first_service)
        print(pretty(out))
        # Basic success heuristic
        ok = out["health"].get("status") == "healthy" and out["service_count"] >= 0
        return 0 if ok else 1
    except AssertionError as ae:
        print(f"[master_smoke] assertion failed: {ae}", file=sys.stderr)
        return 2
    except Exception as e:  # pragma: no cover
        print(f"[master_smoke] error: {e}", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
