#!/usr/bin/env python3
"""Standalone smoke script (excluded from normal pytest collection)."""
import json, sys, time
from urllib.parse import urlencode
import requests
if "pytest" in sys.modules:  # pragma: no cover
    raise ImportError("Skip standalone smoke script during test collection")

BASE = "http://localhost"


def pretty(obj):
    return json.dumps(obj, indent=2, sort_keys=True)


def check_transformer_health():
    r = requests.get(f"{BASE}/transformer/health", timeout=5)
    r.raise_for_status()
    return r.json()


def post_transformer_predict(series, window=64):
    params = {"window": window}
    r = requests.post(
        f"{BASE}/transformer/predict?{urlencode(params)}",
        json={"series": series},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def get_engine_forecast(symbol="GC=F", period="6mo", window=64, retries=3, delay=1.0):
    params = urlencode({"symbol": symbol, "period": period, "window": window})
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(f"{BASE}/engine/forecast?{params}", timeout=20)
            r.raise_for_status()
            return r.json()
        except Exception:
            if attempt < retries:
                time.sleep(delay)
            else:
                raise


def get_engine_forecast_any(symbol="GC=F", period="6mo", window=64, retries=3, delay=1.0):
    params = urlencode({"symbol": symbol, "period": period, "window": window})
    # Try gateway first
    try:
        data = get_engine_forecast(symbol, period, window, retries=retries, delay=delay)
        return "gateway", data
    except Exception:
        # Fallback to direct engine port
        url = f"http://localhost:9010/forecast?{params}"
        for attempt in range(1, retries + 1):
            try:
                r = requests.get(url, timeout=20)
                r.raise_for_status()
                return "direct", r.json()
            except Exception:
                if attempt < retries:
                    time.sleep(delay)
                else:
                    raise


def main():
    try:
        print("- Checking transformer health…")
        h = check_transformer_health()
        print(pretty(h))

        print("- Posting transformer predict…")
        series = [100 + i for i in range(80)]
        p = post_transformer_predict(series, window=48)
        print(pretty({k: p.get(k) for k in ["ok", "shape", "horizon_pred", "device"]}))

        print("- Getting engine forecast…")
        res = get_engine_forecast_any(symbol="GC=F", period="6mo", window=48)
        if isinstance(res, tuple) and len(res) == 2:
            source, f = res
        else:
            source = "unknown"
            f = res if isinstance(res, dict) else {}
        f = f or {}
        tf = (f.get("transformer") or {}) if isinstance(f, dict) else {}
        tf_view = {k: tf.get(k) for k in ["ok", "shape", "horizon_pred", "device", "window_used"]}
        raw = (f.get("transformer_raw") or {}) if isinstance(f, dict) else {}
        if tf_view.get("horizon_pred") is None:
            tf_view["horizon_pred_raw"] = raw.get("horizon_pred")
        out = {k: (f.get(k) if isinstance(f, dict) else None) for k in ["ok", "symbol", "n", "last_date", "window"]}
        out["transformer"] = tf_view
        out["source"] = source
        print(pretty(out))
        return 0
    except Exception as e:
        print(f"Smoke test failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
