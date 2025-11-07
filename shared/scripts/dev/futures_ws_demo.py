#!/usr/bin/env python3
"""
Minimal Futures Beta WebSocket demo.
Config via env:
  FUTURES_BETA_WS_URL: ws url
  FUTURES_BETA_API_KEY: api key (if required)
  FUTURES_BETA_SUBSCRIBE: JSON string for subscribe message, e.g. '{"action":"subscribe","symbols":["ESZ5"]}'

Run:
  python scripts/dev/futures_ws_demo.py
"""
import os
import json
import time
import threading

try:
    import websocket  # type: ignore
except Exception:
    websocket = None  # type: ignore


def main():
    ws_url = os.getenv("FUTURES_BETA_WS_URL")
    sub_raw = os.getenv("FUTURES_BETA_SUBSCRIBE")
    api_key = os.getenv("FUTURES_BETA_API_KEY")

    if not ws_url:
        print("Missing FUTURES_BETA_WS_URL")
        return 1
    if websocket is None:
        print("Please 'pip install websocket-client' to use this demo")
        return 2

    headers = []
    if api_key:
        # Common pattern; adjust header name per provider docs
        headers.append(f"Authorization: Bearer {api_key}")

    sub_msg = None
    if sub_raw:
        try:
            sub_msg = json.loads(sub_raw)
        except Exception:
            sub_msg = None

    def on_open(ws):  # type: ignore
        print("[ws] open")
        if sub_msg:
            ws.send(json.dumps(sub_msg))

    def on_message(ws, message):  # type: ignore
        print("[ws] msg:", message[:200])

    def on_error(ws, error):  # type: ignore
        print("[ws] error:", error)

    def on_close(ws, code, reason):  # type: ignore
        print("[ws] closed:", code, reason)

    wsapp = websocket.WebSocketApp(
        ws_url,
        header=headers,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
    )

    # Run in thread to allow graceful stop
    t = threading.Thread(target=wsapp.run_forever, kwargs={"ping_interval": 20}, daemon=True)
    t.start()

    try:
        for _ in range(60):
            time.sleep(1)
        print("[ws] demo done")
    finally:
        try:
            wsapp.close()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
