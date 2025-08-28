"""
Ollama proxy router

Provides lightweight endpoints that proxy to a local Ollama server.
This lets the web app use a stable REST API and centralizes auth.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import StreamingResponse
from loguru import logger

from framework.middleware.auth import get_auth_token, authenticate_user


router = APIRouter(tags=["ai", "ollama"])

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "ollama")
OLLAMA_PORT = int(os.getenv("OLLAMA_PORT", "11434"))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", f"http://{OLLAMA_HOST}:{OLLAMA_PORT}")
APP_ENV = os.getenv("APP_ENV", "development").lower()


def _maybe_authenticate(token: Optional[str]) -> None:
    """Authenticate when not in development. In development, allow optional token.
    If a token is provided in development, attempt to validate but ignore failures.
    """
    if APP_ENV != "development":
        if not token:
            raise HTTPException(status_code=401, detail="Missing token")
        authenticate_user(token)
    else:
        if token:
            try:
                authenticate_user(token)
            except Exception:
                # Ignore auth errors in development when token is present but invalid
                pass


async def _post(path: str, json: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{OLLAMA_BASE_URL.rstrip('/')}{path}"
    timeout = httpx.Timeout(60.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(url, json=json)
        if r.status_code >= 400:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        try:
            return r.json()
        except Exception:
            return {"ok": False, "error": r.text}


@router.get("/ai/ollama/health")
async def ollama_health(token: Optional[str] = Depends(get_auth_token)) -> Dict[str, Any]:
    # health is open to ease local dev; if token provided, validate
    if token:
        try:
            authenticate_user(token)
        except Exception:
            pass
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{OLLAMA_BASE_URL.rstrip('/')}/api/tags")
            ok = r.status_code < 400
        return {"ok": ok}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/ai/chat")
async def ai_chat(
    payload: Dict[str, Any] = Body(...),
    token: Optional[str] = Depends(get_auth_token),
) -> Dict[str, Any]:
    _maybe_authenticate(token)
    model = payload.get("model") or os.getenv("OLLAMA_MODEL", "gpt-oss:20b")
    messages = payload.get("messages") or []
    options = payload.get("options") or {}
    stream = bool(payload.get("stream", False))
    req = {"model": model, "messages": messages, "stream": stream, "options": options}
    return await _post("/api/chat", req)


@router.post("/ai/generate")
async def ai_generate(
    payload: Dict[str, Any] = Body(...),
    token: Optional[str] = Depends(get_auth_token),
) -> Dict[str, Any]:
    _maybe_authenticate(token)
    model = payload.get("model") or os.getenv("OLLAMA_MODEL", "gpt-oss:20b")
    prompt = payload.get("prompt") or ""
    options = payload.get("options") or {}
    stream = bool(payload.get("stream", False))
    req = {"model": model, "prompt": prompt, "stream": stream, "options": options}
    return await _post("/api/generate", req)


@router.post("/ai/chat/stream")
async def ai_chat_stream(
    payload: Dict[str, Any] = Body(...),
    token: Optional[str] = Depends(get_auth_token),
):
    """Stream chat tokens to the client. Returns text/plain NDJSON or plain text chunks."""
    _maybe_authenticate(token)
    model = payload.get("model") or os.getenv("OLLAMA_MODEL", "gpt-oss:20b")
    messages = payload.get("messages") or []
    options = payload.get("options") or {}
    req = {"model": model, "messages": messages, "stream": True, "options": options}
    url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/chat"

    async def _iter():
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
            async with client.stream("POST", url, json=req) as r:
                r.raise_for_status()
                async for chunk in r.aiter_bytes():
                    if not chunk:
                        continue
                    yield chunk

    return StreamingResponse(_iter(), media_type="application/x-ndjson")


@router.post("/ai/generate/stream")
async def ai_generate_stream(
    payload: Dict[str, Any] = Body(...),
    token: Optional[str] = Depends(get_auth_token),
):
    """Stream generate tokens to the client. Returns text/plain stream of NDJSON or raw text."""
    _maybe_authenticate(token)
    model = payload.get("model") or os.getenv("OLLAMA_MODEL", "gpt-oss:20b")
    prompt = payload.get("prompt") or ""
    options = payload.get("options") or {}
    req = {"model": model, "prompt": prompt, "stream": True, "options": options}
    url = f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate"

    async def _iter():
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
            async with client.stream("POST", url, json=req) as r:
                r.raise_for_status()
                async for chunk in r.aiter_bytes():
                    if not chunk:
                        continue
                    yield chunk

    return StreamingResponse(_iter(), media_type="application/x-ndjson")


@router.post("/ai/embeddings")
async def ai_embeddings(
    payload: Dict[str, Any] = Body(...),
    token: Optional[str] = Depends(get_auth_token),
) -> Dict[str, Any]:
    _maybe_authenticate(token)
    model = payload.get("model") or os.getenv("OLLAMA_EMBEDDINGS_MODEL", "nomic-embed-text:latest")
    input_text = payload.get("input") or payload.get("texts") or ""
    req = {"model": model, "prompt": input_text}
    return await _post("/api/embeddings", req)


@router.post("/ai/ollama/pull")
async def ollama_pull(
    payload: Dict[str, Any] = Body(default={}),
    token: Optional[str] = Depends(get_auth_token),
) -> Dict[str, Any]:
    _maybe_authenticate(token)
    model = payload.get("model") or os.getenv("OLLAMA_MODEL", "gpt-oss:20b")
    req = {"name": model}
    return await _post("/api/pull", req)


@router.get("/ai/ollama/models")
async def ollama_models(token: Optional[str] = Depends(get_auth_token)) -> Dict[str, Any]:
    _maybe_authenticate(token)
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(f"{OLLAMA_BASE_URL.rstrip('/')}/api/tags")
        if r.status_code >= 400:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()
