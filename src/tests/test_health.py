from fastapi import status
import pytest
import httpx

from fks_api.fastapi_main import app


@pytest.mark.asyncio
async def test_health():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/health")
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data.get("status") in {"healthy", "ok"}
