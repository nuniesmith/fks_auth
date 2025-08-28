"""FastAPI application setup (lightweight placeholder)."""

from __future__ import annotations

from fastapi import FastAPI


def create_app() -> FastAPI:
	app = FastAPI(title="FKS API", version="0.1.0")

	@app.get("/health")
	def health() -> dict[str, str]:
		return {"status": "ok"}

	return app


app = create_app()

__all__ = ["app", "create_app"]

