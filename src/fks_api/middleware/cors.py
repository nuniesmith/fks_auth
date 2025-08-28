"""CORS handling middleware (placeholder)."""

from starlette.types import ASGIApp, Scope, Receive, Send


class CORSMiddlewareLite:
	def __init__(self, app: ASGIApp):
		self.app = app

	async def __call__(self, scope: Scope, receive: Receive, send: Send):  # pragma: no cover
		await self.app(scope, receive, send)


__all__ = ["CORSMiddlewareLite"]

