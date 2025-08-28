"""
CLI Command Router Configuration.

This module configures the main FastAPI router for CLI-related endpoints,
organizing them into logical groups with appropriate path prefixes and tags.
"""

from api.routes.v1.cli.endpoints.analyze_endpoints import router as analyze_router

# Import routers from the endpoints package
# Option 1: Individual imports (more explicit)
from api.routes.v1.cli.endpoints.fetch_endpoints import router as fetch_router
from api.routes.v1.cli.endpoints.job_endpoints import router as job_router
from api.routes.v1.cli.endpoints.pipeline_endpoints import router as pipeline_router
from api.routes.v1.cli.endpoints.report_endpoints import router as report_router
from api.routes.v1.cli.endpoints.visualize_endpoints import router as visualize_router
from fastapi import APIRouter

# Option 2: Using the updated __init__.py (more concise)
# Uncomment these lines if you've implemented the endpoints/__init__.py update
# from api.routes.v1.cli.endpoints import (
#     fetch_router,
#     analyze_router,
#     report_router,
#     visualize_router,
#     pipeline_router,
#     job_router
# )

# Create the main CLI router
router = APIRouter()

# Register all endpoint routers with appropriate prefixes and tags
# Data operations
router.include_router(fetch_router, prefix="/fetch", tags=["fetch"])
router.include_router(analyze_router, prefix="/analyze", tags=["analyze"])

# Output generation
router.include_router(report_router, prefix="/report", tags=["report"])
router.include_router(visualize_router, prefix="/visualize", tags=["visualize"])

# Workflow and management
router.include_router(pipeline_router, prefix="/pipeline", tags=["pipeline"])
router.include_router(job_router, prefix="/jobs", tags=["jobs"])
