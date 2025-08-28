from api.routes.v1.cli.background_tasks import run_fetch_background
from api.routes.v1.cli.job_manager import create_job
from api.routes.v1.cli.utils.notification import safe_notify  # Fixed import
from api.routes.v1.cli.utils.response_helpers import (
    create_error_response,
    create_success_response,
)
from cli.commands.analyze import analyze_sentiment
from fastapi import APIRouter, BackgroundTasks, HTTPException
from framework.infrastructure.monitoring.metrics.request_metrics import (
    CommandResponse,
    FetchRequest,
)

router = APIRouter(tags=["fetch"])


@router.post("/", response_model=CommandResponse)  # Fixed route path
async def run_fetch_command(
    request: FetchRequest, background_tasks: BackgroundTasks = None
):
    """Execute the fetch command to retrieve cryptocurrency and forex data"""
    try:
        job_id = create_job("fetch")
        background_tasks.add_task(
            run_fetch_background,
            job_id=job_id,
            save=request.save,
            source=request.source,
        )

        safe_notify(f"Fetch job started ({job_id})", type="info")
        return create_success_response(
            command="fetch",
            message="Fetch command started in background",
            job_id=job_id,
        )
    except Exception as e:
        return create_error_response("fetch", e)
