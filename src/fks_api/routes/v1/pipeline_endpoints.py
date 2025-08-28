from api.routes.v1.cli.background_tasks import execute_pipeline
from api.routes.v1.cli.job_manager import create_job
from api.routes.v1.cli.utils.notification import safe_notify
from api.routes.v1.cli.utils.response_helpers import (
    create_error_response,
    create_success_response,
)
from fastapi import APIRouter, BackgroundTasks
from framework.infrastructure.monitoring.metrics.request_metrics import (
    CommandResponse,
    PipelineRequest,
)

router = APIRouter(tags=["pipeline"])


@router.post("/", response_model=CommandResponse)
async def run_pipeline(
    request: PipelineRequest, background_tasks: BackgroundTasks = None
):
    """Execute the complete sentiment analysis pipeline"""
    try:
        job_id = create_job("pipeline")
        background_tasks.add_task(
            execute_pipeline,
            job_id=job_id,
            save_data=request.save_data,
            report_format=request.report_format,
            include_visualizations=request.include_visualizations,
            source=request.source,
        )

        safe_notify(f"Full pipeline execution started ({job_id})", type="info")
        return create_success_response(
            command="pipeline",
            message="Full pipeline execution started in background",
            job_id=job_id,
        )
    except Exception as e:
        return create_error_response("pipeline", e)
