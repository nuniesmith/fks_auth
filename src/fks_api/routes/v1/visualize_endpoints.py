from typing import Optional

from api.routes.v1.cli.background_tasks import run_visualize_background
from api.routes.v1.cli.job_manager import create_job
from api.routes.v1.cli.utils.notification import safe_notify
from api.routes.v1.cli.utils.response_helpers import (
    create_error_response,
    create_success_response,
)
from cli.commands.visualize import visualize_data
from fastapi import APIRouter, BackgroundTasks, HTTPException
from framework.infrastructure.monitoring.metrics.request_metrics import (
    CommandResponse,
    VisualizeRequest,
)

router = APIRouter(tags=["visualization"])


@router.post("/", response_model=CommandResponse)
async def run_visualize_command(
    request: VisualizeRequest, background_tasks: BackgroundTasks = None
):
    """Execute the visualize command to generate visualizations"""
    try:
        if background_tasks:
            job_id = create_job("visualize")
            background_tasks.add_task(
                run_visualize_background,
                job_id=job_id,
                data_dir=request.data_dir,
                output_dir=request.output_dir,
                viz_type=request.viz_type,
            )

            safe_notify(f"Visualization job started ({job_id})", type="info")
            return create_success_response(
                command="visualize",
                message="Visualization generation started in background",
                job_id=job_id,
            )
        else:
            # Run synchronously
            safe_notify(
                f"Generating {request.viz_type} visualizations...",
                type="ongoing",
                timeout=0,
            )
            result = visualize_data(
                data_dir=request.data_dir,
                output_dir=request.output_dir,
                viz_type=request.viz_type,
            )

            if result is None:
                return create_success_response(
                    command="visualize",
                    message="Failed to generate visualizations",
                    success=False,
                )

            return create_success_response(
                command="visualize", result={"visualization_dir": result}
            )
    except Exception as e:
        return create_error_response("visualize", e)
