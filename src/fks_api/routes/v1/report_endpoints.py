from api.routes.v1.cli.background_tasks import run_report_background
from api.routes.v1.cli.job_manager import create_job  # Fixed import
from api.routes.v1.cli.utils.notification import safe_notify
from api.routes.v1.cli.utils.response_helpers import (
    create_error_response,
    create_success_response,
)
from cli.commands.report import ReportCommand
from fastapi import APIRouter, BackgroundTasks, HTTPException
from framework.infrastructure.monitoring.metrics.request_metrics import (
    CommandResponse,
    ReportRequest,
)

router = APIRouter(tags=["report"])


@router.post("/", response_model=CommandResponse)
async def run_report_command(request: ReportRequest):
    """Execute the report command synchronously"""
    try:
        safe_notify(
            f"Generating {request.output_format} report...", type="ongoing", timeout=0
        )
        command = ReportCommand()
        result = command.run(
            output_format=request.output_format,
            include_visualizations=request.include_visualizations,
        )
        if result is None:
            safe_notify("Failed to generate report", type="negative")
            return create_success_response(
                command="report", message="Failed to generate report", success=False
            )
        safe_notify(f"Report generated successfully: {result}", type="positive")
        return create_success_response(command="report", result={"report_file": result})
    except Exception as e:
        return create_error_response("report", e)


@router.post("/async", response_model=CommandResponse)
async def run_report_command_async(
    request: ReportRequest, background_tasks: BackgroundTasks = None
):
    """Execute the report command asynchronously"""
    try:
        job_id = create_job("report")
        background_tasks.add_task(
            run_report_background,
            job_id=job_id,
            output_format=request.output_format,
            include_visualizations=request.include_visualizations,
        )
        safe_notify(f"Report generation job started ({job_id})", type="info")
        return create_success_response(
            command="report",
            message="Report generation started in background",
            job_id=job_id,
        )
    except Exception as e:
        return create_error_response("report", e)
