from typing import Optional

from api.routes.v1.cli.background_tasks import run_analyze_background
from api.routes.v1.cli.job_manager import create_job
from api.routes.v1.cli.utils.notification import safe_notify
from api.routes.v1.cli.utils.response_helpers import (
    create_error_response,
    create_success_response,
)
from cli.commands.analyze import analyze_sentiment
from fastapi import APIRouter, BackgroundTasks, HTTPException
from framework.infrastructure.monitoring.metrics.request_metrics import (
    AnalyzeRequest,
    CommandResponse,
)
from loguru import logger

router = APIRouter(tags=["analyze"])


@router.post("/", response_model=CommandResponse)
async def run_analyze_command(
    request: AnalyzeRequest, background_tasks: BackgroundTasks = None
):
    """Execute the analyze command to analyze market sentiment data"""
    try:
        if background_tasks is not None:
            job_id = create_job("analyze")
            background_tasks.add_task(
                run_analyze_background, job_id=job_id, source=request.source
            )

            safe_notify(f"Analysis job started ({job_id})", type="info")
            return create_success_response(
                command="analyze",
                message="Analysis started in background",
                job_id=job_id,
            )
        else:
            # Run synchronously
            safe_notify("Running synchronous analysis...", type="ongoing", timeout=0)
            result = analyze_sentiment(source=request.source)

            if result is None:
                safe_notify("Failed to analyze sentiment data", type="negative")
                return create_success_response(
                    command="analyze",
                    message="Failed to analyze sentiment data",
                    success=False,
                )

            # Only include summary information in the response
            if "report" in result:
                summary = {
                    "overall_sentiment": result["report"].get("overall_sentiment", {}),
                    "report_file": result.get("report_file", None),
                    "visualization_dir": result.get("visualization_dir", None),
                }
            else:
                summary = {}

            safe_notify("Analysis completed successfully", type="positive")
            return create_success_response(command="analyze", result=summary)
    except Exception as e:
        logger.exception("Error executing analyze command")
        return create_error_response("analyze", e)
