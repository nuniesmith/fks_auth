from typing import Optional

from api.routes.v1.cli.job_manager import (
    background_jobs,
)
from api.routes.v1.cli.job_manager import delete_job as delete_job_manager
from api.routes.v1.cli.job_manager import (
    get_job,
)
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Response
from framework.infrastructure.monitoring.metrics.request_metrics import (
    CommandResponse,
    JobStatusResponse,
)

router = APIRouter(tags=["job-management"])


@router.get("/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    """Get the status of a background job"""
    if job_id not in background_jobs:
        raise HTTPException(status_code=404, detail=f"Job with ID {job_id} not found")

    return JobStatusResponse(**background_jobs[job_id])


@router.get("/", response_model=dict)
async def list_jobs_paginated(
    response: Response,
    status: Optional[str] = Query(None, description="Filter jobs by status"),
    command: Optional[str] = Query(None, description="Filter jobs by command type"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
):
    """List all background jobs with pagination and optional filtering"""
    filtered_jobs = list(background_jobs.values())

    if status:
        filtered_jobs = [job for job in filtered_jobs if job["status"] == status]

    if command:
        filtered_jobs = [job for job in filtered_jobs if job["command"] == command]

    total_jobs = len(filtered_jobs)
    total_pages = (total_jobs + page_size - 1) // page_size

    if page > total_pages and total_jobs > 0:
        raise HTTPException(
            status_code=404, detail=f"Page {page} not found. Total pages: {total_pages}"
        )

    start_idx = (page - 1) * page_size
    end_idx = min(start_idx + page_size, total_jobs)
    paginated_jobs = filtered_jobs[start_idx:end_idx]

    response.headers["X-Total-Count"] = str(total_jobs)
    response.headers["X-Total-Pages"] = str(total_pages)
    response.headers["X-Current-Page"] = str(page)

    job_objects = [JobStatusResponse(**job) for job in paginated_jobs]

    return {
        "items": job_objects,
        "total": total_jobs,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


@router.delete("/{job_id}", response_model=CommandResponse)
async def delete_job(job_id: str):
    """Delete a job from the job store"""
    if job_id not in background_jobs:
        raise HTTPException(status_code=404, detail=f"Job with ID {job_id} not found")

    del background_jobs[job_id]

    return CommandResponse(
        success=True, command="delete_job", message=f"Job {job_id} deleted"
    )
