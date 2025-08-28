"""
Background Job Manager.

This module provides utilities for managing background jobs, including creation,
status tracking, updating, and retrieval of job information.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from loguru import logger

# In-memory store for background job status tracking
# In a production environment, this would likely be replaced with a database
background_jobs: Dict[str, Dict[str, Any]] = {}


def create_job(command: str) -> str:
    """Create a new background job and return its ID.

    Args:
        command: The type of command being executed in the background

    Returns:
        str: A unique job identifier (UUID)
    """
    job_id = str(uuid.uuid4())
    background_jobs[job_id] = {
        "job_id": job_id,
        "status": "started",
        "command": command,
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "result": None,
        "error": None,
    }
    logger.debug(f"Created new job: {job_id} for command: {command}")
    return job_id


def update_job_success(job_id: str, result: Optional[Dict[str, Any]] = None) -> None:
    """Update job status to completed with result.

    Args:
        job_id: The unique identifier for the job
        result: Optional dictionary containing the job's results
    """
    if job_id in background_jobs:
        background_jobs[job_id]["status"] = "completed"
        background_jobs[job_id]["completed_at"] = datetime.now().isoformat()
        background_jobs[job_id]["result"] = result
        logger.debug(f"Job {job_id} completed successfully")


def update_job_failure(job_id: str, error: str) -> None:
    """Update job status to failed with error message.

    Args:
        job_id: The unique identifier for the job
        error: Error message describing the failure reason
    """
    if job_id in background_jobs:
        background_jobs[job_id]["status"] = "failed"
        background_jobs[job_id]["completed_at"] = datetime.now().isoformat()
        background_jobs[job_id]["error"] = error
        logger.debug(f"Job {job_id} failed with error: {error}")


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    """Get job details by ID.

    Args:
        job_id: The unique identifier for the job

    Returns:
        Optional[Dict[str, Any]]: Job details if found, None otherwise
    """
    return background_jobs.get(job_id)


def delete_job(job_id: str) -> bool:
    """Delete a job from the store.

    Args:
        job_id: The unique identifier for the job

    Returns:
        bool: True if job was found and deleted, False otherwise
    """
    if job_id in background_jobs:
        del background_jobs[job_id]
        logger.debug(f"Job {job_id} deleted")
        return True
    logger.debug(f"Attempted to delete non-existent job: {job_id}")
    return False


def list_jobs(
    status: Optional[str] = None, command: Optional[str] = None, limit: int = 50
) -> List[Dict[str, Any]]:
    """List jobs with optional filtering.

    Args:
        status: Optional filter by job status (started, completed, failed)
        command: Optional filter by command type
        limit: Maximum number of jobs to return

    Returns:
        List[Dict[str, Any]]: List of job details matching the filters
    """
    filtered_jobs = list(background_jobs.values())

    # Apply filters
    if status:
        filtered_jobs = [job for job in filtered_jobs if job["status"] == status]

    if command:
        filtered_jobs = [job for job in filtered_jobs if job["command"] == command]

    # Sort by start time (newest first) and limit
    sorted_jobs = sorted(filtered_jobs, key=lambda j: j["started_at"], reverse=True)[
        :limit
    ]

    return sorted_jobs
