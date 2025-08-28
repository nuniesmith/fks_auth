"""
FastAPI router for ML training endpoints with job management.
"""

import json
import os
import pickle
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from loguru import logger
from pydantic import BaseModel, Field
from services.data_service import DataService
from services.model_service import ModelService
from services.training_service import TrainingService
from shared.utilities.common.logging_utils import log_execution
from training.job_manager import TrainingJobManager


# Pydantic models for request validation
class TrainRequest(BaseModel):
    data_file: str = Field(
        ..., description="Path to the data file or data source identifier"
    )
    timeframe: str = Field(
        "1m", description="Timeframe for analysis (e.g., 1m, 5m, 1h, 1d)"
    )
    date_column: str = Field(
        "timestamp", description="Column name containing datetime information"
    )
    models: List[str] = Field(
        ["ARIMA", "Prophet", "LSTM"], description="List of models to train"
    )
    forecast_horizon: int = Field(
        5, description="Number of periods to forecast", gt=0, lt=100
    )
    hyperparameters: Optional[Dict[str, Any]] = Field(
        None, description="Optional model hyperparameters"
    )


class TrainingStatus(BaseModel):
    job_id: str
    status: str
    progress: float = 0.0
    start_time: float
    models_completed: List[str] = []
    message: str = ""
    version: str = "1.0.0"  # Will use the version from job_manager


def get_api_key(api_key: Optional[str] = Header(None)) -> str:
    """
    Simple API key validation dependency.
    For production, implement a more secure authentication system.
    """
    if api_key is None:
        raise HTTPException(status_code=401, detail="API key is required")
    expected_api_key = os.environ.get("API_KEY", "development-key")
    if api_key != expected_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key


# Add a dependency function to get the job manager
def get_job_manager():
    """Dependency to get job manager."""
    # This will be replaced with the actual job_manager instance by the router factory
    # It's just a placeholder for the dependency injection
    pass


def create_router(job_manager):
    """Factory function to create a router with injected job_manager."""

    router = APIRouter(tags=["Training"])

    # Override the get_job_manager dependency to return our specific job_manager
    def get_job_manager_override():
        return job_manager

    router.dependency_overrides[get_job_manager] = get_job_manager_override  # type: ignore

    @router.post(
        "/train", dependencies=[Depends(get_api_key)], response_model=Dict[str, Any]
    )
    @log_execution
    async def train(request: TrainRequest, background_tasks: BackgroundTasks):
        """
        Start a training job in the background and return a job ID.
        """
        logger.info(f"Received training request: {request}")

        # Check for too many active jobs
        if job_manager.is_at_capacity():
            raise HTTPException(
                status_code=429,
                detail=f"Too many active from jobs. Maximum concurrent jobs: {job_manager.max_concurrent_jobs}",
            )

        # Validate data file exists
        if not os.path.exists(request.data_file):
            raise HTTPException(
                status_code=400, detail=f"Data file not found: {request.data_file}"
            )

        # Create job and schedule it
        try:
            job_id = job_manager.create_job(request)
            background_tasks.add_task(job_manager.run_job, job_id, request)

            return {
                "job_id": job_id,
                "status": "queued",
                "message": "Training job submitted",
            }
        except Exception as e:
            logger.exception(f"Error submitting training job: {e}")
            return {"error": str(e), "traceback": traceback.format_exc()}

    @router.get(
        "/train/{job_id}",
        dependencies=[Depends(get_api_key)],
        response_model=Dict[str, Any],
    )
    @log_execution
    async def get_training_status(job_id: str):
        """
        Get the status of a training job.
        """
        if not job_manager.job_exists(job_id):
            raise HTTPException(
                status_code=404, detail=f"Training job {job_id} not found"
            )

        return job_manager.get_job_status(job_id)

    @router.delete(
        "/train/{job_id}",
        dependencies=[Depends(get_api_key)],
        response_model=Dict[str, str],
    )
    @log_execution
    async def cancel_training_job(
        job_id: str, job_manager_instance: TrainingJobManager = Depends(get_job_manager)
    ):
        """
        Cancel a training job if it's still running.
        """
        if not job_manager_instance.job_exists(job_id):
            raise HTTPException(
                status_code=404, detail=f"Training job {job_id} not found"
            )

        result = job_manager_instance.cancel_job(job_id)
        if result["success"]:
            return {"message": result["message"]}
        else:
            return {"message": f"Cannot cancel job: {result['message']}"}

    @router.get("/train/{job_id}/download", dependencies=[Depends(get_api_key)])
    @log_execution
    async def download_results(
        job_id: str, job_manager_instance: TrainingJobManager = Depends(get_job_manager)
    ):
        """
        Download the complete results for a training job.
        """
        if not job_manager_instance.job_exists(job_id):
            raise HTTPException(
                status_code=404, detail=f"Training job {job_id} not found"
            )

        file_path = job_manager_instance.get_results_file_path(job_id)

        if file_path is None:
            raise HTTPException(status_code=404, detail=f"Results file not found")

        return FileResponse(
            path=str(file_path),
            filename=f"results_{job_id}.pkl",
            media_type="application/octet-stream",
        )

    @router.get(
        "/models",
        dependencies=[Depends(get_api_key)],
        response_model=Dict[str, List[Dict[str, Any]]],
    )
    @log_execution
    async def list_available_models(
        job_manager_instance: TrainingJobManager = Depends(get_job_manager),
    ):
        """
        List available models and their capabilities.
        """
        return {"models": job_manager_instance.get_available_models()}

    @router.get(
        "/jobs",
        dependencies=[Depends(get_api_key)],
        response_model=Dict[str, List[Dict[str, Any]]],
    )
    @log_execution
    async def list_training_jobs(
        job_manager_instance: TrainingJobManager = Depends(get_job_manager),
    ):
        """
        List all training jobs with basic information.
        """
        return {"jobs": job_manager_instance.get_all_jobs()}

    # Additional route that utilizes your provided training_service code
    @router.post("/simple-train", dependencies=[Depends(get_api_key)])
    @log_execution
    async def train_models(
        data_file: str,
        forecast_horizon: int = 5,
        date_column: str = "timestamp",
        timeframe: str = "1m",
        selected_models: List[str] = Field(["ARIMA", "Prophet", "LSTM"]),
    ):
        try:
            logger.info(
                "Starting training job with data_file: {}, date_column: {}, timeframe: {}",
                data_file,
                date_column,
                timeframe,
            )

            # Prepare data first
            data_service = DataService(
                file_path=data_file, date_column=date_column, timeframe=timeframe
            )
            data = data_service.prepare_data()
            logger.info("Data prepared successfully with shape: {}", data.shape)

            # Initialize model service and training service
            model_service = ModelService(selected_models=selected_models)
            training_service = TrainingService(
                model_service, data, target_column="close"
            )

            # Run training
            metrics = training_service.train_all(forecast_horizon=forecast_horizon)
            logger.info("Training completed with metrics: {}", metrics)
            return {"message": "Training completed", "metrics": metrics}
        except Exception as e:
            logger.exception("Error in train_models endpoint: {}", e)
            raise HTTPException(status_code=500, detail=str(e))

    return router
