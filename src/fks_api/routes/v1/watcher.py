"""
API routes for watcher price model training.
"""

import os
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from loguru import logger
from pydantic import BaseModel, Field, validator


class WatcherTrainingMode(str, Enum):
    """Training mode for watcher price models."""

    WEEKEND = "weekend"
    WEEKDAY = "weekday"
    AUTO = "auto"


class WatcherTrainingRequest(BaseModel):
    """Request model for watcher price training."""

    data_path: str = Field(..., description="Path to the input data file")
    models: List[str] = Field(
        default=["WatcherPrice", "WatcherDirection"],
        description="List of models to train",
    )
    target_column: Optional[str] = Field(
        "close", description="Target column for prediction"
    )
    output_dir: Optional[str] = Field(
        None, description="Directory to save models and results"
    )
    training_mode: WatcherTrainingMode = Field(
        WatcherTrainingMode.AUTO,
        description="Training mode (weekend, weekday, or auto)",
    )
    strategy: Optional[str] = Field(
        None, description="Training strategy ('default' or 'cv')"
    )
    version: str = Field("1.0.0", description="Model version string")
    hyperparameters: Optional[Dict[str, Any]] = Field(
        None, description="Advanced hyperparameters"
    )

    # Renamed validator method for Pydantic v2
    @validator("data_path")
    def validate_data_path(cls, v):
        if not os.path.exists(v):
            raise ValueError(f"Data file not found: {v}")
        return v


def create_watcher_router(job_manager):
    """
    Create a router for watcher price model training.

    Args:
        job_manager: TrainingJobManager instance

    Returns:
        FastAPI router
    """
    router = APIRouter(tags=["Watcher Price Training"])

    @router.post("/watcher/train", response_model=Dict[str, Any])
    async def train_watcher_model(
        request: WatcherTrainingRequest, background_tasks: BackgroundTasks
    ):
        """
        Train a watcher price prediction model.

        This endpoint will start a training job for watcher price prediction models,
        using either weekend (intensive) or weekday (lightweight) training mode.
        """
        try:
            # Check if the system is at capacity
            if job_manager.is_at_capacity():
                raise HTTPException(
                    status_code=429,
                    detail="System at capacity. Please try again later.",
                )

            # Prepare job configuration
            hyperparams = request.hyperparameters or {}

            # Add watcher-specific parameters to hyperparams
            hyperparams.update(
                {
                    "data_path": request.data_path,
                    "watcher_mode": request.training_mode,
                    "training_mode": (
                        request.training_mode
                    ),  # For backward compatibility
                    "version": request.version,
                }
            )

            # Create a training job request object
            job_request = type(
                "JobRequest",
                (),
                {
                    "models": request.models,
                    "data_path": request.data_path,
                    "target_column": request.target_column,
                    "hyperparameters": hyperparams,
                    "dict": lambda: {
                        "models": request.models,
                        "data_path": request.data_path,
                        "target_column": request.target_column,
                        "hyperparameters": hyperparams,
                        "training_mode": request.training_mode,
                        "version": request.version,
                    },
                },
            )

            # Create the job
            job_id = job_manager.create_job(job_request)

            # Run the job in the background with the specified strategy
            background_tasks.add_task(
                job_manager.run_job, job_id, job_request, request.strategy
            )

            return {
                "job_id": job_id,
                "status": "created",
                "timestamp": datetime.now().isoformat(),
                "message": (
                    f"Watcher price model training job created with mode: {request.training_mode}"
                ),
                "models": request.models,
            }

        except Exception as e:
            logger.error(f"Error creating watcher training job: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @router.get("/watcher/modes", response_model=Dict[str, Any])
    async def get_watcher_training_modes():
        """Get available watcher price training modes."""
        return {
            "modes": [
                {
                    "id": "weekend",
                    "name": "Weekend Mode",
                    "description": (
                        "Intensive training with hyperparameter optimization and advanced features"
                    ),
                },
                {
                    "id": "weekday",
                    "name": "Weekday Mode",
                    "description": "Fast training with basic features",
                },
                {
                    "id": "auto",
                    "name": "Auto Mode",
                    "description": (
                        "Automatically select weekend mode on weekends, weekday mode otherwise"
                    ),
                },
            ],
            "features": {
                "weekend": [
                    "Advanced technical indicators (RSI, MACD, Bollinger Bands)",
                    "Hyperparameter optimization",
                    "Cross-validation",
                    "More extensive historical data",
                    "Advanced feature engineering",
                ],
                "weekday": [
                    "Basic technical indicators",
                    "Faster training time",
                    "Focus on recent data",
                    "Minimal preprocessing",
                ],
            },
        }

    return router
