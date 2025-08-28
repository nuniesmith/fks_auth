import hashlib
import io
import json
import mimetypes
import os
import re
import shutil
import time
import uuid
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from core.telemetry.telemetry import telemetry
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import FileResponse, JSONResponse
from framework.middleware.auth import (
    authenticate_user,
    cache_response,
    check_permission,
    get_auth_token,
    get_cached_response,
)
from loguru import logger
from models.base.pagination import PaginatedResponse, PaginationParams
from pydantic import BaseModel, Field, validator

# Configure logger
logger = logger.opt(colors=True).getLogger("visualization_api")

# Constants
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".svg", ".pdf", ".html", ".gif", ".webp"}
THUMBNAIL_SIZE = (200, 200)
CACHE_TTL_SECONDS = 300  # 5 minutes
MAX_FILENAME_LENGTH = 255
DEFAULT_VIZ_PER_PAGE = 20


# Models
class VisualizationType(str, Enum):
    """Types of visualizations."""

    CHART = "chart"
    GRAPH = "graph"
    HEATMAP = "heatmap"
    MAP = "map"
    DASHBOARD = "dashboard"
    TABLE = "table"
    CUSTOM = "custom"


class VisualizationFormat(str, Enum):
    """Formats of visualization files."""

    PNG = "png"
    JPG = "jpg"
    JPEG = "jpeg"
    SVG = "svg"
    PDF = "pdf"
    HTML = "html"
    GIF = "gif"
    WEBP = "webp"


class VisualizationMetadata(BaseModel):
    """Metadata for a visualization."""

    id: str
    name: str
    description: Optional[str] = None
    type: Optional[VisualizationType] = None
    format: VisualizationFormat
    path: str
    size_bytes: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)
    category: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None
    thumbnail_path: Optional[str] = None
    generated_by: Optional[str] = None
    source_data: Optional[Dict[str, Any]] = None


class VisualizationListItem(BaseModel):
    """Simplified visualization item for list responses."""

    id: str
    name: str
    type: Optional[VisualizationType] = None
    format: VisualizationFormat
    path: str
    size_bytes: int
    created_at: datetime
    thumbnail_path: Optional[str] = None
    category: Optional[str] = None


class VisualizationResponse(BaseModel):
    """Response with visualization data."""

    metadata: VisualizationMetadata
    related_visualizations: List[VisualizationListItem] = Field(default_factory=list)


class GenerateVisualizationRequest(BaseModel):
    """Request to generate a visualization."""

    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    type: VisualizationType
    format: VisualizationFormat = VisualizationFormat.PNG
    category: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)

    @validator("tags")
    def validate_tags(cls, v):
        if len(v) > 10:
            raise ValueError("Maximum of 10 tags allowed")
        for tag in v:
            if not isinstance(tag, str) or len(tag) < 2 or len(tag) > 30:
                raise ValueError("Tags must be strings between 2 and 30 characters")
        return v

    @validator("name")
    def validate_name(cls, v):
        if not re.match(r"^[a-zA-Z0-9_\-\. ]+$", v):
            raise ValueError(
                "Name can only contain alphanumeric characters, spaces, underscores, hyphens, and periods"
            )
        return v


class GenerateVisualizationResponse(BaseModel):
    """Response from visualization generation."""

    job_id: str
    status: str
    message: str
    visualization_id: Optional[str] = None


class VisualizationJobStatus(BaseModel):
    """Status of a visualization generation job."""

    job_id: str
    status: str
    progress: float
    message: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None


# Helper functions
def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal attacks.

    Args:
        filename: The filename to sanitize

    Returns:
        Sanitized filename
    """
    # Get just the basename (no path components)
    safe_name = os.path.basename(filename)

    # Remove any suspicious characters
    safe_name = re.sub(r"[^\w\-. ]", "_", safe_name)

    # Ensure the name isn't too long
    if len(safe_name) > MAX_FILENAME_LENGTH:
        base, ext = os.path.splitext(safe_name)
        safe_name = base[: MAX_FILENAME_LENGTH - len(ext)] + ext

    return safe_name


def validate_file_type(file_path: str) -> bool:
    """
    Validate that a file has an allowed extension.

    Args:
        file_path: Path to the file

    Returns:
        True if allowed, False otherwise
    """
    ext = os.path.splitext(file_path)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def get_file_metadata(file_path: str, relative_path: str) -> Dict[str, Any]:
    """
    Get metadata for a visualization file.

    Args:
        file_path: Absolute path to the file
        relative_path: Relative path for API access

    Returns:
        Dictionary with file metadata
    """
    if not os.path.exists(file_path):
        return {}

    file_stats = os.stat(file_path)
    file_name = os.path.basename(file_path)
    base_name, ext = os.path.splitext(file_name)

    # Generate an ID based on file path
    file_id = hashlib.md5(file_path.encode()).hexdigest()

    # Determine visualization type from filename or set default
    viz_type = VisualizationType.CHART
    for t in VisualizationType:
        if t.value in base_name.lower():
            viz_type = t
            break

    # Determine format
    try:
        format_str = ext[1:].lower()
        viz_format = VisualizationFormat(format_str)
    except ValueError:
        # Default to png if not recognized
        viz_format = VisualizationFormat.PNG

    # Extract category from path or filename
    category = None
    path_parts = os.path.dirname(file_path).split(os.sep)
    if len(path_parts) > 1:
        category = path_parts[-1]

    # Create thumbnail path
    thumbnail_path = None
    thumbnail_dir = os.path.join(os.path.dirname(file_path), "thumbnails")
    thumbnail_file = os.path.join(thumbnail_dir, f"thumb_{file_name}")
    if os.path.exists(thumbnail_file):
        thumbnail_path = (
            f"{os.path.dirname(relative_path)}/thumbnails/thumb_{file_name}"
        )

    return {
        "id": file_id,
        "name": base_name,
        "description": None,
        "type": viz_type,
        "format": viz_format,
        "path": relative_path,
        "size_bytes": file_stats.st_size,
        "created_at": datetime.fromtimestamp(file_stats.st_ctime),
        "updated_at": datetime.fromtimestamp(file_stats.st_mtime),
        "tags": [],
        "category": category,
        "thumbnail_path": thumbnail_path,
    }


def create_visualization_metadata(
    file_metadata: Dict[str, Any],
) -> VisualizationMetadata:
    """
    Create a VisualizationMetadata object from file metadata.

    Args:
        file_metadata: Dictionary with file metadata

    Returns:
        VisualizationMetadata object
    """
    return VisualizationMetadata(**file_metadata)


def create_thumbnail(
    file_path: str, thumbnail_size: tuple = THUMBNAIL_SIZE
) -> Optional[str]:
    """
    Create a thumbnail for a visualization.

    Args:
        file_path: Path to the visualization file
        thumbnail_size: Size of the thumbnail (width, height)

    Returns:
        Path to the thumbnail or None if creation failed
    """
    try:
        # Ensure the extension is supported
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in [".png", ".jpg", ".jpeg", ".gif"]:
            # For unsupported formats, we'd need format-specific handling
            # This is a simplified implementation
            return None

        # Create thumbnails directory if it doesn't exist
        thumbnail_dir = os.path.join(os.path.dirname(file_path), "thumbnails")
        os.makedirs(thumbnail_dir, exist_ok=True)

        # Create thumbnail name
        file_name = os.path.basename(file_path)
        thumbnail_path = os.path.join(thumbnail_dir, f"thumb_{file_name}")

        # Check if thumbnail already exists and is newer than the source file
        if os.path.exists(thumbnail_path):
            thumb_mtime = os.path.getmtime(thumbnail_path)
            src_mtime = os.path.getmtime(file_path)
            if thumb_mtime >= src_mtime:
                return thumbnail_path

        # Generate thumbnail
        try:
            from PIL import Image

            image = Image.open(file_path)
            image.thumbnail(thumbnail_size)
            image.save(thumbnail_path)
            return thumbnail_path
        except ImportError:
            # If PIL is not available, copy the file as a fallback
            # (in a real application, you'd want a proper thumbnail generation)
            shutil.copy2(file_path, thumbnail_path)
            return thumbnail_path

    except Exception as e:
        logger.error(f"Error creating thumbnail for {file_path}: {str(e)}")
        return None


def get_visualizations_from_directory(
    directory: str,
    base_path: str,
    filter_type: Optional[VisualizationType] = None,
    filter_format: Optional[VisualizationFormat] = None,
    filter_category: Optional[str] = None,
    search_term: Optional[str] = None,
    created_after: Optional[datetime] = None,
    include_metrics: bool = False,
) -> List[Dict[str, Any]]:
    """
    Get visualizations from a directory with optional filtering.

    Args:
        directory: Directory to scan for visualizations
        base_path: Base API path for visualization URLs
        filter_type: Optional filter by visualization type
        filter_format: Optional filter by visualization format
        filter_category: Optional filter by category
        search_term: Optional search term for name or description
        created_after: Optional filter by creation date
        include_metrics: Whether to include metric data

    Returns:
        List of visualization metadata dictionaries
    """
    visualizations = []

    if not os.path.exists(directory) or not os.path.isdir(directory):
        return visualizations

    # Walk through directory and subdirectories
    for root, dirs, files in os.walk(directory):
        # Skip thumbnails directory
        if os.path.basename(root) == "thumbnails":
            continue

        # Process each file
        for filename in files:
            file_path = os.path.join(root, filename)

            # Check if file has allowed extension
            if not validate_file_type(file_path):
                continue

            # Get relative path from visualization directory
            rel_path = os.path.relpath(root, directory)
            if rel_path == ".":
                rel_path = ""

            # Create API path
            if rel_path:
                api_path = f"{base_path}/{rel_path}/{filename}"
                category = os.path.basename(rel_path)
            else:
                api_path = f"{base_path}/{filename}"
                category = None

            # Get file metadata
            metadata = get_file_metadata(file_path, api_path)

            # Apply filters
            if filter_type and metadata.get("type") != filter_type:
                continue

            if filter_format and metadata.get("format") != filter_format:
                continue

            if filter_category and metadata.get("category") != filter_category:
                continue

            if search_term:
                name = metadata.get("name", "").lower()
                desc = metadata.get("description", "").lower()
                if search_term.lower() not in name and search_term.lower() not in desc:
                    continue

            if created_after and metadata.get("created_at") < created_after:
                continue

            # Add metrics if requested and available
            if include_metrics:
                # Check for an accompanying metadata file
                meta_file = os.path.splitext(file_path)[0] + ".json"
                if os.path.exists(meta_file):
                    try:
                        with open(meta_file, "r") as f:
                            meta_data = json.load(f)
                            if "metrics" in meta_data:
                                metadata["metrics"] = meta_data["metrics"]
                            if "description" in meta_data and not metadata.get(
                                "description"
                            ):
                                metadata["description"] = meta_data["description"]
                            if "tags" in meta_data:
                                metadata["tags"] = meta_data["tags"]
                            if "generated_by" in meta_data:
                                metadata["generated_by"] = meta_data["generated_by"]
                    except Exception as e:
                        logger.warning(
                            f"Error reading metadata file {meta_file}: {str(e)}"
                        )

            visualizations.append(metadata)

    return visualizations


async def generate_visualization(
    request: GenerateVisualizationRequest, tracker, job_id: str, user_id: str
) -> Dict[str, Any]:
    """
    Generate a visualization based on the request parameters.

    Args:
        request: Visualization generation request
        tracker: Visualization tracker
        job_id: Job ID for tracking
        user_id: User ID

    Returns:
        Dictionary with generation results
    """
    try:
        # Get visualization directory
        viz_dir = os.path.join(
            tracker.reports_dir, "viz_" + datetime.now().strftime("%Y%m%d")
        )
        os.makedirs(viz_dir, exist_ok=True)

        # If request has a category, create subdirectory
        if request.category:
            category_dir = os.path.join(viz_dir, request.category)
            os.makedirs(category_dir, exist_ok=True)
            viz_path = category_dir
        else:
            viz_path = viz_dir

        # Create a safe filename
        safe_name = sanitize_filename(request.name)
        base_name = re.sub(r"\s+", "_", safe_name)
        extension = f".{request.format.value}"

        # Add timestamp to ensure uniqueness
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{base_name}_{timestamp}{extension}"
        file_path = os.path.join(viz_path, filename)

        # Generate visualization using tracker
        success = False

        # Update job status to generating
        job_status = {
            "job_id": job_id,
            "status": "generating",
            "progress": 0.3,
            "message": "Generating visualization...",
            "started_at": datetime.now(),
            "completed_at": None,
            "result": None,
        }

        # Store job status - in a real app, this would be in a database
        viz_jobs[job_id] = job_status

        # Choose generation method based on visualization type
        if request.type == VisualizationType.CHART:
            # Call specific chart generation method
            file_path = await tracker.generate_chart(
                file_path=file_path, parameters=request.parameters
            )
            success = file_path is not None
        elif request.type == VisualizationType.HEATMAP:
            # Call specific heatmap generation method
            file_path = await tracker.generate_heatmap(
                file_path=file_path, parameters=request.parameters
            )
            success = file_path is not None
        elif request.type == VisualizationType.DASHBOARD:
            # Call specific dashboard generation method
            file_path = await tracker.generate_dashboard(
                file_path=file_path, parameters=request.parameters
            )
            success = file_path is not None
        else:
            # Call generic visualization generation method
            file_path = await tracker.generate_visualization(
                viz_type=request.type.value,
                file_path=file_path,
                parameters=request.parameters,
            )
            success = file_path is not None

        # Update job status
        job_status["progress"] = 0.7

        if not success:
            # Update job status to failed
            job_status["status"] = "failed"
            job_status["progress"] = 1.0
            job_status["message"] = "Failed to generate visualization"
            job_status["completed_at"] = datetime.now()

            return {
                "success": False,
                "message": "Failed to generate visualization",
                "job_id": job_id,
            }

        # Create thumbnail
        thumbnail_path = create_thumbnail(file_path)

        # Create metadata file
        metadata = {
            "name": request.name,
            "description": request.description,
            "type": request.type.value,
            "format": request.format.value,
            "tags": request.tags,
            "category": request.category,
            "generated_by": "API",
            "generated_at": datetime.now().isoformat(),
            "user_id": user_id,
            "parameters": request.parameters,
            "thumbnail_path": (
                os.path.relpath(thumbnail_path, viz_dir) if thumbnail_path else None
            ),
        }

        meta_file = os.path.splitext(file_path)[0] + ".json"
        with open(meta_file, "w") as f:
            json.dump(metadata, f, indent=2)

        # Generate ID for the visualization
        viz_id = hashlib.md5(file_path.encode()).hexdigest()

        # Create API path
        if request.category:
            api_path = f"/api/v1/visualizations/{request.category}/{filename}"
        else:
            api_path = f"/api/v1/visualizations/{filename}"

        # Update job status to completed
        job_status["status"] = "completed"
        job_status["progress"] = 1.0
        job_status["message"] = "Visualization generated successfully"
        job_status["completed_at"] = datetime.now()
        job_status["result"] = {
            "visualization_id": viz_id,
            "path": api_path,
            "file_path": file_path,
        }

        return {
            "success": True,
            "message": "Visualization generated successfully",
            "job_id": job_id,
            "visualization_id": viz_id,
            "path": api_path,
            "file_path": file_path,
        }

    except Exception as e:
        logger.error(f"Error generating visualization: {str(e)}")

        # Update job status to failed
        job_status = viz_jobs.get(job_id)
        if job_status:
            job_status["status"] = "failed"
            job_status["progress"] = 1.0
            job_status["message"] = f"Error: {str(e)}"
            job_status["completed_at"] = datetime.now()

        return {
            "success": False,
            "message": f"Error generating visualization: {str(e)}",
            "job_id": job_id,
        }


# Storage for visualization generation jobs
# In a real application, this would be in a database
viz_jobs = {}


# Create router
router = APIRouter(tags=["visualizations"])


@router.get("/visualizations", response_model=PaginatedResponse[VisualizationListItem])
async def list_visualizations(
    request: Request,
    response: Response,
    type: Optional[VisualizationType] = Query(
        None, description="Filter by visualization type"
    ),
    format: Optional[VisualizationFormat] = Query(
        None, description="Filter by visualization format"
    ),
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search by name or description"),
    created_after: Optional[datetime] = Query(
        None, description="Filter by creation date"
    ),
    include_metrics: bool = Query(False, description="Include metric data in response"),
    refresh_cache: bool = Query(False, description="Force refresh cache"),
    pagination: PaginationParams = Depends(get_pagination),
    token: Optional[str] = Depends(get_auth_token),
):
    """
    List available visualizations with filtering and pagination.

    Args:
        request: FastAPI request object
        response: FastAPI response object
        type: Filter by visualization type
        format: Filter by visualization format
        category: Filter by category
        search: Search term for name or description
        created_after: Filter by creation date
        include_metrics: Include metric data in response
        refresh_cache: Force refresh cache
        pagination: Pagination parameters
        token: Optional authentication token

    Returns:
        Paginated list of visualizations
    """
    # Start telemetry span
    with telemetry.start_span("list_visualizations"):
        try:
            # Check if user is authenticated
            user = None
            if token:
                try:
                    user = authenticate_user(token)
                    # Check user permissions if needed
                    check_permission(user, "visualizations:list")
                except:
                    # Continue without authentication
                    pass

            # Get tracker from request state
            tracker = request.app.state.tracker

            if not tracker:
                raise HTTPException(
                    status_code=503, detail="Visualization service unavailable"
                )

            # Check if tracker has combined report (optional)
            if hasattr(tracker, "combined_report") and not tracker.combined_report:
                # Continue anyway, maybe there are still visualizations available
                logger.warning("No combined report available in tracker")

            # Create cache key if caching is enabled
            cache_key = None
            if not refresh_cache:
                # Create deterministic cache key based on parameters
                params = {
                    "type": type.value if type else None,
                    "format": format.value if format else None,
                    "category": category,
                    "search": search,
                    "created_after": (
                        created_after.isoformat() if created_after else None
                    ),
                    "include_metrics": include_metrics,
                    "page": pagination.page,
                    "page_size": pagination.page_size,
                    "sort_by": pagination.sort_by,
                    "sort_dir": pagination.sort_dir,
                }

                # Add user ID if authenticated
                if user:
                    params["user_id"] = user["sub"]

                # Create cache key
                cache_str = json.dumps(params, sort_keys=True)
                cache_key = (
                    f"visualizations_list_{hashlib.md5(cache_str.encode()).hexdigest()}"
                )

                # Check cache
                cached_response = get_cached_response(cache_key)
                if cached_response:
                    # Set cache hit header
                    response.headers["X-Cache"] = "HIT"
                    return PaginatedResponse(**cached_response)

            # Get visualization directory
            reports_dir = getattr(tracker, "reports_dir", None)
            if not reports_dir:
                raise HTTPException(
                    status_code=503, detail="Visualization directory not configured"
                )

            viz_dir = os.path.join(
                reports_dir, "viz_" + datetime.now().strftime("%Y%m%d")
            )

            # Check if directory exists
            if not os.path.exists(viz_dir):
                # Try to generate visualizations if they don't exist
                try:
                    viz_dir = tracker.generate_visualizations()
                except Exception as e:
                    logger.error(f"Error generating visualizations: {str(e)}")

                # Check again if directory exists
                if not viz_dir or not os.path.exists(viz_dir):
                    # Return empty result instead of error
                    empty_response = PaginatedResponse(
                        items=[],
                        page=pagination.page,
                        page_size=pagination.page_size,
                        total_count=0,
                        total_pages=0,
                        has_more=False,
                    )

                    # Cache empty response
                    if cache_key:
                        cache_response(
                            cache_key, empty_response.dict(), ttl_seconds=60
                        )  # Short TTL for empty results

                    return empty_response

            # Get base path for visualization URLs
            base_path = "/api/v1/visualizations"

            # Get visualizations with filtering
            visualizations = get_visualizations_from_directory(
                directory=viz_dir,
                base_path=base_path,
                filter_type=type,
                filter_format=format,
                filter_category=category,
                search_term=search,
                created_after=created_after,
                include_metrics=include_metrics,
            )

            # Apply sorting
            sort_by = pagination.sort_by or "created_at"
            sort_desc = pagination.sort_dir == "desc"

            visualizations.sort(
                key=lambda x: x.get(sort_by) if sort_by in x else x.get("created_at"),
                reverse=sort_desc,
            )

            # Get total count
            total_count = len(visualizations)

            # Apply pagination
            start = (pagination.page - 1) * pagination.page_size
            end = start + pagination.page_size
            paginated_visualizations = visualizations[start:end]

            # Convert to response model
            items = [VisualizationListItem(**viz) for viz in paginated_visualizations]

            # Create paginated response
            response_data = PaginatedResponse(
                items=items,
                page=pagination.page,
                page_size=pagination.page_size,
                total_count=total_count,
                total_pages=(total_count + pagination.page_size - 1)
                // pagination.page_size,
                has_more=end < total_count,
            )

            # Cache response if caching is enabled
            if cache_key:
                cache_response(
                    cache_key, response_data.dict(), ttl_seconds=CACHE_TTL_SECONDS
                )
                response.headers["X-Cache"] = "MISS"

            return response_data

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error listing visualizations: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error listing visualizations: {str(e)}",
            )


@router.get("/visualizations/{visualization_id}", response_model=VisualizationResponse)
async def get_visualization_metadata(
    request: Request,
    visualization_id: str = Path(..., description="ID of the visualization"),
    token: Optional[str] = Depends(get_auth_token),
):
    """
    Get detailed metadata for a visualization.

    Args:
        visualization_id: ID of the visualization
        token: Optional authentication token

    Returns:
        Visualization metadata
    """
    # Check if user is authenticated
    if token:
        try:
            user = authenticate_user(token)
            # Check user permissions if needed
            check_permission(user, "visualizations:read")
        except:
            # Continue without authentication
            pass

    try:
        # Get all visualizations to find the one with matching ID
        # In a real application, this would be a database lookup

        # For simplicity, we'll scan the visualization directory
        # This is inefficient for large sets of visualizations
        # A real implementation would use a database or index

        # First, get the tracker and visualization directory
        tracker = request.app.state.tracker

        if not tracker:
            raise HTTPException(
                status_code=503, detail="Visualization service unavailable"
            )

        reports_dir = getattr(tracker, "reports_dir", None)
        if not reports_dir:
            raise HTTPException(
                status_code=503, detail="Visualization directory not configured"
            )

        viz_dir = os.path.join(reports_dir, "viz_" + datetime.now().strftime("%Y%m%d"))

        if not os.path.exists(viz_dir):
            raise HTTPException(
                status_code=404, detail="Visualization directory not found"
            )

        # Get base path for visualization URLs
        base_path = "/api/v1/visualizations"

        # Get all visualizations
        all_visualizations = get_visualizations_from_directory(
            directory=viz_dir, base_path=base_path, include_metrics=True
        )

        # Find the visualization with matching ID
        visualization = None
        for viz in all_visualizations:
            if viz.get("id") == visualization_id:
                visualization = viz
                break

        if not visualization:
            raise HTTPException(
                status_code=404,
                detail=f"Visualization with ID {visualization_id} not found",
            )

        # Create metadata response
        metadata = VisualizationMetadata(**visualization)

        # Find related visualizations (same category or type)
        related = []

        for viz in all_visualizations:
            # Skip the current visualization
            if viz.get("id") == visualization_id:
                continue

            # Check if related by category or type
            if (
                visualization.get("category")
                and viz.get("category") == visualization.get("category")
            ) or (
                visualization.get("type")
                and viz.get("type") == visualization.get("type")
            ):
                related.append(VisualizationListItem(**viz))

                # Limit to 5 related visualizations
                if len(related) >= 5:
                    break

        # Create response
        return VisualizationResponse(metadata=metadata, related_visualizations=related)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting visualization metadata: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting visualization metadata: {str(e)}",
        )


@router.get("/visualizations/file/{filename:path}")
async def get_visualization_file(
    request: Request,
    filename: str = Path(..., description="Visualization filename"),
    token: Optional[str] = Depends(get_auth_token),
):
    """
    Get a specific visualization file.

    Args:
        request: FastAPI request object
        filename: Visualization filename (can include path)
        token: Optional authentication token

    Returns:
        Visualization file
    """
    # Check if user is authenticated
    if token:
        try:
            user = authenticate_user(token)
            # Check user permissions if needed
            check_permission(user, "visualizations:read")
        except:
            # Continue without authentication
            pass

    try:
        # Get tracker from request state
        tracker = request.app.state.tracker

        if not tracker:
            raise HTTPException(
                status_code=503, detail="Visualization service unavailable"
            )

        # Get visualization directory
        reports_dir = getattr(tracker, "reports_dir", None)
        if not reports_dir:
            raise HTTPException(
                status_code=503, detail="Visualization directory not configured"
            )

        viz_dir = os.path.join(reports_dir, "viz_" + datetime.now().strftime("%Y%m%d"))

        if not os.path.exists(viz_dir):
            raise HTTPException(
                status_code=404, detail="Visualization directory not found"
            )

        # Sanitize filename to prevent path traversal
        safe_filename = sanitize_filename(filename)

        # Check if path is trying to navigate outside the viz directory
        if ".." in filename:
            raise HTTPException(status_code=403, detail="Invalid file path")

        # Construct the full file path
        file_path = os.path.join(viz_dir, filename)

        # Check if file exists
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            raise HTTPException(
                status_code=404, detail=f"Visualization '{filename}' not found"
            )

        # Check if file type is allowed
        if not validate_file_type(file_path):
            raise HTTPException(status_code=403, detail=f"File type not allowed")

        # Set content type based on file extension
        content_type, _ = mimetypes.guess_type(file_path)
        if not content_type:
            content_type = "application/octet-stream"

        # Return file
        return FileResponse(
            path=file_path,
            media_type=content_type,
            filename=os.path.basename(file_path),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting visualization file: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting visualization file: {str(e)}",
        )


@router.get("/visualizations/categories", response_model=List[str])
async def get_visualization_categories(
    request: Request, token: Optional[str] = Depends(get_auth_token)
):
    """
    Get available visualization categories.

    Args:
        request: FastAPI request object
        token: Optional authentication token

    Returns:
        List of available categories
    """
    # Check if user is authenticated
    if token:
        try:
            user = authenticate_user(token)
            # Check user permissions if needed
            check_permission(user, "visualizations:list")
        except:
            # Continue without authentication
            pass

    try:
        # Get tracker from request state
        tracker = request.app.state.tracker

        if not tracker:
            raise HTTPException(
                status_code=503, detail="Visualization service unavailable"
            )

        # Get visualization directory
        reports_dir = getattr(tracker, "reports_dir", None)
        if not reports_dir:
            raise HTTPException(
                status_code=503, detail="Visualization directory not configured"
            )

        viz_dir = os.path.join(reports_dir, "viz_" + datetime.now().strftime("%Y%m%d"))

        if not os.path.exists(viz_dir):
            # Return empty list if directory doesn't exist
            return []

        # Get categories (subdirectories)
        categories = []

        for item in os.listdir(viz_dir):
            item_path = os.path.join(viz_dir, item)
            if os.path.isdir(item_path) and item != "thumbnails":
                categories.append(item)

        return sorted(categories)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting visualization categories: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting visualization categories: {str(e)}",
        )


@router.post("/visualizations/generate", response_model=GenerateVisualizationResponse)
async def generate_visualization_request(
    request: Request,
    generation_request: GenerateVisualizationRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(get_auth_token),
):
    """
    Request generation of a new visualization.

    Args:
        request: FastAPI request object
        generation_request: Visualization generation request
        background_tasks: FastAPI background tasks
        token: Authentication token

    Returns:
        Generation job information
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "visualizations:generate")

    try:
        # Get tracker from request state
        tracker = request.app.state.tracker

        if not tracker:
            raise HTTPException(
                status_code=503, detail="Visualization service unavailable"
            )

        # Generate job ID
        job_id = str(uuid.uuid4())

        # Initialize job status
        viz_jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "progress": 0.0,
            "message": "Visualization generation queued",
            "started_at": datetime.now(),
            "completed_at": None,
            "result": None,
        }

        # Start generation in background
        background_tasks.add_task(
            generate_visualization,
            request=generation_request,
            tracker=tracker,
            job_id=job_id,
            user_id=user["sub"],
        )

        # Return job ID
        return GenerateVisualizationResponse(
            job_id=job_id,
            status="queued",
            message="Visualization generation has been queued",
        )

    except Exception as e:
        logger.error(f"Error requesting visualization generation: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error requesting visualization generation: {str(e)}",
        )


@router.get("/visualizations/jobs/{job_id}", response_model=VisualizationJobStatus)
async def get_visualization_job_status(
    job_id: str = Path(..., description="Job ID"), token: str = Depends(get_auth_token)
):
    """
    Get status of a visualization generation job.

    Args:
        job_id: Job ID
        token: Authentication token

    Returns:
        Job status information
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "visualizations:read")

    try:
        # Check if job exists
        if job_id not in viz_jobs:
            raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

        # Get job status
        job_status = viz_jobs[job_id]

        # Return job status
        return VisualizationJobStatus(**job_status)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting visualization job status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting visualization job status: {str(e)}",
        )


@router.delete(
    "/visualizations/{visualization_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_visualization(
    request: Request,
    visualization_id: str = Path(..., description="ID of the visualization"),
    token: str = Depends(get_auth_token),
):
    """
    Delete a visualization.

    Args:
        request: FastAPI request object
        visualization_id: ID of the visualization
        token: Authentication token

    Returns:
        No content on success
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "visualizations:delete")

    try:
        # Get tracker from request state
        tracker = request.app.state.tracker

        if not tracker:
            raise HTTPException(
                status_code=503, detail="Visualization service unavailable"
            )

        # Get visualization directory
        reports_dir = getattr(tracker, "reports_dir", None)
        if not reports_dir:
            raise HTTPException(
                status_code=503, detail="Visualization directory not configured"
            )

        viz_dir = os.path.join(reports_dir, "viz_" + datetime.now().strftime("%Y%m%d"))

        if not os.path.exists(viz_dir):
            raise HTTPException(
                status_code=404, detail="Visualization directory not found"
            )

        # Get base path for visualization URLs
        base_path = "/api/v1/visualizations"

        # Get all visualizations
        all_visualizations = get_visualizations_from_directory(
            directory=viz_dir, base_path=base_path
        )

        # Find the visualization with matching ID
        visualization = None
        for viz in all_visualizations:
            if viz.get("id") == visualization_id:
                visualization = viz
                break

        if not visualization:
            raise HTTPException(
                status_code=404,
                detail=f"Visualization with ID {visualization_id} not found",
            )

        # Get the file path
        # Convert API path to file path
        api_path = visualization.get("path")
        if not api_path:
            raise HTTPException(
                status_code=404, detail="Visualization file path not found"
            )

        # Extract filename and optional category
        path_parts = api_path.split("/")
        filename = path_parts[-1]

        # Determine file path
        if len(path_parts) > 4:  # Has category
            category = path_parts[-2]
            file_path = os.path.join(viz_dir, category, filename)
        else:
            file_path = os.path.join(viz_dir, filename)

        # Check if file exists
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Visualization file not found")

        # Delete the file
        os.remove(file_path)

        # Delete metadata file if it exists
        meta_file = os.path.splitext(file_path)[0] + ".json"
        if os.path.exists(meta_file):
            os.remove(meta_file)

        # Delete thumbnail if it exists
        if visualization.get("thumbnail_path"):
            # Convert API thumbnail path to file path
            thumb_api_path = visualization.get("thumbnail_path")
            thumb_parts = thumb_api_path.split("/")
            thumb_filename = thumb_parts[-1]

            # Determine thumbnail path
            if len(path_parts) > 4:  # Has category
                category = path_parts[-2]
                thumb_path = os.path.join(
                    viz_dir, category, "thumbnails", thumb_filename
                )
            else:
                thumb_path = os.path.join(viz_dir, "thumbnails", thumb_filename)

            # Delete thumbnail if it exists
            if os.path.exists(thumb_path):
                os.remove(thumb_path)

        # Return no content
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting visualization: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting visualization: {str(e)}",
        )
