"""
Sentiment analysis API routes.

This module contains routes for the sentiment analysis API, providing text sentiment
analysis with various levels of detail including basic sentiment scoring,
emotion detection, and aspect-based sentiment analysis.
"""

import asyncio
import hashlib
import time
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Any, Dict, List, Optional

from core.models.requests import (
    AspectSentimentRequest,
    BatchSentimentRequest,
    SentimentAnalysisType,
    SentimentRequest,
)
from core.models.responses import (
    BatchSentimentResponse,
    ErrorResponse,
    ModelInfoResponse,
    SentimentResponse,
)
from core.services.sentiment import (
    SentimentModelInfo,
    SentimentService,
    get_sentiment_service,
)
from core.telemetry.telemetry import telemetry
from core.utils.text import detect_language, truncate_text
from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse
from framework.common.exceptions.validation import (
    ModelNotAvailableError,
    RateLimitExceededError,
    ValidationError,
)
from framework.middleware.auth import (
    authenticate_user,
    cache_response,
    check_permission,
    get_auth_token,
    get_cached_response,
)
from loguru import logger
from pydantic import BaseModel, Field, validator

# Configure logger
logger = logger.opt(colors=True).getLogger("sentiment_api")

# Constants
MAX_TEXT_LENGTH = 10000
MAX_BATCH_SIZE = 100
DEFAULT_CACHE_TTL = 3600  # 1 hour cache for sentiment results

# Rate limiting state - in production, use Redis or other distributed cache
rate_limit_data = {}


class LanguageOption(str, Enum):
    """Supported language options for sentiment analysis."""

    AUTO = "auto"
    EN = "en"
    ES = "es"
    FR = "fr"
    DE = "de"
    IT = "it"
    PT = "pt"
    NL = "nl"
    RU = "ru"
    ZH = "zh"
    JA = "ja"
    KO = "ko"
    AR = "ar"


class SortOrder(str, Enum):
    """Sort order options for batch results."""

    ASCENDING = "asc"
    DESCENDING = "desc"


class SentimentStatisticsResponse(BaseModel):
    """Response model for sentiment statistics."""

    total_analyzed: int
    sentiment_distribution: Dict[str, int]
    average_confidence: float
    language_distribution: Dict[str, int]
    processing_time_ms: float


class SentimentHistoryItem(BaseModel):
    """Historical sentiment analysis record."""

    id: str
    text_preview: str
    timestamp: datetime
    sentiment: str
    confidence: float
    language: str


# Create router
router = APIRouter(
    prefix="/sentiment",
    tags=["sentiment"],
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
        status.HTTP_429_TOO_MANY_REQUESTS: {"model": ErrorResponse},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponse},
    },
)


# Rate limiting decorator
def rate_limit(max_requests: int = 10, window_seconds: int = 60):
    """
    Rate limiting decorator for endpoints.

    Args:
        max_requests: Maximum number of requests allowed in the window
        window_seconds: Time window in seconds
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            # Get client IP for rate limiting
            client_ip = request.client.host

            # Get current timestamp
            now = time.time()

            # Get or initialize client's request history
            if client_ip not in rate_limit_data:
                rate_limit_data[client_ip] = []

            # Remove requests outside the window
            rate_limit_data[client_ip] = [
                ts for ts in rate_limit_data[client_ip] if now - ts < window_seconds
            ]

            # Check if rate limit is exceeded
            if len(rate_limit_data[client_ip]) >= max_requests:
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")

                # Calculate retry-after time
                oldest_request = min(rate_limit_data[client_ip])
                retry_after = int(window_seconds - (now - oldest_request))

                # Raise rate limit error
                raise RateLimitExceededError(
                    message=f"Rate limit exceeded. Try again in {retry_after} seconds.",
                    retry_after=retry_after,
                )

            # Record this request
            rate_limit_data[client_ip].append(now)

            # Call the original function
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator


# Helper function for creating cache keys
def create_cache_key(text: str, analysis_type: str, language: str) -> str:
    """Create a hash-based cache key for sentiment analysis."""
    key_data = f"{text}|{analysis_type}|{language}"
    return hashlib.md5(key_data.encode()).hexdigest()


# Error handling middleware
@router.middleware("http")
async def sentiment_error_handler(request: Request, call_next):
    """Handle specific errors from the sentiment analysis API."""
    try:
        return await call_next(request)

    except ValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "error": e.message},
        )

    except RateLimitExceededError as e:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"success": False, "error": e.message},
            headers={"Retry-After": str(e.retry_after)},
        )

    except ModelNotAvailableError as e:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"success": False, "error": e.message},
        )

    except Exception as e:
        logger.error(f"Unhandled error in sentiment API: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "error": "Internal server error"},
        )


# Routes
@router.post("/analyze", response_model=SentimentResponse)
@rate_limit(max_requests=20, window_seconds=60)
async def analyze_sentiment(
    request: Request,
    sentiment_request: SentimentRequest,
    response: Response,
    service: SentimentService = Depends(get_sentiment_service),
    x_request_id: Optional[str] = Header(None),
    use_cache: bool = Query(
        True, description="Whether to use cached results if available"
    ),
):
    """
    Analyze sentiment of text.

    Performs sentiment analysis on the provided text and returns
    the detected sentiment label, confidence score, and optional
    detailed scores and emotion detection.

    - **text**: Text to analyze
    - **analysis_type**: Type of analysis (BASIC, DETAILED, EMOTION)
    - **language**: Language code (ISO 639-1) or "auto" for auto-detection
    - **use_cache**: Whether to use cached results

    Returns a SentimentResponse with the analysis results.
    """
    # Start telemetry span
    with telemetry.start_span("analyze_sentiment"):
        # Validate text
        if not sentiment_request.text.strip():
            raise ValidationError(message="Text cannot be empty")

        # Check text length
        if len(sentiment_request.text) > MAX_TEXT_LENGTH:
            raise ValidationError(
                message=f"Text exceeds maximum length of {MAX_TEXT_LENGTH} characters"
            )

        # Create cache key
        cache_key = None
        if use_cache:
            cache_key = create_cache_key(
                sentiment_request.text,
                sentiment_request.analysis_type.value,
                sentiment_request.language or "auto",
            )
            cached_result = get_cached_response(cache_key)
            if cached_result:
                # Set cache hit header
                response.headers["X-Cache"] = "HIT"
                return SentimentResponse(success=True, data=cached_result)

        # Auto-detect language if set to auto
        if sentiment_request.language == "auto" or not sentiment_request.language:
            detected_language = detect_language(sentiment_request.text)
            sentiment_request.language = detected_language

        # Track start time for performance measurement
        start_time = time.time()

        # Analyze sentiment
        try:
            result = await service.analyze_sentiment(
                text=sentiment_request.text,
                analysis_type=sentiment_request.analysis_type,
                language=sentiment_request.language,
                request_id=x_request_id,
            )

            # Calculate processing time
            processing_time = time.time() - start_time

            # Add processing time to result
            result["processing_time_ms"] = round(processing_time * 1000, 2)

            # Log successful analysis
            logger.info(
                f"Sentiment analysis completed: {result['sentiment']} "
                f"({result['confidence']:.2f}) for text of length {len(sentiment_request.text)} "
                f"in {processing_time:.3f}s"
            )

            # Cache result if caching is enabled
            if use_cache and cache_key:
                cache_response(cache_key, result, ttl_seconds=DEFAULT_CACHE_TTL)
                response.headers["X-Cache"] = "MISS"

            # Set custom headers
            response.headers["X-Processing-Time"] = str(round(processing_time * 1000))

            return SentimentResponse(
                success=True,
                data=result,
            )

        except Exception as e:
            logger.error(f"Error during sentiment analysis: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error during sentiment analysis: {str(e)}",
            )


@router.post("/batch", response_model=BatchSentimentResponse)
@rate_limit(max_requests=5, window_seconds=60)
async def analyze_batch(
    request: Request,
    batch_request: BatchSentimentRequest,
    service: SentimentService = Depends(get_sentiment_service),
    x_request_id: Optional[str] = Header(None),
    sort_by: Optional[str] = Query(None, description="Field to sort results by"),
    sort_order: SortOrder = Query(SortOrder.DESCENDING, description="Sort order"),
    use_cache: bool = Query(
        True, description="Whether to use cached results if available"
    ),
):
    """
    Analyze sentiment of multiple texts.

    Performs sentiment analysis on multiple texts and returns
    results for each text along with summary statistics.

    - **texts**: List of texts to analyze
    - **analysis_type**: Type of analysis (BASIC, DETAILED, EMOTION)
    - **language**: Language code (ISO 639-1) or "auto" for auto-detection
    - **sort_by**: Optional field to sort results by
    - **sort_order**: Sort order (asc or desc)
    - **use_cache**: Whether to use cached results

    Returns a BatchSentimentResponse with analysis results for each text.
    """
    # Start telemetry span
    with telemetry.start_span("analyze_batch"):
        # Validate texts
        if not batch_request.texts:
            raise ValidationError(message="No texts provided for analysis")

        if any(not text.strip() for text in batch_request.texts):
            raise ValidationError(message="Texts cannot be empty")

        # Check batch size
        if len(batch_request.texts) > MAX_BATCH_SIZE:
            raise ValidationError(
                message=f"Batch size exceeds maximum of {MAX_BATCH_SIZE} texts"
            )

        # Track start time for performance measurement
        start_time = time.time()

        # Process batch
        try:
            # If caching is enabled, check individual texts for cache hits
            results = []

            if use_cache:
                # Check cache for each text
                for text in batch_request.texts:
                    cache_key = create_cache_key(
                        text,
                        batch_request.analysis_type.value,
                        batch_request.language or "auto",
                    )

                    cached_result = get_cached_response(cache_key)
                    if cached_result:
                        results.append(cached_result)
                    else:
                        # Mark for processing
                        results.append(None)

                # Get indices of texts that need processing
                process_indices = [i for i, r in enumerate(results) if r is None]
                process_texts = [batch_request.texts[i] for i in process_indices]

                # Only process texts that weren't in cache
                if process_texts:
                    processed_results = await service.analyze_batch(
                        texts=process_texts,
                        analysis_type=batch_request.analysis_type,
                        language=batch_request.language,
                        request_id=x_request_id,
                    )

                    # Cache individual results
                    for i, result in enumerate(processed_results.get("results", [])):
                        original_idx = process_indices[i]
                        text = batch_request.texts[original_idx]
                        results[original_idx] = result

                        # Cache this result
                        cache_key = create_cache_key(
                            text,
                            batch_request.analysis_type.value,
                            batch_request.language or "auto",
                        )
                        cache_response(cache_key, result, ttl_seconds=DEFAULT_CACHE_TTL)

                # Reconstruct batch results
                batch_result = {
                    "results": results,
                    "summary": (
                        processed_results.get("summary", {})
                        if process_texts
                        else {
                            "total": len(batch_request.texts),
                            "positive": sum(
                                1 for r in results if r.get("sentiment") == "positive"
                            ),
                            "negative": sum(
                                1 for r in results if r.get("sentiment") == "negative"
                            ),
                            "neutral": sum(
                                1 for r in results if r.get("sentiment") == "neutral"
                            ),
                            "processing_time_ms": 0,
                        }
                    ),
                }

            else:
                # Process entire batch without caching
                batch_result = await service.analyze_batch(
                    texts=batch_request.texts,
                    analysis_type=batch_request.analysis_type,
                    language=batch_request.language,
                    request_id=x_request_id,
                )

            # Sort results if requested
            if sort_by and "results" in batch_result:
                reverse = sort_order == SortOrder.DESCENDING
                batch_result["results"].sort(
                    key=lambda x: (
                        x.get(sort_by, 0)
                        if sort_by != "sentiment"
                        else {"negative": 0, "neutral": 1, "positive": 2}.get(
                            x.get("sentiment", ""), -1
                        )
                    ),
                    reverse=reverse,
                )

            # Calculate processing time
            processing_time = time.time() - start_time
            if "summary" in batch_result:
                batch_result["summary"]["processing_time_ms"] = round(
                    processing_time * 1000, 2
                )

            # Log successful batch analysis
            logger.info(
                f"Batch sentiment analysis completed for {len(batch_request.texts)} texts "
                f"in {processing_time:.3f}s"
            )

            return BatchSentimentResponse(
                success=True,
                data=batch_result,
            )

        except Exception as e:
            logger.error(f"Error during batch sentiment analysis: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error during batch sentiment analysis: {str(e)}",
            )


@router.get("/analyze", response_model=SentimentResponse)
@rate_limit(max_requests=30, window_seconds=60)
async def analyze_sentiment_get(
    request: Request,
    response: Response,
    text: str = Query(..., description="Text to analyze"),
    analysis_type: SentimentAnalysisType = Query(
        SentimentAnalysisType.BASIC,
        description="Type of sentiment analysis to perform",
    ),
    language: LanguageOption = Query(
        LanguageOption.AUTO,
        description="Language code (ISO 639-1) or auto for detection",
    ),
    service: SentimentService = Depends(get_sentiment_service),
    x_request_id: Optional[str] = Header(None),
    use_cache: bool = Query(
        True, description="Whether to use cached results if available"
    ),
):
    """
    Analyze sentiment of text using GET request.

    Convenience endpoint for simple usage via GET requests.
    For more complex scenarios, use the POST endpoint.

    - **text**: Text to analyze
    - **analysis_type**: Type of analysis (BASIC, DETAILED, EMOTION)
    - **language**: Language code or "auto" for auto-detection
    - **use_cache**: Whether to use cached results

    Returns a SentimentResponse with the analysis results.
    """
    # Validate text
    if not text.strip():
        raise ValidationError(message="Text cannot be empty")

    # Check text length
    if len(text) > MAX_TEXT_LENGTH:
        raise ValidationError(
            message=f"Text exceeds maximum length of {MAX_TEXT_LENGTH} characters"
        )

    # Create cache key
    cache_key = None
    if use_cache:
        cache_key = create_cache_key(text, analysis_type.value, language)
        cached_result = get_cached_response(cache_key)
        if cached_result:
            # Set cache hit header
            response.headers["X-Cache"] = "HIT"
            return SentimentResponse(success=True, data=cached_result)

    # Handle auto language detection
    lang = language
    if language == LanguageOption.AUTO:
        lang = detect_language(text)

    # Track start time for performance measurement
    start_time = time.time()

    # Analyze sentiment
    try:
        result = await service.analyze_sentiment(
            text=text,
            analysis_type=analysis_type,
            language=lang,
            request_id=x_request_id,
        )

        # Calculate processing time
        processing_time = time.time() - start_time

        # Add processing time to result
        result["processing_time_ms"] = round(processing_time * 1000, 2)

        # Cache result if caching is enabled
        if use_cache and cache_key:
            cache_response(cache_key, result, ttl_seconds=DEFAULT_CACHE_TTL)
            response.headers["X-Cache"] = "MISS"

        # Set custom headers
        response.headers["X-Processing-Time"] = str(round(processing_time * 1000))

        return SentimentResponse(
            success=True,
            data=result,
        )

    except Exception as e:
        logger.error(f"Error during sentiment analysis: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during sentiment analysis: {str(e)}",
        )


@router.post("/analyze/aspects", response_model=SentimentResponse)
@rate_limit(max_requests=10, window_seconds=60)
async def analyze_aspect_sentiment(
    request: Request,
    aspect_request: AspectSentimentRequest,
    service: SentimentService = Depends(get_sentiment_service),
    x_request_id: Optional[str] = Header(None),
):
    """
    Analyze aspect-based sentiment in text.

    Performs sentiment analysis for specific aspects or topics within the text.
    Useful for analyzing reviews, feedback, or surveys with multiple topics.

    - **text**: Text to analyze
    - **aspects**: List of aspects/topics to analyze
    - **language**: Language code or "auto" for auto-detection

    Returns a SentimentResponse with aspect-based sentiment analysis.
    """
    # Start telemetry span
    with telemetry.start_span("analyze_aspect_sentiment"):
        # Validate text
        if not aspect_request.text.strip():
            raise ValidationError(message="Text cannot be empty")

        # Validate aspects
        if not aspect_request.aspects:
            raise ValidationError(message="No aspects provided for analysis")

        # Check text length
        if len(aspect_request.text) > MAX_TEXT_LENGTH:
            raise ValidationError(
                message=f"Text exceeds maximum length of {MAX_TEXT_LENGTH} characters"
            )

        # Track start time for performance measurement
        start_time = time.time()

        # Auto-detect language if set to auto
        if aspect_request.language == "auto" or not aspect_request.language:
            detected_language = detect_language(aspect_request.text)
            aspect_request.language = detected_language

        # Analyze aspect sentiment
        try:
            result = await service.analyze_aspect_sentiment(
                text=aspect_request.text,
                aspects=aspect_request.aspects,
                language=aspect_request.language,
                request_id=x_request_id,
            )

            # Calculate processing time
            processing_time = time.time() - start_time

            # Add processing time to result
            result["processing_time_ms"] = round(processing_time * 1000, 2)

            # Log successful analysis
            logger.info(
                f"Aspect sentiment analysis completed for {len(aspect_request.aspects)} aspects "
                f"in text of length {len(aspect_request.text)} in {processing_time:.3f}s"
            )

            return SentimentResponse(
                success=True,
                data=result,
            )

        except Exception as e:
            logger.error(f"Error during aspect sentiment analysis: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error during aspect sentiment analysis: {str(e)}",
            )


@router.get("/models", response_model=List[ModelInfoResponse])
async def list_sentiment_models(
    token: str = Depends(get_auth_token),
    service: SentimentService = Depends(get_sentiment_service),
):
    """
    List available sentiment analysis models.

    Returns information about all available sentiment analysis models
    including their capabilities, languages, and status.

    Requires authentication.
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "sentiment:read")

    try:
        # Get models from service
        models = await service.list_models()

        return models

    except Exception as e:
        logger.error(f"Error listing sentiment models: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing sentiment models: {str(e)}",
        )


@router.get("/stats", response_model=SentimentStatisticsResponse)
async def get_sentiment_statistics(
    token: str = Depends(get_auth_token),
    service: SentimentService = Depends(get_sentiment_service),
    days: int = Query(
        7, ge=1, le=30, description="Number of days to include in statistics"
    ),
):
    """
    Get sentiment analysis usage statistics.

    Returns statistics about sentiment analysis usage including
    sentiment distribution, average confidence, and language distribution.

    Requires authentication.

    - **days**: Number of days to include in statistics (1-30)
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "sentiment:stats")

    try:
        # Get statistics from service
        stats = await service.get_statistics(user_id=user["sub"], days=days)

        return stats

    except Exception as e:
        logger.error(f"Error getting sentiment statistics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting sentiment statistics: {str(e)}",
        )


@router.get("/history", response_model=List[SentimentHistoryItem])
async def get_sentiment_history(
    token: str = Depends(get_auth_token),
    service: SentimentService = Depends(get_sentiment_service),
    limit: int = Query(
        20, ge=1, le=100, description="Maximum number of records to return"
    ),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """
    Get user's sentiment analysis history.

    Returns the user's recent sentiment analysis requests with
    text previews, results, and timestamps.

    Requires authentication.

    - **limit**: Maximum number of records to return
    - **offset**: Offset for pagination
    """
    # Authenticate user
    user = authenticate_user(token)

    # Check user permissions
    check_permission(user, "sentiment:history")

    try:
        # Get history from service
        history = await service.get_user_history(
            user_id=user["sub"], limit=limit, offset=offset
        )

        return history

    except Exception as e:
        logger.error(f"Error getting sentiment history: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting sentiment history: {str(e)}",
        )
