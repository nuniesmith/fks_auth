"""
Background tasks for CLI commands.

This module provides asynchronous task handlers for CLI commands that can be
executed in the background using FastAPI's BackgroundTasks.
"""

from api.routes.v1.cli.job_manager import update_job_failure, update_job_success
from api.routes.v1.cli.utils import safe_notify  # Using the simplified import
from cli.commands.analyze import analyze_sentiment
from cli.commands.fetch import FetchCommand
from cli.commands.report import ReportCommand
from cli.commands.visualize import visualize_data
from fastapi import BackgroundTasks
from loguru import logger


async def run_fetch_background(job_id: str, save: bool, source: str):
    """Background task for fetching data.

    Args:
        job_id: The unique identifier for the background job
        save: Whether to save the fetched data to disk
        source: The data source to fetch from
    """
    safe_notify(f"Starting fetch operation from {source}...", type="ongoing", timeout=0)
    try:
        command = FetchCommand()
        result = command.fetch_data(save=save, source=source)

        if result:
            serializable_result = {
                "crypto_data_count": (
                    len(result.get("crypto_data", {}).get("data", []))
                    if "crypto_data" in result
                    else 0
                ),
                "forex_data_count": (
                    len(result.get("forex_data", {})) if "forex_data" in result else 0
                ),
            }
            update_job_success(job_id, serializable_result)
            safe_notify(f"Successfully fetched data from {source}", type="positive")
        else:
            update_job_failure(job_id, "Failed to fetch data")
            safe_notify(f"Failed to fetch data from {source}", type="negative")
    except Exception as e:
        logger.exception(f"Error in background fetch task: {e}")
        update_job_failure(job_id, str(e))
        safe_notify(f"Error fetching data: {str(e)}", type="negative")


async def run_analyze_background(job_id: str, source: str):
    """Background task for analyzing sentiment.

    Args:
        job_id: The unique identifier for the background job
        source: The data source to analyze
    """
    safe_notify("Starting sentiment analysis...", type="ongoing", timeout=0)
    try:
        result = analyze_sentiment(source=source)

        if result and "report" in result:
            summary = {
                "overall_sentiment": result["report"].get("overall_sentiment", {}),
                "report_file": result.get("report_file", None),
                "visualization_dir": result.get("visualization_dir", None),
            }
            update_job_success(job_id, summary)
            safe_notify("Sentiment analysis completed successfully", type="positive")
        else:
            update_job_failure(job_id, "Failed to analyze sentiment data")
            safe_notify("Failed to analyze sentiment data", type="negative")
    except Exception as e:
        logger.exception(f"Error in background analyze task: {e}")
        update_job_failure(job_id, str(e))
        safe_notify(f"Error analyzing data: {str(e)}", type="negative")


async def run_report_background(
    job_id: str, output_format: str, include_visualizations: bool
):
    """Background task for generating reports.

    Args:
        job_id: The unique identifier for the background job
        output_format: The format for the report (e.g., 'pdf', 'html')
        include_visualizations: Whether to include visualizations in the report
    """
    safe_notify(f"Generating {output_format} report...", type="ongoing", timeout=0)
    try:
        command = ReportCommand()
        result = command.run(
            output_format=output_format, include_visualizations=include_visualizations
        )

        if result:
            update_job_success(job_id, {"report_file": result})
            safe_notify(f"Report generated successfully: {result}", type="positive")
        else:
            update_job_failure(job_id, "Failed to generate report")
            safe_notify("Failed to generate report", type="negative")
    except Exception as e:
        logger.exception(f"Error in background report task: {e}")
        update_job_failure(job_id, str(e))
        safe_notify(f"Error generating report: {str(e)}", type="negative")


async def run_visualize_background(
    job_id: str, data_dir: str, output_dir: str, viz_type: str
):
    """Background task for generating visualizations.

    Args:
        job_id: The unique identifier for the background job
        data_dir: Directory containing data to visualize
        output_dir: Directory where visualizations will be saved
        viz_type: Type of visualization to generate
    """
    safe_notify(f"Generating {viz_type} visualizations...", type="ongoing", timeout=0)
    try:
        result = visualize_data(
            data_dir=data_dir, output_dir=output_dir, viz_type=viz_type
        )

        if result:
            update_job_success(job_id, {"visualization_dir": result})
            safe_notify(
                f"Visualizations generated successfully in {result}", type="positive"
            )
        else:
            update_job_failure(job_id, "Failed to generate visualizations")
            safe_notify("Failed to generate visualizations", type="negative")
    except Exception as e:
        logger.exception(f"Error in background visualization task: {e}")
        update_job_failure(job_id, str(e))
        safe_notify(f"Error generating visualizations: {str(e)}", type="negative")


async def execute_pipeline(
    job_id: str,
    save_data: bool,
    report_format: str,
    include_visualizations: bool,
    source: str,
):
    """Execute the complete sentiment analysis pipeline.

    This function combines the fetch, analyze, and report generation steps
    into a single end-to-end pipeline.

    Args:
        job_id: The unique identifier for the background job
        save_data: Whether to save the fetched data to disk
        report_format: The format for the final report
        include_visualizations: Whether to include visualizations in the report
        source: The data source to fetch and analyze
    """
    safe_notify("Starting full analysis pipeline...", type="ongoing", timeout=0)

    try:
        # Step 1: Fetch data
        safe_notify("Pipeline step 1/3: Fetching data...", type="ongoing")
        fetch_command = FetchCommand()
        fetch_result = fetch_command.fetch_data(save=save_data, source=source)

        if not fetch_result:
            update_job_failure(job_id, "Pipeline failed at fetch stage")
            safe_notify("Pipeline failed at fetch stage", type="negative")
            return

        # Step 2: Analyze data
        safe_notify("Pipeline step 2/3: Analyzing data...", type="ongoing")
        analyze_result = analyze_sentiment(source=source)

        if not analyze_result or "report" not in analyze_result:
            update_job_failure(job_id, "Pipeline failed at analyze stage")
            safe_notify("Pipeline failed at analyze stage", type="negative")
            return

        # Step 3: Generate report
        safe_notify("Pipeline step 3/3: Generating report...", type="ongoing")
        report_command = ReportCommand()
        report_result = report_command.run(
            output_format=report_format, include_visualizations=include_visualizations
        )

        if not report_result:
            update_job_failure(job_id, "Pipeline failed at report stage")
            safe_notify("Pipeline failed at report stage", type="negative")
            return

        # Pipeline complete with improved null handling
        pipeline_result = {
            "report_file": report_result,
            "data_stats": {
                "crypto_data_count": (
                    len(fetch_result.get("crypto_data", {}).get("data", []))
                    if fetch_result
                    and "crypto_data" in fetch_result
                    and isinstance(fetch_result["crypto_data"], dict)
                    and "data" in fetch_result["crypto_data"]
                    else 0
                ),
                "forex_data_count": (
                    len(fetch_result.get("forex_data", {}))
                    if fetch_result and "forex_data" in fetch_result
                    else 0
                ),
            },
            "sentiment": (
                analyze_result["report"].get("overall_sentiment", {})
                if analyze_result and "report" in analyze_result
                else {}
            ),
        }

        update_job_success(job_id, pipeline_result)
        safe_notify("Full pipeline completed successfully", type="positive")

    except Exception as e:
        logger.exception(f"Error in pipeline execution: {e}")
        update_job_failure(job_id, str(e))
        safe_notify(f"Pipeline error: {str(e)}", type="negative")
