from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from flask import current_app, has_app_context

from backend.ingestion.cowrie_ingest import ingest_events


SessionProcessor = Callable[[str], None]


@dataclass
class ProcessingResult:
    inserted_events: int = 0
    affected_sessions: list[str] = field(default_factory=list)
    processing_errors: list[dict[str, Any]] = field(
        default_factory=list
    )
    clustered: bool = False
    cluster_status: str | None = None

    @property
    def success(self) -> bool:
        return not self.processing_errors


def _collect_session_ids(
    events: Iterable[dict[str, Any]],
) -> list[str]:
    """Return unique session IDs in their first-seen order."""

    session_ids: list[str] = []
    seen: set[str] = set()

    for event in events:
        session_id = event.get("session_id")

        if not session_id:
            continue

        if session_id in seen:
            continue

        seen.add(session_id)
        session_ids.append(session_id)

    return session_ids


def _default_session_processors() -> list[SessionProcessor]:
    """Return the configured Phase 6–12 processor boundary."""
    if not has_app_context():
        return []

    if not current_app.config.get("RUN_ANALYSIS_ON_INGEST", True):
        return []

    from backend.analysis.session_analyzer import analyze_session

    return [analyze_session]


def _run_session_processors(
    session_ids: Iterable[str],
    processors: Iterable[SessionProcessor],
    result: ProcessingResult,
) -> None:
    """
    Run optional session processors.

    Processor failures are isolated from core telemetry.
    """

    for processor in processors:
        processor_name = getattr(
            processor,
            "__name__",
            processor.__class__.__name__,
        )

        for session_id in session_ids:
            try:
                processor(session_id)

            except Exception as exc:
                result.processing_errors.append(
                    {
                        "stage": "session_processor",
                        "processor": processor_name,
                        "session_id": session_id,
                        "error_type": type(exc).__name__,
                        "message": str(exc),
                    }
                )


def _run_reclustering(
    result: ProcessingResult,
) -> None:
    if not has_app_context():
        return

    if not current_app.config.get("RUN_RECLUSTER_ON_INGEST", True):
        result.cluster_status = "disabled"
        return

    if not result.affected_sessions:
        result.cluster_status = "no_affected_sessions"
        return

    try:
        from backend.analysis.clustering import recluster_session_analyses

        cluster_result = recluster_session_analyses()
        result.cluster_status = cluster_result["status"]
        result.clustered = cluster_result["status"] == "clustered"
    except Exception as exc:
        result.processing_errors.append(
            {
                "stage": "clustering",
                "error_type": type(exc).__name__,
                "message": str(exc),
            }
        )


def process_cowrie_events(
    events: Iterable[dict[str, Any]],
    *,
    session_processors: Iterable[SessionProcessor] | None = None,
) -> ProcessingResult:
    """
    Process normalized Cowrie events.

    Core ingestion is always performed first.

    Only genuinely newly inserted events are used to determine
    affected sessions.

    When session_processors is omitted, the configured default
    behavioral-analysis processor is used. Explicit processor
    lists retain the Phase 5 extension contract.
    """

    event_list = list(events)

    result = ProcessingResult()

    if not event_list:
        return result

    inserted_events = ingest_events(
        event_list,
        return_inserted_events=True,
    )

    result.inserted_events = len(inserted_events)
    result.affected_sessions = _collect_session_ids(inserted_events)

    if not result.affected_sessions:
        return result

    if session_processors is None:
        processors = _default_session_processors()
    else:
        processors = list(session_processors)

    if processors:
        _run_session_processors(
            result.affected_sessions,
            processors,
            result,
        )

    # Clustering is downstream of feature extraction and classification.
    _run_reclustering(result)

    # Final intelligence is deliberately downstream of core telemetry.
    # Provider, risk, MITRE and alert failures are isolated from ingestion.
    try:
        from backend.analysis.finalize import finalize_session_intelligence
        for session_id in result.affected_sessions:
            try:
                finalize_session_intelligence(session_id)
            except Exception as exc:
                result.processing_errors.append({
                    "stage": "final_intelligence",
                    "session_id": session_id,
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                })
    except Exception as exc:
        result.processing_errors.append({
            "stage": "final_intelligence_import",
            "error_type": type(exc).__name__,
            "message": str(exc),
        })

    return result
