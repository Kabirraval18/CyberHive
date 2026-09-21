from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from backend.ingestion.cowrie_ingest import ingest_events


SessionProcessor = Callable[[str], None]


@dataclass
class ProcessingResult:
    inserted_events: int = 0
    affected_sessions: list[str] = field(default_factory=list)
    processing_errors: list[dict[str, Any]] = field(
        default_factory=list
    )

    @property
    def success(self) -> bool:
        return not self.processing_errors


def _collect_session_ids(
    events: Iterable[dict[str, Any]],
) -> list[str]:
    """
    Return unique session IDs in their first-seen order.
    """

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

    Optional session processors run after successful core
    telemetry persistence.

    Failures in optional processors are captured and do not
    propagate back into the core ingestion path.
    """

    event_list = list(events)

    result = ProcessingResult()

    if not event_list:
        return result

    # ---------------------------------------------------------
    # CORE TELEMETRY
    # ---------------------------------------------------------
    #
    # This is the authoritative existing ingestion path.
    #
    # Do not create another database insertion mechanism here.
    #
    inserted_events = ingest_events(
        event_list,
        return_inserted_events=True,
    )

    result.inserted_events = len(inserted_events)

    # Only genuinely new events can cause a session to require
    # downstream processing.
    result.affected_sessions = _collect_session_ids(
        inserted_events
    )

    # ---------------------------------------------------------
    # OPTIONAL SESSION PROCESSING
    # ---------------------------------------------------------

    if not result.affected_sessions:
        return result

    processors = list(session_processors or [])

    if not processors:
        return result

    _run_session_processors(
        result.affected_sessions,
        processors,
        result,
    )

    return result