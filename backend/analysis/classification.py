from __future__ import annotations

from typing import Any


BEHAVIOR_LABELS = (
    "Brute Force",
    "Reconnaissance / Discovery",
    "Payload Activity",
    "Interactive Exploration",
    "Persistence Attempt",
    "Insufficient Evidence",
)


_PRIORITY = {
    "Persistence Attempt": 0,
    "Payload Activity": 1,
    "Brute Force": 2,
    "Reconnaissance / Discovery": 3,
    "Interactive Exploration": 4,
    "Insufficient Evidence": 5,
}


def classify_behavior(features: dict[str, Any]) -> dict[str, Any]:
    """Apply deterministic rule-based behavior classification."""

    candidates: dict[str, float] = {}
    evidence: dict[str, list[str]] = {}

    failed = int(features.get("failed_login_count") or 0)
    auth_attempts = int(features.get("authentication_attempt_count") or 0)
    failure_ratio = features.get("authentication_failure_ratio")

    brute_evidence: list[str] = []
    if failed >= 3:
        brute_evidence.append(
            f"{failed} failed authentication attempts observed"
        )
    if auth_attempts >= 4 and failure_ratio is not None and failure_ratio >= 0.75:
        brute_evidence.append(
            f"authentication failure ratio is {failure_ratio:.2f}"
        )
    if brute_evidence:
        candidates["Brute Force"] = float(min(5, 2 + len(brute_evidence)))
        evidence["Brute Force"] = brute_evidence

    transfer_commands = int(features.get("transfer_command_count") or 0)
    transfer_events = int(features.get("transfer_event_count") or 0)
    download_events = int(features.get("download_event_count") or 0)
    upload_events = int(features.get("upload_event_count") or 0)

    payload_evidence: list[str] = []
    if transfer_commands:
        payload_evidence.append(
            f"{transfer_commands} transfer-related command(s) observed"
        )
    if transfer_events:
        payload_evidence.append(
            f"{transfer_events} observable file-transfer event(s) recorded"
        )
    if download_events:
        payload_evidence.append(
            f"{download_events} file download event(s) recorded"
        )
    if upload_events:
        payload_evidence.append(
            f"{upload_events} file upload event(s) recorded"
        )

    # Payload activity is only a classification when telemetry contains
    # observable transfer evidence in addition to a transfer-oriented command.
    if transfer_commands and transfer_events:
        candidates["Payload Activity"] = float(
            min(5, 3 + int(transfer_events > 0) + int(transfer_commands > 1))
        )
        evidence["Payload Activity"] = payload_evidence

    discovery_count = int(features.get("discovery_command_count") or 0)
    discovery_category_count = int(features.get("discovery_category_count") or 0)
    discovery_evidence: list[str] = []
    if discovery_count >= 2:
        discovery_evidence.append(
            f"{discovery_count} discovery-oriented commands observed"
        )
    if discovery_category_count >= 2:
        categories = ", ".join(features.get("discovery_categories") or [])
        discovery_evidence.append(
            f"discovery evidence spans {discovery_category_count} categories: {categories}"
        )
    if discovery_count >= 2 and discovery_category_count >= 2:
        candidates["Reconnaissance / Discovery"] = float(
            min(5, 2 + discovery_category_count)
        )
        evidence["Reconnaissance / Discovery"] = discovery_evidence

    persistence_count = int(features.get("persistence_command_count") or 0)
    if persistence_count > 0:
        candidates["Persistence Attempt"] = float(
            min(5, 3 + persistence_count)
        )
        evidence["Persistence Attempt"] = [
            f"{persistence_count} persistence-oriented command(s) observed"
        ]

    command_count = int(features.get("command_count") or 0)
    unique_ratio = float(features.get("unique_command_ratio") or 0.0)
    duration = features.get("session_duration_seconds")
    mean_gap = features.get("mean_time_between_commands_seconds")

    interactive_evidence: list[str] = []
    if command_count >= 3:
        interactive_evidence.append(
            f"{command_count} commands observed"
        )
    if unique_ratio >= 0.67:
        interactive_evidence.append(
            f"command uniqueness ratio is {unique_ratio:.2f}"
        )
    if duration is not None and duration >= 30:
        interactive_evidence.append(
            f"session duration is {duration:.1f} seconds"
        )
    if mean_gap is not None and mean_gap >= 5:
        interactive_evidence.append(
            f"mean command interval is {mean_gap:.1f} seconds"
        )

    if (
        command_count >= 3
        and unique_ratio >= 0.67
        and duration is not None
        and duration >= 30
        and not any(
            label in candidates
            for label in (
                "Persistence Attempt",
                "Payload Activity",
                "Brute Force",
                "Reconnaissance / Discovery",
            )
        )
    ):
        candidates["Interactive Exploration"] = min(5.0, 2.0 + len(interactive_evidence) * 0.5)
        evidence["Interactive Exploration"] = interactive_evidence

    if not candidates:
        return {
            "label": "Insufficient Evidence",
            "confidence": 0.0,
            "evidence": [
                "No behavior rule reached its evidence threshold."
            ],
            "candidate_scores": {},
        }

    label = min(
        candidates,
        key=lambda item: (-candidates[item], _PRIORITY[item]),
    )
    top_score = candidates[label]
    total_score = sum(candidates.values())

    # This is a rule-derived confidence indicator, not a probability.
    confidence = min(
        0.95,
        round(top_score / max(total_score, 1.0), 3),
    )

    return {
        "label": label,
        "confidence": confidence,
        "evidence": evidence.get(label, []),
        "candidate_scores": candidates,
    }
