from __future__ import annotations

from typing import Any


def profile_automation(features: dict[str, Any]) -> dict[str, Any]:
    """Classify observable interaction characteristics without claiming actor identity."""

    command_count = int(features.get("command_count") or 0)
    mean_gap = features.get("mean_time_between_commands_seconds")
    repeated_ratio = float(features.get("repeated_command_ratio") or 0.0)
    unique_ratio = float(features.get("unique_command_ratio") or 0.0)
    duration = features.get("session_duration_seconds")

    if command_count < 2 or mean_gap is None:
        return {
            "profile": "insufficient data",
            "confidence": 0.0,
            "signals": [
                "At least two timestamped commands are required for timing-based profiling."
            ],
        }

    signals: list[str] = []
    automated_score = 0
    interactive_score = 0

    if mean_gap <= 2.0:
        automated_score += 2
        signals.append(
            f"mean command interval is {mean_gap:.2f} seconds"
        )
    elif mean_gap >= 5.0:
        interactive_score += 2
        signals.append(
            f"mean command interval is {mean_gap:.2f} seconds"
        )

    if repeated_ratio >= 0.5:
        automated_score += 2
        signals.append(
            f"repeated command ratio is {repeated_ratio:.2f}"
        )
    elif unique_ratio >= 0.75:
        interactive_score += 1
        signals.append(
            f"unique command ratio is {unique_ratio:.2f}"
        )

    if duration is not None and duration >= 60 and unique_ratio >= 0.67:
        interactive_score += 1
        signals.append(
            f"session lasted {duration:.1f} seconds with diverse commands"
        )

    if automated_score >= 3 and automated_score > interactive_score:
        profile = "likely automated"
    elif interactive_score >= 3 and interactive_score > automated_score:
        profile = "likely interactive"
    else:
        profile = "mixed"

    confidence = round(
        min(0.9, max(automated_score, interactive_score) / 5.0),
        3,
    )

    return {
        "profile": profile,
        "confidence": confidence,
        "signals": signals,
    }
