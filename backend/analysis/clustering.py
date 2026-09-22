from __future__ import annotations

from math import sqrt
from typing import Any, Iterable

from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from backend.extensions import db
from backend.models import SessionAnalysis


CLUSTER_FEATURES = (
    "failed_login_count",
    "successful_login_count",
    "command_count",
    "unique_command_count",
    "session_duration_seconds",
    "repeated_command_ratio",
    "transfer_event_count",
    "discovery_command_count",
    "persistence_command_count",
)


def _numeric_feature(row: dict[str, Any], name: str) -> float:
    value = row.get(name)
    if value is None:
        # For clustering only, undefined ratio/timing fields are treated as
        # absence of the corresponding observed signal. The original JSON
        # feature remains unchanged and can still be None.
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def choose_cluster_count(session_count: int) -> int | None:
    if session_count < 3:
        return None
    return min(
        4,
        max(2, int(round(sqrt(session_count)))),
    )


def cluster_feature_rows(rows: Iterable[tuple[int, dict[str, Any]]]) -> dict[int, int]:
    rows = list(rows)
    cluster_count = choose_cluster_count(len(rows))
    if cluster_count is None:
        return {}

    matrix = [
        [
            _numeric_feature(features, name)
            for name in CLUSTER_FEATURES
        ]
        for _, features in rows
    ]

    distinct_rows = {tuple(row) for row in matrix}
    if len(distinct_rows) == 1:
        return {analysis_id: 0 for analysis_id, _ in rows}

    cluster_count = min(cluster_count, len(distinct_rows))
    if cluster_count <= 1:
        return {analysis_id: 0 for analysis_id, _ in rows}

    scaled = StandardScaler().fit_transform(matrix)
    model = KMeans(
        n_clusters=cluster_count,
        random_state=42,
        n_init=10,
    )
    labels = model.fit_predict(scaled)

    return {
        analysis_id: int(label)
        for (analysis_id, _), label in zip(rows, labels)
    }


def recluster_session_analyses() -> dict[str, Any]:
    """Recompute deterministic clusters across analyzed sessions."""

    analyses = (
        SessionAnalysis.query
        .filter(SessionAnalysis.behavioral_features.isnot(None))
        .order_by(SessionAnalysis.id.asc())
        .all()
    )

    rows = [
        (analysis.id, analysis.behavioral_features)
        for analysis in analyses
    ]

    cluster_count = choose_cluster_count(len(rows))
    if cluster_count is None:
        for analysis in analyses:
            analysis.cluster_id = None
        db.session.commit()
        return {
            "status": "insufficient_data",
            "session_count": len(rows),
            "cluster_count": None,
            "assignments": {},
        }

    assignments = cluster_feature_rows(rows)
    for analysis in analyses:
        analysis.cluster_id = assignments.get(analysis.id)

    db.session.commit()

    return {
        "status": "clustered",
        "session_count": len(rows),
        "cluster_count": cluster_count,
        "assignments": {
            str(analysis_id): cluster_id
            for analysis_id, cluster_id in assignments.items()
        },
    }
