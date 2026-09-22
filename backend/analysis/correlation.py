from __future__ import annotations

from difflib import SequenceMatcher
from itertools import combinations
from typing import Any

from backend.models import AttackSession, SessionAnalysis


def _command_sequence(analysis: SessionAnalysis) -> list[str]:
    features = analysis.behavioral_features or {}
    values = features.get("normalized_command_sequence") or []
    return [str(value) for value in values]


def session_similarity(left: SessionAnalysis, right: SessionAnalysis) -> float:
    left_sequence = _command_sequence(left)
    right_sequence = _command_sequence(right)

    if left.behavior_signature and left.behavior_signature == right.behavior_signature:
        return 1.0

    if not left_sequence and not right_sequence:
        return 1.0
    if not left_sequence or not right_sequence:
        return 0.0

    return round(
        SequenceMatcher(
            a=left_sequence,
            b=right_sequence,
            autojunk=False,
        ).ratio(),
        6,
    )


def build_behavior_correlations(
    *,
    similarity_threshold: float = 0.70,
) -> dict[str, Any]:
    analyses = (
        SessionAnalysis.query
        .join(AttackSession, AttackSession.session_id == SessionAnalysis.session_id)
        .order_by(SessionAnalysis.id.asc())
        .all()
    )

    signature_groups: dict[str, list[dict[str, Any]]] = {}
    for analysis in analyses:
        signature = analysis.behavior_signature
        if not signature:
            continue
        signature_groups.setdefault(signature, []).append(
            {
                "session_id": analysis.session_id,
                "source_ip": analysis.session.source_ip if analysis.session else None,
                "behavior_label": analysis.behavior_label,
            }
        )

    repeated_signatures = [
        {
            "behavior_signature": signature,
            "session_count": len(entries),
            "cross_source": len({entry["source_ip"] for entry in entries}) > 1,
            "sessions": entries,
        }
        for signature, entries in sorted(
            signature_groups.items(),
            key=lambda item: (-len(item[1]), item[0]),
        )
        if len(entries) > 1
    ]

    similar_pairs = []
    for left, right in combinations(analyses, 2):
        similarity = session_similarity(left, right)
        if similarity < similarity_threshold:
            continue
        similar_pairs.append(
            {
                "left_session_id": left.session_id,
                "right_session_id": right.session_id,
                "left_source_ip": left.session.source_ip if left.session else None,
                "right_source_ip": right.session.source_ip if right.session else None,
                "similarity": similarity,
                "same_source": (
                    left.session.source_ip == right.session.source_ip
                    if left.session and right.session
                    else False
                ),
                "same_signature": (
                    bool(left.behavior_signature)
                    and left.behavior_signature == right.behavior_signature
                ),
            }
        )

    similar_pairs.sort(
        key=lambda item: (
            -item["similarity"],
            item["left_session_id"],
            item["right_session_id"],
        )
    )

    return {
        "similarity_threshold": similarity_threshold,
        "analyzed_session_count": len(analyses),
        "repeated_signatures": repeated_signatures,
        "similar_session_pairs": similar_pairs,
    }


def find_similar_sessions(
    session_id: str,
    *,
    similarity_threshold: float = 0.70,
) -> list[dict[str, Any]]:
    target = SessionAnalysis.query.filter_by(session_id=session_id).one_or_none()
    if target is None:
        return []

    analyses = (
        SessionAnalysis.query
        .filter(SessionAnalysis.session_id != session_id)
        .order_by(SessionAnalysis.id.asc())
        .all()
    )

    matches = []
    for analysis in analyses:
        similarity = session_similarity(target, analysis)
        if similarity < similarity_threshold:
            continue
        matches.append(
            {
                "session_id": analysis.session_id,
                "source_ip": (
                    analysis.session.source_ip
                    if analysis.session
                    else None
                ),
                "behavior_label": analysis.behavior_label,
                "cluster_id": analysis.cluster_id,
                "behavior_signature": analysis.behavior_signature,
                "similarity": similarity,
                "same_signature": (
                    bool(target.behavior_signature)
                    and target.behavior_signature == analysis.behavior_signature
                ),
            }
        )

    matches.sort(
        key=lambda item: (
            -item["similarity"],
            item["session_id"],
        )
    )
    return matches
