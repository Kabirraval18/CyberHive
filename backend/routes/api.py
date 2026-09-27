from datetime import timezone

from flask import Blueprint, current_app, jsonify, request

from backend.extensions import db
from backend.models import AttackSession, CowrieEvent, SessionAnalysis, Alert


api_bp = Blueprint("api", __name__)

def _serialize_datetime(value):
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.isoformat()

def _serialize_event(event: CowrieEvent) -> dict:
    return {
        "id": event.id,
        "event_id": event.event_id,
        "session_id": event.session_id,
        "timestamp": _serialize_datetime(event.timestamp),
        "source_ip": event.source_ip,
        "event_type": event.event_type,
        "username": event.username,
        "command": event.command,
        "event_metadata": event.event_metadata,
        "created_at": _serialize_datetime(event.created_at),
    }


def _serialize_session(session: AttackSession) -> dict:
    return {
        "id": session.id,
        "session_id": session.session_id,
        "source_ip": session.source_ip,
        "protocol": session.protocol,
        "username": session.username,
        "authentication_result": session.authentication_result,
        "start_time": _serialize_datetime(session.start_time),
        "end_time": _serialize_datetime(session.end_time),
        "duration": session.duration,
        "command_count": session.command_count,
        "created_at": _serialize_datetime(session.created_at),
    }



def _normalize_timestamp(timestamp):
    """
    Normalize a timestamp to UTC while preserving its precise
    date, hour, minute, second and microsecond values.

    Naive timestamps are treated as UTC.
    """
    if timestamp is None:
        return None

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


@api_bp.get("/api/events")
def get_events():
    events = (
        CowrieEvent.query
        .order_by(CowrieEvent.timestamp.desc())
        .all()
    )

    return jsonify({
        "success": True,
        "count": len(events),
        "events": [
            _serialize_event(event)
            for event in events
        ],
    }), 200


@api_bp.get("/api/events/<int:event_id>")
def get_event(event_id: int):
    event = db.session.get(CowrieEvent, event_id)

    if event is None:
        return jsonify({
            "success": False,
            "error": "Event not found",
        }), 404

    return jsonify({
        "success": True,
        "event": _serialize_event(event),
    }), 200


@api_bp.get("/api/sessions")
def get_sessions():
    sessions = (
        AttackSession.query
        .order_by(AttackSession.start_time.desc())
        .all()
    )

    return jsonify({
        "success": True,
        "count": len(sessions),
        "sessions": [
            _serialize_session(session)
            for session in sessions
        ],
    }), 200


@api_bp.get("/api/sessions/<int:session_id>")
def get_session(session_id: int):
    session = db.session.get(AttackSession, session_id)

    if session is None:
        return jsonify({
            "success": False,
            "error": "Session not found",
        }), 404

    return jsonify({
        "success": True,
        "session": _serialize_session(session),
    }), 200


def _build_dashboard_stats() -> dict:
    total_sessions = db.session.query(AttackSession).count()
    total_events = db.session.query(CowrieEvent).count()

    total_commands = (
        db.session.query(
            db.func.coalesce(
                db.func.sum(AttackSession.command_count),
                0,
            )
        )
        .scalar()
    )

    unique_source_ips = (
        db.session.query(
            db.func.count(
                db.func.distinct(CowrieEvent.source_ip)
            )
        )
        .scalar()
    )

    return {
        "total_sessions": total_sessions,
        "total_events": total_events,
        "total_commands": int(total_commands or 0),
        "unique_source_ips": int(unique_source_ips or 0),
    }


def _build_activity_analytics() -> list[dict]:
    """
    Build a chronological activity timeline using the exact
    timestamps stored in the database.

    Events use CowrieEvent.timestamp.

    Sessions use AttackSession.start_time.

    Session command_count is kept with the session activity
    because the database stores command_count at session level
    rather than storing a timestamp for every individual command.
    """
    activity = []

    events = (
        CowrieEvent.query
        .filter(CowrieEvent.timestamp.isnot(None))
        .all()
    )

    for event in events:
        timestamp = _normalize_timestamp(event.timestamp)

        activity.append({
            "timestamp": timestamp.isoformat(),
            "activity_type": "event",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "source_ip": event.source_ip,
            "event_type": event.event_type,
            "command": event.command,
        })

    sessions = (
        AttackSession.query
        .filter(AttackSession.start_time.isnot(None))
        .all()
    )

    for session in sessions:
        timestamp = _normalize_timestamp(session.start_time)

        activity.append({
            "timestamp": timestamp.isoformat(),
            "activity_type": "session",
            "session_id": session.session_id,
            "source_ip": session.source_ip,
            "protocol": session.protocol,
            "username": session.username,
            "command_count": session.command_count or 0,
        })

    activity.sort(key=lambda item: item["timestamp"])

    return activity


@api_bp.get("/api/analytics/activity")
def get_activity_analytics():
    activity = _build_activity_analytics()

    return jsonify({
        "success": True,
        "activity": activity,
    }), 200


@api_bp.get("/api/stats")
def get_stats():
    stats = _build_dashboard_stats()

    return jsonify({
        "success": True,
        "stats": stats,
    }), 200


@api_bp.get("/api/dashboard")
def get_dashboard():
    stats = _build_dashboard_stats()

    recent_events = (
        CowrieEvent.query
        .order_by(CowrieEvent.timestamp.desc())
        .limit(5)
        .all()
    )

    recent_sessions = (
        AttackSession.query
        .order_by(AttackSession.start_time.desc())
        .limit(5)
        .all()
    )

    return jsonify({
        "success": True,
        "stats": stats,
        "recent_events": [
            _serialize_event(event)
            for event in recent_events
        ],
        "recent_sessions": [
            _serialize_session(session)
            for session in recent_sessions
        ],
    }), 200
# ============================================================
# PHASE 6–12 BEHAVIORAL INTELLIGENCE API
# ============================================================


def _serialize_analysis(analysis):
    if analysis is None:
        return None

    return {
        "id": analysis.id,
        "session_id": analysis.session_id,
        "behavior_label": analysis.behavior_label,
        "behavior_confidence": analysis.behavior_confidence,
        "behavioral_features": analysis.behavioral_features,
        "automation_profile": analysis.automation_profile,
        "behavior_signature": analysis.behavior_signature,
        "cluster_id": analysis.cluster_id,
        "anomaly_score": analysis.anomaly_score,
        "analyzed_at": _serialize_datetime(analysis.analyzed_at),
        "created_at": _serialize_datetime(analysis.created_at),
    }


@api_bp.get("/api/sessions/by-session-id/<path:session_id>")
def get_session_by_cowrie_session_id(session_id: str):
    session = AttackSession.query.filter_by(
        session_id=session_id,
    ).one_or_none()

    if session is None:
        return jsonify({
            "success": False,
            "error": "Session not found",
        }), 404

    risk = session.risk_scores[0] if session.risk_scores else None

    return jsonify({
        "success": True,
        "session": _serialize_session(session),
        "analysis": _serialize_analysis(session.analysis),
        "latest_risk": (
            {
                "score": risk.score,
                "severity": risk.severity,
                "scoring_version": risk.scoring_version,
                "contributing_factors": risk.contributing_factors,
                "calculated_at": _serialize_datetime(risk.calculated_at),
            }
            if risk is not None
            else None
        ),
    }), 200


@api_bp.get("/api/sessions/by-session-id/<path:session_id>/analysis")
def get_session_analysis(session_id: str):
    analysis = SessionAnalysis.query.filter_by(
        session_id=session_id,
    ).one_or_none()

    if analysis is None:
        return jsonify({
            "success": False,
            "error": "Session analysis not found",
        }), 404

    return jsonify({
        "success": True,
        "analysis": _serialize_analysis(analysis),
    }), 200


@api_bp.get("/api/behavior/summary")
def get_behavior_summary():
    from backend.models import SessionAnalysis

    total_sessions = AttackSession.query.count()
    analyzed_sessions = SessionAnalysis.query.count()

    behavior_counts = {}
    for analysis in SessionAnalysis.query.all():
        label = analysis.behavior_label or "Unclassified"
        behavior_counts[label] = behavior_counts.get(label, 0) + 1

    automation_counts = {}
    for analysis in SessionAnalysis.query.all():
        profile = analysis.automation_profile or "insufficient data"
        automation_counts[profile] = automation_counts.get(profile, 0) + 1

    cluster_counts = {}
    for analysis in SessionAnalysis.query.filter(
        SessionAnalysis.cluster_id.isnot(None)
    ).all():
        cluster = str(analysis.cluster_id)
        cluster_counts[cluster] = cluster_counts.get(cluster, 0) + 1

    return jsonify({
        "success": True,
        "total_sessions": total_sessions,
        "analyzed_sessions": analyzed_sessions,
        "analysis_coverage": (
            round(analyzed_sessions / total_sessions, 6)
            if total_sessions
            else None
        ),
        "behavior_distribution": dict(sorted(behavior_counts.items())),
        "automation_distribution": dict(sorted(automation_counts.items())),
        "cluster_distribution": dict(sorted(cluster_counts.items())),
        "cluster_status": (
            "clustered"
            if cluster_counts
            else (
                "insufficient_data"
                if analyzed_sessions < 3
                else "no_cluster_assignments"
            )
        ),
    }), 200


@api_bp.get("/api/behavior/correlations")
def get_behavior_correlations():
    from backend.analysis.correlation import build_behavior_correlations

    raw_threshold = (request.args.get("threshold") or "0.70").strip()
    try:
        threshold = float(raw_threshold)
    except ValueError:
        return jsonify({
            "success": False,
            "error": "threshold must be a number between 0 and 1",
        }), 400

    if threshold < 0 or threshold > 1:
        return jsonify({
            "success": False,
            "error": "threshold must be between 0 and 1",
        }), 400

    return jsonify({
        "success": True,
        **build_behavior_correlations(
            similarity_threshold=threshold,
        ),
    }), 200


@api_bp.get("/api/behavior/similar/<path:session_id>")
def get_similar_sessions(session_id: str):
    from backend.analysis.correlation import find_similar_sessions

    if SessionAnalysis.query.filter_by(session_id=session_id).one_or_none() is None:
        return jsonify({
            "success": False,
            "error": "Session analysis not found",
        }), 404

    return jsonify({
        "success": True,
        "session_id": session_id,
        "similar_sessions": find_similar_sessions(session_id),
    }), 200


@api_bp.get("/api/sources")
def get_source_profiles():
    from backend.analysis.profiling import build_all_source_profiles

    profiles = build_all_source_profiles()

    return jsonify({
        "success": True,
        "count": len(profiles),
        "sources": profiles,
    }), 200


@api_bp.get("/api/sources/<path:source_ip>")
def get_source_profile(source_ip: str):
    from backend.analysis.profiling import build_source_profile

    profile = build_source_profile(source_ip)
    if profile is None:
        return jsonify({
            "success": False,
            "error": "Source IP not found",
        }), 404

    return jsonify({
        "success": True,
        "source": profile,
    }), 200


@api_bp.get("/api/threat-intelligence/status")
def get_threat_intelligence_status():
    abuse_key = bool(str(current_app.config.get("ABUSEIPDB_API_KEY") or "").strip())
    return jsonify({
        "success": True,
        "providers": {
            "abuseipdb": {
                "enabled": bool(current_app.config.get("ABUSEIPDB_ENABLED", True)),
                "configured": abuse_key,
            },
            "virustotal": {
                "enabled": bool(current_app.config.get("VIRUSTOTAL_ENABLED", True)),
                "configured": bool(
                    str(current_app.config.get("VIRUSTOTAL_API_KEY") or "").strip()
                ),
            },
        },
    }), 200


@api_bp.get("/api/threat-intelligence/abuseipdb")
def get_abuseipdb_intelligence():
    from backend.intelligence.abuseipdb import lookup_abuseipdb

    source_ip = (request.args.get("ip") or "").strip()
    if not source_ip:
        return jsonify({
            "success": False,
            "error": "ip query parameter is required",
        }), 400

    force_refresh = (request.args.get("refresh") or "false").strip().lower() in {
        "1",
        "true",
        "yes",
    }

    result = lookup_abuseipdb(
        source_ip,
        force_refresh=force_refresh,
    )
    status_code = 200 if result.get("success") else {
        "invalid_ip": 400,
        "non_public_ip": 200,
        "disabled": 200,
        "not_configured": 503,
        "timeout": 504,
        "rate_limited": 429,
        "authentication_error": 502,
        "provider_error": 502,
        "provider_unavailable": 503,
        "malformed_response": 502,
        "unexpected_response": 502,
    }.get(result.get("status"), 502)

    return jsonify(result), status_code

# ============================================================
# PHASE 13–21 INTELLIGENCE, INVESTIGATION, ALERTING, REPORTING
# ============================================================
from backend.auth import require_auth, require_role

@api_bp.before_request
def _api_auth_boundary():
    if current_app.config.get('TESTING'):
        return None
    from backend.auth import current_user
    if current_user() is None:
        return jsonify({'success':False,'error':'Authentication required'}),401
    return None


def _serialize_risk(r):
    if not r: return None
    return {'score':r.score,'severity':r.severity,'contributing_factors':r.contributing_factors or [],'scoring_version':r.scoring_version,'calculated_at':_serialize_datetime(r.calculated_at)}

def _serialize_alert(a):
    return {'id':a.id,'session_id':a.session_id,'source_ip':a.session.source_ip if a.session else None,'risk_score':a.risk_score,'severity':a.severity,'title':a.title,'message':a.message,'acknowledged':a.acknowledged,'created_at':_serialize_datetime(a.created_at),'acknowledged_at':_serialize_datetime(a.acknowledged_at)}

def _serialize_mitre(m):
    return {'id':m.id,'session_id':m.session_id,'event_id':m.event_id,'command':m.command,'technique_id':m.technique_id,'technique_name':m.technique_name,'tactic':m.tactic,'evidence':m.evidence,'confidence':m.confidence,'created_at':_serialize_datetime(m.created_at)}

@api_bp.get('/api/sessions/by-session-id/<path:session_id>/investigation')
def get_investigation(session_id):
    from backend.models import IPIntelligence, MITREMapping
    from backend.analysis.recommendations import generate_recommendations
    session=AttackSession.query.filter_by(session_id=session_id).one_or_none()
    if not session: return jsonify({'success':False,'error':'Session not found'}),404
    events=[_serialize_event(e) for e in session.events.order_by(CowrieEvent.timestamp.asc()).all()]
    intel=[]
    if session.source_ip:
        intel=[{
            'provider':r.provider,'ip_address':r.ip_address,'reputation':r.reputation,'abuse_confidence':r.abuse_confidence,
            'report_count':r.report_count,'country':r.country,'asn':r.asn,'isp':r.isp,
            'category_data':r.category_data,'provider_metadata':r.provider_metadata,
            'retrieved_at':_serialize_datetime(r.retrieved_at),'expires_at':_serialize_datetime(r.expires_at)
        } for r in IPIntelligence.query.filter_by(ip_address=session.source_ip).all()]
    return jsonify({'success':True,'session':_serialize_session(session),'analysis':_serialize_analysis(session.analysis),
                    'events':events,'threat_intelligence':intel,'risk':_serialize_risk(session.risk_scores[0] if session.risk_scores else None),
                    'mitre':[_serialize_mitre(m) for m in session.mitre_mappings],
                    'recommendations':generate_recommendations(session)})

@api_bp.get('/api/threat-intelligence/virustotal')
def get_virustotal_intelligence():
    from backend.intelligence.virustotal import lookup_virustotal
    ip=(request.args.get('ip') or '').strip()
    if not ip: return jsonify({'success':False,'error':'ip query parameter is required'}),400
    force=(request.args.get('refresh') or '').lower() in {'1','true','yes'}
    result=lookup_virustotal(ip,force_refresh=force)
    code={'invalid_ip':400,'non_public_ip':200,'disabled':200,'not_configured':503,'timeout':504,'rate_limited':429,'authentication_error':502,'provider_error':502,'provider_unavailable':503,'malformed_response':502,'unexpected_response':502}.get(result.get('status'),200 if result.get('success') else 502)
    return jsonify(result),code

@api_bp.get('/api/risk/<path:session_id>')
def get_risk(session_id):
    from backend.analysis.risk import calculate_risk
    try: return jsonify({'success':True,'risk':calculate_risk(session_id,persist=True)})
    except ValueError: return jsonify({'success':False,'error':'Session not found'}),404

@api_bp.get('/api/mitre/<path:session_id>')
def get_mitre(session_id):
    from backend.analysis.mitre import map_session
    try: return jsonify({'success':True,'mappings':map_session(session_id,persist=True)})
    except ValueError: return jsonify({'success':False,'error':'Session not found'}),404

@api_bp.get('/api/recommendations/<path:session_id>')
def get_recommendations(session_id):
    from backend.analysis.recommendations import generate_recommendations
    session=AttackSession.query.filter_by(session_id=session_id).one_or_none()
    if not session: return jsonify({'success':False,'error':'Session not found'}),404
    return jsonify({'success':True,'recommendations':generate_recommendations(session)})

@api_bp.get('/api/alerts')
def get_alerts():
    limit=min(max(int(request.args.get('limit',50)),1),200)
    acknowledged=request.args.get('acknowledged')
    q=Alert.query.order_by(Alert.created_at.desc())
    if acknowledged in {'true','false'}: q=q.filter_by(acknowledged=acknowledged=='true')
    alerts=q.limit(limit).all()
    return jsonify({'success':True,'count':len(alerts),'alerts':[_serialize_alert(a) for a in alerts]})

@api_bp.post('/api/alerts/<int:alert_id>/acknowledge')
def acknowledge_alert(alert_id):
    from datetime import datetime, timezone
    a=db.session.get(Alert,alert_id)
    if not a: return jsonify({'success':False,'error':'Alert not found'}),404
    a.acknowledged=True; a.acknowledged_at=datetime.now(timezone.utc); db.session.commit()
    return jsonify({'success':True,'alert':_serialize_alert(a)})

@api_bp.get('/api/reports/sessions.csv')
def report_csv():
    from flask import Response
    from backend.reports import sessions_csv
    return Response(sessions_csv(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=cyberhive-sessions.csv'})

@api_bp.get('/api/reports/session/<path:session_id>.pdf')
def report_session(session_id):
    from flask import Response
    from backend.reports import session_pdf
    data=session_pdf(session_id)
    if data is None: return jsonify({'success':False,'error':'Session not found'}),404
    return Response(data,mimetype='application/pdf',headers={'Content-Disposition':f'attachment; filename=cyberhive-{session_id}.pdf'})

@api_bp.get('/api/reports/summary.pdf')
def report_summary():
    from flask import Response
    from backend.reports import summary_pdf
    return Response(summary_pdf(),mimetype='application/pdf',headers={'Content-Disposition':'attachment; filename=cyberhive-summary.pdf'})

@api_bp.get('/api/analytics/security')
def security_analytics():
    from collections import Counter
    sessions=AttackSession.query.all(); analyses=[s.analysis for s in sessions if s.analysis]; risks=[s.risk_scores[0] for s in sessions if s.risk_scores]
    return jsonify({'success':True,'analytics':{'sessions':len(sessions),'analyzed_sessions':len(analyses),'analysis_coverage':round(len(analyses)/len(sessions),4) if sessions else 0,
        'behaviors':dict(Counter(a.behavior_label or 'Unclassified' for a in analyses)),
        'automation':dict(Counter(a.automation_profile or 'insufficient data' for a in analyses)),
        'risk_severity':dict(Counter(r.severity for r in risks)),
        'mitre_techniques':dict(Counter(m.technique_id for m in __import__('backend.models',fromlist=['MITREMapping']).MITREMapping.query.all()))}})

@api_bp.get('/api/sessions/filter')
def filter_sessions():
    q=AttackSession.query
    source=(request.args.get('source_ip') or '').strip(); behavior=(request.args.get('behavior') or '').strip(); severity=(request.args.get('severity') or '').strip()
    if source: q=q.filter(AttackSession.source_ip==source)
    sessions=q.order_by(AttackSession.start_time.desc()).all()
    out=[]
    for s in sessions:
        if behavior and (not s.analysis or s.analysis.behavior_label!=behavior): continue
        if severity and (not s.risk_scores or s.risk_scores[0].severity!=severity): continue
        row=_serialize_session(s); row['behavior_label']=s.analysis.behavior_label if s.analysis else None; row['risk']=_serialize_risk(s.risk_scores[0] if s.risk_scores else None); out.append(row)
    return jsonify({'success':True,'count':len(out),'sessions':out})
