from __future__ import annotations
from backend.extensions import db
from backend.models import AttackSession, RiskScore, IPIntelligence
SCORING_VERSION='1.0'

def _clamp(v): return max(0,min(100,int(round(v))))
def _severity(s): return 'Low' if s<25 else 'Medium' if s<50 else 'High' if s<80 else 'Critical'

def calculate_risk(session_id, *, persist=True):
    session=AttackSession.query.filter_by(session_id=session_id).one_or_none()
    if not session: raise ValueError('Session not found')
    a=session.analysis; f=(a.behavioral_features if a else {}) or {}
    factors=[]; score=0
    failed=int(f.get('failed_login_count') or 0)
    auth_attempts=int(f.get('authentication_attempt_count') or 0)
    if failed:
        c=min(25,failed*5); score+=c; factors.append({'name':'authentication_abuse','contribution':c,'evidence':f'{failed} failed authentication attempts'})
    label=(a.behavior_label if a else '') or ''
    behavior_points={'Brute Force':25,'Persistence Attempt':22,'Payload Activity':20,'Reconnaissance / Discovery':14,'Interactive Exploration':6}.get(label,0)
    if behavior_points:
        score+=behavior_points; factors.append({'name':'behavior_classification','contribution':behavior_points,'evidence':label})
    discovery=int(f.get('discovery_command_count') or 0)
    if discovery:
        c=min(15,discovery*2); score+=c; factors.append({'name':'discovery_activity','contribution':c,'evidence':f'{discovery} discovery-oriented commands'})
    transfers=int(f.get('transfer_event_count') or 0)+int(f.get('transfer_command_count') or 0)
    if transfers:
        c=min(15,transfers*5); score+=c; factors.append({'name':'transfer_activity','contribution':c,'evidence':f'{transfers} transfer indicators'})
    freq=float(f.get('command_frequency_per_minute') or 0)
    if freq>=10:
        c=10; score+=c; factors.append({'name':'command_frequency','contribution':c,'evidence':f'{freq:.2f} commands/minute'})
    repeated=float(f.get('repeated_command_ratio') or 0)
    if repeated>=0.5:
        c=5; score+=c; factors.append({'name':'repetition','contribution':c,'evidence':f'repeated command ratio {repeated:.2f}'})
    intel=[]
    if session.source_ip:
        for provider in ('abuseipdb','virustotal'):
            r=IPIntelligence.query.filter_by(ip_address=session.source_ip,provider=provider).one_or_none()
            if r: intel.append(r)
    for r in intel:
        if r.provider=='abuseipdb' and r.abuse_confidence is not None:
            c=min(15,int(round(r.abuse_confidence*0.15))); score+=c; factors.append({'name':'abuseipdb_reputation','contribution':c,'evidence':f'AbuseIPDB abuse confidence {r.abuse_confidence}'})
        elif r.provider=='virustotal' and r.reputation is not None:
            c=min(15,int(round(r.reputation*0.15))); score+=c; factors.append({'name':'virustotal_reputation','contribution':c,'evidence':f'VirusTotal detection ratio {r.reputation:.2f}%'})
    score=_clamp(score); sev=_severity(score)
    payload={'score':score,'severity':sev,'contributing_factors':factors,'scoring_version':SCORING_VERSION}
    if persist:
        existing=RiskScore.query.filter_by(session_id=session_id,scoring_version=SCORING_VERSION).order_by(RiskScore.calculated_at.desc()).first()
        if existing:
            existing.score=score; existing.severity=sev; existing.contributing_factors=factors
            record=existing
        else:
            record=RiskScore(session_id=session_id,score=score,severity=sev,contributing_factors=factors,scoring_version=SCORING_VERSION); db.session.add(record)
        db.session.commit()
        payload['calculated_at']=record.calculated_at.isoformat() if record.calculated_at else None
    return payload
