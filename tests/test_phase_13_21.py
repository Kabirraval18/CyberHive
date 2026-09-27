from datetime import datetime, timezone, timedelta
from backend.models import AttackSession, CowrieEvent, SessionAnalysis, RiskScore, MITREMapping, Alert, User
from backend.analysis.risk import calculate_risk
from backend.analysis.mitre import map_session
from backend.analysis.recommendations import generate_recommendations
from backend.intelligence.virustotal import lookup_virustotal

def make_session():
    s=AttackSession(session_id='phase-test',source_ip='8.8.8.8',protocol='ssh',username='root',command_count=4,start_time=datetime.now(timezone.utc),end_time=datetime.now(timezone.utc))
    db=s.events
    return s

def test_risk_is_deterministic(app):
    with app.app_context():
        s=AttackSession(session_id='risk-test',source_ip='8.8.8.8',protocol='ssh',username='root',command_count=4)
        a=SessionAnalysis(session_id=s.session_id,behavior_label='Reconnaissance / Discovery',behavior_confidence=.95,behavioral_features={'failed_login_count':2,'discovery_command_count':3,'command_frequency_per_minute':12,'repeated_command_ratio':.6},automation_profile='likely interactive')
        s.analysis=a
        from backend.extensions import db
        db.session.add(s); db.session.commit()
        one=calculate_risk(s.session_id,persist=False); two=calculate_risk(s.session_id,persist=False)
        assert one['score']==two['score'] and one['contributing_factors']==two['contributing_factors']

def test_mitre_positive_and_negative(app):
    with app.app_context():
        from backend.extensions import db
        s=AttackSession(session_id='mitre-test',source_ip='8.8.8.8',protocol='ssh')
        db.session.add(s); db.session.flush()
        db.session.add(CowrieEvent(event_id='evt-1',session_id=s.session_id,source_ip=s.source_ip,event_type='cowrie.command.input',command='whoami'))
        db.session.add(CowrieEvent(event_id='evt-2',session_id=s.session_id,source_ip=s.source_ip,event_type='cowrie.command.input',command='echo hello'))
        db.session.commit(); mappings=map_session(s.session_id,persist=True)
        assert len(mappings)==1 and mappings[0]['technique_id']=='T1033'

def test_recommendations_are_evidence_based(app):
    with app.app_context():
        from backend.extensions import db
        s=AttackSession(session_id='rec-test',source_ip='8.8.8.8',protocol='ssh')
        a=SessionAnalysis(session_id=s.session_id,behavior_label='Brute Force',behavioral_features={'failed_login_count':5})
        s.analysis=a; db.session.add(s); db.session.commit(); recs=generate_recommendations(s)
        assert any(r['category']=='Authentication' for r in recs)

def test_virustotal_rejects_private_ip(app):
    with app.app_context():
        result=lookup_virustotal('127.0.0.1')
        assert result['status']=='non_public_ip'

def test_user_password_is_hashed(app):
    with app.app_context():
        from backend.extensions import db
        u=User(username='tester',role='analyst'); u.set_password('password-123'); db.session.add(u); db.session.commit()
        assert u.password_hash!='password-123' and u.check_password('password-123') and not u.check_password('wrong')


def test_session_expires_and_protected_endpoint_is_rejected(
    app,
    client,
):
    from backend.extensions import db
    import time

    # Short lifetime for deterministic testing.
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
        seconds=2
    )

    app.config['SESSION_LIFETIME_SECONDS'] = 2

    user = User(
        username='expiry-user',
        role='analyst',
    )

    user.set_password('password-123')

    db.session.add(user)
    db.session.commit()

    response = client.post(
        '/api/auth/login',
        json={
            'username': 'expiry-user',
            'password': 'password-123',
        },
    )

    assert response.status_code == 200

    # Disable the test-only authentication bypass.
    app.config['AUTH_TEST_BYPASS'] = False

    # Do not extend the permanent-session lifetime on each request.
    app.config['SESSION_REFRESH_EACH_REQUEST'] = False

    valid_response = client.get('/api/sessions')

    assert valid_response.status_code == 200

    # Allow enough time to cross the signed-cookie timestamp boundary.
    time.sleep(3)

    expired = client.get('/api/sessions')

    assert expired.status_code == 401

    assert expired.get_json()['error'] == (
        'Authentication required'
    )


def test_settings_endpoint_exposes_safe_configuration_only(app, client):
    from backend.extensions import db
    user = User(username='settings-user', role='analyst')
    user.set_password('password-123')
    db.session.add(user)
    db.session.commit()

    client.post('/api/auth/login', json={'username': 'settings-user', 'password': 'password-123'})
    response = client.get('/api/settings')
    assert response.status_code == 200
    payload = response.get_json()['settings']
    assert payload['risk_alert_threshold'] == 40
    assert 'ABUSEIPDB_API_KEY' not in str(payload)
    assert 'VIRUSTOTAL_API_KEY' not in str(payload)
    assert 'SMTP_PASSWORD' not in str(payload)
