from __future__ import annotations
from backend.extensions import db
from backend.models import AttackSession, CowrieEvent, MITREMapping
RULES=[
 ('whoami','T1033','System Owner/User Discovery','Discovery',0.95),
 ('id','T1033','System Owner/User Discovery','Discovery',0.9),
 ('uname','T1082','System Information Discovery','Discovery',0.9),
 ('ls','T1083','File and Directory Discovery','Discovery',0.9),
 ('find','T1083','File and Directory Discovery','Discovery',0.9),
 ('ps','T1057','Process Discovery','Discovery',0.9),
 ('wget','T1105','Ingress Tool Transfer','Command and Control',0.9),
 ('curl','T1105','Ingress Tool Transfer','Command and Control',0.9),
]
def map_session(session_id, *, persist=True):
    session=AttackSession.query.filter_by(session_id=session_id).one_or_none()
    if not session: raise ValueError('Session not found')
    mappings=[]
    if persist:
        MITREMapping.query.filter_by(session_id=session_id).delete(synchronize_session=False)
    for e in session.events.order_by(CowrieEvent.timestamp.asc()).all():
        cmd=(e.command or '').strip(); low=cmd.lower()
        for token,tid,name,tactic,conf in RULES:
            if low==token or low.startswith(token+' '):
                evidence=f'Observed Cowrie command: {cmd}'
                m=MITREMapping(session_id=session_id,event_id=e.event_id,command=cmd,technique_id=tid,technique_name=name,tactic=tactic,evidence=evidence,confidence=conf)
                if persist: db.session.add(m)
                mappings.append({'event_id':e.event_id,'command':cmd,'technique_id':tid,'technique_name':name,'tactic':tactic,'evidence':evidence,'confidence':conf})
                break
    if persist: db.session.commit()
    return mappings
