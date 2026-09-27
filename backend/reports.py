from __future__ import annotations
import csv, io
from collections import Counter
from flask import current_app
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from backend.models import AttackSession, CowrieEvent, RiskScore, MITREMapping
from backend.analysis.recommendations import generate_recommendations

def session_data(session_id):
    s=AttackSession.query.filter_by(session_id=session_id).one_or_none()
    if not s: return None
    r=s.risk_scores[0] if s.risk_scores else None; maps=[m for m in s.mitre_mappings]
    return {'session':s,'events':s.events.order_by(CowrieEvent.timestamp.asc()).all(),'risk':r,'mitre':maps,'recommendations':generate_recommendations(s)}

def session_pdf(session_id):
    d=session_data(session_id)
    if not d: return None
    b=io.BytesIO(); doc=SimpleDocTemplate(b,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36); styles=getSampleStyleSheet(); story=[Paragraph('CyberHive Session Report',styles['Title']),Spacer(1,12)]
    s=d['session']; story += [Paragraph(f'Session ID: {s.session_id}',styles['BodyText']),Paragraph(f'Source IP: {s.source_ip}',styles['BodyText']),Paragraph(f'Protocol: {s.protocol}',styles['BodyText']),Paragraph(f'Username: {s.username or "N/A"}',styles['BodyText']),Paragraph(f'Commands: {s.command_count}',styles['BodyText']),Spacer(1,10)]
    if s.analysis: story += [Paragraph(f'Behavior: {s.analysis.behavior_label} ({s.analysis.behavior_confidence})',styles['BodyText']),Paragraph(f'Automation profile: {s.analysis.automation_profile}',styles['BodyText']),Spacer(1,8)]
    if d['risk']: story += [Paragraph(f'Risk: {d["risk"].score}/100 — {d["risk"].severity}',styles['Heading2']),Paragraph(f'Factors: {d["risk"].contributing_factors}',styles['BodyText']),Spacer(1,8)]
    story.append(Paragraph('Event Timeline',styles['Heading2'])); rows=[['Timestamp','Type','Command','Source']]+[[str(e.timestamp),e.event_type,e.command or '',e.source_ip or ''] for e in d['events']]
    t=Table(rows,repeatRows=1); t.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.25,colors.grey),('BACKGROUND',(0,0),(-1,0),colors.lightgrey),('FONTSIZE',(0,0),(-1,-1),7)])); story += [t,Spacer(1,10)]
    story.append(Paragraph('MITRE ATT&CK Mappings',styles['Heading2']))
    for m in d['mitre']: story.append(Paragraph(f'{m.technique_id} — {m.technique_name} — {m.tactic} — {m.evidence}',styles['BodyText']))
    story.append(Paragraph('Recommendations',styles['Heading2']))
    for r in d['recommendations']: story.append(Paragraph(f'{r["title"]}: {r["reason"]}',styles['BodyText']))
    doc.build(story); return b.getvalue()

def summary_pdf():
    sessions=AttackSession.query.all(); b=io.BytesIO(); doc=SimpleDocTemplate(b,pagesize=A4); styles=getSampleStyleSheet(); story=[Paragraph('CyberHive Security Summary',styles['Title']),Spacer(1,12)]
    risks=[s.risk_scores[0].score for s in sessions if s.risk_scores]; behaviors=Counter((s.analysis.behavior_label if s.analysis else 'Unclassified') for s in sessions); sources=Counter(s.source_ip for s in sessions); commands=Counter(e.command for e in CowrieEvent.query.all() if e.command)
    for text in [f'Total sessions: {len(sessions)}',f'Total events: {CowrieEvent.query.count()}',f'Average risk: {sum(risks)/len(risks):.2f}' if risks else 'Average risk: N/A',f'Behavior distribution: {dict(behaviors)}',f'Top sources: {sources.most_common(10)}',f'Top commands: {commands.most_common(10)}']:
        story.append(Paragraph(text,styles['BodyText'])); story.append(Spacer(1,6))
    doc.build(story); return b.getvalue()

def sessions_csv():
    out=io.StringIO(); w=csv.writer(out); w.writerow(['session_id','source_ip','protocol','username','start_time','end_time','duration','command_count','behavior','automation_profile','cluster_id','risk_score','severity'])
    for s in AttackSession.query.order_by(AttackSession.start_time.desc()).all():
        a=s.analysis; r=s.risk_scores[0] if s.risk_scores else None; w.writerow([s.session_id,s.source_ip,s.protocol,s.username or '',s.start_time or '',s.end_time or '',s.duration if s.duration is not None else '',s.command_count,a.behavior_label if a else '',a.automation_profile if a else '',a.cluster_id if a else '',r.score if r else '',r.severity if r else ''])
    return out.getvalue().encode('utf-8')
