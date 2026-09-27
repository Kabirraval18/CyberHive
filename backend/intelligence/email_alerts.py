from __future__ import annotations
import smtplib
from email.message import EmailMessage
from flask import current_app

def send_alert_email(alert, *, context=None):
    if not current_app.config.get('EMAIL_ALERTS_ENABLED',False): return {'success':False,'status':'disabled'}
    host=str(current_app.config.get('SMTP_HOST') or '').strip(); sender=str(current_app.config.get('SMTP_FROM') or '').strip(); recipients=current_app.config.get('ALERT_EMAIL_RECIPIENTS') or []
    if not host or not sender or not recipients: return {'success':False,'status':'not_configured'}
    msg=EmailMessage(); msg['Subject']=f'CyberHive alert: {alert.severity} risk {alert.risk_score}'; msg['From']=sender; msg['To']=', '.join(recipients)
    c=context or {}; msg.set_content(f"CyberHive security alert\n\nSession: {alert.session_id}\nRisk: {alert.risk_score}\nSeverity: {alert.severity}\nSource: {c.get('source_ip','unknown')}\nBehavior: {c.get('behavior','unknown')}\n\n{alert.message}")
    try:
        with smtplib.SMTP(host,int(current_app.config.get('SMTP_PORT',587)),timeout=10) as smtp:
            smtp.starttls()
            user=current_app.config.get('SMTP_USERNAME'); password=current_app.config.get('SMTP_PASSWORD')
            if user: smtp.login(user,password)
            smtp.send_message(msg)
        return {'success':True,'status':'sent'}
    except (OSError,smtplib.SMTPException) as exc:
        return {'success':False,'status':'smtp_error','error':str(exc)}
