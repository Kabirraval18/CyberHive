from __future__ import annotations
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any
import requests
from flask import current_app
from backend.extensions import db
from backend.models import IPIntelligence

URL='https://www.virustotal.com/api/v3/ip_addresses/{}'
PROVIDER_NAME='virustotal'

class VirusTotalError(RuntimeError):
    def __init__(self, message, *, status):
        super().__init__(message); self.status=status

def _now(): return datetime.now(timezone.utc).replace(tzinfo=None)

def _validate(ip):
    try: parsed=ipaddress.ip_address(ip.strip())
    except ValueError as e: raise VirusTotalError('Invalid IP address.', status='invalid_ip') from e
    if not parsed.is_global: raise VirusTotalError('IP address is not globally routable and will not be queried.', status='non_public_ip')
    return str(parsed)

def _serialize(r):
    return {'provider':r.provider,'ip_address':r.ip_address,'reputation':r.reputation,
            'abuse_confidence':r.abuse_confidence,'report_count':r.report_count,
            'country':r.country,'asn':r.asn,'isp':r.isp,'category_data':r.category_data,
            'provider_metadata':r.provider_metadata,'retrieved_at':r.retrieved_at.isoformat() if r.retrieved_at else None,
            'expires_at':r.expires_at.isoformat() if r.expires_at else None}

def _parse(payload, ip):
    if not isinstance(payload,dict) or not isinstance(payload.get('data'),dict):
        raise VirusTotalError('Provider response is malformed.','malformed_response')
    data=payload['data']; attrs=data.get('attributes')
    if not isinstance(attrs,dict): raise VirusTotalError('Provider response has no attributes.','malformed_response')
    if data.get('id') and data.get('id') != ip: raise VirusTotalError('Provider returned a different IP.','unexpected_response')
    stats=attrs.get('last_analysis_stats') or {}
    malicious=stats.get('malicious',0) or 0; suspicious=stats.get('suspicious',0) or 0
    total=sum(int(v or 0) for v in stats.values() if isinstance(v,(int,float)))
    detections=malicious+suspicious
    reputation=None
    if total: reputation=round(detections/total*100,2)
    return {'reputation':reputation,'abuse_confidence':None,'report_count':detections,
            'country':attrs.get('country'),'asn':str(attrs.get('asn')) if attrs.get('asn') is not None else None,
            'isp':attrs.get('as_owner') or attrs.get('network'),
            'category_data':{'last_analysis_stats':stats,'reputation':attrs.get('reputation')},
            'provider_metadata':{'type':data.get('type'),'id':data.get('id'),'last_analysis_date':attrs.get('last_analysis_date'),
                                 'whois':attrs.get('whois')},}

def lookup_virustotal(ip_address, *, force_refresh=False):
    try: ip=_validate(ip_address)
    except VirusTotalError as e: return {'success':False,'status':e.status,'error':str(e)}
    if not current_app.config.get('VIRUSTOTAL_ENABLED',True): return {'success':False,'status':'disabled','error':'VirusTotal is disabled.'}
    key=str(current_app.config.get('VIRUSTOTAL_API_KEY') or '').strip()
    if not key: return {'success':False,'status':'not_configured','error':'VirusTotal is not configured.'}
    cached=IPIntelligence.query.filter_by(ip_address=ip,provider=PROVIDER_NAME).one_or_none()
    if cached and not force_refresh and cached.expires_at and cached.expires_at > _now():
        return {'success':True,'status':'cache_hit','data':_serialize(cached)}
    try:
        resp=requests.get(URL.format(ip),headers={'x-apikey':key,'accept':'application/json'},timeout=10)
    except requests.Timeout as e: return {'success':False,'status':'timeout','error':'VirusTotal request timed out.'}
    except requests.RequestException as e: return {'success':False,'status':'provider_unavailable','error':f'VirusTotal unavailable: {e}'}
    if resp.status_code in (401,403): return {'success':False,'status':'authentication_error','error':'VirusTotal authentication failed.'}
    if resp.status_code==429: return {'success':False,'status':'rate_limited','error':'VirusTotal rate limit reached.'}
    if resp.status_code>=500: return {'success':False,'status':'provider_unavailable','error':'VirusTotal is unavailable.'}
    if resp.status_code>=400: return {'success':False,'status':'provider_error','error':f'VirusTotal returned HTTP {resp.status_code}.'}
    try: payload=resp.json()
    except ValueError as e: return {'success':False,'status':'malformed_response','error':'VirusTotal returned invalid JSON.'}
    try: normalized=_parse(payload,ip)
    except VirusTotalError as e: return {'success':False,'status':e.status,'error':str(e)}
    now=_now(); exp=now+timedelta(seconds=int(current_app.config.get('INTEL_CACHE_SECONDS',86400)))
    if cached is None: cached=IPIntelligence(ip_address=ip,provider=PROVIDER_NAME); db.session.add(cached)
    for k,v in normalized.items(): setattr(cached,k,v)
    cached.retrieved_at=now; cached.expires_at=exp
    db.session.commit()
    return {'success':True,'status':'success','data':_serialize(cached)}
