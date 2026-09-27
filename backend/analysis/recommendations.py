def generate_recommendations(session, analysis=None, mappings=None):
    a=analysis or session.analysis; f=(a.behavioral_features if a else {}) or {}; out=[]
    failed=int(f.get('failed_login_count') or 0)
    if failed>=2 or (a and a.behavior_label=='Brute Force'):
        out.append({'id':'ssh-auth-controls','category':'Authentication','title':'Strengthen SSH authentication controls','reason':f'{failed} failed authentication attempts were observed.','actions':['Review exposed SSH access','Apply rate limiting or connection throttling','Use strong credentials or key-based authentication where appropriate']})
    if a and a.behavior_label=='Reconnaissance / Discovery' or int(f.get('discovery_command_count') or 0)>0:
        out.append({'id':'enumeration-monitoring','category':'Monitoring','title':'Review discovery and enumeration exposure','reason':f"{int(f.get('discovery_command_count') or 0)} discovery-oriented commands were observed.",'actions':['Review exposed services','Monitor repeated enumeration patterns','Restrict unnecessary management interfaces']})
    transfers=int(f.get('transfer_event_count') or 0)+int(f.get('transfer_command_count') or 0)
    if transfers or (a and a.behavior_label=='Payload Activity'):
        out.append({'id':'artifact-investigation','category':'Payload','title':'Investigate transferred artifacts','reason':f'{transfers} transfer indicators were observed.','actions':['Review downloaded artifact metadata','Preserve relevant evidence','Review outbound network controls']})
    if int(f.get('persistence_command_count') or 0)>0 or (a and a.behavior_label=='Persistence Attempt'):
        out.append({'id':'persistence-review','category':'Persistence','title':'Review persistence mechanisms','reason':'Persistence-related evidence was observed.','actions':['Inspect startup and scheduled execution locations','Review account and service changes','Preserve evidence before remediation']})
    if not out: out.append({'id':'continue-monitoring','category':'Monitoring','title':'Continue monitoring the session','reason':'The available evidence does not support a stronger targeted recommendation.','actions':['Retain telemetry','Monitor repeated source behavior','Review new activity as it arrives']})
    return out
