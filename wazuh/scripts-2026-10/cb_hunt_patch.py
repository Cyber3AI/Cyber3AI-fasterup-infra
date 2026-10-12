# -*- coding: utf-8 -*-
"""Patch idempotent CyberBot: notificări CYBER3 Threat Hunt (fără blocare, fără AI).
Utilizare: python3 cb_hunt_patch.py /var/ossec/integrations/cyberbot.py"""
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
if "def handle_threat_hunt(" in s:
    print("cyberbot.py: ramura Threat Hunt există deja")
    sys.exit(0)

FUNC = r'''# ============ CYBER3 THREAT HUNT (v3.7 — 10 oct 2026) ============
# Constatările vânătorii automate (portal, cyber3-threat-hunt) vin ca evenimente Wazuh (regula 100260, grup cyber3_threat_hunt).
# Doar NOTIFICARE pe canalele existente (aceeași izolare de tenant ca alertele): fără blocare, fără AI, cu deduplicare.
HUNT_NAMES = {
    'H1': 'Răspuns reușit la atac (date sensibile livrate)', 'H2': 'Încărcare de cod acceptată (HTTP 200)',
    'H3': 'Stager PowerShell urmat de C2', 'H4': 'Comunicare C2 permisă, inițiată din interior',
    'H5': 'Volum mare ieșit spre o adresă externă', 'H6': 'Honeytoken declanșat',
    'H7': 'Acces la distanță pe o stație nouă', 'H8': 'Senzor fără alerte de rețea',
}


def _hunt_ro_time(t):
    try:
        from datetime import datetime
        from zoneinfo import ZoneInfo
        return datetime.fromisoformat(str(t).replace('Z', '+00:00')).astimezone(ZoneInfo('Europe/Bucharest')).strftime('%d.%m.%Y %H:%M')
    except Exception:
        return str(t)


def handle_threat_hunt(alert):
    import html as _h
    h = (alert.get('data') or {}).get('cyber3_hunt') or {}
    fid = str(h.get('id') or '')
    sev = str(h.get('severity') or '')
    agent = str(h.get('agent') or 'unknown')
    agent_id = str(h.get('agent_id') or '000')
    if not fid or sev not in ('CRITIC', 'ÎNALT'):
        log_event('SUPPRESSED', f'hunt_ignored id={fid} sev={sev} agent={agent}')
        return
    if is_duplicate(agent_id, fid, 'HUNT'):
        log_event('SUPPRESSED', f'hunt_duplicate id={fid} agent={agent}')
        return
    client_info = resolve_client(agent, agent_id)
    e = lambda x: _h.escape(str(x if x is not None else ''))
    emoji = '🚨' if sev == 'CRITIC' else '🔴'
    hunt = str(h.get('hunt') or '')
    msg = f"""{emoji} <b>CYBER3 Threat Hunt — {e(sev)}</b>

<b>Client:</b> {e(client_info.get('name', agent))}
<b>Constatare:</b> {e(h.get('title'))}
<b>Detalii:</b> {e(h.get('detail'))}
<b>Stație / gazdă:</b> {e(h.get('host'))} | <b>Senzor:</b> {e(agent)}
<b>Interval:</b> {e(_hunt_ro_time(h.get('first_seen')))} → {e(_hunt_ro_time(h.get('last_seen')))} (ora României)
<b>Vânătoare:</b> {e(hunt)} — {e(HUNT_NAMES.get(hunt, ''))}

<b>Unde vedeți:</b> Portal SOC → ▸ HUNT

<i>FasterUp AI Autonomous</i>"""
    if os.environ.get('HUNT_DRY_RUN') == '1':
        log_event('HUNT_DRYRUN', f'id={fid} sev={sev} agent={agent} chats={len(client_info.get("telegram_chat_ids", []))} email={bool(client_info.get("email"))} bytes={len(msg)}')
        return
    sent = False
    for _cid in client_info.get('telegram_chat_ids', []):
        if send_telegram(_cid, msg, tag='HUNT'):
            sent = True
    emails = {x for x in (client_info.get('email'), DEFAULT_EMAIL) if x}
    for _to in emails:
        if send_email(_to, f"FasterUp SOC - Threat Hunt {sev} - {client_info.get('name', agent)}", msg, tag='HUNT'):
            sent = True
    mark_sent(agent_id, fid, 'HUNT')
    log_event('HUNT', f'id={fid} sev={sev} agent={agent} hunt={hunt} host={h.get("host")} sent={sent}')


'''
anchor_def = "def process_alert(alert_json):"
assert s.count(anchor_def) == 1, "ancora process_alert"
s = s.replace(anchor_def, FUNC + anchor_def)

BRANCH = '''        # --- v3.7: CYBER3 Threat Hunt → doar notificare (fără blocare / AI), înaintea oricărui filtru ---
        if 'cyber3_threat_hunt' in (alert.get('rule', {}).get('groups') or []):
            handle_threat_hunt(alert)
            return

'''
anchor_br = "        # --- FILTRE HARD (înainte de orice) ---"
assert s.count(anchor_br) == 1, "ancora FILTRE HARD"
s = s.replace(anchor_br, BRANCH + anchor_br)
import re as _re
if not _re.search(r"^import\s+(?:[\w, ]*\b)?os\b", s, _re.M):
    m = _re.search(r"^import .*$", s, _re.M)
    s = s[:m.end()] + "\nimport os" + s[m.end():]
open(p, "w", encoding="utf-8").write(s)
print("cyberbot.py: ramura Threat Hunt adăugată")
