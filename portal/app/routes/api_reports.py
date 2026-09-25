# -*- coding: utf-8 -*-
"""Report generation endpoints — REAL DATA from OpenSearch + Wazuh API.

v3 (03 aug 2026): reconstructie completa.
  - Sectiunea VEDETA "Atacuri blocate (extern)" pe date REALE de active-response
    (firewall-drop, rule.id=651), sursa PUBLICA, exhaustiv pe AMBELE campuri IP
    (data.srcip + data.parameters.alert.data.src_ip). ONESTITATE: separata clar de
    "evenimente nivel 10+"; clientul plateste blocarea reala, nu nivel 10+.
  - REGULA DE EXCLUDERE OBLIGATORIE: infrastructura proprie (SOC 10.0.0.0/24,
    tuneluri 10.1.0.0/16, retea scan 10.242.0.0/16) + IP-ul de scan al senzorului
    pe LAN-ul clientului sunt excluse din blocarile "externe".
  - R13 (port->serviciu, portul bate app_proto gresit), R14 (MITRE integral,
    unificare ET<->Wazuh fara dubla numarare), R15 (audit MISP/Suricata = activitate
    CYBER3), R16 (anexa actiuni per terminal), R2 (nota context senzor atipic).
  - Iesire PDF + Word (.docx) + routing pe organizatie (FASTERUP_DIRECT -> laptop,
    ICI_SOC -> portal).

REGULA GENERIC: niciun nume real de client/organizatie/locatie/persoana in continut.
"""
from flask import Blueprint, jsonify, request, current_app, send_file, g
from datetime import datetime, timezone, timedelta
import os
import io
import re
import ipaddress
import sqlite3

from app.services.report_generator import generate_pdf, R16_L
from app.services.opensearch_client import get_client as get_opensearch, CLIENT_NOISE_GROUPS
from app.services.wazuh_client import get_client as get_wazuh
from app.utils.auth_decorators import require_org_access

bp = Blueprint('reports', __name__)


# ============================================================================
# R13 — PORT -> SERVICIU + normalizare app_proto ("failed"/necunoscut -> generic)
# ============================================================================
# Verificat pe date: Suricata raporteaza frecvent app_proto="http" pe porturi
# NON-HTTP (ex. port 22 cu proto "http"). CORECTIE: pentru porturi bine-cunoscute
# portul e autoritatea; app_proto se foloseste doar cand portul e efemer/necunoscut.
PORT_SVC = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
    69: 'TFTP', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 111: 'RPCbind', 123: 'NTP',
    135: 'MSRPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP',
    161: 'SNMP', 162: 'SNMP-Trap', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
    464: 'Kerberos (kpasswd)', 465: 'SMTPS', 500: 'IKE/IPsec', 514: 'Syslog',
    515: 'Printer (LPD)', 587: 'SMTP', 623: 'IPMI', 636: 'LDAPS', 992: 'Telnet-TLS', 993: 'IMAPS',
    995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL', 1434: 'MSSQL', 1521: 'Oracle',
    1723: 'PPTP', 1883: 'MQTT', 1900: 'SSDP/UPnP', 2049: 'NFS', 2375: 'Docker',
    2376: 'Docker (TLS)', 3268: 'LDAP (Global Catalog)', 3269: 'LDAPS (Global Catalog)',
    3306: 'MySQL', 3389: 'RDP', 4444: 'port suspect (implicit Metasploit)', 4500: 'IPsec NAT-T',
    5060: 'SIP', 5061: 'SIP-TLS', 5353: 'mDNS', 5432: 'PostgreSQL', 5900: 'VNC',
    5985: 'WinRM', 5986: 'WinRM (HTTPS)', 6379: 'Redis', 6667: 'IRC', 8000: 'HTTP',
    8080: 'HTTP', 8443: 'HTTPS', 8883: 'MQTT (TLS)', 9100: 'Printer (RAW)',
    9200: 'Elasticsearch', 9300: 'Elasticsearch', 11211: 'Memcached',
    27017: 'MongoDB', 47808: 'BACnet', 502: 'Modbus', 20000: 'DNP3', 102: 'S7comm',
}
PROTO_LABEL = {
    'http': 'HTTP', 'tls': 'HTTPS/TLS', 'dns': 'DNS', 'smb': 'SMB', 'ssh': 'SSH',
    'rdp': 'RDP', 'ldap': 'LDAP', 'snmp': 'SNMP', 'ntp': 'NTP', 'sip': 'SIP',
    'krb5': 'Kerberos', 'mdns': 'mDNS', 'quic': 'QUIC', 'ftp': 'FTP', 'smtp': 'SMTP',
    'imap': 'IMAP', 'pop3': 'POP3', 'tftp': 'TFTP', 'dhcp': 'DHCP', 'nfs': 'NFS',
    'bittorrent-dht': 'BitTorrent DHT', 'dcerpc': 'MSRPC/DCERPC', 'modbus': 'Modbus',
    'dnp3': 'DNP3', 'enip': 'EtherNet/IP',
}
EPHEMERAL_MIN = 32768


def svc_for_port(port, app_proto, lang='ro'):
    """R13 — denumirea serviciului pentru (port, app_proto). Portul bine-cunoscut e
    autoritatea; app_proto valid doar pentru porturi efemere/necunoscute; nu tipareste
    niciodata 'failed'/'unknown'."""
    unknown = 'neidentificat' if lang == 'ro' else 'unidentified'
    ephem = 'port dinamic (client)' if lang == 'ro' else 'dynamic port (client)'
    try:
        pnum = int(port)
    except (TypeError, ValueError):
        pnum = -1
    proto = (app_proto or '').strip().lower()
    if pnum in PORT_SVC:
        return PORT_SVC[pnum]
    if proto and proto not in ('failed', 'unknown', 'template', 'ntlm'):
        return PROTO_LABEL.get(proto, proto.upper())
    if pnum >= EPHEMERAL_MIN:
        return ephem
    return unknown


# ============================================================================
# R14 — DENUMIRI MITRE ATT&CK CORECTE (normalizare + unificare ET <-> Wazuh)
# ============================================================================
def _mkey(name):
    """Cheie canonica insensibila la _ / spatiu / cratima / caz."""
    return re.sub(r'[^a-z0-9]', '', str(name or '').lower())


MITRE_TECH_CANON = {
    _mkey('System Location Discovery'):        ('T1614', 'System Location Discovery'),
    _mkey('Exploit Public-Facing Application'): ('T1190', 'Exploit Public-Facing Application'),
    _mkey('Exploit Public Facing Application'): ('T1190', 'Exploit Public-Facing Application'),
    _mkey('Lateral Tool Transfer'):            ('T1570', 'Lateral Tool Transfer'),
    _mkey('File and Directory Discovery'):     ('T1083', 'File and Directory Discovery'),
    _mkey('Dynamic Resolution'):               ('T1568', 'Dynamic Resolution'),
    _mkey('Exploitation of Remote Services'):  ('T1210', 'Exploitation of Remote Services'),
    _mkey('System Information Discovery'):      ('T1082', 'System Information Discovery'),
    _mkey('Exfiltration Over Web Service'):     ('T1567', 'Exfiltration Over Web Service'),
    _mkey('Remote Services'):                  ('T1021', 'Remote Services'),
    _mkey('Phishing'):                         ('T1566', 'Phishing'),
    _mkey('Server Software Component'):        ('T1505', 'Server Software Component'),
    _mkey('Drive-by Compromise'):              ('T1189', 'Drive-by Compromise'),
    _mkey('Drive by Compromise'):              ('T1189', 'Drive-by Compromise'),
    _mkey('Obfuscated Files or Information'):   ('T1027', 'Obfuscated Files or Information'),
    _mkey('Valid Accounts'):                   ('T1078', 'Valid Accounts'),
    _mkey('Exploitation for Privilege Escalation'): ('T1068', 'Exploitation for Privilege Escalation'),
    _mkey('Stored Data Manipulation'):         ('T1565.001', 'Stored Data Manipulation'),
    _mkey('Sudo and Sudo Caching'):            ('T1548.003', 'Sudo and Sudo Caching'),
    _mkey('Application Layer Protocol'):        ('T1071', 'Application Layer Protocol'),
    _mkey('Disable or Modify Tools'):          ('T1562.001', 'Impair Defenses: Disable or Modify Tools'),
    _mkey('Data Destruction'):                 ('T1485', 'Data Destruction'),
    _mkey('File Deletion'):                    ('T1070.004', 'Indicator Removal: File Deletion'),
    _mkey('Network Sniffing'):                 ('T1040', 'Network Sniffing'),
    _mkey('Password Guessing'):                ('T1110.001', 'Brute Force: Password Guessing'),
    _mkey('Create Account'):                   ('T1136', 'Create Account'),
    _mkey('Cron'):                             ('T1053.003', 'Scheduled Task/Job: Cron'),
    _mkey('Brute Force'):                      ('T1110', 'Brute Force'),
    _mkey('Rootkit'):                          ('T1014', 'Rootkit'),
    _mkey('SSH'):                              ('T1021.004', 'Remote Services: SSH'),
    _mkey('Ingress Tool Transfer'):            ('T1105', 'Ingress Tool Transfer'),
    _mkey('OS Credential Dumping'):            ('T1003', 'OS Credential Dumping'),
    _mkey('Command and Scripting Interpreter'): ('T1059', 'Command and Scripting Interpreter'),
}
MITRE_TACTIC_CANON = {
    _mkey('Reconnaissance'):      ('TA0043', 'Reconnaissance'),
    _mkey('Resource Development'): ('TA0042', 'Resource Development'),
    _mkey('Initial Access'):      ('TA0001', 'Initial Access'),
    _mkey('Execution'):           ('TA0002', 'Execution'),
    _mkey('Persistence'):         ('TA0003', 'Persistence'),
    _mkey('Privilege Escalation'): ('TA0004', 'Privilege Escalation'),
    _mkey('Defense Evasion'):     ('TA0005', 'Defense Evasion'),
    _mkey('Credential Access'):   ('TA0006', 'Credential Access'),
    _mkey('Discovery'):           ('TA0007', 'Discovery'),
    _mkey('Lateral Movement'):    ('TA0008', 'Lateral Movement'),
    _mkey('Collection'):          ('TA0009', 'Collection'),
    _mkey('Exfiltration'):        ('TA0010', 'Exfiltration'),
    _mkey('Command and Control'): ('TA0011', 'Command and Control'),
    _mkey('Impact'):              ('TA0040', 'Impact'),
}


def _pretty_fallback(name):
    s = str(name or '').replace('_', ' ').strip()
    words = []
    for w in s.split():
        if w.islower():
            words.append(w if w in ('and', 'or', 'of', 'the', 'for', 'to') else w.capitalize())
        else:
            words.append(w)
    out = ' '.join(words)
    return out[0].upper() + out[1:] if out else out


def mitre_technique(name):
    hit = MITRE_TECH_CANON.get(_mkey(name))
    return hit if hit else ('', _pretty_fallback(name))


def mitre_tactic(name):
    hit = MITRE_TACTIC_CANON.get(_mkey(name))
    return hit if hit else ('', _pretty_fallback(name))


def build_mitre(a5):
    """R14 — unifica ET si Wazuh pe ID/nume canonic (fara dublare). (tactics, techniques)."""
    tac = {}
    for src in ('tactics_et', 'tactics_wz'):
        for b in a5.get(src, {}).get('buckets', []):
            tid, tname = mitre_tactic(b['key'])
            key = tid or _mkey(tname)
            e = tac.setdefault(key, {'name': tname, 'id': tid, 'count': 0})
            e['count'] += b['doc_count']
    tactics = sorted(tac.values(), key=lambda x: -x['count'])[:8]

    tech = {}
    for b in a5.get('tech_et', {}).get('buckets', []):
        tid, tname = mitre_technique(b['key'])
        et_ids = b.get('tid', {}).get('buckets', [])
        if not tid and et_ids:
            tid = et_ids[0]['key']
        key = tid or _mkey(tname)
        e = tech.setdefault(key, {'name': tname, 'id': tid, 'count': 0})
        e['count'] += b['doc_count']
    for b in a5.get('tech_wz', {}).get('buckets', []):
        tid, tname = mitre_technique(b['key'])
        key = tid or _mkey(tname)
        e = tech.setdefault(key, {'name': tname, 'id': tid, 'count': 0})
        e['count'] += b['doc_count']
    techniques = sorted(tech.values(), key=lambda x: -x['count'])[:10]
    return tactics, techniques


# ============================================================================
# SECTIUNEA VEDETA — atacuri EXTERNE blocate REAL (active-response, rule.id=651)
# ============================================================================
# Prefixe private / infra proprie de EXCLUS din blocarile "externe":
EXCLUDE_PREFIXES = (
    ['10.', '192.168.', '127.', '169.254.', '0.', '100.64.', '100.65.', 'fe80', '::1']
    + [f'172.{i}.' for i in range(16, 32)]
)
_BLK_IP_FIELDS = ('data.srcip', 'data.parameters.alert.data.src_ip')  # mutual exclusiv per doc
_BLK_SIG_FIELD = 'data.parameters.alert.data.alert.signature'
MIRROR_SENSORS = {'ICISOC107'}  # senzori mirror/monitorizare (NU blocheaza)
# Strat 1 IPS: senzori pe care Suricata ruleaza IDS pasiv (nu blocheaza la fir) -> stratul 1 NU apare ca activ
IDS_ONLY_SENSORS = {'ICISOC107', 'ICISOC110'}
# Surse LEGITIME care au fost blocate eronat de IPS (FP) -> excluse din cifrele de atac
IPS_LEGIT_SRC_PREFIX = ('217.156.52.',)   # ANAF / STS (static.anaf.ro) - FP SID 2016540, corectat 24 sep 2026
# Straturile 5-7 (Cloud Edge / EDR-XDR / mobil) apar DOAR la clientii cu aplicatia CYBER3 instalata pe
# dispozitivele lor (regula operator 24 sep 2026: straturile inactive NU se mentioneaza deloc).
ENDPOINT_LAYER_CLIENTS = set()


def _cyberbot_blocks_period(client_id, client_code, since_iso, until_iso):
    """Stratul 4: blocari REALE CyberBot (BLOCK_IP success=True + PERMA_REBLOCK) pe PERIOADA EXACTA,
    pentru acest senzor (cheia din log = id agent SAU nume). None daca log-ul nu poate fi citit."""
    try:
        import subprocess
        from app.routes.api_wazuh import get_cyberbot
        cb = get_cyberbot()
        cmd = cb._run_on_log_host("grep -hE '\\[BLOCK_IP\\].*success=True|\\[PERMA_REBLOCK\\]' " + cb.log_path + " | grep -vE 'ip=(10[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[01])[.])'")
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode not in (0, 1):
            return None
        s = since_iso[:19].replace('T', ' '); u = until_iso[:19].replace('T', ' ')
        keys = {str(client_id), (client_code or '').lower(), (client_code or '').upper()}
        n = 0
        for line in res.stdout.splitlines():
            m = re.match(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC\].*?agent=([^\s,]+)', line)
            if m and s <= m.group(1) < u and m.group(2) in keys:
                n += 1
        return n
    except Exception:
        return None


def _l2shield_state(client_code):
    """Stratul 3: L2 Shield (ebtables) de pe senzor, din NOC. None = neinstalat / necunoscut."""
    try:
        import requests as _rq
        tok = open('/opt/fasterup-portal/.noc_read_token').read().strip()
        r = _rq.get('https://cyber3-noc.cyber3.workers.dev/v1/noc/l2shield',
                    headers={'Authorization': 'Bearer ' + tok, 'User-Agent': 'cyber3-noc-agent/2.0'}, timeout=6)
        if not r.ok:
            return None
        node = ((r.json() or {}).get('by_node') or {}).get((client_code or '').lower())
        if not node or not int(node.get('armed', 0)):
            return None
        return {'mode': node.get('mode'), 'rules': int(node.get('rules', 0)), 'blocks': int(node.get('blocks', 0))}
    except Exception:
        return None


AR_BLIND_WINDOW_FILE = '/opt/fasterup-portal/data/ar_blind_window_20260915.json'


def _ar_blind_window_count(client_code, since_iso, until_iso):
    """Stratul 2 — blocari AR REALE executate in fereastra 15.09 ~10:30 → 24.09 09:58 UTC, cand
    evenimentele nu au ajuns in indexer (format log \"command\": \"add\" nerecunoscut de regula 100651).
    Extrase o singura data din active-responses.log al fiecarui senzor (fisier de date, fereastra inchisa);
    se numara doar cele din perioada raportului. 0 daca fisierul lipseste."""
    try:
        import json as _json
        rows = (_json.load(open(AR_BLIND_WINDOW_FILE)).get('sensors') or {}).get((client_code or '').lower()) or []
        s = since_iso[:19].replace('T', ' '); u = until_iso[:19].replace('T', ' ')
        return sum(1 for ts, _ip in rows if s <= ts < u)
    except Exception:
        return 0


def _active_layers(client_id, client_code, since_iso, until_iso, blocked):
    """Straturile de blocare ACTIVE la acest senzor, cu interventiile din perioada raportului.
    Doar straturile active apar (nici o mentiune despre cele inactive)."""
    code = (client_code or '').upper()
    if blocked.get('mode') == 'mirror':
        return []
    L = []
    if code not in IDS_ONLY_SENSORS:
        L.append({'n': 1, 'name': 'Rețea — IPS inline (Suricata)',
                  'mech': 'Pachetul ostil este picat la fir, în milisecunde, pe baza semnăturilor și a analizei de protocol.',
                  'count': int(blocked.get('ips_events', 0))})
    L.append({'n': 2, 'name': 'Gazdă — Active Response (regula 651)',
              'mech': 'Regulă firewall-drop scrisă automat pe senzor, care oprește sursa atacului.',
              'count': int(blocked.get('external_events', 0))
                       + _ar_blind_window_count(client_code, since_iso, until_iso)})
    l2 = _l2shield_state(client_code)
    if l2:
        L.append({'n': 3, 'name': 'Ethernet — L2 Shield',
                  'mech': 'Filtrare nativă la nivel Ethernet: oprește falsificarea gateway-ului (ARP spoofing / MITM).',
                  'count': l2['blocks'], 'note': 'armat, mod %s, %d reguli' % (l2.get('mode') or 'drop', l2['rules'])})
    cbn = _cyberbot_blocks_period(client_id, client_code, since_iso, until_iso)
    L.append({'n': 4, 'name': 'Decizie — CyberBot Fusion (AI)',
              'mech': 'Fuziune AI a surselor de context; decizie autonomă de blocare în 2–11 secunde.',
              'count': cbn if cbn is not None else None})
    return L


def _blocked_priv_musts(exclude_ips=None):
    """must_not care elimina IP-urile private/infra + scaner senzor, pe AMBELE campuri."""
    mn = []
    for f in _BLK_IP_FIELDS:
        for p in EXCLUDE_PREFIXES:
            mn.append({'prefix': {f: p}})
    for ip in (exclude_ips or []):
        for f in _BLK_IP_FIELDS:
            mn.append({'term': {f: ip}})
    return mn


# ---- EXCLUDERE la NIVEL base_filter (se aplica la TOATE sectiunile) ----
# Infrastructura proprie SOC care NU e trafic al Beneficiarului:
#   SOC 10.0.0.0/24, tuneluri WireGuard 10.1.0.0/16, retea de scan 10.242.0.0/16.
# Pe octeti curati -> prefixe de string sigure pentru query 'prefix'.
INFRA_EXCLUDE_PREFIXES = ('10.0.0.', '10.1.', '10.242.')
# Toate variantele de camp IP din wazuh-alerts (unele indecsi/decodoare difera).
BASE_IP_FIELDS = ('data.src_ip', 'data.srcip', 'data.dest_ip', 'data.dstip')


def _infra_exclude_musts(exclude_ips=None):
    """Clauze must_not care exclud ORICE alerta unde src SAU dst e in infra proprie
    (SOC/tunel/scan) sau egal cu IP-ul de scan al senzorului (auto-detectat), pe TOATE
    variantele de camp IP. Se pune in base_filter => mostenit de toate interogarile
    (incidente, top-ip, tinte, R16, MITRE, severitate, evolutie)."""
    mn = []
    for f in BASE_IP_FIELDS:
        for p in INFRA_EXCLUDE_PREFIXES:
            mn.append({'prefix': {f: p}})
    for ip in (exclude_ips or []):
        for f in BASE_IP_FIELDS:
            mn.append({'term': {f: ip}})
    return mn


# ============================================================================
# REGULA ICISOC: se EXCLUD din raportul de alerte TOATE alertele generate de noi.
# 1) evenimente gazda/senzor (Wazuh/OS); 2) zgomot motor Suricata; 3) active-response
# propriu (651, ramane doar in sectiunea "Atacuri blocate"); 4) threat-intel propriu
# (MISP IOC / CYBER3). Raman DOAR detectiile reale ET/GPL de trafic ostil.
# ============================================================================
OUR_ALERT_GROUPS = ['ossec', 'systemd', 'local', 'syslog', 'pam', 'authentication_success',
                    'authentication_failed', 'sudo', 'audit', 'wazuh', 'active_response']
OUR_ALERT_DESC = ['SURICATA*', '*MISP IOC*', '*CYBER3*', '*Wazuh agent*',
                  '*Agent event queue*', '*USB*', '*firewall-drop*']


def _our_service_musts():
    """must_not: alerte generate de infrastructura/serviciile noastre (cerinta ICISOC).
    Tiparele se aplica pe AMBELE campuri de semnatura (rule.description SI data.alert.signature),
    fiindca regulile proprii (MISP IOC / CYBER3) si zgomotul de motor Suricata pot fi in oricare."""
    mn = [{'terms': {'rule.id': ['651', '100651']}}, {'terms': {'rule.groups': OUR_ALERT_GROUPS}}]
    for p in OUR_ALERT_DESC + ['SURICATA*', 'Suricata: anomaly*']:
        mn.append({'wildcard': {'rule.description': p}})
        mn.append({'wildcard': {'data.alert.signature': p}})
    return mn


def _detect_scan_ip(os_client, client_id, since_iso, until_iso):
    """BEST-EFFORT: IP-ul de scan/mgmt al senzorului pe LAN clientului = sursa INTERNA
    care emite semnaturi de scanare (ET SCAN / Nmap)."""
    found = set()
    try:
        q = {
            'size': 0,
            'query': {'bool': {'must': [
                {'range': {'@timestamp': {'gte': since_iso, 'lt': until_iso}}},
                {'term': {'agent.id': client_id}},
                # data.alert.signature e KEYWORD: match_phrase = egalitate pe intreg
                # sirul (nu matcheaza NICIODATA "ET SCAN Possible Nmap..."). Folosim
                # wildcard ca sa prindem semnatura ORIUNDE in text.
                {'bool': {'should': [
                    {'wildcard': {'data.alert.signature': '*ET SCAN*'}},
                    {'wildcard': {'data.alert.signature': '*Nmap*'}},
                    {'wildcard': {_BLK_SIG_FIELD: '*ET SCAN*'}},
                    {'wildcard': {_BLK_SIG_FIELD: '*Nmap*'}},
                ], 'minimum_should_match': 1}},
            ]}},
            'aggs': {'s1': {'terms': {'field': 'data.src_ip', 'size': 3}},
                     's2': {'terms': {'field': _BLK_IP_FIELDS[1], 'size': 3}}},
        }
        r = os_client._search('wazuh-alerts-*', q)
        a = r.get('aggregations', {})
        for key in ('s1', 's2'):
            for b in a.get(key, {}).get('buckets', []):
                ip = b.get('key', '')
                if ip and any(ip.startswith(p) for p in EXCLUDE_PREFIXES) and b['doc_count'] >= 20:
                    found.add(ip)
    except Exception:
        pass
    return found


def _valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False


def _blocked_external(os_client, client_id, since_iso, until_iso, lx,
                      client_code=None, exclude_ips=None, interval='1d'):
    """CE PLATESTE CLIENTUL: atacuri EXTERNE blocate REAL (active-response firewall-drop,
    rule.id=651), sursa = IP PUBLIC. Exhaustiv pe AMBELE campuri IP. Returneaza dict."""
    out = {
        'mode': 'mirror' if ((client_code or '').upper() in MIRROR_SENSORS) else 'inline',
        'total_651': 0, 'external_events': 0, 'external_ips': 0, 'top_country': None,
        'top_ips': [], 'threats': [], 'timeline': {'interval': interval, 'bins': []},
        'countries': [], 'geo_partial': False, 'zero_floor': 2,
        'ips_events': 0, 'ips_ips': 0, 'ips_top_ips': [], 'ips_threats': [], 'ips_legit_excluded': 0,
    }
    base = [
        {'range': {'@timestamp': {'gte': since_iso, 'lt': until_iso}}},
        {'term': {'agent.id': client_id}},
        {'terms': {'rule.id': ['651', '100651']}},
    ]
    try:
        exclude_ips = set(exclude_ips or []) | _detect_scan_ip(os_client, client_id, since_iso, until_iso)

        # (0) STRATUL 1 — IPS inline (Suricata nfqueue): drop la fir, event data.alert.action=blocked.
        # Independent de Active Response (651). Poate fi 0 pe senzori in mod IDS/mirror sau in
        # perioade anterioare activarii inline; se afiseaza onest doar cand exista intr-adevar.
        try:
            ips_base = [
                {'range': {'@timestamp': {'gte': since_iso, 'lt': until_iso}}},
                {'term': {'agent.id': client_id}},
                {'term': {'data.alert.action': 'blocked'}},
            ]
            # Trafic LEGITIM blocat eronat (ex. ANAF static.anaf.ro, FP SID 2016540, corectat 24 sep 2026):
            # NU e atac -> exclus din cifre, numarat separat pt nota de transparenta.
            legit_musts = [{'prefix': {'data.src_ip': p}} for p in IPS_LEGIT_SRC_PREFIX]
            ips_q = {'size': 0, 'track_total_hits': True,
                     'query': {'bool': {'must': ips_base,
                                        'must_not': _blocked_priv_musts(exclude_ips) + legit_musts}},
                     'aggs': {'uips': {'cardinality': {'field': 'data.src_ip'}},
                              'src': {'terms': {'field': 'data.src_ip', 'size': 10},
                                      'aggs': {'geo': {'terms': {'field': 'GeoLocation.country_name', 'size': 1}}}},
                              'sig': {'terms': {'field': 'data.alert.signature', 'size': 8}}}}
            ir = os_client._search('wazuh-alerts-*', ips_q)
            ia = ir.get('aggregations', {})
            out['ips_events'] = ir.get('hits', {}).get('total', {}).get('value', 0)
            out['ips_ips'] = int(ia.get('uips', {}).get('value', 0))
            out['ips_top_ips'] = [{'ip': b['key'], 'count': b['doc_count'],
                                   'country': ((b.get('geo') or {}).get('buckets') or [{}])[0].get('key')}
                                  for b in ia.get('src', {}).get('buckets', []) if _valid_ip(b.get('key', ''))]
            out['ips_threats'] = [{'name': b['key'], 'count': b['doc_count']}
                                  for b in ia.get('sig', {}).get('buckets', [])]
            if legit_musts:
                lq = {'size': 0, 'track_total_hits': True,
                      'query': {'bool': {'must': ips_base,
                                         'should': legit_musts, 'minimum_should_match': 1}}}
                lr = os_client._search('wazuh-alerts-*', lq)
                out['ips_legit_excluded'] = lr.get('hits', {}).get('total', {}).get('value', 0)
        except Exception:
            pass

        # (1) TOTAL 651 real — track_total_hits OBLIGATORIU (altfel plafon 10000)
        rt = os_client._search('wazuh-alerts-*',
                               {'size': 0, 'track_total_hits': True, 'query': {'bool': {'must': base}}})
        out['total_651'] = rt.get('hits', {}).get('total', {}).get('value', 0)
        if out['total_651'] == 0:
            return out

        # (2) EXTERN (public) = 651 minus IP-uri private/infra/scaner, pe ambele campuri
        date_sub = {'first': {'min': {'field': '@timestamp'}}, 'last': {'max': {'field': '@timestamp'}}}
        q = {
            'size': 0, 'track_total_hits': True,
            'query': {'bool': {'must': base, 'must_not': _blocked_priv_musts(exclude_ips)}},
            'aggs': {
                'ip_srcip': {'terms': {'field': _BLK_IP_FIELDS[0], 'size': 25},
                             'aggs': {**date_sub,
                                      'geo': {'terms': {'field': 'GeoLocation.country_name', 'size': 1}}}},
                'ip_nested': {'terms': {'field': _BLK_IP_FIELDS[1], 'size': 25}, 'aggs': date_sub},
                'uniq_srcip': {'cardinality': {'field': _BLK_IP_FIELDS[0]}},
                'uniq_nested': {'cardinality': {'field': _BLK_IP_FIELDS[1]}},
                'sig': {'terms': {'field': _BLK_SIG_FIELD, 'size': 8}},
                'country': {'terms': {'field': 'GeoLocation.country_name', 'size': 8}},
                'geo_cov': {'filter': {'exists': {'field': 'GeoLocation.country_name'}}},
                'tl': {'date_histogram': {'field': '@timestamp', 'fixed_interval': interval,
                                          'min_doc_count': 0,
                                          'extended_bounds': {'min': since_iso, 'max': until_iso}}},
            },
        }
        r = os_client._search('wazuh-alerts-*', q)
        a = r.get('aggregations', {})
        out['external_events'] = r.get('hits', {}).get('total', {}).get('value', 0)
        out['external_ips'] = int(a.get('uniq_srcip', {}).get('value', 0)
                                  + a.get('uniq_nested', {}).get('value', 0))

        merged = {}
        for src in ('ip_srcip', 'ip_nested'):
            for b in a.get(src, {}).get('buckets', []):
                ip = b.get('key', '')
                if not _valid_ip(ip):
                    continue
                e = merged.setdefault(ip, {'count': 0, 'first': None, 'last': None, 'country': '-'})
                e['count'] += b['doc_count']
                fv = (b.get('first') or {}).get('value_as_string') or (b.get('first') or {}).get('value')
                lv = (b.get('last') or {}).get('value_as_string') or (b.get('last') or {}).get('value')
                if fv and (e['first'] is None or str(fv) < str(e['first'])):
                    e['first'] = fv
                if lv and (e['last'] is None or str(lv) > str(e['last'])):
                    e['last'] = lv
                gb = (b.get('geo') or {}).get('buckets', [])
                if gb:
                    e['country'] = gb[0]['key']

        def _fmt(ts):
            return (str(ts)[:16].replace('T', ' ')) if ts else '-'

        out['top_ips'] = [
            {'ip': ip, 'count': e['count'], 'country': e['country'],
             'first': _fmt(e['first']), 'last': _fmt(e['last'])}
            for ip, e in sorted(merged.items(), key=lambda x: -x[1]['count'])[:12]
        ]
        out['threats'] = [{'name': (b['key'] or '-')[:50], 'count': b['doc_count']}
                          for b in a.get('sig', {}).get('buckets', [])]
        out['countries'] = [{'name': b['key'], 'count': b['doc_count']}
                            for b in a.get('country', {}).get('buckets', [])]
        if out['countries']:
            out['top_country'] = out['countries'][0]['name']
        geo_cov = a.get('geo_cov', {}).get('doc_count', 0)
        out['geo_partial'] = geo_cov < out['external_events']

        bins = []
        for b in a.get('tl', {}).get('buckets', []):
            ts = b.get('key_as_string', '')
            label = ts[11:16] if interval == '1h' else ts[5:10]
            bins.append({'label': label, 'count': b.get('doc_count', 0)})
        out['timeline'] = {'interval': interval, 'bins': bins}
    except Exception as e:  # pragma: no cover
        try:
            current_app.logger.warning(f'Blocked-external query failed: {e}')
        except Exception:
            pass
    return out


# ============================================================================
# R16 — anexa "Actiuni imediate per terminal" (query + randuri)
# ============================================================================
def q_r16_terminals(base_filter):
    """R16 — query per gazda interna vizata: servicii(port/proto), max nivel, alerte,
    surse (pentru coloana Expunere)."""
    return {
        'size': 0,
        'query': {'bool': {'must': base_filter + [{'exists': {'field': 'data.dest_ip'}}]}},
        'aggs': {'dst': {'terms': {'field': 'data.dest_ip', 'size': 40}, 'aggs': {
            'maxlvl': {'max': {'field': 'rule.level'}},
            'ports': {'terms': {'field': 'data.dest_port', 'size': 6},
                      'aggs': {'proto': {'terms': {'field': 'data.app_proto', 'size': 1}}}},
            'src_types': {'terms': {'field': 'data.src_ip', 'size': 25}},
        }}},
    }


def _r16_priv(ip):
    if ip.startswith(('10.', '192.168.', '127.')):
        return True
    if ip.startswith('172.'):
        try:
            return 16 <= int(ip.split('.')[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


def build_r16_rows(r16, lang='ro', host_names=None, host_types=None):
    """R16 — randurile anexei. host_names/host_types = dict IP->str din discovery.json
    (R12), optional. Doar gazde INTERNE (RFC1918). Expunere = 'expus' daca src public."""
    tt = R16_L.get(lang, R16_L['ro'])
    names = host_names or {}
    types = host_types or {}
    aggs = (r16 or {}).get('aggregations', {})
    rows = []
    for b in aggs.get('dst', {}).get('buckets', []):
        ip = b['key']
        if not _r16_priv(ip):
            continue
        svcs = []
        for pb in b.get('ports', {}).get('buckets', []):
            proto_b = pb.get('proto', {}).get('buckets', [])
            proto = proto_b[0]['key'] if proto_b else ''
            svcs.append(svc_for_port(pb['key'], proto, lang))
        svc_txt = ', '.join(dict.fromkeys(svcs)) or tt['undet']
        srcs = b.get('src_types', {}).get('buckets', [])
        ext = any(not _r16_priv(sb['key']) for sb in srcs)
        int_only = bool(srcs) and all(_r16_priv(sb['key']) for sb in srcs)
        if ext:
            exp = tt['exp_pub']
        elif int_only:
            exp = tt['exp_priv']
        else:
            exp = tt['exp_undet']
        rows.append({
            'ip': ip,
            'name': names.get(ip, tt['undet']),
            'type': types.get(ip, tt['undet']),
            'exposure': exp,
            'services': svc_txt,
            'alerts': b['doc_count'],
            'max_level': int(b.get('maxlvl', {}).get('value') or 0),
        })
    rows.sort(key=lambda r: (-r['max_level'], -r['alerts']))
    return rows


# ============================================================================
# R2 — nota de context per senzor atipic  |  R15 — audit = activitate CYBER3
# ============================================================================
SENSOR_CONTEXT_NOTES = {
    'f010': {
        'ro': ('Context senzor: senzorul inspecteaza integral traficul retelei in regim inline si detecteaza, '
               'la nivel de senzor, sute de evenimente de retea pe zi. Marea lor majoritate reprezinta trafic '
               'IPv4 malformat emis continuu de un echipament din reteaua interna (VLAN 38) — anomalie de '
               'echipament, nu atac; platforma le claseaza automat ca zgomot de nivel informational, motiv '
               'pentru care nu apar ca alerte individuale in acest raport. Recomandare pentru Beneficiar: '
               'identificarea si remedierea echipamentului respectiv. Restul traficului nu a generat '
               'evenimente de securitate semnificative — lantul complet de detectie si blocare este activ '
               'si validat.'),
        'en': ('Sensor context: the sensor inspects all network traffic inline and detects, at sensor level, '
               'hundreds of network events per day. The vast majority is malformed IPv4 traffic continuously '
               'emitted by a device inside the internal network (VLAN 38) — an equipment anomaly, not an '
               'attack; the platform automatically classifies these as informational-level noise, which is '
               'why they do not appear as individual alerts in this report. Recommendation for the '
               'Beneficiary: identify and remediate that device. The remaining traffic generated no '
               'significant security events — the full detection and blocking chain is active and '
               'validated.'),
    },
    'icisoc107': {
        'ro': ('Context senzor: acest senzor este montat in regim de MONITORIZARE (port-mirror), '
               'nu inline — observa si alerteaza integral, dar nu blocheaza activ. In plus, majoritatea '
               'alertelor provin din restrictiile de trafic impuse de Beneficiar in propria retea; ele '
               'reflecta politica interna, nu neaparat atacuri externe.'),
        'en': ('Sensor context: this sensor is deployed in MONITORING mode (port-mirror), not inline — '
               'it fully observes and alerts but does not actively block. Additionally, most alerts stem '
               'from traffic restrictions imposed by the Beneficiary within their own network; they '
               'reflect internal policy rather than necessarily external attacks.'),
    },
    'f002': {
        'ro': ('Context senzor: retea cu componente OT/industriale (protocoale S7/Modbus). O parte din '
               'alertele de protocol reflecta trafic industrial legitim, evaluat ca atare de analistul SOC.'),
        'en': ('Sensor context: network with OT/industrial components (S7/Modbus protocols). Some protocol '
               'alerts reflect legitimate industrial traffic, assessed as such by the SOC analyst.'),
    },
}


def sensor_context_note(client_code, lang='ro'):
    """R2 — textul notei de context sau None."""
    n = SENSOR_CONTEXT_NOTES.get((client_code or '').lower())
    return n.get(lang) if n else None


REC_AUDIT = {
    'ro': ('Ajustarea si intretinerea platformei — activitate CYBER3, fara sarcini pentru Beneficiar. '
           'Ca parte a serviciului SOC administrat, echipa CYBER3 a auditat in perioada raportata '
           'feed-urile de threat intelligence (MISP) si eficacitatea regulilor Suricata/Wazuh: '
           'reguli zgomotoase suprimate, semnaturi noi activate si indicatori (IOC) actualizati. '
           'Rezultatele acestor ajustari sunt deja reflectate in cifrele acestui raport. '
           'Nu este necesara nicio actiune din partea Beneficiarului.'),
    'en': ('Platform tuning and maintenance — a CYBER3 activity, with no tasks for the Beneficiary. '
           'As part of the managed SOC service, the CYBER3 team audited the threat-intelligence feeds '
           '(MISP) and the effectiveness of the Suricata/Wazuh rules during this period: noisy rules '
           'suppressed, new signatures enabled and indicators (IOCs) refreshed. The outcome of this '
           'tuning is already reflected in the figures of this report. No action is required from the '
           'Beneficiary.'),
}


# ---- i18n payload (textele dinamice din raport) ----
L = {
    'en': {
        'kpi_blocked_real': 'External attacks blocked (real)', 'kpi_l10': 'Events level 10+',
        'kpi_sig': 'NIS2 significant candidates',
        'kpi_total': 'Total events', 'kpi_avail': 'Sensor availability',
        'no_threats': 'No threats detected in period', 'no_ips': 'No attacker IPs in period',
        'internal': 'internal host', 'external': 'external', 'intern_short': 'internal',
        'nis2_note': ('Raw level >= 12 events are telemetry, not incidents: one hostile request typically '
                      'fires several rules at once, so events sharing the same network flow are first '
                      'CORRELATED into one incident, then assessed for MATERIALITY — only flows with a '
                      'confirmed successful server response (HTTP 2xx) remain candidates; refused/failed '
                      'requests (4xx/5xx) are not material; non-web flows go to analyst review. Final '
                      'classification as "significant incident" under NIS2 Art. 23 (service disruption, '
                      'financial loss, harm to third parties) is confirmed by the SOC analyst together '
                      'with the client.'),
        'dl': [('Early warning', '24h from detection'), ('Incident notification', '72h from detection'),
               ('Final report', '1 month')],
        'dl_to': 'CSIRT National / DNSC',
        'measures': [
            ('Art.21(2)(a)', 'Risk analysis & security policies', 'SOC continuous monitoring + periodic reports'),
            ('Art.21(2)(b)', 'Incident handling', '24/7 detection pipeline; {blocked} events level 10+ handled this period'),
            ('Art.21(2)(c)', 'Business continuity & crisis management', 'Sensor availability monitored (see KPI); escalation via Telegram + phone'),
            ('Art.21(2)(d)', 'Supply chain security', 'Threat intel on third-party IOCs (MISP feeds, daily sync)'),
            ('Art.21(2)(e)', 'Vulnerability handling & disclosure', 'Authenticated network vulnerability scans (CYBER3 Scan) on demand / scheduled'),
            ('Art.21(2)(f)', 'Effectiveness assessment', 'Monthly report with KPIs, trends and recommendations (this document)'),
            ('Art.21(2)(g)', 'Cyber hygiene & training', 'Recommendations section; awareness materials on request'),
            ('Art.21(2)(h)', 'Cryptography & encryption policies', 'Weak-crypto detections (TLS/IKE) reported when observed'),
            ('Art.21(2)(i)', 'HR security, access control, asset mgmt', 'Detections for NTLM/auth anomalies and RMM tools included'),
            ('Art.21(2)(j)', 'MFA & secured communications', 'Recommended where weak authentication is observed in traffic'),
        ],
        'rec_sig': ('{raw:,} raw events level >= 12 collapse into {flows:,} correlated incidents (unique '
                    'network flows), of which {mat:,} had a confirmed successful server response (HTTP 2xx) '
                    'and qualify as candidates for NIS2 "significant incident" assessment; {nonweb:,} non-web '
                    'flows need analyst review. Review the incident annex and confirm classification within '
                    'the legal deadlines.'),
        'rec_vuln': ('Vulnerable software versions were observed in live traffic. Prioritize patching the '
                     'affected assets (see threat typology) — this is the single highest-impact action this period.'),
        'rec_rmm': ('Remote-access tools (RMM) are active in the network. Maintain an approved-tools allowlist '
                    'and disable unattended access where not strictly needed.'),
        'rec_smb': ('SMB/NTLM activity with executable or DLL transfers was detected. Verify these are legitimate '
                    'software deployments; consider SMB signing and NTLMv2-only policy.'),
        'rec_avail': ('Sensor availability was {pct:.2f}% ({down} non-active samples). Investigate '
                      'connectivity/power at the sensor site to keep monitoring coverage.'),
        'rec_review': ('Review the {total:,} security events of the period — {heightened:,} required heightened '
                       'attention (level 7+), {blocked} reached response threshold (level 10+).'),
    },
    'ro': {
        'kpi_blocked_real': 'Atacuri externe blocate (real)', 'kpi_l10': 'Evenimente nivel 10+',
        'kpi_sig': 'Candidate semnificative NIS2',
        'kpi_total': 'Total evenimente', 'kpi_avail': 'Disponibilitate senzor',
        'no_threats': 'Nicio amenintare detectata in perioada', 'no_ips': 'Niciun IP atacator in perioada',
        'internal': 'gazda interna', 'external': 'extern', 'intern_short': 'intern',
        'nis2_note': ('Evenimentele brute nivel >= 12 sunt telemetrie, nu incidente: o singura cerere ostila '
                      'declanseaza de regula mai multe reguli deodata, asa ca evenimentele aceluiasi flux de '
                      'retea se CORELEAZA intai intr-un singur incident, apoi se evalueaza MATERIALITATEA — '
                      'raman candidate doar fluxurile cu raspuns de succes confirmat al serverului (HTTP 2xx); '
                      'cererile refuzate/esuate (4xx/5xx) nu sunt materiale; fluxurile non-web merg la review '
                      'de analist. Clasificarea finala drept "incident semnificativ" conform NIS2 Art. 23 '
                      '(intreruperea serviciului, pierderi financiare, prejudicii catre terti) se confirma de '
                      'analistul SOC impreuna cu clientul.'),
        'dl': [('Avertizare timpurie', '24h de la detectare'), ('Notificare incident', '72h de la detectare'),
               ('Raport final', '1 luna')],
        'dl_to': 'CSIRT National / DNSC',
        'measures': [
            ('Art.21(2)(a)', 'Analiza de risc si politici de securitate', 'Monitorizare SOC continua + rapoarte periodice'),
            ('Art.21(2)(b)', 'Gestionarea incidentelor', 'Pipeline detectie 24/7; {blocked} evenimente nivel 10+ gestionate in perioada'),
            ('Art.21(2)(c)', 'Continuitatea afacerii si managementul crizelor', 'Disponibilitatea senzorului monitorizata (vezi KPI); escaladare Telegram + telefon'),
            ('Art.21(2)(d)', 'Securitatea lantului de aprovizionare', 'Threat intel pe IOC-uri terti (feed-uri MISP, sincronizare zilnica)'),
            ('Art.21(2)(e)', 'Gestionarea si divulgarea vulnerabilitatilor', 'Scanari de vulnerabilitati in retea (CYBER3 Scan) la cerere / programate'),
            ('Art.21(2)(f)', 'Evaluarea eficacitatii masurilor', 'Raport lunar cu KPI, tendinte si recomandari (acest document)'),
            ('Art.21(2)(g)', 'Igiena cibernetica si instruire', 'Sectiunea de recomandari; materiale de constientizare la cerere'),
            ('Art.21(2)(h)', 'Politici de criptografie si criptare', 'Detectii crypto slab (TLS/IKE) raportate cand sunt observate'),
            ('Art.21(2)(i)', 'Securitatea RU, control acces, management active', 'Detectii pentru anomalii NTLM/autentificare si unelte RMM incluse'),
            ('Art.21(2)(j)', 'MFA si comunicatii securizate', 'Recomandat unde se observa autentificare slaba in trafic'),
        ],
        'rec_sig': ('{raw:,} evenimente brute nivel >= 12 se coreleaza in {flows:,} incidente distincte '
                    '(fluxuri de retea unice), dintre care {mat:,} au avut raspuns de succes confirmat al '
                    'serverului (HTTP 2xx) si se califica drept candidate pentru evaluare ca "incident '
                    'semnificativ" NIS2; {nonweb:,} fluxuri non-web necesita review de analist. Verificati '
                    'anexa de incidente si confirmati clasificarea in termenele legale.'),
        'rec_vuln': ('S-au observat versiuni de software vulnerabile in traficul live. Prioritizati patch-uirea '
                     'activelor afectate (vezi tipologia amenintarilor) — actiunea cu cel mai mare impact in aceasta perioada.'),
        'rec_rmm': ('Unelte de acces la distanta (RMM) sunt active in retea. Mentineti o lista de unelte aprobate '
                    'si dezactivati accesul nesupravegheat unde nu este strict necesar.'),
        'rec_smb': ('S-a detectat activitate SMB/NTLM cu transferuri de executabile sau DLL-uri. Verificati ca '
                    'sunt instalari legitime de software; luati in calcul SMB signing si politica NTLMv2-only.'),
        'rec_avail': ('Disponibilitatea senzorului a fost {pct:.2f}% ({down} esantioane non-active). Investigati '
                      'conectivitatea/alimentarea la locatia senzorului pentru acoperire continua.'),
        'rec_review': ('Treceti in revista cele {total:,} evenimente de securitate ale perioadei — {heightened:,} '
                       'au necesitat atentie sporita (nivel 7+), {blocked} au atins pragul de raspuns (nivel 10+).'),
    },
}


def _safe_filename(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name)[:50]


def _month_bounds(dt, back=0):
    """Returns (first_day, first_day_next_month) for the month `back` months before dt."""
    y, m = dt.year, dt.month - back
    while m <= 0:
        m += 12
        y -= 1
    start = datetime(y, m, 1, tzinfo=timezone.utc)
    if m == 12:
        nxt = datetime(y + 1, 1, 1, tzinfo=timezone.utc)
    else:
        nxt = datetime(y, m + 1, 1, tzinfo=timezone.utc)
    return start, nxt


def _period_range(period, date_from=None, date_to=None):
    """Resolve period to (since_dt, until_dt, label). Supports presets + custom."""
    now = datetime.now(timezone.utc)
    if period == 'custom' and date_from:
        try:
            since = datetime.fromisoformat(date_from)
            if since.tzinfo is None:
                since = since.replace(tzinfo=timezone.utc)
        except ValueError:
            raise ValueError(f'invalid date_from: {date_from}')
        until = now
        if date_to:
            try:
                until = datetime.fromisoformat(date_to)
                if until.tzinfo is None:
                    until = until.replace(tzinfo=timezone.utc)
                if until.hour == 0 and until.minute == 0 and until.second == 0:
                    until = until + timedelta(days=1)
            except ValueError:
                raise ValueError(f'invalid date_to: {date_to}')
        if until <= since:
            raise ValueError('date_to must be after date_from')
        label = f'{since.strftime("%d.%m.%Y")} – {(until - timedelta(seconds=1)).strftime("%d.%m.%Y")}'
        return since, until, label
    if period == 'current_month':
        start, _ = _month_bounds(now)
        label = f'{start.strftime("%B %Y")} (partial, until {now.strftime("%d.%m %H:%M UTC")})'
        return start, now, label
    if period == 'previous_month':
        start, nxt = _month_bounds(now, back=1)
        label = f'{start.strftime("%B %Y")} (full month)'
        return start, nxt, label
    hours = {'last_24h': 24, 'last_week': 168, 'last_month': 744, 'q1_2026': 2160}.get(period, 744)
    label = {'last_24h': 'Last 24 hours', 'last_week': 'Last 7 days',
             'last_month': f'Last {hours // 24} days', 'q1_2026': 'Q1 2026 · Jan-Mar'}.get(
                 period, f'Last {hours} hours')
    return now - timedelta(hours=hours), now, label


def _resolve_client(client_id):
    """Lookup client code/org in DB. Returns (code, organization)."""
    try:
        db = current_app.config.get('DATABASE_PATH', '/opt/fasterup-portal/data/portal.db')
        conn = sqlite3.connect(db)
        cur = conn.cursor()
        cur.execute('SELECT code, organization FROM clients WHERE wazuh_agent_id=?', (client_id,))
        row = cur.fetchone()
        conn.close()
        return (row[0], row[1]) if row else (client_id, None)
    except Exception as e:
        current_app.logger.warning(f'Client lookup failed: {e}')
        return (client_id, None)


def _availability(os_client, client_id, since_iso, until_iso):
    """Sensor availability %% from wazuh-monitoring snapshots (~15 min)."""
    q = {
        'size': 0,
        'track_total_hits': True,
        'query': {'bool': {'must': [
            {'term': {'id': client_id}},
            {'range': {'timestamp': {'gte': since_iso, 'lt': until_iso}}},
        ]}},
        'aggs': {'by_status': {'terms': {'field': 'status', 'size': 6}}},
    }
    try:
        r = os_client._search('wazuh-monitoring-*', q)
        total = r.get('hits', {}).get('total', {}).get('value', 0)
        if not total:
            return None, 0, 0
        buckets = r.get('aggregations', {}).get('by_status', {}).get('buckets', [])
        counts = {b['key']: b['doc_count'] for b in buckets}
        active = counts.get('active', 0)
        pct = 100.0 * active / total
        disconnects = sum(v for k, v in counts.items() if k != 'active')
        return pct, total, disconnects
    except Exception as e:
        current_app.logger.warning(f'Availability query failed: {e}')
        return None, 0, 0


def _build_client_data(client_id, period, lang, date_from=None, date_to=None,
                       host_names=None, host_types=None):
    """Build report payload from REAL OpenSearch + Wazuh API queries."""
    since_dt, until_dt, period_label = _period_range(period, date_from, date_to)
    since = since_dt.isoformat()
    until = until_dt.isoformat()
    period_days = max(1, round((until_dt - since_dt).total_seconds() / 86400))

    client_code, _org = _resolve_client(client_id)
    os_client = get_opensearch()
    lx = L.get(lang, L['en'])

    # EXCLUDERE la NIVEL base_filter: infra proprie SOC (10.0.0.0/24), tuneluri
    # (10.1.0.0/16), retea de scan (10.242.0.0/16) + IP-ul de scan al senzorului pe
    # LAN-ul clientului (auto-detectat din semnaturi ET SCAN/Nmap). Aceste surse NU
    # sunt trafic al Beneficiarului; se exclud din TOATE sectiunile (incidente,
    # top-ip, tinte, R16, MITRE, severitate, evolutie), nu doar din "atacuri blocate".
    scanner_ips = sorted(_detect_scan_ip(os_client, client_id, since, until))
    base_filter = [
        {'range': {'@timestamp': {'gte': since, 'lt': until}}},
        {'term': {'agent.id': client_id}},
        {'bool': {'must_not': {'term': {'location': 'vulnerability-detector'}}}},
        {'bool': {'must_not': {'terms': {'rule.groups': CLIENT_NOISE_GROUPS}}}},
        {'bool': {'must_not': _infra_exclude_musts(scanner_ips)}},
        {'bool': {'must_not': _our_service_musts()}},
    ]

    # ---- Q1: totals + severity bands + compliance tag counts ----
    q_counts = {
        'size': 0,
        'track_total_hits': True,
        'query': {'bool': {'must': base_filter}},
        'aggs': {
            'sev': {'range': {'field': 'rule.level', 'ranges': [
                {'key': 'low', 'from': 1, 'to': 7},
                {'key': 'medium', 'from': 7, 'to': 10},
                {'key': 'high', 'from': 10, 'to': 13},
                {'key': 'critical', 'from': 13},
            ]}},
            'l7': {'filter': {'range': {'rule.level': {'gte': 7}}}},
            'l10': {'filter': {'range': {'rule.level': {'gte': 10}}}},
            'l12': {'filter': {'range': {'rule.level': {'gte': 12}}}},
            'l13': {'filter': {'range': {'rule.level': {'gte': 13}}}},
            'nist': {'filter': {'exists': {'field': 'rule.nist_800_53'}}},
            'pci': {'filter': {'exists': {'field': 'rule.pci_dss'}}},
            'gdpr': {'filter': {'exists': {'field': 'rule.gdpr'}}},
        }
    }
    r1 = os_client._search('wazuh-alerts-*', q_counts)
    total = r1.get('hits', {}).get('total', {}).get('value', 0)
    aggs1 = r1.get('aggregations', {})
    sev_b = {b['key']: b['doc_count'] for b in aggs1.get('sev', {}).get('buckets', [])}
    severity = {
        'low': sev_b.get('low', 0), 'medium': sev_b.get('medium', 0),
        'high': sev_b.get('high', 0), 'critical': sev_b.get('critical', 0),
    }
    heightened = aggs1.get('l7', {}).get('doc_count', 0)
    # ONESTITATE: `events_l10` = evenimente NIVEL 10+, NU blocari. Blocarile REALE
    # se calculeaza separat mai jos (_blocked_external, active-response rule 651).
    events_l10 = aggs1.get('l10', {}).get('doc_count', 0)
    significant = aggs1.get('l12', {}).get('doc_count', 0)
    escalated = aggs1.get('l13', {}).get('doc_count', 0)
    compliance = {
        'nist_800_53': aggs1.get('nist', {}).get('doc_count', 0),
        'pci_dss': aggs1.get('pci', {}).get('doc_count', 0),
        'gdpr': aggs1.get('gdpr', {}).get('doc_count', 0),
    }

    # ---- Q1b: TIERING NIS2 (fix ICI P3) — evenimentele brute nivel>=12 NU sunt
    # incidente: o cerere ostila declanseaza mai multe reguli deodata (acelasi
    # data.flow_id Suricata). Corelam pe flux, apoi materialitate pe raspunsul
    # serverului (data.http.status 2xx = succes; 4xx/5xx = refuz, nematerial;
    # fara HTTP = non-web, review uman). Clasificarea finala ramane pas uman
    # (Art. 23). Evenimentele fara flow_id (non-Suricata) = cate un incident.
    sig_flows = significant; sig_material = 0; sig_nonweb = 0
    try:
        _card = {'cardinality': {'field': 'data.flow_id',
                                 'precision_threshold': 40000}}
        q_tier = {
            'size': 0,
            'query': {'bool': {'must': base_filter + [
                {'range': {'rule.level': {'gte': 12}}}]}},
            'aggs': {
                'flows': _card,
                'noflow': {'missing': {'field': 'data.flow_id'}},
                'success': {'filter': {'prefix': {'data.http.status': '2'}},
                            'aggs': {'flows': _card}},
                'nonweb': {'filter': {'bool': {'must_not': {
                              'exists': {'field': 'data.http.status'}}}},
                           'aggs': {'flows': _card}},
            }
        }
        rt_ = os_client._search('wazuh-alerts-*', q_tier)
        at_ = rt_.get('aggregations', {})
        _noflow = at_.get('noflow', {}).get('doc_count', 0)
        sig_flows = at_.get('flows', {}).get('value', 0) + _noflow
        sig_material = at_.get('success', {}).get('flows', {}).get('value', 0)
        sig_nonweb = (at_.get('nonweb', {}).get('flows', {}).get('value', 0)
                      + _noflow)
    except Exception as e:
        current_app.logger.warning(f'NIS2 tiering query failed: {e}')
        sig_material = significant  # fallback onest: fara corelare, cifra veche

    # ---- Q2: top threat types ----
    q_threats = {
        'size': 0,
        'query': {'bool': {'must': base_filter}},
        'aggs': {
            'sig': {'terms': {'field': 'data.alert.signature', 'size': 8}},
            'rules': {'filter': {'bool': {'must_not': {'exists': {'field': 'data.alert.signature'}}}},
                      'aggs': {'descr': {'terms': {'field': 'rule.description', 'size': 8}}}},
        }
    }
    r2 = os_client._search('wazuh-alerts-*', q_threats)
    a2 = r2.get('aggregations', {})
    merged = {}
    for b in a2.get('sig', {}).get('buckets', []):
        merged[b['key'][:60]] = merged.get(b['key'][:60], 0) + b['doc_count']
    for b in a2.get('rules', {}).get('descr', {}).get('buckets', []):
        merged[b['key'][:60]] = merged.get(b['key'][:60], 0) + b['doc_count']
    threats = sorted(({'name': k, 'count': v} for k, v in merged.items()),
                     key=lambda x: -x['count'])[:8]
    if not threats:
        threats = [{'name': lx['no_threats'], 'count': 0}]

    # ---- Q3: top attacker IPs ----
    q_ips = {
        'size': 0,
        'query': {'bool': {'must': base_filter + [{'exists': {'field': 'data.src_ip'}}]}},
        'aggs': {'ips': {'terms': {'field': 'data.src_ip', 'size': 8},
                         'aggs': {'geo': {'terms': {'field': 'GeoLocation.country_name', 'size': 1}},
                                  'maxlvl': {'max': {'field': 'rule.level'}}}}}
    }
    r3 = os_client._search('wazuh-alerts-*', q_ips)
    top_ips = []
    for b in r3.get('aggregations', {}).get('ips', {}).get('buckets', []):
        geo_b = b.get('geo', {}).get('buckets', [])
        country = geo_b[0]['key'] if geo_b else '-'
        ip = b['key']
        is_internal = ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                                     '172.2', '172.30.', '172.31.', 'fe80', '127.'))
        top_ips.append({
            'ip': ip,
            'country': country if country != '-' else (lx['intern_short'] if is_internal else '-'),
            'isp': '-',
            'context': lx['internal'] if is_internal else lx['external'],
            'attempts': b['doc_count'],
            'max_level': int(b.get('maxlvl', {}).get('value') or 0),
        })
    if not top_ips:
        top_ips = [{'ip': '-', 'country': '-', 'isp': '-', 'context': lx['no_ips'],
                    'attempts': 0, 'max_level': 0}]

    # ---- Q4: evolution over time by severity ----
    hours = max(1, (until_dt - since_dt).total_seconds() / 3600)
    interval = '1h' if hours <= 48 else '1d'
    q_evo = {
        'size': 0,
        'query': {'bool': {'must': base_filter}},
        'aggs': {'over_time': {
            'date_histogram': {'field': '@timestamp', 'fixed_interval': interval,
                               'min_doc_count': 0,
                               'extended_bounds': {'min': since, 'max': until}},
            'aggs': {'by_level': {'range': {'field': 'rule.level', 'ranges': [
                {'key': 'low', 'from': 1, 'to': 7}, {'key': 'medium', 'from': 7, 'to': 10},
                {'key': 'high', 'from': 10, 'to': 13}, {'key': 'critical', 'from': 13}]}}}
        }}
    }
    evo_bins = []
    try:
        r4 = os_client._search('wazuh-alerts-*', q_evo)
        for bkt in r4.get('aggregations', {}).get('over_time', {}).get('buckets', []):
            ts = bkt.get('key_as_string', '')
            rng = {x['key']: x['doc_count'] for x in bkt.get('by_level', {}).get('buckets', [])}
            label = ts[11:16] if interval == '1h' else ts[5:10]
            evo_bins.append({'label': label, 'critical': rng.get('critical', 0),
                             'high': rng.get('high', 0), 'medium': rng.get('medium', 0),
                             'low': rng.get('low', 0)})
    except Exception as e:
        current_app.logger.warning(f'Evolution query failed: {e}')
    evolution = {'interval': interval, 'bins': evo_bins}

    # ---- Q5: MITRE ATT&CK (R14: unificare ET<->Wazuh, nume oficiale) ----
    mitre_tactics, mitre_techniques = [], []
    try:
        q_mitre = {
            'size': 0,
            'query': {'bool': {'must': base_filter}},
            'aggs': {
                'tactics_et': {'terms': {'field': 'data.alert.metadata.mitre_tactic_name', 'size': 8}},
                'tech_et': {'terms': {'field': 'data.alert.metadata.mitre_technique_name', 'size': 10},
                            'aggs': {'tid': {'terms': {'field': 'data.alert.metadata.mitre_technique_id', 'size': 1}}}},
                'tactics_wz': {'terms': {'field': 'rule.mitre.tactic', 'size': 8}},
                'tech_wz': {'terms': {'field': 'rule.mitre.technique', 'size': 10}},
            }
        }
        r5 = os_client._search('wazuh-alerts-*', q_mitre)
        mitre_tactics, mitre_techniques = build_mitre(r5.get('aggregations', {}))
    except Exception as e:
        current_app.logger.warning(f'MITRE query failed: {e}')

    # ---- Q6: tinte interne (dest_ip DOAR RFC1918) + porturi/servicii vizate (R13) ----
    top_targets, top_ports = [], []
    try:
        q_tgt = {
            'size': 0,
            'query': {'bool': {'must': base_filter + [{'exists': {'field': 'data.dest_ip'}}]}},
            'aggs': {
                'targets': {'terms': {'field': 'data.dest_ip', 'size': 20}},
                'ports': {'terms': {'field': 'data.dest_port', 'size': 8},
                          'aggs': {'proto': {'terms': {'field': 'data.app_proto', 'size': 1}}}},
            }
        }
        r6 = os_client._search('wazuh-alerts-*', q_tgt)
        a6 = r6.get('aggregations', {})
        top_targets = [{'ip': b['key'], 'count': b['doc_count']}
                       for b in a6.get('targets', {}).get('buckets', [])
                       if _r16_priv(b['key'])][:6]
        for b in a6.get('ports', {}).get('buckets', []):
            pb = b.get('proto', {}).get('buckets', [])
            proto = (pb[0]['key'] if pb else '')
            svc = svc_for_port(b['key'], proto, lang)
            top_ports.append({'port': str(b['key']), 'service': svc, 'count': b['doc_count']})
    except Exception as e:
        current_app.logger.warning(f'Targets query failed: {e}')

    # ---- Q7: lista incidente nivel >= 10 (anexa) ----
    incidents = []
    try:
        q_inc = {
            'size': 20,
            'query': {'bool': {'must': base_filter + [{'range': {'rule.level': {'gte': 10}}}]}},
            'sort': [{'rule.level': 'desc'}, {'@timestamp': 'desc'}],
            '_source': ['@timestamp', 'rule.level', 'rule.id', 'rule.description',
                        'data.src_ip', 'data.dest_ip', 'data.alert.signature',
                        'data.alert.metadata.mitre_technique_id'],
        }
        r7 = os_client._search('wazuh-alerts-*', q_inc)
        for h in r7.get('hits', {}).get('hits', []):
            s = h.get('_source', {})
            rule = s.get('rule', {})
            d = s.get('data', {})
            alert = d.get('alert', {}) if isinstance(d.get('alert'), dict) else {}
            meta = alert.get('metadata', {}) if isinstance(alert.get('metadata'), dict) else {}
            mtid = meta.get('mitre_technique_id', '') or ''
            mtname = meta.get('mitre_technique_name', '') or ''
            # R14: afiseaza ID-ul oficial cand il putem canonicaliza
            if not mtid and mtname:
                mtid = mitre_technique(mtname)[0]
            incidents.append({
                'timestamp': (s.get('@timestamp') or '')[:19].replace('T', ' '),
                'level': rule.get('level', 0),
                'rule_id': rule.get('id', ''),
                'description': (alert.get('signature') or rule.get('description') or '')[:70],
                'src_ip': d.get('src_ip', '-'),
                'dest_ip': d.get('dest_ip', '-'),
                'mitre': mtid,
            })
    except Exception as e:
        current_app.logger.warning(f'Incidents query failed: {e}')

    # ---- R16: anexa actiuni imediate per terminal ----
    r16_rows = []
    try:
        r16 = os_client._search('wazuh-alerts-*', q_r16_terminals(base_filter))
        r16_rows = build_r16_rows(r16, lang, host_names=host_names, host_types=host_types)
    except Exception as e:
        current_app.logger.warning(f'R16 terminals query failed: {e}')

    # ---- SECTIUNEA VEDETA: atacuri EXTERNE blocate REAL (active-response 651) ----
    blocked = _blocked_external(os_client, client_id, since, until, lx,
                                client_code=client_code, exclude_ips=scanner_ips,
                                interval=interval)
    blocked['layers'] = _active_layers(client_id, client_code, since, until, blocked)
    # RECONCILIERE (un singur adevar pe raport): senzor mirror (nu blocheaza) sau
    # numar de blocari externe sub pragul statistic (zero_floor) => afisam 0, coerent
    # cu nota onesta din sectiunea "Atacuri blocate (extern)". Altfel KPI-ul ar spune
    # un numar (ex. 1) pe care sectiunea 4 il declara, corect, drept "0 extern onest".
    _ext_raw = blocked.get('external_events', 0)
    if blocked.get('mode') == 'mirror' or _ext_raw <= blocked.get('zero_floor', 2):
        real_blocks = 0
    else:
        real_blocks = _ext_raw

    # ---- disponibilitate senzor (wazuh-monitoring) ----
    avail_pct, avail_samples, avail_down = _availability(os_client, client_id, since, until)
    if avail_pct is not None:
        sensor_uptime = f'{avail_pct:.2f}%'
    else:
        sensor_uptime = '100%'
        try:
            wz = get_wazuh()
            agents_resp = wz.get_agents(limit=500).get('data', {}).get('affected_items', [])
            my_agent = next((a for a in agents_resp if str(a.get('id')) == client_id), None)
            if my_agent and my_agent.get('status') != 'active':
                sensor_uptime = my_agent.get('status', 'unknown')
        except Exception as e:
            current_app.logger.warning(f'Wazuh agent lookup failed: {e}')

    # ---- NIS2: clasificare + masuri (Art. 21/23). {blocked} = nivel 10+ (onest). ----
    # significant_candidates = MATERIAL (corelat + succes 2xx), NU evenimente brute.
    nis2 = {
        'significant_candidates': sig_material,
        'tier_raw_l12': significant,
        'tier_correlated': sig_flows,
        'tier_material': sig_material,
        'tier_nonweb': sig_nonweb,
        'high_incidents': events_l10,
        'note_classification': lx['nis2_note'],
        'reporting_deadlines': [
            {'step': s_, 'deadline': d_, 'to': lx['dl_to']} for s_, d_ in lx['dl']
        ],
        'measures': [
            {'art': a_, 'measure': m_, 'status': st_.format(blocked=events_l10)}
            for a_, m_, st_ in lx['measures']
        ],
    }

    # ---- recomandari pe baza datelor ----
    recommendations = []
    threat_names = ' '.join(t['name'].lower() for t in threats)
    if significant:
        recommendations.append(lx['rec_sig'].format(
            raw=significant, flows=sig_flows, mat=sig_material, nonweb=sig_nonweb))
    if 'vulnerable' in threat_names or 'cve' in threat_names:
        recommendations.append(lx['rec_vuln'])
    if ('anydesk' in threat_names or 'rustdesk' in threat_names or 'teamviewer' in threat_names
            or 'remote' in threat_names):
        recommendations.append(lx['rec_rmm'])
    if 'smb' in threat_names or 'ntlm' in threat_names:
        recommendations.append(lx['rec_smb'])
    if avail_pct is not None and avail_pct < 99.5:
        recommendations.append(lx['rec_avail'].format(pct=avail_pct, down=avail_down))
    recommendations.append(lx['rec_review'].format(total=total, heightened=heightened, blocked=events_l10))

    payload = {
        'client_name': client_code,
        'client_id': client_id,
        'organization': _org,
        'period': {
            'label': f'Period: {period_label}',
            'start': since, 'end': until, 'days': period_days,
        },
        'summary': {
            'events_processed': total,
            'heightened_attention': heightened,
            # ONESTITATE: blocari REALE (active-response) vs evenimente nivel 10+
            'real_blocks': real_blocks,
            'events_l10': events_l10,
            'attacks_blocked': events_l10,   # compat vechi (nu mai e folosit ca "blocate")
            'escalated': escalated,
            'significant_candidates': sig_material,
            'avg_response_sec': 0.0,
        },
        'severity': severity,
        'kpis': [
            {'value': f'{real_blocks:,}', 'label': lx['kpi_blocked_real'], 'color': '#c91f3e'},
            {'value': str(events_l10), 'label': lx['kpi_l10']},
            {'value': f'{total:,}', 'label': lx['kpi_total']},
            {'value': sensor_uptime, 'label': lx['kpi_avail']},
        ],
        'blocked': blocked,
        'threats': threats,
        'top_ips': top_ips,
        'mitre': {'tactics': mitre_tactics, 'techniques': mitre_techniques},
        'targets': {'hosts': top_targets, 'ports': top_ports},
        'incidents': incidents,
        'r16_rows': r16_rows,
        'sensor_note': sensor_context_note(client_code, lang),          # R2
        'cyber3_activity': REC_AUDIT.get(lang, REC_AUDIT['ro']),        # R15
        'availability': {
            'pct': avail_pct, 'samples': avail_samples, 'non_active_samples': avail_down,
            'display': sensor_uptime,
        },
        'compliance_tags': compliance,
        'nis2': nis2,
        'evolution': evolution,
        'recommendations': recommendations,
    }
    return payload


def _parse_req(data):
    client_id = str(data.get('client_id', ''))
    period = data.get('period', 'last_month')
    lang = data.get('lang', 'en')
    date_from = data.get('date_from') or None
    date_to = data.get('date_to') or None
    return client_id, period, lang, date_from, date_to


@bp.route('/reports/preview', methods=['POST'])
@require_org_access
def preview():
    """Return JSON payload (same as generate) without producing PDF — for HTML preview."""
    data = request.get_json(silent=True) or {}
    client_id, period, lang, date_from, date_to = _parse_req(data)

    if not client_id:
        return jsonify({'status': 'error', 'error': 'client_id required'}), 400
    if g.visible_agent_ids is not None and client_id not in g.visible_agent_ids:
        return jsonify({'status': 'error', 'error': 'forbidden: client not visible'}), 403

    try:
        payload = _build_client_data(client_id, period, lang, date_from, date_to)
    except ValueError as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400
    except Exception as e:
        current_app.logger.exception('Failed to build preview data')
        return jsonify({'status': 'error', 'error': f'data fetch failed: {e}'}), 500

    return jsonify({'status': 'ok', 'data': payload})


def _try_generate_docx(payload, lang):
    """Best-effort Word (.docx). None daca python-docx lipseste."""
    try:
        from app.services.docx_generator import generate_docx
        return generate_docx(payload, lang=lang)
    except Exception as e:
        current_app.logger.warning(f'DOCX generation skipped: {e}')
        return None


@bp.route('/reports/generate', methods=['POST'])
@require_org_access
def generate():
    """Generate a client report (PDF + Word) using REAL data from OpenSearch + Wazuh.

    Routing: ICI_SOC -> portal (per code/luna + copie flat pt download endpoint);
    FASTERUP_DIRECT -> laptop (NICIODATA pe portal). Pe portal, clientii DIRECT nu se
    genereaza live (se ruleaza prin generate_july.py pe laptop)."""
    data = request.get_json(silent=True) or {}
    client_id, period, lang, date_from, date_to = _parse_req(data)

    if not client_id:
        return jsonify({'status': 'error', 'error': 'client_id required'}), 400
    if g.visible_agent_ids is not None and client_id not in g.visible_agent_ids:
        return jsonify({'status': 'error', 'error': 'forbidden: client not visible'}), 403

    current_app.logger.info(f'Report: client_id={client_id} period={period} from={date_from} to={date_to}')

    try:
        payload = _build_client_data(client_id, period, lang, date_from, date_to)
    except ValueError as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400
    except Exception as e:
        current_app.logger.exception('Failed to build client data')
        return jsonify({'status': 'error', 'error': f'data fetch failed: {e}'}), 500

    try:
        if payload.get('organization') in ('ICI_SOC', 'FASTERUP_DIRECT'):
            from app.services.template_alert_report import generate_alert_pdf_template
            pdf_bytes = generate_alert_pdf_template(payload, lang=lang)
        else:
            pdf_bytes = generate_pdf(payload, lang=lang)
    except Exception as e:
        current_app.logger.exception('PDF generation failed')
        return jsonify({'status': 'error', 'error': str(e)}), 500

    if payload.get('organization') in ('ICI_SOC', 'FASTERUP_DIRECT'):
        try:
            from app.services.template_alert_report import generate_alert_docx_template
            docx_bytes = generate_alert_docx_template(payload, lang)
        except Exception:
            docx_bytes = None
    else:
        docx_bytes = _try_generate_docx(payload, lang)
    client_name = payload['client_name']
    org = payload.get('organization')

    # --- routing pe organizatie (best-effort; fallback la flat REPORTS_DIR) ---
    manifest = None
    try:
        from app.routes.frag_bundle_routing import route_alerts_report, ORG_DIRECT
        # Pe portal NU generam pentru clientii DIRECT (destinatia e laptopul).
        if org != ORG_DIRECT:
            manifest = route_alerts_report(client_id, pdf_bytes, docx_bytes, period, lang)
    except Exception as e:
        current_app.logger.warning(f'Routing bundle skipped: {e}')

    reports_dir = os.getenv('REPORTS_DIR', '/opt/fasterup-portal/data/reports')
    os.makedirs(reports_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    base = f'Report_{_safe_filename(client_name)}_{_safe_filename(period)}_{ts}'
    filename = base + '.pdf'
    filepath = os.path.join(reports_dir, filename)
    # Fallback flat save daca routing nu a lasat o copie servibila. NICIODATA pt clientii DIRECT (raman doar pe laptop).
    if org != 'FASTERUP_DIRECT' and not (manifest and manifest.get('flat_pdf')):
        with open(filepath, 'wb') as f:
            f.write(pdf_bytes)
        if docx_bytes:
            with open(os.path.join(reports_dir, base + '.docx'), 'wb') as f:
                f.write(docx_bytes)
    else:
        filename = manifest.get('download_name', filename)
    current_app.logger.info(f'Report saved: {filename} ({len(pdf_bytes)} bytes pdf)')

    if request.args.get('inline') == '1':
        return send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf',
                         as_attachment=True, download_name=filename)

    return jsonify({
        'status': 'ok',
        'filename': filename,
        'size_bytes': len(pdf_bytes),
        'has_docx': bool(docx_bytes),
        'download_url': f'/api/reports/download/{filename}',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'request': {'client_id': client_id, 'client_name': client_name, 'period': period, 'lang': lang}
    })


def _code_to_agent_map():
    """code (ICISOC102/F002) -> wazuh_agent_id, din clients. Cache pe g."""
    if hasattr(g, '_code_agent_map'):
        return g._code_agent_map
    import sqlite3
    m = {}
    try:
        db = os.getenv('DATABASE_PATH', '/opt/fasterup-portal/data/portal.db')
        conn = sqlite3.connect(db)
        for code, aid in conn.execute("SELECT code, wazuh_agent_id FROM clients WHERE wazuh_agent_id IS NOT NULL"):
            if code and aid:
                m[str(code)] = str(aid)
        conn.close()
    except Exception:
        pass
    g._code_agent_map = m
    return m


def _report_visible(filename):
    """True daca fisierul de raport apartine unui client vizibil userului (RBAC).
    Supervisor/can_see_all (visible_agent_ids None) -> tot; altfel doar clientii din org.
    Fail-closed: cod nemapat -> ascuns pentru useri restrictionati."""
    try:
        if g.visible_agent_ids is None:
            return True
    except Exception:
        return False
    import re as _re
    mm = _re.match(r'Report_([A-Za-z0-9]+)_', filename or '')
    if not mm:
        return False
    mp = _code_to_agent_map()
    aid = mp.get(mm.group(1)) or mp.get(mm.group(1).upper())
    return aid is not None and aid in g.visible_agent_ids


@bp.route('/reports/download/<filename>', methods=['GET'])
@require_org_access
def download(filename):
    safe = _safe_filename(filename.replace('.pdf', '').replace('.docx', ''))
    ext = '.docx' if filename.endswith('.docx') else '.pdf'
    safe = safe + ext
    if not _report_visible(safe):
        return jsonify({'error': 'forbidden'}), 403
    reports_dir = os.getenv('REPORTS_DIR', '/opt/fasterup-portal/data/reports')
    filepath = os.path.join(reports_dir, safe)
    if not os.path.isfile(filepath):
        return jsonify({'error': 'report not found'}), 404
    mime = ('application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            if ext == '.docx' else 'application/pdf')
    return send_file(filepath, mimetype=mime, as_attachment=True, download_name=safe)


@bp.route('/reports/list', methods=['GET'])
@require_org_access
def list_reports():
    reports_dir = os.getenv('REPORTS_DIR', '/opt/fasterup-portal/data/reports')
    files = []
    if os.path.isdir(reports_dir):
        for f in sorted(os.listdir(reports_dir), reverse=True):
            if f.endswith('.pdf') or f.endswith('.docx'):
                if not _report_visible(f):
                    continue
                p = os.path.join(reports_dir, f)
                if not os.path.isfile(p):
                    continue
                files.append({
                    'filename': f,
                    'size_bytes': os.path.getsize(p),
                    'created_at': datetime.fromtimestamp(os.path.getctime(p), timezone.utc).isoformat(),
                    'download_url': f'/api/reports/download/{f}'
                })
    return jsonify({'source': 'filesystem', 'count': len(files), 'reports': files})


@bp.route('/reports/csv', methods=['POST'])
@require_org_access
def export_csv():
    """Export client report data as CSV (offline study in Excel)."""
    import csv as _csv
    data = request.get_json(silent=True) or {}
    client_id, period, lang, date_from, date_to = _parse_req(data)
    if not client_id:
        return jsonify({'status': 'error', 'error': 'client_id required'}), 400
    if g.visible_agent_ids is not None and client_id not in g.visible_agent_ids:
        return jsonify({'status': 'error', 'error': 'forbidden: client not visible'}), 403
    try:
        payload = _build_client_data(client_id, period, lang, date_from, date_to)
    except ValueError as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400
    except Exception as e:
        current_app.logger.exception('CSV build failed')
        return jsonify({'status': 'error', 'error': str(e)}), 500
    buf = io.StringIO(); w = _csv.writer(buf)
    _csv_brand = {'ICI_SOC': 'ICISOC', 'FASTERUP_DIRECT': 'FasterUp SOC'}.get(
        payload.get('organization'), 'CYBER3')
    w.writerow([f'{_csv_brand} - Client Report (CSV export)'])
    w.writerow(['Client', payload.get('client_name', '')])
    w.writerow(['Period', (payload.get('period') or {}).get('label', '')])
    w.writerow([])
    s = payload.get('summary', {})
    w.writerow(['SUMMARY'])
    w.writerow(['Events processed', s.get('events_processed', 0)])
    w.writerow(['Heightened (lvl>=7)', s.get('heightened_attention', 0)])
    w.writerow(['External attacks blocked (real, active-response)', s.get('real_blocks', 0)])
    w.writerow(['Events level 10+', s.get('events_l10', 0)])
    nis2_ = payload.get('nis2', {})
    w.writerow(['NIS2 raw events lvl>=12 (telemetry)', nis2_.get('tier_raw_l12', 0)])
    w.writerow(['NIS2 correlated incidents (unique flows)', nis2_.get('tier_correlated', 0)])
    w.writerow(['NIS2 significant candidates (correlated + confirmed 2xx)',
                s.get('significant_candidates', 0)])
    w.writerow(['NIS2 non-web flows (analyst review)', nis2_.get('tier_nonweb', 0)])
    w.writerow(['Sensor availability', (payload.get('availability') or {}).get('display', '')])
    w.writerow([])
    blk = payload.get('blocked', {})
    w.writerow(['BLOCKED (external, active-response 651)', 'events', 'unique IPs', 'total firewall-drops', 'mode'])
    w.writerow(['', blk.get('external_events', 0), blk.get('external_ips', 0),
                blk.get('total_651', 0), blk.get('mode', '')])
    w.writerow(['TOP BLOCKED IPs', 'country', 'events', 'first', 'last'])
    for ip in blk.get('top_ips', []):
        w.writerow([ip.get('ip', ''), ip.get('country', ''), ip.get('count', 0),
                    ip.get('first', ''), ip.get('last', '')])
    w.writerow([])
    sev = payload.get('severity', {})
    w.writerow(['SEVERITY', 'low', 'medium', 'high', 'critical'])
    w.writerow(['count', sev.get('low', 0), sev.get('medium', 0), sev.get('high', 0), sev.get('critical', 0)])
    w.writerow([])
    w.writerow(['TOP THREATS (rule)', 'count'])
    for t in payload.get('threats', []):
        w.writerow([t.get('name', ''), t.get('count', 0)])
    w.writerow([]); w.writerow(['TOP ATTACKER IPs', 'country', 'attempts', 'max_level'])
    for ip in payload.get('top_ips', []):
        w.writerow([ip.get('ip', ''), ip.get('country', ''), ip.get('attempts', 0), ip.get('max_level', 0)])
    w.writerow([]); w.writerow(['MITRE TECHNIQUES', 'id', 'count'])
    for t in (payload.get('mitre') or {}).get('techniques', []):
        w.writerow([t.get('name', ''), t.get('id', ''), t.get('count', 0)])
    w.writerow([]); w.writerow(['TARGETED PORTS', 'service', 'count'])
    for p in (payload.get('targets') or {}).get('ports', []):
        w.writerow([p.get('port', ''), p.get('service', ''), p.get('count', 0)])
    w.writerow([]); w.writerow(['INCIDENTS LEVEL 10+', 'level', 'rule', 'src', 'dst', 'mitre'])
    for i in payload.get('incidents', []):
        w.writerow([i.get('timestamp', ''), i.get('level', ''), i.get('description', ''),
                    i.get('src_ip', ''), i.get('dest_ip', ''), i.get('mitre', '')])
    w.writerow([]); evo = payload.get('evolution', {})
    w.writerow(['EVOLUTION (' + evo.get('interval', '') + ')', 'critical', 'high', 'medium', 'low'])
    for b in evo.get('bins', []):
        w.writerow([b.get('label', ''), b.get('critical', 0), b.get('high', 0), b.get('medium', 0), b.get('low', 0)])
    out = buf.getvalue().encode('utf-8-sig')
    ts = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    fname = 'Report_' + _safe_filename(payload.get('client_name', 'client')) + '_' + _safe_filename(period) + '_' + ts + '.csv'
    return send_file(io.BytesIO(out), mimetype='text/csv', as_attachment=True, download_name=fname)
