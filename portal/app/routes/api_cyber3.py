"""CYBER3.AI — secțiune portal admin-only: stare noduri VPN exit + endpoint-uri EDR/XDR.

ACCES: DOAR supervisor (contul admin). Orice alt rol → 403.
- /api/cyber3/status    : stare noduri VPN (control-plane) + snapshot monitor.
- /api/cyber3/endpoints : endpoint-urile CYBER3 EDR/XDR raportate la SOC (OpenSearch, rule.groups:cyber3).
Read-only.

Copie de referință în repo: CYBER3.APP/vpn-cp/ops/portal-api_cyber3.py
"""
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
import json, os, re, urllib.request, urllib.error

bp = Blueprint('cyber3', __name__)

WORKER_BASE = os.getenv('CYBER3_WORKER_BASE', 'https://cyber3-vpn-cp.cyber3.workers.dev').rstrip('/')
ADMIN_TOKEN_FILE = os.getenv('CYBER3_ADMIN_TOKEN_FILE', '/opt/cyber3/.vpn-cp-admin.token')
SNAPSHOT_FILE = os.getenv('CYBER3_SNAPSHOT_FILE', '/opt/cyber3/vpn-nodes-status.json')
# Edge CYBER3 (puntea SOC) — pentru management coduri de înrolare organizație.
EDGE_BASE = os.getenv('CYBER3_EDGE_BASE', 'https://cyber3-edge.cyber3.workers.dev').rstrip('/')
EDGE_TOKEN_FILE = os.getenv('CYBER3_SOC_ADMIN_TOKEN_FILE', '/opt/cyber3/.soc-admin.token')
CODE_RE = re.compile(r'^[A-Z0-9-]{6,40}$')


def _supervisor():
    return getattr(current_user, 'role', '') == 'supervisor'


def _admin_token():
    try:
        with open(ADMIN_TOKEN_FILE, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return None


def _fetch_nodes(token):
    req = urllib.request.Request(WORKER_BASE + '/admin/nodes',
                                 headers={'authorization': 'Bearer ' + token,
                                          'user-agent': 'cyber3-portal/1.0'})
    with urllib.request.urlopen(req, timeout=12) as r:
        return json.loads(r.read().decode('utf-8')).get('nodes', [])


def _snapshot():
    try:
        with open(SNAPSHOT_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _edge_token():
    try:
        with open(EDGE_TOKEN_FILE, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return None


def _edge_call(method, path, body=None):
    """Apel autentificat către edge-ul CYBER3 (UA explicit — Cloudflare blochează Python-urllib)."""
    token = _edge_token()
    if not token:
        raise RuntimeError('token edge SOC indisponibil pe portal')
    data = json.dumps(body).encode('utf-8') if body is not None else None
    req = urllib.request.Request(EDGE_BASE + path, data=data, method=method,
                                 headers={'authorization': 'Bearer ' + token,
                                          'user-agent': 'cyber3-portal/1.0',
                                          'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=12) as r:
        return json.loads(r.read().decode('utf-8'))


@bp.route('/cyber3/status', methods=['GET'])
@login_required
def cyber3_status():
    if not _supervisor():
        return jsonify({'error': 'forbidden'}), 403
    token = _admin_token()
    out = {'worker_base': WORKER_BASE, 'monitor': _snapshot()}
    if not token:
        out.update({'ok': False, 'error': 'admin token indisponibil pe portal'})
        return jsonify(out), 200
    try:
        nodes = _fetch_nodes(token)
    except (urllib.error.URLError, ValueError, TimeoutError) as e:
        out.update({'ok': False, 'error': 'control-plane inaccesibil: %s' % e, 'nodes': []})
        return jsonify(out), 200
    norm = [{
        'name': n.get('name'), 'ok': bool(n.get('ok')),
        'peers': int(n.get('peers', 0) or 0), 'load1': round(float(n.get('load1', 0) or 0), 2),
        'endpoint': n.get('endpoint'),
    } for n in nodes]
    healthy = sum(1 for n in norm if n['ok'])
    out.update({'ok': True, 'nodes': norm,
                'summary': {'healthy': healthy, 'total': len(norm),
                            'total_peers': sum(n['peers'] for n in norm if n['ok'])}})
    return jsonify(out), 200


@bp.route('/cyber3/endpoints', methods=['GET'])
@login_required
def cyber3_endpoints():
    """Endpoint-urile CYBER3 EDR/XDR raportate la SOC (din alertele Wazuh, grup cyber3)."""
    if not _supervisor():
        return jsonify({'error': 'forbidden'}), 403
    try:
        from app.services.opensearch_client import get_client as _os_client
        q = {
            'size': 300,
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {'bool': {'must': [
                {'term': {'rule.groups': 'cyber3'}},
                {'range': {'@timestamp': {'gte': 'now-14d'}}},
            ]}},
            '_source': ['@timestamp', 'rule.id', 'rule.level', 'rule.description',
                        'data.c3.org', 'data.c3.device_id', 'data.c3.type', 'data.c3.source',
                        'data.c3.data.score', 'data.c3.data.malware_found', 'agent.name'],
        }
        r = _os_client()._search('wazuh-alerts-*', q)
    except Exception as e:
        return jsonify({'ok': False, 'error': 'opensearch: %s' % e, 'endpoints': [], 'recent': []}), 200

    hits = r.get('hits', {}).get('hits', [])
    devices = {}
    recent = []
    for h in hits:
        s = h.get('_source', {}) or {}
        # Câmpurile CYBER3 sunt sub data.c3.* (namespace propriu, ca să nu coliziune cu data.* Wazuh).
        d = (s.get('data', {}) or {}).get('c3', {}) or {}
        nested = d.get('data', {}) if isinstance(d.get('data'), dict) else {}
        rule = s.get('rule', {}) or {}
        dev = d.get('device_id') or '?'
        org = d.get('org') or '?'
        typ = d.get('type') or ''
        rid = str(rule.get('id', ''))
        lvl = int(rule.get('level', 0) or 0)
        ts = s.get('@timestamp', '')
        key = org + '|' + dev
        e = devices.get(key)
        if e is None:
            e = {'device': dev, 'org': org, 'source': d.get('source') or '',
                 'last_seen': ts, 'last_level': lvl, 'last_desc': rule.get('description', ''),
                 'scans': 0, 'threats': 0, 'malware': 0, 'last_score': None}
            devices[key] = e
        if typ == 'pc_scan':
            e['scans'] += 1
            if e['last_score'] is None and nested.get('score') is not None:
                e['last_score'] = nested.get('score')
        if rid == '100604' or typ == 'threat':
            e['threats'] += 1
        if rid == '100603':
            e['malware'] += 1
        if len(recent) < 40:
            recent.append({'ts': ts, 'org': org, 'device': dev, 'type': typ,
                           'level': lvl, 'desc': rule.get('description', '')})
    endpoints = sorted(devices.values(), key=lambda x: x['last_seen'], reverse=True)
    total = r.get('hits', {}).get('total', {})
    total = total.get('value', len(hits)) if isinstance(total, dict) else len(hits)
    return jsonify({'ok': True, 'count': len(endpoints), 'total_alerts': total,
                    'endpoints': endpoints, 'recent': recent}), 200


@bp.route('/cyber3/orgs', methods=['GET'])
@login_required
def cyber3_orgs_list():
    """Listează codurile de înrolare organizație (EDR/XDR) din edge."""
    if not _supervisor():
        return jsonify({'error': 'forbidden'}), 403
    try:
        out = _edge_call('GET', '/v1/soc/admin/orgs')
    except (urllib.error.URLError, ValueError, TimeoutError, RuntimeError) as e:
        return jsonify({'ok': False, 'error': 'edge inaccesibil: %s' % e, 'codes': []}), 200
    return jsonify({'ok': True, 'codes': out.get('codes', [])}), 200


@bp.route('/cyber3/orgs', methods=['POST'])
@login_required
def cyber3_orgs_create():
    """Creează un cod de înrolare pentru o organizație."""
    if not _supervisor():
        return jsonify({'error': 'forbidden'}), 403
    b = request.get_json(silent=True) or {}
    code = str(b.get('code', '')).strip().upper()
    org = str(b.get('org', '')).strip()
    if not CODE_RE.match(code):
        return jsonify({'ok': False, 'error': 'Cod invalid (6-40 caractere: A-Z, 0-9, -).'}), 400
    if not org:
        return jsonify({'ok': False, 'error': 'Organizația este obligatorie.'}), 400
    try:
        out = _edge_call('POST', '/v1/soc/admin/org', {'code': code, 'org': org})
    except (urllib.error.URLError, ValueError, TimeoutError, RuntimeError) as e:
        return jsonify({'ok': False, 'error': 'edge inaccesibil: %s' % e}), 200
    return jsonify({'ok': bool(out.get('ok')), 'code': out.get('code'), 'org': out.get('org'),
                    'active': out.get('active')}), 200


@bp.route('/cyber3/orgs/deactivate', methods=['POST'])
@login_required
def cyber3_orgs_deactivate():
    """Dezactivează un cod de înrolare (dispozitivele deja înrolate nu mai pot reînrola cu el)."""
    if not _supervisor():
        return jsonify({'error': 'forbidden'}), 403
    b = request.get_json(silent=True) or {}
    code = str(b.get('code', '')).strip().upper()
    if not CODE_RE.match(code):
        return jsonify({'ok': False, 'error': 'Cod invalid.'}), 400
    try:
        out = _edge_call('POST', '/v1/soc/admin/org', {'code': code, 'active': False})
    except (urllib.error.URLError, ValueError, TimeoutError, RuntimeError) as e:
        return jsonify({'ok': False, 'error': 'edge inaccesibil: %s' % e}), 200
    return jsonify({'ok': bool(out.get('ok')), 'code': out.get('code'), 'active': out.get('active')}), 200
