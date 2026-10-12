# -*- coding: utf-8 -*-
"""CYBER3 Threat Hunt — API pentru portal.
Constatările sunt pre-calculate de jobul cyber3-threat-hunt (timer), în data/threat_hunt/latest.json.
RBAC: aceeași regulă ca restul portalului — g.visible_agent_ids (None = toți; listă = doar acei agenți; [] = nimic)."""
import json, os
from flask import Blueprint, jsonify, g, request
from app.utils.auth_decorators import require_org_access, require_supervisor

bp = Blueprint('hunt', __name__)

HUNT_FILE = os.environ.get('HUNT_FILE', '/opt/fasterup-portal/data/threat_hunt/latest.json')
SEV = ['CRITIC', 'ÎNALT', 'MEDIU', 'INFO']
HUNTS = {
    'H1': 'Răspuns reușit la atac (date sensibile livrate)',
    'H2': 'Încărcare de cod acceptată (HTTP 200)',
    'H3': 'Stager PowerShell urmat de C2',
    'H4': 'Comunicare C2 permisă, inițiată din interior',
    'H5': 'Volum mare ieșit spre o adresă externă',
    'H6': 'Honeytoken declanșat',
    'H7': 'Acces la distanță pe o stație nouă',
    'H8': 'Senzor fără alerte de rețea',
}


def _load():
    try:
        with open(HUNT_FILE, encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return {'generated': None, 'window': None, 'findings': []}


def _visible(findings):
    vids = getattr(g, 'visible_agent_ids', None)
    if vids is None:
        return findings
    allowed = {str(v) for v in vids}
    return [f for f in findings if str(f.get('agent_id') or '') in allowed]


def _counts(findings):
    c = {s: 0 for s in SEV}
    for f in findings:
        c[f.get('severity', 'INFO')] = c.get(f.get('severity', 'INFO'), 0) + 1
    return c


@bp.route('/hunt/findings', methods=['GET'])
@require_org_access
def hunt_findings():
    data = _load()
    items = [f for f in _visible(data.get('findings', [])) if f.get('hunt') != 'ERR']
    if request.args.get('include_info', '0') != '1':
        items = [f for f in items if f.get('severity') != 'INFO']
    sev = request.args.get('severity')
    if sev in SEV:
        items = [f for f in items if f.get('severity') == sev]
    agent = request.args.get('agent')
    if agent:
        items = [f for f in items if f.get('agent') == agent]
    return jsonify({'service': 'CYBER3 Threat Hunt', 'generated': data.get('generated'), 'window': data.get('window'),
                    'hunts': HUNTS, 'counts': _counts(items), 'findings': items})


@bp.route('/hunt/summary', methods=['GET'])
@require_org_access
def hunt_summary():
    data = _load()
    items = [f for f in _visible(data.get('findings', [])) if f.get('hunt') != 'ERR']
    return jsonify({'service': 'CYBER3 Threat Hunt', 'generated': data.get('generated'), 'window': data.get('window'),
                    'counts': _counts(items), 'new': sum(1 for f in items if f.get('new') and f.get('severity') != 'INFO')})



MLEO_DB = os.environ.get('MLEO_DB', '/opt/cyber3/mleo/mleo.db')
MLEO_PY = '/opt/cyber3/mleo/mleo.py'
_CKEYS = ('txid', 'ts', 'sensor', 'ip', 'mac', 'source', 'reason', 'ref', 'action', 'critical', 'state', 'last_signal',
          'signals', 'approved_by', 'approved_at', 'expires', 'released_by', 'released_at', 'exec_out')


@bp.route('/hunt/containment', methods=['GET'])
@require_org_access
def hunt_containment():
    """Propuneri MLEO de carantină pentru stații interne compromise. Aprobarea/eliberarea: DOAR supervisor."""
    import sqlite3, time
    from flask_login import current_user
    from app.routes.api_mleo import _visible_sensors
    sup = bool(getattr(current_user, 'is_supervisor', False))
    sens = _visible_sensors()
    if sens is not None and not sens:
        return jsonify({'can_approve': sup, 'items': []})
    q = ('SELECT ' + ','.join(_CKEYS) + " FROM contain WHERE (state IN ('proposed','notify','active')"
         " OR (state IN ('released','rejected','expired') AND COALESCE(released_at, expires, ts) >= ?))")
    args = [int(time.time()) - 7 * 86400]
    if sens is not None:
        q += ' AND LOWER(sensor) IN (' + ','.join('?' * len(sens)) + ')'
        args += list(sens)
    q += " ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'proposed' THEN 1 WHEN 'notify' THEN 2 ELSE 3 END, COALESCE(last_signal, ts) DESC LIMIT 100"
    try:
        c = sqlite3.connect('file:' + MLEO_DB + '?mode=ro', uri=True, timeout=5)
        rows = c.execute(q, args).fetchall()
        c.close()
    except Exception:
        rows = []
    items = [dict(zip(_CKEYS, r)) for r in rows]
    if not sup:
        for it in items:
            it.pop('exec_out', None)
    return jsonify({'can_approve': sup, 'items': items})


def _mleo_action(verb, txid):
    import re, subprocess
    from flask_login import current_user
    if not request.is_json:
        return jsonify({'ok': False, 'error': 'cerere invalidă'}), 400
    if not re.fullmatch(r'[a-z0-9-]{4,64}', txid or ''):
        return jsonify({'ok': False, 'error': 'txid invalid'}), 400
    user = re.sub(r'[^A-Za-z0-9._@-]', '_', str(getattr(current_user, 'username', 'supervisor')))[:64]
    try:
        r = subprocess.run(['/usr/bin/python3', MLEO_PY, verb, txid, user], capture_output=True, text=True, timeout=60)
        out = [l for l in r.stdout.splitlines() if l.startswith('{')]
        res = json.loads(out[-1]) if out else {'ok': False, 'error': (r.stderr or r.stdout)[-300:]}
    except Exception as e:
        res = {'ok': False, 'error': str(e)}
    return jsonify(res), (200 if res.get('ok') else 409)


@bp.route('/hunt/containment/<txid>/approve', methods=['POST'])
@require_supervisor
def hunt_containment_approve(txid):
    return _mleo_action('approve', txid)


@bp.route('/hunt/containment/<txid>/release', methods=['POST'])
@require_supervisor
def hunt_containment_release(txid):
    return _mleo_action('release', txid)
