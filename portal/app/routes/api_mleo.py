"""MLEO — Multi Layer Enforcement Orchestrator panel (RBAC per organizatie).
Citeste /opt/cyber3/mleo/mleo.db (read-only). Nu executa enforcement.
RBAC: analistii vad DOAR senzorii organizatiei lor (g.visible_agent_ids -> clients.code, lowercase);
supervizorul (organizatie ALL) vede toata flota. Filtru pe coloana `sensor` (prezenta in recon/blocks/matches/tx).
"""
from flask import Blueprint, jsonify, g
import sqlite3, os, time
from app.utils.auth_decorators import require_org_access

bp = Blueprint('mleo', __name__)
DB = '/opt/cyber3/mleo/mleo.db'


def _rows(sql, args=()):
    if not os.path.exists(DB):
        return []
    c = sqlite3.connect(f'file:{DB}?mode=ro', uri=True, timeout=5)
    c.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in c.execute(sql, args).fetchall()]
    finally:
        c.close()


def _n(sql, args=()):
    r = _rows(sql, args)
    return (r[0] and list(r[0].values())[0]) if r else 0


def _visible_sensors():
    """Nume senzori (lowercase) vizibili userului curent, din g.visible_agent_ids -> clients.code.
    None = supervisor (fara filtru); [] = niciun senzor; lista = doar acei senzori."""
    vids = getattr(g, 'visible_agent_ids', None)
    if vids is None:
        return None
    if not vids:
        return []
    from app.services.auth_service import get_db
    ph = ','.join('?' * len(vids))
    conn = get_db()
    try:
        rows = conn.execute(
            f'SELECT code FROM clients WHERE wazuh_agent_id IN ({ph}) AND active = 1',
            tuple(vids)
        ).fetchall()
        return [str(r['code']).lower() for r in rows]
    finally:
        conn.close()


def _scope():
    """(sf_where, sf_and, params, empty) pentru filtrarea pe senzor (case-insensitive)."""
    sens = _visible_sensors()
    if sens is None:
        return '', '', (), False           # supervisor: fara filtru
    if not sens:
        return '', '', (), True            # analist fara senzori -> gol
    inlist = '(' + ','.join('?' * len(sens)) + ')'
    return (' WHERE LOWER(sensor) IN ' + inlist,
            ' AND LOWER(sensor) IN ' + inlist,
            tuple(sens), False)


@bp.route('/mleo/summary', methods=['GET'])
@require_org_access
def mleo_summary():
    w, a, p, empty = _scope()
    if empty:
        z = {k: 0 for k in ('recon_rows', 'distinct_mac', 'mac_multi_ip', 'blocks',
                            'blocks_with_mac', 'blocks_external', 'match1', 'tx_proposed', 'tx_armed')}
        return jsonify({'stats': z, 'matches': [], 'tx': [], 'multi_ip': [],
                        'generated': int(time.time()), 'db_present': os.path.exists(DB), 'scoped': True})
    stats = {
        'recon_rows':      _n(f"SELECT COUNT(*) FROM recon{w}", p),
        'distinct_mac':    _n(f"SELECT COUNT(DISTINCT mac) FROM recon{w}", p),
        'mac_multi_ip':    _n(f"SELECT COUNT(*) FROM (SELECT mac FROM recon{w} GROUP BY mac HAVING COUNT(DISTINCT ip)>1)", p),
        'blocks':          _n(f"SELECT COUNT(*) FROM blocks{w}", p),
        'blocks_with_mac': _n(f"SELECT COUNT(*) FROM blocks WHERE mac IS NOT NULL{a}", p),
        'blocks_external': _n(f"SELECT COUNT(*) FROM blocks WHERE mac IS NULL AND enriched=1{a}", p),
        'match1':          _n(f"SELECT COUNT(*) FROM matches WHERE kind='match1'{a}", p),
        'tx_proposed':     _n(f"SELECT COUNT(*) FROM tx WHERE state='proposed'{a}", p),
        'tx_armed':        _n(f"SELECT COUNT(*) FROM tx WHERE state='armed'{a}", p),
    }
    return jsonify({
        'stats': stats,
        'matches': _rows(f"SELECT ts,mac,ips,sensor,note FROM matches{w} ORDER BY ts DESC LIMIT 20", p),
        'tx':      _rows(f"SELECT txid,ts,sensor,mac,ips,state FROM tx{w} ORDER BY ts DESC LIMIT 20", p),
        'multi_ip': _rows(f"SELECT mac, GROUP_CONCAT(DISTINCT ip) AS ips, GROUP_CONCAT(DISTINCT sensor) AS sensors "
                          f"FROM recon{w} GROUP BY mac HAVING COUNT(DISTINCT ip)>1 ORDER BY mac LIMIT 40", p),
        'generated': int(time.time()),
        'db_present': os.path.exists(DB),
        'scoped': bool(w),
    })


@bp.route('/mleo/query/<ip>', methods=['GET'])
@require_org_access
def mleo_query(ip):
    w, a, p, empty = _scope()
    if empty:
        return jsonify({'ip': ip, 'found': False})
    row = _rows(f"SELECT mac,sensor,last_seen FROM recon WHERE ip=?{a} ORDER BY last_seen DESC LIMIT 1", (ip,) + p)
    if not row:
        return jsonify({'ip': ip, 'found': False})
    mac = row[0]['mac']
    return jsonify({
        'ip': ip, 'found': True, 'mac': mac, 'sensor': row[0]['sensor'],
        'history': _rows(f"SELECT ip,sensor,first_seen,last_seen FROM recon WHERE mac=?{a} ORDER BY last_seen DESC", (mac,) + p),
    })
