"""Health Check inline pentru pagina Overview a portalului.

Două endpoint-uri:
- GET /api/health/agents  — lista senzorilor vizibili analistului (cu @require_org_access)
- GET /api/health/system  — starea celor 7 fluxuri (citește snapshot de pe wazuh-server)

Datele alimentează grafica Health Check inserată sub Alert Feed în tab-ul Overview.
"""
from datetime import datetime, timezone
from flask import Blueprint, jsonify, current_app, g
from flask_login import login_required

from app.utils.auth_decorators import require_org_access, get_visible_organizations
from app.services.auth_service import get_db
from app.services.wazuh_client import get_client as get_wazuh_client
from app.services.status_snapshot_client import get_client as get_snapshot_client

bp = Blueprint('health_system', __name__)


# ---------------------------------------------------------------------------
# Mapare status Wazuh -> state pentru frontend (mock-aligned).
# Wazuh API: active / pending / disconnected / never_connected
# Frontend:  online / degraded / offline / empty
# ---------------------------------------------------------------------------
_WAZUH_STATE_MAP = {
    'active':          'online',
    'pending':         'degraded',
    'disconnected':    'offline',
    'never_connected': 'offline',
}


def _format_last_seen(iso_ts):
    """Convertește un timestamp ISO din Wazuh în text relativ ('acum 12s', 'acum 2m').

    Wazuh returnează formate gen '2026-05-27T16:15:30.123Z' sau '9999-12-31T23:59:59Z'
    (sentinel pentru never_connected). Returnează '—' la eșec sau sentinel.
    """
    if not iso_ts or not isinstance(iso_ts, str):
        return '—'
    try:
        # normalizează Z în +00:00 pentru fromisoformat
        ts_str = iso_ts.replace('Z', '+00:00')
        ts = datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return '—'

    # sentinel never_connected — Wazuh folosește 9999-...
    if ts.year >= 9999:
        return '—'

    now = datetime.now(timezone.utc)
    delta_sec = (now - ts).total_seconds()

    if delta_sec < 0:
        return 'acum'
    if delta_sec < 60:
        return f'acum {int(delta_sec)}s'
    if delta_sec < 3600:
        return f'acum {int(delta_sec / 60)}m'
    if delta_sec < 86400:
        return f'acum {int(delta_sec / 3600)}h'
    return f'acum {int(delta_sec / 86400)}z'


def _fetch_clients_for_orgs(orgs):
    """Toate clienții (activi + sloturi rezervate) din organizațiile date.

    Returnează listă ordonată după 'code'. Include și inactive (active=0)
    fiindcă sloturile rezervate apar ca 'NOT DEPLOYED' în grafică.
    """
    if not orgs:
        return []
    placeholders = ','.join('?' * len(orgs))
    conn = get_db()
    try:
        rows = conn.execute(
            f'SELECT code, organization, wazuh_agent_id, active '
            f'FROM clients WHERE organization IN ({placeholders}) '
            f'ORDER BY code',
            tuple(orgs)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _fetch_wazuh_agents_by_id():
    """Returnează dict {agent_id: agent_data} de la Wazuh API.

    La eroare returnează dict gol (endpoint-ul nu pică, doar nu are status real).
    """
    try:
        wz = get_wazuh_client()
        response = wz.get_agents(limit=500)
        agents = response.get('data', {}).get('affected_items', [])
        return {a.get('id'): a for a in agents if a.get('id')}
    except Exception as e:
        current_app.logger.error(f'health_system: get_agents failed: {e}')
        return {}


@bp.route('/health/agents', methods=['GET'])
@require_org_access
def health_agents():
    """Lista senzorilor vizibili analistului, cu status și last seen."""
    orgs = get_visible_organizations()
    clients = _fetch_clients_for_orgs(orgs)
    wazuh_agents = _fetch_wazuh_agents_by_id()

    items = []
    for c in clients:
        agent_id = c.get('wazuh_agent_id')
        is_active = bool(c.get('active'))

        # Slot rezervat / inactiv
        if not is_active or not agent_id:
            items.append({
                'code': c['code'],
                'organization': c['organization'],
                'state': 'empty',
                'last_seen': '—',
                'note': 'slot rezervat',
            })
            continue

        # Activ, dar lipsește din răspunsul Wazuh — Wazuh API inaccesibil
        agent = wazuh_agents.get(agent_id)
        if not agent:
            items.append({
                'code': c['code'],
                'organization': c['organization'],
                'state': 'unknown',
                'last_seen': '—',
                'note': 'stare indisponibilă',
            })
            continue

        wz_status = (agent.get('status') or '').lower()
        state = _WAZUH_STATE_MAP.get(wz_status, 'unknown')

        items.append({
            'code': c['code'],
            'organization': c['organization'],
            'state': state,
            'last_seen': _format_last_seen(agent.get('lastKeepAlive')),
            'note': 'agent activ' if state == 'online' else wz_status or '—',
        })

    deployed = sum(1 for it in items if it['state'] != 'empty')
    return jsonify({
        'items': items,
        'total': len(items),
        'deployed': deployed,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    })


@bp.route('/health/system', methods=['GET'])
@login_required
def health_system():
    """Starea celor 7 fluxuri end-to-end (Cluster 1).

    Cluster 2 (Proxmox) NU se interoghează — frontend-ul îl afișează static
    ca operațional, conform deciziei de design.
    """
    snapshot = get_snapshot_client().get_snapshot()
    return jsonify(snapshot)
