"""Wazuh endpoints — REAL DATA from Wazuh API + OpenSearch + CyberBot log.

All endpoints are auth-protected and filtered by current_user.organization.
- supervisor (organization='ALL') → sees all data
- analyst → sees only data for their organization's clients

Filtering uses g.visible_agent_ids populated by @require_org_access decorator.
"""
from flask import Blueprint, jsonify, request, current_app, g
from datetime import datetime, timedelta, timezone
import sqlite3

from app.services.wazuh_client import get_client as get_wazuh
from app.services.opensearch_client import get_client as get_opensearch
from app.services.cyberbot_log_client import get_client as get_cyberbot
from app.utils.auth_decorators import require_org_access
from app.utils.query_helpers import (
    filter_wazuh_agents,
    filter_alerts_by_agents,
    filter_decisions_by_agents,
    aggregate_decisions_by_hour,
)

bp = Blueprint('wazuh', __name__)



def _get_agent_code_map():
    """Build {wazuh_agent_id: client_code} map from portal DB. Cached on g per-request."""
    if hasattr(g, "_agent_code_map"):
        return g._agent_code_map
    mapping = {}
    try:
        db_path = current_app.config.get("DATABASE_PATH", "/opt/fasterup-portal/data/portal.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT wazuh_agent_id, code FROM clients WHERE wazuh_agent_id IS NOT NULL AND code IS NOT NULL")
        for agent_id, code in cur.fetchall():
            if agent_id and code:
                mapping[str(agent_id)] = code
        conn.close()
    except Exception as e:
        current_app.logger.warning(f"Failed to build agent code map: {e}")
    g._agent_code_map = mapping
    return mapping


def _mask_agent_name(agent_id, wazuh_name):
    """Return client code if mapped, else fall back to wazuh name."""
    if not agent_id:
        return wazuh_name or "unknown"
    code = _get_agent_code_map().get(str(agent_id))
    return code if code else (wazuh_name or "unknown")


def _transform_alert(src):
    """Transform OpenSearch document → portal alert format."""
    rule = src.get('rule', {})
    agent = src.get('agent', {})
    data = src.get('data', {})

    level = rule.get('level', 0)
    rule_id = str(rule.get('id', ''))

    if level >= 13:
        decision = {'code': 'ESCALADARE', 'label': 'ESCALATE'}
    elif level >= 10:
        decision = {'code': 'BLOCARE_IMEDIATA', 'label': 'BLOCK'}
    elif level >= 7:
        decision = {'code': 'MONITORIZARE', 'label': 'MONITOR'}
    else:
        decision = {'code': 'IGNORARE', 'label': 'IGNORE'}

    context_sources = ['WAZ']
    if data.get('srcip'):
        context_sources.insert(0, 'SURI')

    return {
        'id': src.get('id') or src.get('@timestamp', ''),
        'timestamp': src.get('@timestamp', ''),
        'client': {
            'id': agent.get('id', '?'),
            'name': _mask_agent_name(agent.get('id'), agent.get('name')),
            'wazuh_name': agent.get('name', 'unknown')
        },
        'source_ip': data.get('srcip') or data.get('src_ip') or 'N/A',
        'attack_type': rule.get('description', 'Unknown event')[:80],
        'level': level,
        'rule_id': rule_id,
        'decision': decision,
        'context_sources': context_sources,
        'telegram_sent': level >= 10,
        'mitre': {
            'id': (rule.get('mitre') or {}).get('id', []) or [],
            'tactic': (rule.get('mitre') or {}).get('tactic', []) or [],
            'technique': (rule.get('mitre') or {}).get('technique', []) or [],
        },
        'compliance': {
            'gdpr': rule.get('gdpr', []) or [],
            'hipaa': rule.get('hipaa', []) or [],
            'pci_dss': rule.get('pci_dss', []) or [],
            'nist_800_53': rule.get('nist_800_53', []) or [],
            'tsc': rule.get('tsc', []) or [],
        }
    }


@bp.route('/alerts', methods=['GET'])
@require_org_access
def list_alerts():
    """List alerts from OpenSearch, filtered by user's visible agents."""
    try:
        limit = min(int(request.args.get('limit', 50)), 500)
        min_level = int(request.args.get('min_level', 0))
        single_agent = request.args.get('agent_id')
        os_client = get_opensearch()

        # Determine the effective agent scope and push it INTO the OpenSearch query,
        # instead of fetching a global recent window and filtering it post-hoc. On a busy
        # fleet the old approach let a noisy agent crowd out a quiet client → ~1 alert.
        if single_agent:
            if g.visible_agent_ids is not None and single_agent not in g.visible_agent_ids:
                return jsonify({'source': 'error', 'error': 'forbidden: agent not visible'}), 403
            effective_agents = [single_agent]
        else:
            effective_agents = g.visible_agent_ids  # None = all (supervisor); list/[] = scoped

        # R4/R5/R7 (feedback ICISOC): pentru vizualizarea BENEFICIARULUI (scoped, nu SOC/supervisor)
        # excludem evenimentele de GAZDĂ ale senzorului (syscheck/pachete/socadmin/sudo/etc.).
        exclude_noise = g.visible_agent_ids is not None
        raw_alerts = os_client.recent_alerts(limit=limit, min_level=min_level,
                                             agent_ids=effective_agents, exclude_noise=exclude_noise)
        transformed = [_transform_alert(a) for a in raw_alerts]

        # EXACT count over the interval for the same scope (no 10k cap, no window truncation)
        # → matches the number a Wazuh Discover query shows for the same client/interval.
        try:
            total_interval_24h = os_client.count_alerts(agent_ids=effective_agents,
                                                         min_level=min_level, exclude_noise=exclude_noise)
        except Exception as ce:
            current_app.logger.warning(f"count_alerts failed: {ce}")
            total_interval_24h = None

        return jsonify({
            'source': 'opensearch',
            'alerts': transformed,
            'total_returned': len(transformed),
            'total_interval_24h': total_interval_24h,
            'filtered': g.visible_agent_ids is not None,
            'agent_filter': single_agent,
        })
    except Exception as e:
        current_app.logger.error(f"Failed to fetch alerts: {e}")
        return jsonify({'source': 'error', 'error': str(e), 'alerts': []}), 500


@bp.route('/stats', methods=['GET'])
@require_org_access
def overview_stats():
    """Overview KPIs — Wazuh + OpenSearch aggregations, filtered."""
    result = {
        'wazuh': {'source': 'wazuh-api'},
        'clients': {},
        'last_24h': {},
    }

    # Wazuh agents (filtered)
    try:
        wz = get_wazuh()
        agents_resp = wz.get_agents(limit=500)
        all_agents = agents_resp.get('data', {}).get('affected_items', [])
        visible_agents = filter_wazuh_agents(all_agents, g.visible_agent_ids)

        active_count = sum(1 for a in visible_agents
                           if a.get('status') == 'active' and a.get('id') != '000')
        disconnected = sum(1 for a in visible_agents
                           if a.get('status') == 'disconnected')
        total = sum(1 for a in visible_agents if a.get('id') != '000')

        result['wazuh']['agents_active'] = active_count
        result['wazuh']['agents_disconnected'] = disconnected
        result['wazuh']['agents_total'] = total
        manager_info = wz.get_manager_info().get('data', {}).get('affected_items', [{}])
        result['wazuh']['manager_version'] = manager_info[0].get('version', 'unknown') if manager_info else 'unknown'
    except Exception as e:
        current_app.logger.error(f"Wazuh stats failed: {e}")
        result['wazuh']['error'] = str(e)

    # Client count from filtered visible agents
    result['clients']['total'] = result['wazuh'].get('agents_total', 0)
    result['clients']['active'] = result['wazuh'].get('agents_active', 0)
    result['clients']['test'] = result['wazuh'].get('agents_active', 0)

    # 24h alerts — direct from OpenSearch (Wazuh indexer), NO CyberBot dependency
    try:
        os_client = get_opensearch()
        hourly = os_client.alerts_hourly_by_level(agent_ids=g.visible_agent_ids)
        bins = hourly.get('bins', [])
        total_24h = sum(b.get('critical', 0) + b.get('high', 0) +
                        b.get('medium', 0) + b.get('low', 0) for b in bins)
        critical_count = sum(b.get('critical', 0) + b.get('high', 0) for b in bins)
        # Blocari REALE din CyberBot (executie BLOCK_IP + PERMA_REBLOCK), filtrate RBAC.
        # g.visible_agent_ids: None = admin (toata flota); lista = analist (doar agentii lui).
        try:
            _cb = get_cyberbot()
            if g.visible_agent_ids is None:
                _allowed = None
            else:
                _names = {a.get('name') for a in visible_agents if a.get('name')}
                _allowed = set(g.visible_agent_ids) | _names
            block_count = _cb.count_real_blocks(allowed_keys=_allowed, hours=24)
            tg_count = _cb.count_telegram_sent(allowed_keys=_allowed, hours=24)
        except Exception as _e:
            current_app.logger.error(f'CyberBot real blocks failed: {_e}')
            block_count = 0
            tg_count = None
        escalate_count = sum(b.get('critical', 0) for b in bins)
        result['last_24h'] = {
            '_source': 'opensearch',
            'alerts_processed': total_24h,
            'ai_decisions': critical_count,
            'ips_blocked': block_count,
            'escalations': escalate_count,
            'telegram_sent_count': tg_count,
        }
    except Exception as e:
        current_app.logger.error(f'Stats from OpenSearch failed: {e}')
        result['last_24h'] = {'_source': 'error', 'error': str(e)}

    # KPI timp-decizie REAL (punct 2 ICI) — latența medie analyze_with_claude din cyberbot.log
    try:
        avg_ms = get_cyberbot().avg_decision_time_ms()
        if avg_ms is not None and isinstance(result.get('last_24h'), dict):
            result['last_24h']['avg_decision_ms'] = avg_ms
    except Exception as e:
        current_app.logger.warning(f'avg_decision_time failed: {e}')

    return jsonify(result)


@bp.route('/decisions/hourly', methods=['GET'])
@require_org_access
def decisions_hourly():
    """24h hourly histogram of REAL ALERTS from OpenSearch, split by severity level, filtered by user's visible agents."""
    try:
        os_client = get_opensearch()
        result = os_client.alerts_hourly_by_level(agent_ids=g.visible_agent_ids)
        return jsonify({
            'source': 'opensearch',
            'bins': result.get('bins', []),
            'filtered': g.visible_agent_ids is not None,
        })
    except Exception as e:
        current_app.logger.error(f"Hourly alerts failed: {e}")
        return jsonify({'source': 'error', 'error': str(e), 'bins': []}), 500

@bp.route('/blocking/layers', methods=['GET'])
@require_org_access
def blocking_layers():
    """3-STRATURI DE BLOCARE — contoare în timp real, agregat pe flotă SAU pe un senzor.

    Layer 1  IPS Block          — Suricata inline drops   (OpenSearch data.alert.action=blocked)
    Layer 2  AR Native Block    — Wazuh Active-Response    (OpenSearch rule.id 100651/651)
    Layer 3  CyberBot Fusion    — decizii fuziune CyberBot (cyberbot.log [BLOCK_IP]/[PERMA_REBLOCK])

    RBAC: g.visible_agent_ids (None=supervisor toată flota; listă=analist doar senzorii lui;
    []=analist fără senzori). ?agent_id=<id> restrânge la un singur senzor (drill-down),
    validat împotriva setului vizibil. Fiecare strat degradează independent (0, nu 500).
    """
    try:
        hours = min(int(request.args.get('hours', 24)), 168)
    except (TypeError, ValueError):
        hours = 24
    single_agent = request.args.get('agent_id')

    # ---- scope (RBAC + drill-down) ----
    if single_agent:
        if g.visible_agent_ids is not None and single_agent not in g.visible_agent_ids:
            return jsonify({'source': 'error', 'error': 'forbidden: agent not visible'}), 403
        effective_agents = [single_agent]
        scope = single_agent
    else:
        effective_agents = g.visible_agent_ids  # None=all, list, []
        scope = 'fleet' if g.visible_agent_ids is None else 'scoped'

    # ---- Wazuh agent list (filtrat RBAC) → id↔name + etichete mascate ----
    id_to_name, name_to_id, id_to_status = {}, {}, {}
    visible_agents = []
    try:
        wz = get_wazuh()
        all_agents = wz.get_agents(limit=500).get('data', {}).get('affected_items', [])
        visible_agents = filter_wazuh_agents(all_agents, g.visible_agent_ids)
        for a in visible_agents:
            aid, nm = str(a.get('id')), a.get('name')
            id_to_status[aid] = a.get('status')
            if nm:
                id_to_name[aid] = nm
                name_to_id[nm] = aid
    except Exception as e:
        current_app.logger.warning(f"blocking_layers agent list failed: {e}")

    # ---- LAYER 1 + 2 din OpenSearch (filtrare la nivel de query pe agent.id) ----
    os_client = get_opensearch()
    try:
        ips = os_client.blocking_ips(agent_ids=effective_agents, hours=hours)
    except Exception as e:
        current_app.logger.error(f"blocking_layers IPS failed: {e}")
        ips = {'total': 0, 'by_agent': {}, 'by_hour': []}
    try:
        arn = os_client.blocking_ar_native(agent_ids=effective_agents, hours=hours)
    except Exception as e:
        current_app.logger.error(f"blocking_layers AR failed: {e}")
        arn = {'total': 0, 'by_agent': {}, 'by_hour': []}

    # ---- LAYER 3 din cyberbot.log (chei = id-uri SAU nume) ----
    # allowed_keys pentru filtrarea log-ului: id-urile vizibile ∪ numele lor.
    if single_agent:
        allowed_keys = {single_agent}
        nm = id_to_name.get(single_agent)
        if nm:
            allowed_keys.add(nm)
    elif g.visible_agent_ids is None:
        allowed_keys = None  # supervisor: toată flota
    else:
        allowed_keys = set(str(x) for x in g.visible_agent_ids) | set(name_to_id.keys())

    cb_total, cb_hour, cb_by_id = 0, [], {}
    try:
        cb = get_cyberbot()
        cb_total = cb.count_real_blocks(allowed_keys=allowed_keys, hours=hours)
        cb_hour = cb.real_blocks_by_hour(allowed_keys=allowed_keys, hours=hours)
        # per-senzor: pliază cheile (id sau nume) la agent_id
        for key, cnt in cb.real_blocks_by_agent(hours=hours).items():
            aid = key if key in id_to_name else name_to_id.get(key, key)
            if single_agent and aid != single_agent:
                continue
            if allowed_keys is not None and key not in allowed_keys:
                continue
            cb_by_id[aid] = cb_by_id.get(aid, 0) + cnt
    except Exception as e:
        current_app.logger.error(f"blocking_layers CyberBot failed: {e}")

    # ---- STRAT 3 (model 7 straturi): L2 Shield din NOC (ebtables anti-ARP-spoof/rogue-DHCP, agregat flotă) ----
    # Complementar straturilor IP: blochează ARP-spoof/MAC (nu IP-uri) -> se adună DISTINCT la total.
    l2shield = {'sensors_with_l2': 0, 'armed': 0, 'enforce': 0, 'blocks': 0}
    l2_by_node = {}
    try:
        import requests as _rq
        _tok = ''
        try:
            _tok = open('/opt/fasterup-portal/.noc_read_token').read().strip()
        except Exception:
            pass
        _h = {'authorization': 'Bearer ' + _tok} if _tok else {}
        _r = _rq.get('https://cyber3-noc.cyber3.workers.dev/v1/noc/l2shield', headers=_h, timeout=4)
        if _r.ok:
            _d = _r.json()
            l2shield = {'sensors_with_l2': int(_d.get('sensors_with_l2', 0)),
                        'armed': int(_d.get('armed', 0)),
                        'enforce': int(_d.get('enforce', 0)),
                        'blocks': int(_d.get('blocks', 0))}
            l2_by_node = _d.get('by_node', {}) or {}
    except Exception as e:
        current_app.logger.warning(f'blocking_layers L2 Shield NOC fetch failed: {e}')

    # ---- numărătoare INDEPENDENTĂ (dedup pe IP între straturi) ----
    # Regulă (cerere operator): o amenințare blocată de IPS SAU AR nu se mai contorizează la CyberBot.
    # Atribuire pe strat, prioritate IPS(fir) > AR(gazdă) > CyberBot(AI); fiecare IP o singură dată.
    independent = {'ips': ips['total'], 'ar_native': arn['total'], 'cyberbot': cb_total}
    unique_total = None
    try:
        sets = os_client.blocked_ip_sets(agent_ids=effective_agents, hours=hours)
        cb_ips = get_cyberbot().blocked_ip_set(allowed_keys=allowed_keys, hours=hours)
        ips_s, ar_s = sets.get('ips', set()), sets.get('ar', set())
        independent = {
            'ips': len(ips_s),
            'ar_native': len(ar_s - ips_s),
            'cyberbot': len(cb_ips - ips_s - ar_s),
        }
        unique_total = len(ips_s | ar_s | cb_ips)
    except Exception as e:
        current_app.logger.warning(f'blocking_layers independent count failed: {e}')

    # L2 Shield (ARP-spoof/MAC, nu IP) — se adaugă DISTINCT la totalul unic
    if unique_total is not None:
        unique_total += l2shield['blocks']

    # ---- tabel per-senzor: TOȚI senzorii vizibili (chiar și cu 0), exclude managerul 000 ----
    ids = set(id_to_name.keys()) | set(ips['by_agent']) | set(arn['by_agent']) | set(cb_by_id)
    ids.discard('000')
    if single_agent:
        ids = {single_agent}
    per_sensor = []
    for aid in ids:
        per_sensor.append({
            'agent_id': aid,
            'label': _mask_agent_name(aid, id_to_name.get(aid)),
            'status': id_to_status.get(aid, 'unknown'),
            'ips': ips['by_agent'].get(aid, 0),
            'ar_native': arn['by_agent'].get(aid, 0),
            'cyberbot': cb_by_id.get(aid, 0),
            'l2shield': int((l2_by_node.get(id_to_name.get(aid, ''), {}) or {}).get('blocks', 0)),
        })
    # sortare: după total desc, apoi alfabetic (senzorii liniștiți cu 0 grupați stabil)
    per_sensor.sort(key=lambda r: (-(r['ips'] + r['ar_native'] + r['cyberbot'] + r.get('l2shield', 0)), str(r['label'])))

    return jsonify({
        'source': 'live',
        'scope': scope,
        'hours': hours,
        'filtered': g.visible_agent_ids is not None,
        'totals': {
            'ips': ips['total'],
            'ar_native': arn['total'],
            'cyberbot': cb_total,
            'l2shield': l2shield['blocks'],
        },
        'independent': independent,        # IP-uri distincte atribuite unui singur strat (fără dubla numărare)
        'unique_total': unique_total,      # amenințări unice blocate (union IP, dedup între straturi)
        'l2shield': l2shield,              # STRAT 3 Ethernet: sensors_with_l2/armed/enforce/blocks (agregat flotă)
        'hourly': {
            'ips': ips['by_hour'],
            'ar_native': arn['by_hour'],
            'cyberbot': cb_hour,
        },
        'per_sensor': per_sensor,
    })


@bp.route('/agents', methods=['GET'])
@require_org_access
def list_agents():
    """List Wazuh agents, filtered by user's organization."""
    try:
        wz = get_wazuh()
        agents_resp = wz.get_agents(limit=500)
        all_agents = agents_resp.get('data', {}).get('affected_items', [])
        visible_agents = filter_wazuh_agents(all_agents, g.visible_agent_ids)

        simplified = [{
            'id': a.get('id'),
            'name': _mask_agent_name(a.get('id'), a.get('name')),
            'wazuh_name': a.get('name'),
            'ip': a.get('ip'),
            'status': a.get('status'),
            'os': a.get('os', {}).get('name') if isinstance(a.get('os'), dict) else None,
            'version': a.get('version'),
            'last_keepalive': a.get('lastKeepAlive'),
            'group': a.get('group', []),
        } for a in visible_agents]

        # Per-agent operational metrics (Incidents 7d + Uptime) — real data for the Client Fleet table
        try:
            metrics = get_opensearch().per_agent_metrics(agent_ids=g.visible_agent_ids)
        except Exception as me:
            current_app.logger.warning(f"per_agent_metrics failed: {me}")
            metrics = {}
        for s in simplified:
            m = metrics.get(str(s.get('id')), {})
            s['incidents_7d'] = m.get('incidents_7d', 0)
            s['uptime_pct'] = m.get('uptime_pct')  # None if no telemetry in window

        # Compute summary from filtered agents
        summary = {
            'active': sum(1 for a in simplified if a.get('status') == 'active'),
            'disconnected': sum(1 for a in simplified if a.get('status') == 'disconnected'),
            'never_connected': sum(1 for a in simplified if a.get('status') == 'never_connected'),
            'pending': sum(1 for a in simplified if a.get('status') == 'pending'),
            'total': len(simplified),
        }

        return jsonify({
            'source': 'wazuh-api',
            'summary': summary,
            'agents': simplified,
            'filtered': g.visible_agent_ids is not None,
        })
    except Exception as e:
        current_app.logger.error(f"Failed to fetch agents: {e}")
        return jsonify({'source': 'error', 'error': str(e), 'agents': []}), 500
