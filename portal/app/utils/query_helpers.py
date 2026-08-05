"""Reusable filtering helpers for organization-aware endpoints.

Used by any endpoint that needs to restrict data per current_user.organization.
Pattern:
    from flask import g
    from app.utils.auth_decorators import require_org_access
    from app.utils.query_helpers import filter_wazuh_agents

    @bp.route('/agents')
    @require_org_access
    def list_agents():
        all_agents = wazuh_client.get_agents()
        visible = filter_wazuh_agents(all_agents, g.visible_agent_ids)
        return jsonify({'agents': visible})
"""
from typing import Optional, List, Dict, Any


def filter_wazuh_agents(agents: List[Dict[str, Any]],
                         allowed_ids: Optional[List[str]]) -> List[Dict[str, Any]]:
    """Filter Wazuh agents response by allowed agent IDs.

    Args:
        agents: list of dicts with 'id' field (string)
        allowed_ids: None = no filter (supervisor); list = strict filter

    Returns:
        Filtered list. Always excludes agent '000' (manager itself) for analysts.
    """
    if allowed_ids is None:
        return agents  # supervisor sees everything including '000'
    allowed_set = set(str(x) for x in allowed_ids)
    return [a for a in agents if str(a.get('id')) in allowed_set]


def filter_alerts_by_agents(alerts: List[Dict[str, Any]],
                             allowed_ids: Optional[List[str]]) -> List[Dict[str, Any]]:
    """Filter OpenSearch alerts by agent.id.

    Args:
        alerts: list of alert dicts with nested 'agent.id' field
        allowed_ids: None = no filter; list = strict filter

    Returns:
        Filtered list of alerts.
    """
    if allowed_ids is None:
        return alerts
    allowed_set = set(str(x) for x in allowed_ids)
    out = []
    for a in alerts:
        agent_id = str(a.get('agent', {}).get('id', ''))
        if agent_id in allowed_set:
            out.append(a)
    return out


def filter_decisions_by_agents(decisions: List[Dict[str, Any]],
                                allowed_ids: Optional[List[str]]) -> List[Dict[str, Any]]:
    """Filter CyberBot decisions by agent_id.

    Args:
        decisions: list from cyberbot_log_client (dicts with 'agent_id' field)
        allowed_ids: None = no filter; list = strict filter

    Returns:
        Filtered list of decisions.
    """
    if allowed_ids is None:
        return decisions
    allowed_set = set(str(x) for x in allowed_ids)
    return [d for d in decisions if str(d.get('agent_id')) in allowed_set]


def aggregate_decisions_by_hour(decisions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Re-aggregate filtered decisions into 24 hourly buckets.

    Used after filter_decisions_by_agents() to rebuild the hourly chart from
    a possibly reduced set of decisions.
    """
    from datetime import datetime, timedelta, timezone

    DECISION_LABELS = {
        'BLOCARE_IMEDIATA': 'block',
        'ESCALADARE': 'escalate',
        'MONITORIZARE': 'monitor',
        'IGNORARE': 'ignore',
    }

    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    buckets = {}
    for h_offset in range(24, -1, -1):
        bucket_ts = now - timedelta(hours=h_offset)
        buckets[bucket_ts.isoformat()] = {
            'hour': bucket_ts.isoformat(),
            'label': bucket_ts.strftime('%H'),
            'block': 0,
            'escalate': 0,
            'monitor': 0,
            'ignore': 0,
        }

    for d in decisions:
        ts_dt = d.get('timestamp_dt')
        if ts_dt is None:
            continue
        bucket_ts = ts_dt.replace(minute=0, second=0, microsecond=0)
        key = bucket_ts.isoformat()
        if key not in buckets:
            continue
        label = DECISION_LABELS.get(d.get('decision'))
        if label:
            buckets[key][label] += 1

    return list(buckets.values())
