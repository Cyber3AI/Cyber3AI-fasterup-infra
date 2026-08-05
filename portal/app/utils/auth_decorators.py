"""Authentication & authorization decorators for API endpoints."""
from functools import wraps
from flask import jsonify
from flask_login import current_user


def require_supervisor(fn):
    """Endpoint accessible only to users with role='supervisor'."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'authentication_required'}), 401
        if not current_user.is_supervisor:
            return jsonify({'error': 'supervisor_role_required'}), 403
        return fn(*args, **kwargs)
    return wrapper


def get_visible_organizations():
    """Returns list of organizations the current user can see.

    - supervisor (organization='ALL') → ['ICI_SOC', 'FASTERUP_DIRECT']
    - analyst ICI → ['ICI_SOC']
    - analyst FasterUp → ['FASTERUP_DIRECT']
    """
    if not current_user.is_authenticated:
        return []
    if current_user.can_see_all_orgs:
        return ['ICI_SOC', 'FASTERUP_DIRECT']
    return [current_user.organization]


def get_visible_agent_ids():
    """Returns list of Wazuh agent_ids visible to current user (active clients only).

    Used by API endpoints to filter alerts/decisions/agents per organization.
    Returns None if user has no restrictions (supervisor sees all).
    Returns [] if user is unauthenticated or has no visible clients.
    """
    if not current_user.is_authenticated:
        return []
    if current_user.can_see_all_orgs:
        return None  # signal: no filter

    from app.services.auth_service import get_db
    orgs = get_visible_organizations()
    if not orgs:
        return []
    placeholders = ','.join('?' * len(orgs))
    conn = get_db()
    try:
        rows = conn.execute(
            f'SELECT wazuh_agent_id FROM clients '
            f'WHERE organization IN ({placeholders}) AND wazuh_agent_id IS NOT NULL AND active = 1',
            tuple(orgs)
        ).fetchall()
        return [r['wazuh_agent_id'] for r in rows]
    finally:
        conn.close()


# ============================================================
# SCALABLE PATTERN: @require_org_access
# ============================================================
# Use on any endpoint that should respect organization-based filtering.
# Populates flask.g.visible_agent_ids for use in queries.
#
# Pattern for new endpoints (client-specific or aggregated):
#   @bp.route('/some/new/endpoint')
#   @require_org_access
#   def my_endpoint():
#       agent_ids = g.visible_agent_ids   # None = supervisor (no filter); list = restricted
#       # use agent_ids in your query
# ============================================================

from flask import g


def require_org_access(fn):
    """Decorator: enforces auth + populates g.visible_agent_ids.

    Behavior:
    - Unauthenticated → 401
    - User must change password → 403 (force redirect to change-password)
    - Sets g.visible_agent_ids:
        * None  → supervisor (organization='ALL'), no filter applied
        * list  → analyst, restricted to those wazuh_agent_id values
        * []    → analyst with no deployed clients in their org (empty result is OK)
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'authentication_required'}), 401
        if current_user.must_change_password:
            return jsonify({
                'error': 'password_change_required',
                'message': 'Trebuie să schimbi parola la primul login înainte de orice acces.'
            }), 403
        g.visible_agent_ids = get_visible_agent_ids()
        return fn(*args, **kwargs)
    return wrapper


def user_can_access_client(client_code):
    """Check if current user has access to a specific client (by code).

    Used in endpoints like /api/clients/<code>/something to enforce
    that an analyst can only see their own organization's clients.
    Supervisor sees all.
    """
    if not current_user.is_authenticated:
        return False
    if current_user.can_see_all_orgs:
        return True

    from app.services.auth_service import get_db
    conn = get_db()
    try:
        row = conn.execute(
            'SELECT organization FROM clients WHERE code = ? AND active = 1',
            (client_code,)
        ).fetchone()
        if row is None:
            return False
        return row['organization'] == current_user.organization
    finally:
        conn.close()
