"""SSO portal -> Wazuh Dashboard prin JWT scurt (fara a doua parola).

Analistul autentificat in portal apasa link-ul; portalul minteaza un JWT
semnat (HS256, secret comun cu wazuh-indexer) cu identitatea lui si un
backend-role care determina scope-ul in dashboard:
  - supervisor (org ALL) -> backend_role 'admin' (acces complet)
  - analist ICI_SOC       -> backend_role 'icisoc' (DLS + run_as: doar icisoc*)
OpenSearch valideaza JWT-ul (authc jwt_auth_domain, subject_key=user_name,
roles_key=backend_roles) -> aplica rolul icisoc_analyst + run_as icisoc_role.
"""
import os, time, json, hmac, hashlib, base64
from flask import Blueprint, redirect, jsonify
from flask_login import current_user, login_required

bp = Blueprint('dashboard_sso', __name__)


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def _mint(user_name, backend_role, ttl=None):
    if ttl is None:
        # R9 (feedback ICISOC): 120s era prea scurt (forța relogare) → 600s (10 min), configurabil via env.
        # Token în URL → rămâne scurt din motive de securitate (mult sub cele 8h originale).
        ttl = int(os.environ.get('SSO_JWT_TTL', '600'))
    secret = base64.b64decode(os.environ['WAZUH_JWT_SECRET_B64'])
    now = int(time.time())
    header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(',', ':')).encode())
    payload = _b64u(json.dumps({
        "user_name": user_name,
        "backend_roles": backend_role,
        "iat": now,
        "exp": now + ttl,
    }, separators=(',', ':')).encode())
    sig = _b64u(hmac.new(secret, (header + '.' + payload).encode(), hashlib.sha256).digest())
    return header + '.' + payload + '.' + sig


@bp.route('/wazuh-dashboard')
@login_required
def wazuh_dashboard():
    if current_user.is_supervisor:
        backend_role = 'admin'
    elif current_user.organization == 'ICI_SOC':
        backend_role = 'icisoc'
    else:
        return jsonify({'error': 'dashboard_not_configured_for_org'}), 403
    if not os.environ.get('WAZUH_JWT_SECRET_B64'):
        return jsonify({'error': 'sso_secret_missing'}), 500
    token = _mint(current_user.username, backend_role)
    dash = os.environ.get('WAZUH_DASHBOARD_URL', 'https://10.0.0.100').rstrip('/')
    return redirect(dash + '/app/wz-home?jwtToken=' + token, code=302)
