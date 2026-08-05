"""MISP endpoints — feeds status, IOC counts. REAL DATA."""
from flask import Blueprint, jsonify, current_app
from flask_login import login_required, current_user
from app.services.misp_client import get_client as get_misp

bp = Blueprint('misp', __name__)


@bp.route('/misp/authcheck', methods=['GET'])
def misp_authcheck():
    """Pentru nginx auth_request (poarta la /misp/): 200 daca analistul e autentificat in portal,
    401 altfel. MISP servit prin portal arata DOAR feed-uri publice (fara date de client), deci
    orice analist logat are acces read-only (SSO ca la Wazuh, via CustomAuth header)."""
    if current_user.is_authenticated and not getattr(current_user, 'must_change_password', False):
        return ('', 200)
    return ('', 401)


@bp.route('/misp/stats', methods=['GET'])
@login_required
def misp_stats():
    """MISP global stats — version, IOC total, feed counts."""
    try:
        c = get_misp()
        version = c.server_version()
        feeds = c.feeds_status()
        ioc_total = c.attribute_count()
        return jsonify({
            'source': 'misp-api',
            'version': version,
            'url': 'https://192.168.0.21',
            'feeds_total': feeds.get('total', 0),
            'feeds_active': feeds.get('enabled', 0),
            'ioc_total': ioc_total,
            'last_fetch': c.latest_ioc_timestamp(),  # REAL: cel mai recent IOC din MISP
            'queries_24h': 0,  # TODO: track via cyberbot logs
            'avg_query_latency_ms': 0
        })
    except Exception as e:
        current_app.logger.error(f"MISP stats failed: {e}")
        return jsonify({'source': 'error', 'error': str(e)}), 500


@bp.route('/misp/feeds', methods=['GET'])
@login_required
def misp_feeds():
    """Per-feed breakdown — real data from MISP API."""
    try:
        c = get_misp()
        feeds_data = c.feeds_status()
        raw_feeds = feeds_data.get('feeds', [])

        simplified = []
        for f in raw_feeds:
            fd = f.get('Feed', {})
            simplified.append({
                'name': fd.get('name'),
                'url': fd.get('url'),
                'provider': fd.get('provider'),
                'enabled': fd.get('enabled', False),
                'caching_enabled': fd.get('caching_enabled', False),
                'source_format': fd.get('source_format'),
                'last_updated': fd.get('last_updated'),
            })

        return jsonify({
            'source': 'misp-api',
            'total': len(simplified),
            'feeds': simplified
        })
    except Exception as e:
        current_app.logger.error(f"MISP feeds failed: {e}")
        return jsonify({'source': 'error', 'error': str(e), 'feeds': []}), 500
