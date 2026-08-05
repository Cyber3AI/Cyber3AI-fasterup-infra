"""Health check endpoint — verifica status portal."""
from flask import Blueprint, jsonify, current_app
import os
from datetime import datetime, timezone

bp = Blueprint('health', __name__)


@bp.route('/health', methods=['GET'])
def health():
    """Return portal health status."""
    return jsonify({
        'status': 'ok',
        'service': 'fasterup-portal',
        'version': '0.1',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'components': {
            'flask': 'ok',
            'config_loaded': bool(os.getenv('SECRET_KEY')),
            'wazuh_configured': bool(os.getenv('WAZUH_API_URL')),
            'misp_configured': bool(os.getenv('MISP_URL')),
            'telegram_configured': bool(os.getenv('TELEGRAM_BOT_TOKEN')),
        }
    })
