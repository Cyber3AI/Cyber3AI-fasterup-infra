"""Telegram bot endpoints — bot status from API + real feed from cyberbot.log."""
from flask import Blueprint, jsonify, current_app, g, request
from flask_login import login_required
from datetime import datetime, timedelta, timezone
from app.services.telegram_client import get_client as get_tg
from app.services.cyberbot_log_client import get_client as get_cyberbot
from app.utils.auth_decorators import require_org_access
from app.utils.query_helpers import filter_decisions_by_agents

bp = Blueprint('telegram', __name__)


@bp.route('/telegram/stats', methods=['GET'])
@login_required
def telegram_stats():
    try:
        tg = get_tg()
        info = tg.get_me()
        bot = info.get('result', {})
        return jsonify({
            'source': 'telegram-api',
            'bot_username': '@' + bot.get('username', 'unknown'),
            'bot_name': bot.get('first_name'),
            'bot_id': bot.get('id'),
            'is_bot': bot.get('is_bot', False),
            'active_client_channels': 21,
            'analyst_channels': 1,
            'messages_24h': 0,
            'delivery_rate_pct': 100.0,
            'bidirectional_enabled': False
        })
    except Exception as e:
        current_app.logger.error(f"Telegram getMe failed: {e}")
        return jsonify({'source': 'error', 'error': str(e)}), 500


@bp.route('/telegram/recent', methods=['GET'])
@require_org_access
def telegram_recent():
    """Real Telegram feed from /var/ossec/logs/cyberbot.log — only [OK] entries with sent=True
    and decision != IGNORARE. RBAC-filtered by current_user.organization."""
    try:
        cb = get_cyberbot()
        decisions = cb.decisions_recent(days=30)
        # Filter: only delivered (sent=True) and not ignored
        delivered = [d for d in decisions
                     if d.get('sent') is True
                     and d.get('decision') != 'IGNORARE']
        # RBAC filter via shared helper (consistent with /api/alerts and /api/agents)
        delivered = filter_decisions_by_agents(delivered, g.visible_agent_ids)
        # Sort descending by timestamp (newest first)
        delivered.sort(key=lambda d: d.get('timestamp', ''), reverse=True)
        # Optional limit via ?limit=N (default: no cap, return all)
        limit = request.args.get('limit', type=int)
        if limit and limit > 0:
            delivered = delivered[:limit]
        # Map to frontend format
        messages = [{
            'timestamp': d.get('timestamp'),
            'client': d.get('client', '?'),
            'agent_id': d.get('agent_id'),
            'decision': d.get('decision'),
            'ip': d.get('ip'),
            'rule': d.get('rule'),
        } for d in delivered]
        return jsonify({
            'source': 'cyberbot-log',
            'messages': messages,
            'total': len(messages),
            'filtered': g.visible_agent_ids is not None,
        })
    except Exception as e:
        current_app.logger.error(f"Telegram recent failed: {e}")
        return jsonify({'source': 'error', 'error': str(e), 'messages': []}), 500
