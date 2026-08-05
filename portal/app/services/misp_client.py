"""MISP client via PyMISP."""
import os
import logging
from typing import Optional, Dict, Any
from pymisp import PyMISP

log = logging.getLogger(__name__)


class MispClient:
    def __init__(self, url, api_key, verify_ssl=False):
        self.url = url
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self._misp: Optional[PyMISP] = None

    def _connect(self):
        if self._misp is None:
            self._misp = PyMISP(self.url, self.api_key, self.verify_ssl)
        return self._misp

    def server_version(self) -> str:
        try:
            m = self._connect()
            info = m.misp_instance_version
            return info.get('version', 'unknown') if isinstance(info, dict) else str(info)
        except Exception as e:
            log.error(f"MISP version: {e}")
            return 'error'

    def feeds_status(self) -> Dict[str, Any]:
        """Return feeds list with status (enabled/disabled + cached counts)."""
        try:
            m = self._connect()
            feeds = m.feeds(pythonify=False)
            if isinstance(feeds, list):
                return {
                    'feeds': feeds,
                    'total': len(feeds),
                    'enabled': sum(1 for f in feeds if f.get('Feed', {}).get('enabled'))
                }
            return {'feeds': [], 'total': 0, 'enabled': 0}
        except Exception as e:
            log.error(f"MISP feeds: {e}")
            return {'error': str(e), 'feeds': [], 'total': 0, 'enabled': 0}

    def attribute_count(self) -> int:
        """Total attribute count (IOCs) across all events."""
        try:
            m = self._connect()
            stats = m.attributes_statistics()
            if isinstance(stats, dict):
                # Sum all attribute types
                total = sum(int(v) for v in stats.values() if str(v).isdigit())
                return total
            return 0
        except Exception as e:
            log.error(f"MISP attr count: {e}")
            return 0


    def latest_ioc_timestamp(self):
        """Cel mai recent timestamp de atribut (IOC) = prospetime reala. ISO sau None."""
        import datetime
        try:
            m = self._connect()
            for win in ['1d', '7d', '30d', '365d']:
                r = m.search('attributes', timestamp=win, limit=5000, pythonify=False)
                attrs = r.get('Attribute', []) if isinstance(r, dict) else []
                if attrs:
                    mx = max(int(a['timestamp']) for a in attrs if a.get('timestamp'))
                    return datetime.datetime.fromtimestamp(mx, datetime.timezone.utc).isoformat()
            return None
        except Exception as e:
            log.error(f"MISP latest ioc ts: {e}")
            return None


_client = None

def get_client():
    global _client
    if _client is None:
        _client = MispClient(
            url=os.getenv('MISP_URL', 'https://192.168.0.21'),
            api_key=os.getenv('MISP_API_KEY', ''),
            verify_ssl=os.getenv('MISP_VERIFY_SSL', 'False').lower() == 'true'
        )
    return _client
