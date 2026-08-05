"""Status snapshot client — citește /var/lib/wazuh-healthcheck/last_status.json de pe Wazuh Server.

Snapshot-ul e produs de wazuh-healthcheck.service (rulează la 10 min pe wazuh-server).
Conține starea celor 7 fluxuri verificate de healthcheck — folosit de Health Check
inline din pagina Overview a portalului.

Cache 30s evită SSH la fiecare request al unui analist (refresh browser la 30s).
"""
import os
import json
import logging
import subprocess
import time
from typing import Dict, Any

log = logging.getLogger(__name__)

# Structura goală returnată în caz de eroare — frontend-ul o gestionează.
EMPTY_SNAPSHOT: Dict[str, Any] = {
    'timestamp': None,
    'agents_active': None,
    'flow': {
        k: {'state': 'unknown', 'msg': ''}
        for k in ('vpn', 'alerts_json', 'filebeat', 'indexer',
                  'integratord', 'anthropic', 'telegram')
    },
    'error': None,
}


class StatusSnapshotClient:
    def __init__(self, ssh_host, ssh_user, snapshot_path, cache_ttl=30):
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.snapshot_path = snapshot_path
        self.cache_ttl = cache_ttl
        self._cache = {}  # key → (timestamp, value)

    def _fetch_snapshot_raw(self) -> str:
        """SSH la Wazuh Server, returnează conținutul last_status.json (text)."""
        cmd = [
            'ssh',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'ConnectTimeout=5',
            '-o', 'BatchMode=yes',
            f'{self.ssh_user}@{self.ssh_host}',
            f'cat {self.snapshot_path}'
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                log.error(f'SSH fetch snapshot failed: {result.stderr.strip()}')
                return ''
            return result.stdout
        except subprocess.TimeoutExpired:
            log.error('SSH fetch snapshot timeout (>10s)')
            return ''
        except Exception as e:
            log.error(f'SSH fetch snapshot exception: {e}')
            return ''

    def get_snapshot(self) -> Dict[str, Any]:
        """Returnează snapshot-ul actual. Cu cache 30s TTL.

        Returnează EMPTY_SNAPSHOT + error="..." la eroare; nu ridică excepție.
        """
        cache_key = 'snapshot'
        now = time.time()
        if cache_key in self._cache:
            cached_at, cached_val = self._cache[cache_key]
            if now - cached_at < self.cache_ttl:
                return cached_val

        raw = self._fetch_snapshot_raw()
        if not raw:
            result = dict(EMPTY_SNAPSHOT)
            result['error'] = 'snapshot indisponibil (ssh sau fișier)'
            # cache scurt și pentru eroare ca să nu spamăm SSH
            self._cache[cache_key] = (now, result)
            return result

        try:
            data = json.loads(raw)
            # validare minimală — trebuie să aibă cheia "flow"
            if 'flow' not in data:
                raise ValueError("snapshot fără cheia 'flow'")
            self._cache[cache_key] = (now, data)
            log.info(f"Status snapshot loaded: timestamp={data.get('timestamp')}, "
                     f"agents_active={data.get('agents_active')}")
            return data
        except (json.JSONDecodeError, ValueError) as e:
            log.error(f'Snapshot JSON parse error: {e}')
            result = dict(EMPTY_SNAPSHOT)
            result['error'] = f'snapshot invalid: {e}'
            self._cache[cache_key] = (now, result)
            return result


_client = None


def get_client():
    global _client
    if _client is None:
        _client = StatusSnapshotClient(
            ssh_host=os.getenv('WAZUH_SERVER_HOST', '192.168.0.10'),
            ssh_user=os.getenv('WAZUH_SERVER_USER', 'socadmin'),
            snapshot_path=os.getenv('STATUS_SNAPSHOT_PATH',
                                    '/var/lib/wazuh-healthcheck/last_status.json'),
            cache_ttl=int(os.getenv('STATUS_SNAPSHOT_CACHE_TTL_SEC', '30')),
        )
    return _client
