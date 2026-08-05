"""Wazuh API client — JWT auth with auto-renewal, typed wrappers.

Usage:
    from app.services.wazuh_client import get_client
    client = get_client()
    alerts = client.get_alerts(limit=50)
"""
import os
import time
import logging
from typing import Optional, List, Dict, Any
import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Disable SSL warnings for self-signed Wazuh cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


class WazuhClient:
    """Thin wrapper over Wazuh REST API (port 55000) with JWT token cache."""

    def __init__(self, base_url: str, user: str, password: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip('/')
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl
        self._token: Optional[str] = None
        self._token_expires_at: float = 0

    def _authenticate(self) -> str:
        """Obtain fresh JWT token. Valid for 15 minutes on Wazuh default."""
        r = requests.post(
            f'{self.base_url}/security/user/authenticate',
            auth=HTTPBasicAuth(self.user, self.password),
            verify=self.verify_ssl,
            timeout=10
        )
        r.raise_for_status()
        data = r.json()
        token = data['data']['token']
        # Wazuh tokens default 900s (15min). We renew 60s before expiry.
        self._token = token
        self._token_expires_at = time.time() + (15 * 60) - 60
        log.debug("Wazuh: new JWT token obtained")
        return token

    def _get_token(self) -> str:
        """Return cached token or refresh if expired."""
        if not self._token or time.time() >= self._token_expires_at:
            return self._authenticate()
        return self._token

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """Signed request to Wazuh API with automatic 401 retry."""
        headers = kwargs.pop('headers', {})
        headers['Authorization'] = f'Bearer {self._get_token()}'
        url = f'{self.base_url}{path}'

        r = requests.request(method, url, headers=headers,
                             verify=self.verify_ssl, timeout=15, **kwargs)

        if r.status_code == 401:
            # Token expired unexpectedly — force renew and retry once
            log.warning("Wazuh: 401 on %s, re-authenticating", path)
            self._token = None
            headers['Authorization'] = f'Bearer {self._get_token()}'
            r = requests.request(method, url, headers=headers,
                                 verify=self.verify_ssl, timeout=15, **kwargs)

        r.raise_for_status()
        return r.json()

    # -------- Public API methods --------

    def get_manager_info(self) -> Dict[str, Any]:
        """Wazuh manager version and status."""
        return self._request('GET', '/manager/info')

    def get_agents(self, status: Optional[str] = None, limit: int = 500) -> Dict[str, Any]:
        """List agents. status: active, disconnected, never_connected, pending."""
        params: Dict[str, Any] = {'limit': limit}
        if status:
            params['status'] = status
        return self._request('GET', '/agents', params=params)

    def get_agents_summary(self) -> Dict[str, Any]:
        """Summary counts by status (total, active, disconnected, etc.)."""
        return self._request('GET', '/agents/summary/status')

    def get_alerts_count(self) -> Dict[str, Any]:
        """Overall stats — we query manager logs/summary.

        Note: Wazuh 4.x doesn't expose alerts directly via this API.
        Alerts are read from /var/ossec/logs/alerts/alerts.json by dashboard.
        For portal MVP we'll parse that file via a dedicated endpoint (future).
        """
        # Placeholder; returns manager info for now.
        return self.get_manager_info()


# -------- Singleton factory --------

_client_instance: Optional[WazuhClient] = None


def get_client() -> WazuhClient:
    """Return process-wide WazuhClient from env vars."""
    global _client_instance
    if _client_instance is None:
        _client_instance = WazuhClient(
            base_url=os.getenv('WAZUH_API_URL', 'https://192.168.0.10:55000'),
            user=os.getenv('WAZUH_API_USER', 'wazuh'),
            password=os.getenv('WAZUH_API_PASSWORD', ''),
            verify_ssl=os.getenv('WAZUH_VERIFY_SSL', 'False').lower() == 'true'
        )
    return _client_instance
