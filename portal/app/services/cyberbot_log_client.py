"""CyberBot log parser — citește deciziile reale din /var/ossec/logs/cyberbot.log.

Citește log-ul de pe Wazuh Server prin SSH (cu cheia portal@fasterup-portal),
parsează liniile [OK] decision=... și agregă pe oră pentru endpoint-ul
/api/decisions/hourly.

Cache-ul de 60s evită load-ul pe Wazuh Server la fiecare request.
"""
import os
import re
import logging
import subprocess
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

log = logging.getLogger(__name__)

# Format așteptat al liniei [OK]:
# [2026-04-27 11:54:14 UTC] [OK] decision=BLOCARE_IMEDIATA agent_id=002 client=Client Test FasterUp ip=185.220.101.50 rule=100200 sent=True
DECISION_PATTERN = re.compile(
    r'^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC\]\s+'
    r'\[OK\]\s+'
    r'decision=(?P<decision>\S+)\s+'
    r'agent_id=(?P<agent_id>\S+)\s+'
    r'client=(?P<client>.+?)\s+'
    r'ip=(?P<ip>\S+)\s+'
    r'rule=(?P<rule>\S+)\s+'
    r'sent=(?P<sent>True|False)\b.*$'  # tolerant: [MISP+], latency_ms=N sau orice camp adaugat ulterior
)

# Mapping decizie CyberBot → label scurt pentru chart
DECISION_LABELS = {
    'BLOCARE_IMEDIATA': 'block',
    'ESCALADARE': 'escalate',
    'MONITORIZARE': 'monitor',
    'IGNORARE': 'ignore',
}


class CyberBotLogClient:
    def __init__(self, ssh_host, ssh_user, log_path, tail_lines=10000, cache_ttl=60):
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.log_path = log_path
        self.tail_lines = tail_lines
        self.cache_ttl = cache_ttl
        self._cache = {}  # key → (timestamp, value)

    def _fetch_log_lines(self) -> List[str]:
        """SSH la Wazuh Server, returnează ultimele N linii din cyberbot.log."""
        cmd = [
            'ssh',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'ConnectTimeout=5',
            '-o', 'BatchMode=yes',
            f'{self.ssh_user}@{self.ssh_host}',
            f'tail -{self.tail_lines} {self.log_path}'
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                log.error(f'SSH fetch failed: {result.stderr.strip()}')
                return []
            return result.stdout.splitlines()
        except subprocess.TimeoutExpired:
            log.error('SSH fetch timeout (>10s)')
            return []
        except Exception as e:
            log.error(f'SSH fetch exception: {e}')
            return []

    def _parse_decision_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parsează o linie [OK] decision=...; returnează dict sau None."""
        m = DECISION_PATTERN.match(line.strip())
        if not m:
            return None
        try:
            ts = datetime.strptime(m.group('ts'), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        return {
            'timestamp': ts.isoformat(),
            'timestamp_dt': ts,
            'decision': m.group('decision'),
            'agent_id': m.group('agent_id'),
            'client': m.group('client').strip(),
            'ip': m.group('ip'),
            'rule': m.group('rule'),
            'sent': m.group('sent') == 'True',
        }

    def decisions_24h(self) -> List[Dict[str, Any]]:
        """Returnează deciziile [OK] din ultimele 24h. Cu cache 60s TTL."""
        cache_key = 'decisions_24h'
        now = time.time()
        if cache_key in self._cache:
            cached_at, cached_val = self._cache[cache_key]
            if now - cached_at < self.cache_ttl:
                return cached_val

        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        lines = self._fetch_log_lines()
        decisions = []
        for line in lines:
            d = self._parse_decision_line(line)
            if d and d['timestamp_dt'] >= cutoff:
                decisions.append(d)

        self._cache[cache_key] = (now, decisions)
        log.info(f'CyberBot decisions parsed: {len(decisions)} in last 24h from {len(lines)} log lines')
        return decisions

    def avg_decision_time_ms(self, hours: int = 24):
        """Latența medie a deciziei AI (ms) din liniile [OK] cu latency_ms=... (ultimele N ore).
        Măsurat real în cyberbot (durata analyze_with_claude). None dacă nu există date. Cache 60s."""
        import re as _re
        cache_key = f'avg_decision_ms_{hours}h'
        now = time.time()
        if cache_key in self._cache:
            cached_at, cached_val = self._cache[cache_key]
            if now - cached_at < self.cache_ttl:
                return cached_val
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        vals = []
        for line in self._fetch_log_lines():
            m = _re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[^\]]*\].*latency_ms=(\d+)', line)
            if not m:
                continue
            try:
                ts = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if ts >= cutoff:
                vals.append(int(m.group(2)))
        avg = int(sum(vals) / len(vals)) if vals else None
        self._cache[cache_key] = (now, avg)
        return avg

    def decisions_recent(self, days: int = 30) -> List[Dict[str, Any]]:
        """Returnează toate deciziile [OK] din ultimele N zile. Cache 60s TTL per N."""
        cache_key = f'decisions_recent_{days}d'
        now = time.time()
        if cache_key in self._cache:
            cached_at, cached_val = self._cache[cache_key]
            if now - cached_at < self.cache_ttl:
                return cached_val

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        lines = self._fetch_log_lines()
        decisions = []
        for line in lines:
            d = self._parse_decision_line(line)
            if d and d['timestamp_dt'] >= cutoff:
                decisions.append(d)

        self._cache[cache_key] = (now, decisions)
        log.info(f'CyberBot decisions_recent: {len(decisions)} in last {days}d from {len(lines)} log lines')
        return decisions

    def decisions_by_hour(self) -> List[Dict[str, Any]]:
        """Agregare orară a deciziilor în ultimele 24h."""
        decisions = self.decisions_24h()
        # Build 24 buckets, hour-aligned, ending at current hour
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
        # Populate from decisions
        for d in decisions:
            bucket_ts = d['timestamp_dt'].replace(minute=0, second=0, microsecond=0)
            key = bucket_ts.isoformat()
            if key not in buckets:
                continue
            label = DECISION_LABELS.get(d['decision'])
            if label:
                buckets[key][label] += 1
        return list(buckets.values())


_client = None


def get_client():
    global _client
    if _client is None:
        _client = CyberBotLogClient(
            ssh_host=os.getenv('WAZUH_SERVER_HOST', '192.168.0.10'),
            ssh_user=os.getenv('WAZUH_SERVER_USER', 'socadmin'),
            log_path=os.getenv('CYBERBOT_LOG_PATH', '/var/ossec/logs/cyberbot.log'),
            tail_lines=int(os.getenv('CYBERBOT_LOG_TAIL_LINES', '10000')),
            cache_ttl=int(os.getenv('CYBERBOT_CACHE_TTL_SEC', '60')),
        )
    return _client
