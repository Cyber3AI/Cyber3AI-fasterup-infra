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

    def _run_on_log_host(self, remote_cmd):
        """Comanda pe hostul cu cyberbot.log: LOCAL daca host=localhost (DR relay-2), altfel SSH (primar)."""
        if self.ssh_host in ('127.0.0.1', 'localhost', '', None):
            return ['bash', '-c', remote_cmd]
        return ['ssh', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=5',
                '-o', 'BatchMode=yes', f'{self.ssh_user}@{self.ssh_host}', remote_cmd]

    def _fetch_log_lines(self) -> List[str]:
        """Ultimele N linii din cyberbot.log (LOCAL pe DR / SSH pe primar)."""
        cmd = self._run_on_log_host(f'tail -{self.tail_lines} {self.log_path}')
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

    def real_blocks_by_agent(self, hours: int = 24):
        """Blocari REALE executate de CyberBot (BLOCK_IP success=True + PERMA_REBLOCK)
        in ultimele N ore, grupate pe agent (id sau nume, cum apare in log). Cache 60s."""
        cache_key = f'real_blocks_{hours}h'
        now = time.time()
        if cache_key in self._cache:
            cached_at, cached_val = self._cache[cache_key]
            if now - cached_at < self.cache_ttl:
                return cached_val
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        cmd = self._run_on_log_host(
            "grep -hE '\\[BLOCK_IP\\].*success=True|\\[PERMA_REBLOCK\\]' " + self.log_path + " | grep -vE 'ip=(10[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[01])[.])' | tail -50000")
        counts = {}
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode not in (0, 1):
                log.error(f'CyberBot blocks fetch failed: {result.stderr.strip()}')
                return {}
            for line in result.stdout.splitlines():
                m = re.match(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC\].*?agent=(\S+)', line)
                if not m:
                    continue
                try:
                    ts = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                if ts < cutoff:
                    continue
                ag = m.group(2)
                counts[ag] = counts.get(ag, 0) + 1
        except subprocess.TimeoutExpired:
            log.error('CyberBot blocks fetch timeout (>15s)')
            return {}
        except Exception as e:
            log.error(f'CyberBot blocks exception: {e}')
            return {}
        self._cache[cache_key] = (now, counts)
        log.info(f'CyberBot real blocks: {sum(counts.values())} in {hours}h / {len(counts)} agents')
        return counts

    def count_real_blocks(self, allowed_keys=None, hours: int = 24):
        """Total blocari reale, filtrat pe set de chei vizibile (id-uri SI nume). None = toata flota."""
        per = self.real_blocks_by_agent(hours=hours)
        if allowed_keys is None:
            return sum(per.values())
        return sum(v for k, v in per.items() if k in allowed_keys)

    def real_blocks_by_hour(self, allowed_keys=None, hours: int = 24):
        """LAYER 3 sparkline — blocari CyberBot pe ora (25 buckete, vechi→nou), filtrat RBAC.
        allowed_keys: None = toata flota; set = doar cheile (id-uri SI nume) vizibile. Cache 60s."""
        cache_key = f'blocks_by_hour_{hours}_{("all" if allowed_keys is None else len(allowed_keys))}'
        now = time.time()
        if cache_key in self._cache:
            cached_at, cached_val = self._cache[cache_key]
            if now - cached_at < self.cache_ttl:
                return cached_val
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        base = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        # 25 buckete aliniate la ora, vechi→nou (identic cu date_histogram extended_bounds now-24h..now)
        order = [base - timedelta(hours=h) for h in range(hours, -1, -1)]
        idx = {t: i for i, t in enumerate(order)}
        series = [0] * len(order)
        cmd = self._run_on_log_host(
            "grep -hE '\\[BLOCK_IP\\].*success=True|\\[PERMA_REBLOCK\\]' " + self.log_path + " | grep -vE 'ip=(10[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[01])[.])' | tail -50000")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode not in (0, 1):
                log.error(f'CyberBot blocks-by-hour fetch failed: {result.stderr.strip()}')
                return series
            for line in result.stdout.splitlines():
                m = re.match(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC\].*?agent=(\S+)', line)
                if not m:
                    continue
                try:
                    ts = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                if ts < cutoff:
                    continue
                if allowed_keys is not None and m.group(2) not in allowed_keys:
                    continue
                bkt = ts.replace(minute=0, second=0, microsecond=0)
                if bkt in idx:
                    series[idx[bkt]] += 1
        except subprocess.TimeoutExpired:
            log.error('CyberBot blocks-by-hour timeout (>15s)')
            return series
        except Exception as e:
            log.error(f'CyberBot blocks-by-hour exception: {e}')
            return series
        self._cache[cache_key] = (now, series)
        return series


    def telegram_sent_by_client(self, hours: int = 24):
        """Mesaje Telegram trimise (sent=True) in ultimele N ore, pe client. Cache 60s."""
        cache_key = f'tg_sent_{hours}h'
        now = time.time()
        if cache_key in self._cache:
            cached_at, cached_val = self._cache[cache_key]
            if now - cached_at < self.cache_ttl:
                return cached_val
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        cmd = self._run_on_log_host("grep -h 'sent=True' " + self.log_path + " | tail -50000")
        counts = {}
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode not in (0, 1):
                log.error(f'CyberBot tg fetch failed: {result.stderr.strip()}')
                return {}
            for line in result.stdout.splitlines():
                m = re.match(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC\].*?client=(\S+)', line)
                if not m:
                    continue
                try:
                    ts = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                if ts >= cutoff:
                    counts[m.group(2)] = counts.get(m.group(2), 0) + 1
        except Exception as e:
            log.error(f'telegram_sent parse failed: {e}')
            return {}
        self._cache[cache_key] = (now, counts)
        return counts

    def blocked_ip_set(self, allowed_keys=None, hours: int = 24):
        """Set de IP-uri distincte blocate de CyberBot (pt dedup între straturi), filtrat RBAC.
        allowed_keys None = toată flota; set = doar cheile (id/nume) vizibile. Cache 60s."""
        cache_key = f'blocked_ips_{hours}_{("all" if allowed_keys is None else len(allowed_keys))}'
        now = time.time()
        if cache_key in self._cache:
            cached_at, cached_val = self._cache[cache_key]
            if now - cached_at < self.cache_ttl:
                return cached_val
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        cmd = self._run_on_log_host(
            "grep -hE '\\[BLOCK_IP\\].*success=True|\\[PERMA_REBLOCK\\]' " + self.log_path + " | grep -vE 'ip=(10[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[01])[.])' | tail -50000")
        ips = set()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode not in (0, 1):
                return ips
            for line in result.stdout.splitlines():
                m = re.match(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC\]', line)
                if not m:
                    continue
                try:
                    ts = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                if ts < cutoff:
                    continue
                if allowed_keys is not None:
                    ag = re.search(r'agent=(\S+)', line)
                    if not ag or ag.group(1) not in allowed_keys:
                        continue
                ip = re.search(r'\bip=([0-9.]+)', line)
                if ip:
                    ips.add(ip.group(1))
        except Exception as e:
            log.error(f'blocked_ip_set failed: {e}')
            return ips
        self._cache[cache_key] = (now, ips)
        return ips

    def count_telegram_sent(self, allowed_keys=None, hours: int = 24):
        """Total mesaje Telegram trimise, filtrat pe cheile vizibile (RBAC). None = toata flota."""
        per = self.telegram_sent_by_client(hours=hours)
        if allowed_keys is None:
            return sum(per.values())
        return sum(v for k, v in per.items() if k in allowed_keys)


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
