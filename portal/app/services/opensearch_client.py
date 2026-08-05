"""OpenSearch client for Wazuh indexer queries.

Queries against wazuh-alerts-* indices via HTTP REST API.
"""
import os
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger(__name__)

# R4/R5/R7 (feedback ICISOC): grupuri de reguli = evenimente ale GAZDEI SENZORULUI, nu din rețeaua
# clientului → excluse din vizualizarea beneficiarului (listă + contoare). Datele brute rămân în indexer.
CLIENT_NOISE_GROUPS = [
    # R4 — gazda senzorului: integritate fișiere, pachete, rootcheck, CIS, vulnerabilitățile senzorului, config, syslog
    "syscheck", "syscheck_file", "syscheck_entry_modified", "syscheck_entry_added",
    "rootcheck", "dpkg", "sca", "vulnerability-detector", "vulnerability_overrides",
    "config_changed", "syslog",
    # R5 — cont de administrare socadmin: login/sesiune/sudo
    "pam", "authentication_success", "authentication_failed", "sudo",
    # R7 — test/dev: se adaugă semnăturile de test când apar
]


class OpenSearchClient:
    def __init__(self, base_url, user, password, verify_ssl=False):
        self.base_url = base_url.rstrip('/')
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl

    def _search(self, index, query):
        url = f'{self.base_url}/{index}/_search'
        r = requests.post(url, json=query,
                          auth=HTTPBasicAuth(self.user, self.password),
                          verify=self.verify_ssl, timeout=15,
                          headers={'Content-Type': 'application/json'})
        r.raise_for_status()
        return r.json()

    def recent_alerts(self, limit=50, min_level=0, hours=24, agent_ids=None, exclude_noise=False):
        """Return the most recent alerts. Default last 24h, any level.

        agent_ids: None = all agents; list = restrict to those agent.ids IN THE QUERY
        (empty list = zero results). Filtering happens in the query — NOT post-hoc on a
        global recent window — so a specific client's alerts are never crowded out by a
        noisy agent (previously a busy fleet made a quiet client show ~1 alert).
        """
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        must = [
            {"range": {"@timestamp": {"gte": since}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]
        if agent_ids is not None:
            must.append({"terms": {"agent.id": [str(x) for x in agent_ids]}})
        bool_q = {"must": must}
        if exclude_noise:
            bool_q["must_not"] = [{"terms": {"rule.groups": CLIENT_NOISE_GROUPS}}]
        query = {
            "size": limit,
            "track_total_hits": True,
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": bool_q}
        }
        resp = self._search('wazuh-alerts-*', query)
        hits = resp.get('hits', {}).get('hits', [])
        return [h.get('_source', {}) for h in hits]

    def count_alerts(self, agent_ids=None, min_level=0, hours=24, exclude_noise=False):
        """EXACT count of alerts over the interval, scoped to agent_ids.

        Uses the _count API, so there is NO 10,000 hits.total cap (a plain search with
        size:0 and no track_total_hits stops counting at 10k → e.g. agent with 10,176
        real alerts reported only 10,000). agent_ids None = all, list = restrict, [] = 0.
        """
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        must = [
            {"range": {"@timestamp": {"gte": since}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]
        if agent_ids is not None:
            must.append({"terms": {"agent.id": [str(x) for x in agent_ids]}})
        bool_q = {"must": must}
        if exclude_noise:
            bool_q["must_not"] = [{"terms": {"rule.groups": CLIENT_NOISE_GROUPS}}]
        url = f'{self.base_url}/wazuh-alerts-*/_count'
        r = requests.post(url, json={"query": {"bool": bool_q}},
                          auth=HTTPBasicAuth(self.user, self.password),
                          verify=self.verify_ssl, timeout=15,
                          headers={'Content-Type': 'application/json'})
        r.raise_for_status()
        return r.json().get('count', 0)

    def stats_24h(self):
        """Aggregated stats for last 24h: total count, by level, by agent."""
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        query = {
            "size": 0,
            "track_total_hits": True,
            "query": {
                "range": {"@timestamp": {"gte": since}}
            },
            "aggs": {
                "by_level": {
                    "terms": {"field": "rule.level", "size": 20}
                },
                "by_agent": {
                    "terms": {"field": "agent.name", "size": 50}
                },
                "by_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "min_doc_count": 0,
                        "extended_bounds": {
                            "min": since,
                            "max": "now"
                        }
                    }
                }
            }
        }
        resp = self._search('wazuh-alerts-*', query)
        total = resp.get('hits', {}).get('total', {}).get('value', 0)
        aggs = resp.get('aggregations', {})
        return {
            'total_24h': total,
            'by_level': [{'level': b['key'], 'count': b['doc_count']}
                         for b in aggs.get('by_level', {}).get('buckets', [])],
            'by_agent': [{'agent': b['key'], 'count': b['doc_count']}
                         for b in aggs.get('by_agent', {}).get('buckets', [])],
            'by_hour': [{'hour': b['key_as_string'], 'count': b['doc_count']}
                        for b in aggs.get('by_hour', {}).get('buckets', [])]
        }

    def high_level_24h(self, min_level=10):
        """Count critical alerts (level >= min_level) in last 24h."""
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        query = {
            "size": 0,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": since}}},
                        {"range": {"rule.level": {"gte": min_level}}}
                    ]
                }
            }
        }
        resp = self._search('wazuh-alerts-*', query)
        return resp.get('hits', {}).get('total', {}).get('value', 0)

    def alerts_hourly_by_level(self, agent_ids=None, hours=24):
        """Hourly histogram of alerts in last N hours, split by severity level.

        Args:
            agent_ids: None = all agents (supervisor); list = filter to those agents
            hours: how many hours back to query (default 24)

        Returns:
            dict with 'bins' = list of 25 hourly buckets, each with:
                hour, label, critical (>=13), high (10-12), medium (7-9), low (1-6)
        """
        from datetime import datetime, timedelta, timezone

        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        must = [{"range": {"@timestamp": {"gte": since}}}]
        if agent_ids is not None:
            # If list is empty, we explicitly want zero results (analyst with no clients)
            must.append({"terms": {"agent.id": [str(x) for x in agent_ids]}})

        query = {
            "size": 0,
            "query": {"bool": {"must": must}},
            "aggs": {
                "by_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "min_doc_count": 0,
                        "extended_bounds": {"min": since, "max": "now"}
                    },
                    "aggs": {
                        "by_level": {
                            "range": {
                                "field": "rule.level",
                                "ranges": [
                                    {"key": "low",      "from": 1,  "to": 7},
                                    {"key": "medium",   "from": 7,  "to": 10},
                                    {"key": "high",     "from": 10, "to": 13},
                                    {"key": "critical", "from": 13}
                                ]
                            }
                        }
                    }
                }
            }
        }

        resp = self._search('wazuh-alerts-*', query)
        buckets = resp.get('aggregations', {}).get('by_hour', {}).get('buckets', [])

        bins = []
        for b in buckets:
            ts = b.get('key_as_string', '')
            ranges = {r['key']: r['doc_count']
                      for r in b.get('by_level', {}).get('buckets', [])}
            bins.append({
                'hour': ts,
                'label': ts[11:13] if len(ts) >= 13 else '',
                'critical': ranges.get('critical', 0),
                'high':     ranges.get('high', 0),
                'medium':   ranges.get('medium', 0),
                'low':      ranges.get('low', 0),
            })
        return {'bins': bins}



    def per_agent_metrics(self, agent_ids=None, incident_level=10):
        """Per-agent operational metrics in ONE batch (two aggregations), for the Client Fleet table:
          - incidents_7d: high-severity alerts (rule.level >= incident_level) in the last 7 days
          - uptime_pct: % of the last 24 hourly buckets in which the agent produced telemetry
            (inline sensors always emit Suricata traffic → a real liveness signal)
        Returns {agent_id: {'incidents_7d': int, 'uptime_pct': int}}.
        """
        now = datetime.now(timezone.utc)
        since_7d = (now - timedelta(days=7)).isoformat()
        since_24h = (now - timedelta(hours=24)).isoformat()
        out = {}

        must7 = [
            {"range": {"@timestamp": {"gte": since_7d}}},
            {"range": {"rule.level": {"gte": incident_level}}},
        ]
        if agent_ids is not None:
            must7.append({"terms": {"agent.id": [str(x) for x in agent_ids]}})
        q7 = {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"must": must7}},
            "aggs": {"by_agent": {"terms": {"field": "agent.id", "size": 200}}},
        }
        for b in self._search('wazuh-alerts-*', q7).get('aggregations', {}).get('by_agent', {}).get('buckets', []):
            out.setdefault(str(b['key']), {})['incidents_7d'] = b['doc_count']

        must24 = [{"range": {"@timestamp": {"gte": since_24h}}}]
        if agent_ids is not None:
            must24.append({"terms": {"agent.id": [str(x) for x in agent_ids]}})
        q24 = {
            "size": 0,
            "query": {"bool": {"must": must24}},
            "aggs": {"by_agent": {"terms": {"field": "agent.id", "size": 200},
                     "aggs": {"hours": {"date_histogram": {"field": "@timestamp",
                              "fixed_interval": "1h", "min_doc_count": 1}}}}},
        }
        for b in self._search('wazuh-alerts-*', q24).get('aggregations', {}).get('by_agent', {}).get('buckets', []):
            hours_present = len(b.get('hours', {}).get('buckets', []))
            out.setdefault(str(b['key']), {})['uptime_pct'] = round(min(hours_present, 24) / 24 * 100)

        return out


_client = None


def get_client():
    global _client
    if _client is None:
        _client = OpenSearchClient(
            base_url=os.getenv('WAZUH_INDEXER_URL', 'https://192.168.0.10:9200'),
            user=os.getenv('WAZUH_INDEXER_USER', 'readall'),
            password=os.getenv('WAZUH_INDEXER_PASS', ''),
            verify_ssl=os.getenv('WAZUH_INDEXER_VERIFY_SSL', 'False').lower() == 'true'
        )
    return _client
