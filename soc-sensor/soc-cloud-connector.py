#!/usr/bin/env python3
"""CYBER3 SOC — connector cloud (Faza 4, calea FALLBACK pentru remote/BYOD).

Rulează pe manager (wazuh-server). Trage evenimentele endpoint-urilor care au raportat la cloud
(cyber3-edge, fiindcă nu aveau senzor în LAN) și le scrie în /var/log/cyber3/cloud.json — citit de
logcollector-ul managerului → decoder JSON → regulile `cyber3`. Calea prin senzor (Faza 2/3) NU
trece pe aici (merge direct: senzor → agent → manager).

Necesită edge ADMIN_TOKEN în /opt/cyber3/.soc-admin.token. Idempotent: trage → scrie → ack (șterge
din edge). Rulat de un timer systemd (cyber3-soc-connector.timer) la 2 minute.
"""
import json, os, urllib.request

EDGE = os.environ.get("CYBER3_EDGE", "https://cyber3-edge.cyber3.workers.dev").rstrip("/")
TOKEN_FILE = os.environ.get("CYBER3_ADMIN_TOKEN_FILE", "/opt/cyber3/.soc-admin.token")
LOG = os.environ.get("CYBER3_LOG", "/var/log/cyber3/cloud.json")
MAXBYTES = 16 * 1024 * 1024
UA = "cyber3-soc-connector/1.0"  # Cloudflare blochează UA implicit Python-urllib

TOKEN = open(TOKEN_FILE).read().strip()


def api(method, path, body=None):
    data = body.encode() if body else None
    req = urllib.request.Request(EDGE + path, data=data, method=method,
                                 headers={"authorization": "Bearer " + TOKEN,
                                          "user-agent": UA, "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def main():
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    try:
        if os.path.exists(LOG) and os.path.getsize(LOG) > MAXBYTES:
            os.replace(LOG, LOG + ".1")
    except OSError:
        pass
    orgs = api("GET", "/v1/soc/orgs").get("orgs", [])
    total = 0
    for org in orgs:
        res = api("GET", "/v1/soc/pull?org=%s&limit=500" % org)
        events = res.get("events", [])
        if not events:
            continue
        with open(LOG, "a", encoding="utf-8") as f:
            for ev in events:
                e = ev.get("e")
                if e:
                    f.write(e + "\n")
        keys = [ev["key"] for ev in events if ev.get("key")]
        if keys:
            api("POST", "/v1/soc/pull/ack", json.dumps({"keys": keys}))
        total += len(events)
    print("ingestat %d evenimente cloud din %d org" % (total, len(orgs)))


if __name__ == "__main__":
    main()
