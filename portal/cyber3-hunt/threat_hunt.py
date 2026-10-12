# -*- coding: utf-8 -*-
"""CYBER3 Threat Hunt — vânătoare proactivă de amenințări pe indexul Wazuh (read-only).

Caută tiparele de compromitere pe care regulile de alertare obișnuite (praguri, supresii) le lasă nevăzute:
  H1  răspuns reușit la atac (ATTACK_RESPONSE: fișiere sensibile livrate, ex. /etc/passwd)
  H2  încărcare de cod/webshell acceptată de server (HTTP 200)
  H3  stager PowerShell urmat de contact cu panou de comandă (C2) de pe aceeași stație
  H4  comunicare C2 / troian permisă (nu blocată)
  H5  volum mare de date ieșit spre o singură adresă externă (> 100 MB pe sesiune)
  H6  honeytoken / canary token declanșat
  H7  instrument de acces la distanță pe o stație nouă (nevăzut în ultimele 30 de zile)
  H8  senzor fără alerte de rețea (posibil orb: SPAN/punte fără trafic)

Utilizare:  python3 threat_hunt.py [--start ISO] [--end ISO] [--agents a,b] [--out fisier.json]
Implicit: ultimele 24 h. Ieșire: JSON {generated, window, findings[]}.
"""
import argparse, base64, datetime as dt, hashlib, ipaddress, json, os, ssl, sys, urllib.request, collections

ENV_FILE = os.environ.get("PORTAL_ENV", "/opt/fasterup-portal/.env")
SEV_ORDER = {"CRITIC": 0, "ÎNALT": 1, "MEDIU": 2, "INFO": 3}
# adresele publice ale clienților (din inventar); pot fi suprascrise de fișierul HUNT_PUBLIC_IPS (JSON {agent: [ip, ...]})
CLIENT_PUBLIC = {"icisoc101": ["5.2.180.41"], "icisoc102": ["86.34.176.99"], "icisoc103": ["5.2.130.195"], "icisoc104": ["81.12.178.170"],
                 "icisoc105": ["213.177.4.186"], "icisoc106": ["86.122.127.2"], "icisoc107": ["109.103.90.106"], "icisoc108": ["5.2.164.82"],
                 "icisoc109": ["92.55.148.251"], "icisoc110": ["213.177.15.181"], "f001": ["109.103.139.130"], "f002": ["92.180.55.78"],
                 "f003": ["213.177.12.198"], "f005": ["89.121.236.202"]}
_pf = os.environ.get("HUNT_PUBLIC_IPS", "/opt/fasterup-portal/data/hunt_client_public_ips.json")
if os.path.exists(_pf):
    try:
        CLIENT_PUBLIC.update(json.load(open(_pf, encoding="utf-8")))
    except Exception:
        pass
ALL_PUBLIC = {ip for v in CLIENT_PUBLIC.values() for ip in v}
# furnizori cloud cunoscuți (backup / sincronizare): transferurile mari spre ei rămân vizibile, dar ca INFO
KNOWN_CLOUD = [ipaddress.ip_network(n) for n in (
    "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19", "74.125.0.0/16", "142.251.0.0/16",   # Google
    "13.64.0.0/11", "13.104.0.0/14", "20.0.0.0/8", "40.64.0.0/10", "52.96.0.0/12", "204.79.197.0/24",  # Microsoft
    "17.0.0.0/8",                                                                                  # Apple
)]


def known_cloud(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in KNOWN_CLOUD)
    except Exception:
        return False


# ----------------------------------------------------------------------------- acces index
def _env():
    e = {}
    for line in open(ENV_FILE, encoding="utf-8"):
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.rstrip("\n").split("=", 1)
            e[k.strip()] = v.strip().strip('"').strip("'")
    return e


class Index:
    def __init__(self):
        e = _env()
        self.url = e["WAZUH_INDEXER_URL"].rstrip("/") + "/wazuh-alerts-*/_search"
        self.auth = base64.b64encode(("%s:%s" % (e["WAZUH_INDEXER_USER"], e["WAZUH_INDEXER_PASS"])).encode()).decode()
        self.ctx = ssl.create_default_context()
        if e.get("WAZUH_INDEXER_VERIFY_SSL", "false").lower() in ("0", "false", "no"):
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def q(self, body):
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", "Authorization": "Basic " + self.auth})
        return json.load(urllib.request.urlopen(req, context=self.ctx, timeout=120))


def private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def internal(ip):
    """adresă a clientului: privată sau una dintre adresele publice ale clienților"""
    return private(ip) or ip in ALL_PUBLIC


def g(d, path, default=None):
    for p in path.split("."):
        if not isinstance(d, dict) or p not in d:
            return default
        d = d[p]
    return d


def fid(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


# ----------------------------------------------------------------------------- vânători
class Hunter:
    def __init__(self, start, end, agents=None):
        self.ix = Index()
        self.start, self.end = start, end
        self.agents = agents
        self.findings = []

    def base(self, *extra):
        f = [{"range": {"timestamp": {"gte": self.start, "lt": self.end}}}]
        if self.agents:
            f.append({"terms": {"agent.name": self.agents}})
        return {"bool": {"filter": f + list(extra)}}

    def add(self, hunt, sev, agent, host, title, detail, first, last, count, evidence=None, key=None):
        self.findings.append({
            "id": fid(hunt, agent, host, key or title),
            "hunt": hunt, "severity": sev, "agent": agent, "host": host,
            "title": title, "detail": detail, "first_seen": first, "last_seen": last,
            "count": count, "evidence": evidence or {},
        })

    def group(self, query, keys, extra_aggs=None, size=200):
        """agregare pe chei (agent + câmp gazdă), cu first/last și semnăturile principale"""
        aggs = {"first": {"min": {"field": "timestamp"}}, "last": {"max": {"field": "timestamp"}},
                "sig": {"terms": {"field": "data.alert.signature", "size": 3}}}
        aggs.update(extra_aggs or {})
        body = {"size": 0, "query": query,
                "aggs": {"k": {"multi_terms": {"terms": [{"field": k} for k in keys], "size": size}, "aggs": aggs}}}
        return self.ix.q(body)["aggregations"]["k"]["buckets"]

    # H1 — răspuns reușit la atac (fișier sensibil livrat)
    def h1_attack_response(self):
        q = self.base({"bool": {"should": [{"wildcard": {"data.alert.signature": {"value": "*ATTACK_RESPONSE*"}}},
                                           {"terms": {"data.alert.signature_id": [2002034, 2025879]}}], "minimum_should_match": 1}})
        for b in self.group(q, ["agent.name", "data.src_ip"], {"dst": {"cardinality": {"field": "data.dest_ip"}},
                                                                "allowed": {"filter": {"term": {"data.alert.action": "allowed"}}}}):
            agent, host = b["key"]
            if not private(host):
                continue
            n, dst, allowed = b["doc_count"], b["dst"]["value"], b["allowed"]["doc_count"]
            sev = "CRITIC" if allowed > 0 else "ÎNALT"
            self.add("H1", sev, agent, host, "Răspuns reușit la atac: %s a livrat date sensibile" % host,
                     "%d livrări către %d adrese externe (%d permise de IPS). Semnătură: %s" % (n, dst, allowed, b["sig"]["buckets"][0]["key"] if b["sig"]["buckets"] else "-"),
                     b["first"]["value_as_string"], b["last"]["value_as_string"], n,
                     {"destinatii_distincte": dst, "permise": allowed, "semnaturi": [s["key"] for s in b["sig"]["buckets"]]})

    # H2 — încărcare de cod acceptată (HTTP 200)
    def h2_upload_accepted(self):
        sigs = ["*PHP tags in HTTP POST*", "*WebShell*", "*webshell*", "*File Upload*", "*fileUpload*"]
        q = self.base({"bool": {"should": [{"wildcard": {"data.alert.signature": {"value": s}}} for s in sigs], "minimum_should_match": 1}},
                      {"term": {"data.http.status": "200"}})
        for b in self.group(q, ["agent.name", "data.dest_ip"], {"src": {"terms": {"field": "data.src_ip", "size": 3}}}):
            agent, host = b["key"]
            if not private(host):
                continue
            self.add("H2", "ÎNALT", agent, host, "Încărcare de cod acceptată de %s (HTTP 200)" % host,
                     "%d încărcări cu răspuns 200; surse: %s" % (b["doc_count"], ", ".join(s["key"] for s in b["src"]["buckets"])),
                     b["first"]["value_as_string"], b["last"]["value_as_string"], b["doc_count"],
                     {"surse": [s["key"] for s in b["src"]["buckets"]], "semnaturi": [s["key"] for s in b["sig"]["buckets"]]})

    # H3 — stager PowerShell urmat de C2 pe aceeași stație (≤ 5 minute)
    def h3_stager_then_c2(self):
        ps = self.ix.q({"size": 500, "_source": ["timestamp", "agent.name", "data.src_ip", "data.dest_ip", "data.alert.signature", "data.http.hostname"],
                        "sort": [{"timestamp": "asc"}],
                        "query": self.base({"wildcard": {"data.alert.signature": {"value": "*PowerShell*"}}})})["hits"]["hits"]
        seen = set()
        for h in ps:
            s = h["_source"]; agent = g(s, "agent.name")
            src, dst = g(s, "data.src_ip"), g(s, "data.dest_ip")
            host = dst if private(dst) and not private(src) else src   # stația internă (descărcarea vine ca răspuns spre stație)
            if not private(host) or (agent, host) in seen:
                continue
            t0 = dt.datetime.fromisoformat(s["timestamp"].replace("Z", "+00:00"))
            win = {"range": {"timestamp": {"gte": t0.isoformat(), "lte": (t0 + dt.timedelta(minutes=5)).isoformat()}}}
            c2 = self.ix.q({"size": 3, "_source": ["timestamp", "data.alert.signature", "data.dest_ip", "data.src_ip"], "sort": [{"timestamp": "asc"}],
                            "query": {"bool": {"filter": [win, {"term": {"agent.name": agent}},
                                                          {"term": {"data.alert.category": "A Network Trojan was detected"}},
                                                          {"bool": {"should": [{"term": {"data.src_ip": host}}, {"term": {"data.dest_ip": host}}], "minimum_should_match": 1}}]}}})["hits"]["hits"]
            if c2:
                c = c2[0]["_source"]
                tc = dt.datetime.fromisoformat(c["timestamp"].replace("Z", "+00:00"))
                seen.add((agent, host))
                self.add("H3", "CRITIC", agent, host, "Stager PowerShell urmat de contact C2 pe %s (%d s)" % (host, int((tc - t0).total_seconds())),
                         "Descărcare: %s (%s). C2: %s" % (g(s, "data.alert.signature"), g(s, "data.http.hostname") or (dst if not private(dst) else src), c["data"]["alert"]["signature"]),
                         s["timestamp"], c["timestamp"], 1 + len(c2),
                         {"server_descarcare": src if private(dst) else dst, "c2": c2[0]["_source"]["data"].get("dest_ip"), "secunde": int((tc - t0).total_seconds())})

    # H4 — comunicare C2 / troian permisă, inițiată din interior (stația internă contactează exteriorul)
    def h4_c2_allowed(self):
        q = {"bool": {"filter": self.base({"term": {"data.alert.category": "A Network Trojan was detected"}},
                                          {"term": {"data.alert.action": "allowed"}})["bool"]["filter"],
                      "must_not": [{"wildcard": {"data.alert.signature": {"value": "CYBER3 BEACON*"}}},
                                   {"wildcard": {"data.alert.signature": {"value": "ET WEB_SERVER*"}}}]}}
        for b in self.group(q, ["agent.name", "data.flow.src_ip"], {"peer": {"terms": {"field": "data.flow.dest_ip", "size": 10}}}, size=500):
            agent, host = b["key"]
            peers = [p["key"] for p in b["peer"]["buckets"] if not internal(p["key"])]
            if not private(host) or not peers:
                continue
            sev = "INFO" if all(known_cloud(p) for p in peers) else "ÎNALT"
            self.add("H4", sev, agent, host, "Comunicare C2 permisă de la %s" % host,
                     "%d alerte de troian/C2 nelocate, spre %s. Semnătură: %s" % (b["doc_count"], ", ".join(peers[:5]), b["sig"]["buckets"][0]["key"] if b["sig"]["buckets"] else "-"),
                     b["first"]["value_as_string"], b["last"]["value_as_string"], b["doc_count"],
                     {"parteneri_externi": peers, "semnaturi": [s["key"] for s in b["sig"]["buckets"]]})

    # H5 — volum mare ieșit (> 100 MB pe sesiune) spre o adresă externă
    def h5_large_outbound(self):
        big = "[1-9][0-9]{8,}"    # câmpurile de volum sunt text: ≥ 9 cifre = ≥ 100.000.000 octeți
        q = self.base({"bool": {"should": [{"regexp": {"data.flow.bytes_toclient": big}},
                                            {"regexp": {"data.flow.bytes_toserver": big}}], "minimum_should_match": 1}})
        comp = {"composite": {"size": 500, "sources": [{"a": {"terms": {"field": "agent.name"}}},
                                                        {"s": {"terms": {"field": "data.flow.src_ip"}}},
                                                        {"d": {"terms": {"field": "data.flow.dest_ip"}}},
                                                        {"t": {"terms": {"field": "data.flow.start"}}}]},
                "aggs": {"tc": {"terms": {"field": "data.flow.bytes_toclient", "size": 30}},
                         "ts": {"terms": {"field": "data.flow.bytes_toserver", "size": 30}},
                         "first": {"min": {"field": "timestamp"}}, "last": {"max": {"field": "timestamp"}},
                         "sig": {"terms": {"field": "data.alert.signature", "size": 1}},
                         "port": {"terms": {"field": "data.flow.dest_port", "size": 1}}}}
        after, pages = None, 0
        while pages < 200:
            if after:
                comp["composite"]["after"] = after
            r = self.ix.q({"size": 0, "query": q, "aggs": {"f": comp}})["aggregations"]["f"]
            pages += 1
            for b in r["buckets"]:
                agent, fs, fd, start = b["key"]["a"], b["key"]["s"], b["key"]["d"], b["key"]["t"]
                def mx(bk):
                    vals = [int(x["key"]) for x in bk["buckets"] if str(x["key"]).isdigit()]
                    return max(vals) if vals else 0
                tc, ts = mx(b["tc"]), mx(b["ts"])
                if internal(fd) and not internal(fs):      # conexiune din Internet spre client: ieșirea = toclient
                    inh, ext, out, din_internet = fd, fs, tc, True
                elif internal(fs) and not internal(fd):    # conexiune inițiată din rețeaua clientului: ieșirea = toserver
                    inh, ext, out, din_internet = fs, fd, ts, False
                else:
                    continue
                if out < 100_000_000:
                    continue
                first, last = b["first"]["value_as_string"], b["last"]["value_as_string"]
                gb = out / 1e9
                weekend = dt.datetime.fromisoformat(first.replace("Z", "+00:00")).weekday() >= 5
                sev = "CRITIC" if gb >= 1 or (weekend and gb >= 0.5) else "ÎNALT"
                if known_cloud(ext):
                    sev = "INFO"
                sig = b["sig"]["buckets"][0]["key"] if b["sig"]["buckets"] else "-"
                port = b["port"]["buckets"][0]["key"] if b["port"]["buckets"] else "-"
                self.add("H5", sev, agent, inh, "Volum mare ieșit: %.2f GB de la %s spre %s" % (gb, inh, ext),
                         "Sesiune %s (port %s), %s. Semnătură asociată: %s" % ("inițiată din Internet" if din_internet else "inițiată din rețea",
                                                                              port, "weekend" if weekend else "zi lucrătoare", sig),
                         first, last, b["doc_count"], {"octeti_iesiti": out, "extern": ext, "inceput_flux": start, "port": port}, key=ext + str(start))
            after = r.get("after_key")
            if not after or not r["buckets"]:
                break

    # H6 — honeytoken / canary token
    def h6_honeytoken(self):
        q = self.base({"bool": {"should": [{"term": {"rule.id": "100251"}},
                                           {"wildcard": {"data.alert.signature": {"value": "*oneytoken*"}}},
                                           {"wildcard": {"data.alert.signature": {"value": "*anary*"}}},
                                           {"wildcard": {"data.alert.signature": {"value": "*Thinkst*"}}}], "minimum_should_match": 1}})
        for b in self.group(q, ["agent.name", "data.src_ip"]):
            agent, host = b["key"]
            self.add("H6", "CRITIC", agent, host, "Honeytoken declanșat (%s)" % host,
                     "Cineva a accesat un document sau o credențială-capcană. %s" % (b["sig"]["buckets"][0]["key"] if b["sig"]["buckets"] else ""),
                     b["first"]["value_as_string"], b["last"]["value_as_string"], b["doc_count"])

    # H7 — acces la distanță pe o stație nouă (nevăzut în ultimele 30 de zile)
    def h7_remote_access_new(self):
        q = self.base({"term": {"rule.id": "100250"}})
        cur = self.group(q, ["agent.name", "data.src_ip"])
        if not cur:
            return
        start = dt.datetime.fromisoformat(self.start.replace("Z", "+00:00"))
        prev_q = {"bool": {"filter": [{"range": {"timestamp": {"gte": (start - dt.timedelta(days=30)).isoformat(), "lt": self.start}}},
                                      {"term": {"rule.id": "100250"}}]}}
        prev = {tuple(b["key"]) for b in self.group(prev_q, ["agent.name", "data.src_ip"], size=1000)}
        hist = self.ix.q({"size": 0, "query": {"bool": {"filter": [{"term": {"rule.id": "100250"}},
                          {"range": {"timestamp": {"lt": (start - dt.timedelta(days=7)).isoformat()}}}]}}})["hits"]["total"]["value"]
        sev7 = "MEDIU" if hist > 0 else "INFO"     # sub 7 zile de istoric pentru 100250: „nou” nu e încă semnificativ
        for b in cur:
            agent, host = b["key"]
            if not private(host) or (agent, host) in prev:
                continue
            self.add("H7", sev7, agent, host, "Acces la distanță nou pe %s" % host,
                     "%d evenimente; instrument: %s" % (b["doc_count"], b["sig"]["buckets"][0]["key"] if b["sig"]["buckets"] else "-"),
                     b["first"]["value_as_string"], b["last"]["value_as_string"], b["doc_count"])

    # H8 — senzor fără alerte de rețea în fereastră (posibil orb)
    def h8_blind_sensor(self):
        span_days = (dt.datetime.fromisoformat(self.end.replace("Z", "+00:00")) - dt.datetime.fromisoformat(self.start.replace("Z", "+00:00"))).days
        lookback_start = self.start if span_days >= 3 else (dt.datetime.fromisoformat(self.end.replace("Z", "+00:00")) - dt.timedelta(days=3)).isoformat()
        f = [{"range": {"timestamp": {"gte": lookback_start, "lt": self.end}}}]
        if self.agents:
            f.append({"terms": {"agent.name": self.agents}})
        r = self.ix.q({"size": 0, "query": {"bool": {"filter": f}},
                       "aggs": {"a": {"terms": {"field": "agent.name", "size": 100},
                                      "aggs": {"net": {"filter": {"bool": {"filter": [{"exists": {"field": "data.alert.signature"}}],
                                                                           "must_not": [{"prefix": {"data.alert.signature": "SURICATA "}}]}}},
                                               "last": {"max": {"field": "timestamp"}}}}}})
        for b in r["aggregations"]["a"]["buckets"]:
            agent = b["key"]
            if not (agent.startswith("icisoc") or agent.startswith("f0")):
                continue
            if b["net"]["doc_count"] == 0:
                self.add("H8", "MEDIU", agent, "senzor", "Senzor fără alerte de rețea: %s" % agent,
                         "Agentul raportează (%d evenimente), dar 0 alerte de rețea în ultimele %s zile — verificați captura (SPAN/punte)."
                         % (b["doc_count"], max(span_days, 3)), lookback_start, b["last"]["value_as_string"], 0)

    def run(self):
        for fn in (self.h1_attack_response, self.h2_upload_accepted, self.h3_stager_then_c2, self.h4_c2_allowed,
                   self.h5_large_outbound, self.h6_honeytoken, self.h7_remote_access_new, self.h8_blind_sensor):
            try:
                fn()
            except Exception as e:   # o vânătoare care eșuează nu oprește restul
                self.findings.append({"id": fid("ERR", fn.__name__), "hunt": "ERR", "severity": "INFO", "agent": "-", "host": "-",
                                      "title": "Eroare la %s" % fn.__name__, "detail": str(e)[:300],
                                      "first_seen": self.start, "last_seen": self.end, "count": 0, "evidence": {}})
        try:
            r = self.ix.q({"size": 0, "query": {"range": {"timestamp": {"gte": "now-30d"}}},
                           "aggs": {"a": {"terms": {"field": "agent.name", "size": 200}, "aggs": {"i": {"terms": {"field": "agent.id", "size": 1}}}}}})
            amap = {b["key"]: (b["i"]["buckets"][0]["key"] if b["i"]["buckets"] else None) for b in r["aggregations"]["a"]["buckets"]}
        except Exception:
            amap = {}
        for x in self.findings:
            x["agent_id"] = amap.get(x["agent"])
        self.findings.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["agent"], x["first_seen"]))
        return {"generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "window": {"start": self.start, "end": self.end}, "agents": self.agents, "findings": self.findings}


def push_to_wazuh(findings, limit=20):
    """Trimite constatările în Wazuh (PUT /events) → regula 100260 → CyberBot notifică pe canalele existente."""
    e = _env()
    url = e["WAZUH_API_URL"].rstrip("/")
    ctx = ssl.create_default_context()
    if e.get("WAZUH_VERIFY_SSL", "false").lower() in ("0", "false", "no"):
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    auth = base64.b64encode(("%s:%s" % (e["WAZUH_API_USER"], e["WAZUH_API_PASSWORD"])).encode()).decode()
    req = urllib.request.Request(url + "/security/user/authenticate", method="POST", headers={"Authorization": "Basic " + auth})
    tok = json.load(urllib.request.urlopen(req, context=ctx, timeout=20))["data"]["token"]
    keep = ("id", "hunt", "severity", "agent", "agent_id", "host", "title", "detail", "first_seen", "last_seen", "count")
    events = [json.dumps({"cyber3_hunt": {k: f.get(k) for k in keep}}, ensure_ascii=False) for f in findings[:limit]]
    if not events:
        return 0
    body = json.dumps({"events": events}).encode()
    req = urllib.request.Request(url + "/events", data=body, method="PUT",
                                 headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, context=ctx, timeout=30))
    return len(events) if r.get("error", 1) == 0 else -1


def main():
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=float, default=1.0, help="fereastra în zile, terminată acum (ignorat dacă se dă --start)")
    ap.add_argument("--start", default="")
    ap.add_argument("--end", default=now.isoformat())
    ap.add_argument("--agents", default="")
    ap.add_argument("--out", default="", help="fișier JSON; păstrează și istoric în același folder")
    ap.add_argument("--keep", type=int, default=120, help="câte rulări se păstrează în istoric")
    ap.add_argument("--notify", action="store_true", help="trimite constatările NOI CRITIC/ÎNALT în Wazuh (CyberBot notifică)")
    a = ap.parse_args()
    start = a.start or (dt.datetime.fromisoformat(a.end) - dt.timedelta(days=a.days)).isoformat()
    res = Hunter(start, a.end, [x for x in a.agents.split(",") if x] or None).run()
    if a.out:
        prev_ids = set()
        baseline = not os.path.exists(a.out)
        if os.path.exists(a.out):
            try:
                prev_ids = {x["id"] for x in json.load(open(a.out, encoding="utf-8")).get("findings", [])}
            except Exception:
                prev_ids = set()
        for x in res["findings"]:
            x["new"] = x["id"] not in prev_ids
        js = json.dumps(res, ensure_ascii=False, indent=1)
        d = os.path.dirname(os.path.abspath(a.out))
        os.makedirs(d, exist_ok=True)
        tmp = a.out + ".tmp"
        open(tmp, "w", encoding="utf-8").write(js)
        os.replace(tmp, a.out)
        hist = os.path.join(d, "hunt-%s.json" % now.strftime("%Y%m%d-%H%M"))
        open(hist, "w", encoding="utf-8").write(js)
        old = sorted(p for p in os.listdir(d) if p.startswith("hunt-") and p.endswith(".json"))
        for p in old[:-a.keep]:
            try:
                os.remove(os.path.join(d, p))
            except OSError:
                pass
        if a.notify and not baseline:
            to_send = [x for x in res["findings"] if x.get("new") and x["severity"] in ("CRITIC", "ÎNALT") and x["hunt"] != "ERR"]
            try:
                n = push_to_wazuh(to_send)
                print("notificări trimise prin CyberBot: %s" % n)
            except Exception as ex:
                print("EROARE trimitere notificări: %s" % ex)
        elif a.notify:
            print("prima rulare = referință: nu se trimit notificări pentru istoric")
        crit = sum(1 for x in res["findings"] if x["severity"] == "CRITIC")
        print("CYBER3 Threat Hunt: %d constatari (%d CRITIC, %d noi) -> %s" % (len(res["findings"]), crit, sum(1 for x in res["findings"] if x.get("new")), a.out))
    else:
        print(json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
