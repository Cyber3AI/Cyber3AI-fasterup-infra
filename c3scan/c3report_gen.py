# -*- coding: utf-8 -*-
"""CYBER3 Scan — generator de rapoarte per client (model f003/f002) cu MATCH CAUZAL pe gazdă.

Rulează PE PORTAL (are acces OpenSearch :9200 + SSH la senzori + reportlab). Ia discovery/findings
de pe senzor (ssh) + alerte SOC (30z din OpenSearch) și produce:
  - CYBER3_Scan_Raport_<sensor>_<data>.md   (raport complet, 7 capitole)
  - CYBER3_Scan_MATCH_REPORT_<sensor>_<data>.md (MATCH cauzal separat)
  - discovery.json / findings.json (dovezi brute)
PDF-urile se randează cu c3report_md2pdf.py (reportlab+DejaVu). DOCX cu brand/mkdocx.py.

Uz: python3 c3report_gen.py <sensor> <agent_id> <wg_host> <scan_id> "<ORG>" <bd:0/1> "<nota>" <outdir>

POLITICĂ STRICTĂ DE CONFIDENȚIALITATE: parametrul <ORG> trebuie să fie GENERIC
("Organizație client (confidențial)"). Numele real al clientului NU apare NICIODATĂ în raport.
Maparea senzor→client se ține separat (intern), nu în livrabile.

MATCH CAUZAL (diferențiatorul): pentru fiecare gazdă scanată care apare și în alerte, leagă
tipul EXPUNERII (din scan: SMB/RDP/WEB/DB/SNMP/CLEARTEXT) de tipul ACTIVITĂȚII (signatura reală)
ȘI direcția (extern vs intern):
  - expunere ⟷ atac de același tip DIN EXTERIOR  → ⚠️ CAUZAL (vizată activ, prioritate)
  - expunere ⟷ activitate de același tip DIN INTERIOR → administrare legitimă probabilă (FP), NU atac
  - atac extern fără potrivire de expunere → vizat din exterior, asigurați patch-uri
  - doar trafic informațional → expus fără atac corelat (proactiv)
Plus interpretarea onestă a alertelor nivel≥10 (extern vs intern; verificare „nu e generat de scan").

CHANGELOG:
  2026-06-30 — versiune inițială + MATCH cauzal direcție-aware (rezolvă FP: PowerShell-SMB intern =
    administrare, nu atac; web-attack extern pe server expus = cauzal real). Vezi c3scan CHANGELOG 2026-06-29.
"""
import sys, json, subprocess, os, re, collections

SENSOR, AGENT, HOST, SCANID, ORG, BD, NOTE, OUT = sys.argv[1:9]
BD = BD == "1"; os.makedirs(OUT, exist_ok=True)
ENVF = os.environ.get("PORTAL_ENV", "/opt/fasterup-portal/.env")
SSH_KEY = os.environ.get("SSH_KEY", "/home/socadmin/.ssh/id_ed25519")
DATE = os.environ.get("REPORT_DATE", "29 iunie 2026")
DATE_ISO = os.environ.get("REPORT_DATE_ISO", "2026-06-29")
PROFILE = os.environ.get("REPORT_PROFILE", "adaptiv (low-and-slow, non-distructiv)")
ALERT_WINDOW = os.environ.get("ALERT_WINDOW", "30d")
ALERT_WINDOW_TXT = os.environ.get("ALERT_WINDOW_TXT", "30 zile")
EXCLUDE_SRC = [x.strip() for x in os.environ.get("EXCLUDE_SRC", "").split(",") if x.strip()]
SOC_NAME = os.environ.get("SOC_NAME", "FasterUp Security Operations Center")
SOC_SHORT = os.environ.get("SOC_SHORT", "FasterUp SOC")
# Brand model (24 iul): SOC = "ICISOC" pt clienți ICI / "FasterUp SOC" pt clienți direcți; produsul de scan = "CYBER3 Global Scan".
SCAN_BRAND = os.environ.get("SCAN_BRAND", "CYBER3 Global Scan")
SKIP_MATCH = os.environ.get("SKIP_MATCH", "") not in ("", "0", "false")  # 1 = generează DOAR raportul Scan (MATCH separat, mai târziu)

def env(k):
    for ln in open(ENVF):
        if ln.startswith(k + "="): return ln.split("=", 1)[1].strip()
    return ""
OUSER, OPASS = env("WAZUH_INDEXER_USER"), env("WAZUH_INDEXER_PASS")

def ssh_sensor(cmd):
    return subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=12",
        "-i", SSH_KEY, "socadmin@" + HOST, cmd], capture_output=True, text=True, timeout=40).stdout

def osearch(body):
    r = subprocess.run(["curl", "-s", "-k", "-u", OUSER + ":" + OPASS,
        "https://127.0.0.1:9200/wazuh-alerts-*/_search", "-H", "Content-Type: application/json",
        "-d", json.dumps(body)], capture_output=True, text=True, timeout=40).stdout
    try: return json.loads(r)
    except Exception: return {}

def priv(ip):
    try: a, b = int(ip.split(".")[0]), int(ip.split(".")[1])
    except Exception: return False
    return a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)
emoji = re.compile(r'^[^\x00-\x7F]+\s*'); clean = lambda x: emoji.sub("", str(x or "")).strip()
PORTNAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 102: "S7/OT", 110: "POP3",
    135: "RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 502: "Modbus/OT", 554: "RTSP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 8006: "Proxmox", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9100: "Print"}
portname = lambda p: "%s (%d)" % (PORTNAMES.get(p, "port"), p)

# ---- date scan ----
disc = {}; fnd = {}
_DF = os.environ.get("DISC_FILE"); _FF = os.environ.get("FND_FILE")  # fișiere locale (senzori fără socadmin/cheie, ex ANRE)
try: disc = json.loads((open(_DF, encoding="utf-8").read() if _DF else ssh_sensor("cat /var/log/cyber3/scans/%s.discovery.json 2>/dev/null || cat /var/log/cyber3/discovery.json" % SCANID)) or "{}")
except Exception: pass
try: fnd = json.loads((open(_FF, encoding="utf-8").read() if _FF else ssh_sensor("cat /var/log/cyber3/scans/%s.json 2>/dev/null || cat /var/log/cyber3/findings.json" % SCANID)) or "{}")
except Exception: pass
ds = disc.get("summary", {}); hosts = disc.get("hosts", []); findings = fnd.get("findings", []); fsum = fnd.get("summary", {})
# Scan ȚINTIT pe interval (ex. /21): parse_targets adaugă TOATE IP-urile ca intrări, chiar dacă n-au răspuns.
# Păstrează DOAR gazdele cu semnal real de liveness (servicii/MAC/rol/hostname/vendor/VLAN passive) → „gazde active"
# onest (altfel icisoc105 raporta 2046 în loc de ~245). La scanuri normale efectul e neglijabil (toate au dovadă).
_live = lambda h: bool(h.get("services") or h.get("mac") or h.get("hostname") or h.get("role")
                       or h.get("vendor") or h.get("mac_real") or h.get("vlans") or (h.get("home_vlan") is not None))
_n0 = len(hosts); hosts = [h for h in hosts if _live(h)]
if len(hosts) != _n0:
    ds["hosts"] = len(hosts); disc["hosts"] = hosts; disc.setdefault("summary", {})["hosts"] = len(hosts)
svc_by_ip = {h["ip"]: set(h.get("services", []) or []) for h in hosts}
fnd_by_ip = collections.defaultdict(list)
for f in findings: fnd_by_ip[f["ip"]].append(f)

# ---- alerte 30z ----
_netonly = {"bool": {"should": [{"exists": {"field": "data.src_ip"}}, {"exists": {"field": "data.dest_ip"}}], "minimum_should_match": 1}}
_excl = [{"term": {"data.src_ip": ip}} for ip in EXCLUDE_SRC] + [{"term": {"data.dest_ip": ip}} for ip in EXCLUDE_SRC]
base = {"bool": {"filter": [{"term": {"agent.id": AGENT}}, {"range": {"@timestamp": {"gte": "now-" + ALERT_WINDOW}}}, _netonly], "must_not": _excl}}
tot = osearch({"size": 0, "track_total_hits": True, "query": base}).get("hits", {}).get("total", {}).get("value", 0)
sigs = [(b["key"], b["doc_count"]) for b in osearch({"size": 0, "query": base, "aggs": {"s": {"terms": {"field": "data.alert.signature", "size": 15}}}}).get("aggregations", {}).get("s", {}).get("buckets", [])]
levels = {int(b["key"]): b["doc_count"] for b in osearch({"size": 0, "query": base, "aggs": {"l": {"terms": {"field": "rule.level", "size": 15}}}}).get("aggregations", {}).get("l", {}).get("buckets", [])}
maxlvl = max(levels) if levels else 0
amap = {}
ag = osearch({"size": 0, "query": base, "aggs": {
    "dst": {"terms": {"field": "data.dest_ip", "size": 400}, "aggs": {"mx": {"max": {"field": "rule.level"}}}},
    "src": {"terms": {"field": "data.src_ip", "size": 400}, "aggs": {"mx": {"max": {"field": "rule.level"}}}}}}).get("aggregations", {})
for grp in ("dst", "src"):
    for b in ag.get(grp, {}).get("buckets", []):
        ip = b["key"]
        if not priv(ip): continue
        e = amap.setdefault(ip, {"c": 0, "mx": 0}); e["c"] += b["doc_count"]; e["mx"] = max(e["mx"], int(b.get("mx", {}).get("value") or 0))
vuln_ips = {f["ip"] for f in findings}
match_ips = sorted(vuln_ips & set(amap), key=lambda ip: (-amap[ip]["mx"], -amap[ip]["c"]))

# ---- analiza nivel>=10 (real vs FP vs scan propriu) ----
hlq = {"bool": {"filter": [{"term": {"agent.id": AGENT}}, {"range": {"rule.level": {"gte": 10}}}, {"range": {"@timestamp": {"gte": "now-" + ALERT_WINDOW}}}, _netonly], "must_not": _excl}}
hl = osearch({"size": 0, "track_total_hits": True, "query": hlq, "aggs": {"sig": {"terms": {"field": "data.alert.signature", "size": 8}}, "src": {"terms": {"field": "data.src_ip", "size": 80}}, "dst": {"terms": {"field": "data.dest_ip", "size": 8}}}})
hl_tot = hl.get("hits", {}).get("total", {}).get("value", 0); hla = hl.get("aggregations", {})
hl_sigs = [(b["key"], b["doc_count"]) for b in hla.get("sig", {}).get("buckets", [])]
hl_ext = sum(b["doc_count"] for b in hla.get("src", {}).get("buckets", []) if not priv(b["key"]))
hl_intl = sum(b["doc_count"] for b in hla.get("src", {}).get("buckets", []) if priv(b["key"]))
hl_dst = [(b["key"], b["doc_count"]) for b in hla.get("dst", {}).get("buckets", [])]
recent = osearch({"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [{"term": {"agent.id": AGENT}}, {"range": {"rule.level": {"gte": 10}}}, {"range": {"@timestamp": {"gte": "now-4h"}}}, _netonly], "must_not": _excl}}}).get("hits", {}).get("total", {}).get("value", 0)
htxt = " ".join(s for s, _ in hl_sigs).lower()
top_src = hla.get("src", {}).get("buckets", [{}])[0].get("key", "?") if hla.get("src", {}).get("buckets") else "?"
if not hl_sigs: HLV = "Fără alerte de nivel ridicat în perioadă."
elif hl_ext > hl_intl * 2: HLV = "Alertele de nivel ridicat sunt **tentative AUTOMATE de exploatare din EXTERIOR** spre servicii expuse (ex. %s) — zgomot de fond de internet (scanere/exploit automate). **Fără compromitere confirmată.** Asigurați patch-uri și restrângeți serviciile expuse." % (", ".join(ip for ip, _ in hl_dst[:3]))
elif "powershell" in htxt and "smb" in htxt: HLV = "Alertele sunt **PowerShell peste SMB** de la multe stații interne spre un singur server (%s) — tipar de **administrare legitimă** (deployment/GPO/PsExec) reclasificat automat ca lateral movement. **Foarte probabil fals-pozitiv** — confirmați că %s e serverul de administrare." % ((hl_dst[0][0] if hl_dst else "?"), (hl_dst[0][0] if hl_dst else "?"))
elif "nmap" in htxt or " scan" in htxt: HLV = "Alertele indică **scanare internă** din %s (User-Agent Nmap + tentative de exploit). Atribuiți sursa: instrument autorizat (inclusiv scanerele noastre) vs amenințare reală." % top_src
elif "sudo" in htxt or "failed" in htxt: HLV = "Alertele de nivel ridicat sunt **evenimente de gazdă** (ex. eșecuri sudo) — benigne, nu atac de rețea."
else: HLV = "Alerte de nivel ridicat prezente — verificați direcția și sursa înainte de a concluziona; fără compromitere confirmată automat."

# ---- MATCH CAUZAL pe gazdă (direcție-aware) ----
def surface(ip):
    s = set(); svc = svc_by_ip.get(ip, set()); txt = " ".join(clean(f["category"]) + " " + clean(f["title"]) for f in fnd_by_ip.get(ip, [])).upper()
    if {445, 139} & svc or "SMB" in txt: s.add("SMB")
    if 3389 in svc or "RDP" in txt: s.add("RDP")
    if {80, 443, 8080, 8443, 8000, 8888} & svc or "WEB" in txt or "PANOU" in txt or "TLS" in txt: s.add("WEB")
    if {1433, 3306, 5432, 6379} & svc or any(x in txt for x in ("MSSQL", "MYSQL", "POSTGRES", "REDIS")): s.add("DB")
    if {23, 21} & svc or "TELNET" in txt or "FTP" in txt: s.add("CLEARTEXT")
    if 161 in svc or "SNMP" in txt: s.add("SNMP")
    return s
def atype(sig):
    s = sig.lower()
    if any(x in s for x in ("web", "php", "apache", "/bin/sh", "environ", "htpasswd", " iis", "wordpress", "http")): return "WEB"
    if any(x in s for x in ("smb", "powershell", "eternalblue")): return "SMB"
    if any(x in s for x in ("mssql", "1433", "mysql", "3306", "postgres", "5432", "redis")): return "DB"
    if "rdp" in s or "3389" in s: return "RDP"
    if "telnet" in s or "ftp" in s: return "CLEARTEXT"
    if "snmp" in s: return "SNMP"
    if "scan" in s: return "SCAN"
    return "INFO"
caus = []
if match_ips:
    inc = match_ips[:40]
    qd = osearch({"size": 0, "query": base, "aggs": {"ip": {"terms": {"field": "data.dest_ip", "size": 40, "include": inc}, "aggs": {"sig": {"terms": {"field": "data.alert.signature", "size": 4}}, "mx": {"max": {"field": "rule.level"}}}}}}).get("aggregations", {}).get("ip", {}).get("buckets", [])
    qs = osearch({"size": 0, "query": base, "aggs": {"ip": {"terms": {"field": "data.src_ip", "size": 40, "include": inc}, "aggs": {"sig": {"terms": {"field": "data.alert.signature", "size": 4}}, "mx": {"max": {"field": "rule.level"}}}}}}).get("aggregations", {}).get("ip", {}).get("buckets", [])
    inbound = {b["key"]: b for b in qd}; outbound = {b["key"]: b for b in qs}
    # directia activitatii de nivel ridicat per IP (extern vs intern) — decisiv pt FP administrare interna
    qdir = osearch({"size": 0, "query": {"bool": {"filter": [{"term": {"agent.id": AGENT}}, {"range": {"rule.level": {"gte": 10}}}, {"range": {"@timestamp": {"gte": "now-" + ALERT_WINDOW}}}, {"terms": {"data.dest_ip": inc}}], "must_not": _excl}}, "aggs": {"ip": {"terms": {"field": "data.dest_ip", "size": 40, "include": inc}, "aggs": {"s": {"terms": {"field": "data.src_ip", "size": 20}}}}}}).get("aggregations", {}).get("ip", {}).get("buckets", [])
    dirmap = {}
    for b in qdir:
        ext = sum(x["doc_count"] for x in b.get("s", {}).get("buckets", []) if not priv(x["key"]))
        intl = sum(x["doc_count"] for x in b.get("s", {}).get("buckets", []) if priv(x["key"]))
        dirmap[b["key"]] = (ext, intl)
    for ip in match_ips:
        exp = surface(ip)
        inb = inbound.get(ip, {}); sig_in = [b["key"] for b in inb.get("sig", {}).get("buckets", [])]
        outb = outbound.get(ip, {}); sig_out = [b["key"] for b in outb.get("sig", {}).get("buckets", [])]
        mx = amap[ip]["mx"]; ext, intl = dirmap.get(ip, (0, 0))
        atk = {atype(s) for s in sig_in}; atk.discard("INFO")
        causal = exp & atk; dom_sig = clean((sig_in or sig_out or ["—"])[0])[:48]
        real_causal = False
        if causal and mx >= 10 and ext > intl:
            verdict = "⚠️ CAUZAL: expunere %s vizată ACTIV din EXTERIOR (%s)" % ("/".join(sorted(causal)), dom_sig[:26]); real_causal = True
        elif causal and mx >= 10 and intl >= ext:
            verdict = "expunere %s + activitate INTERNĂ nivel ridicat — probabil administrare legitimă (PowerShell/SMB), FP; confirmați. NU atac extern" % ("/".join(sorted(causal)))
        elif mx >= 10 and ("WEB" in atk or "SCAN" in atk) and ext > intl:
            verdict = "vizat din EXTERIOR (%s); expunere %s — asigurați patch-uri" % (", ".join(sorted(atk))[:16], "/".join(sorted(exp)) or "—")
        elif mx >= 10 and intl >= ext:
            verdict = "activitate INTERNĂ nivel ridicat spre gazdă — atribuiți sursa (admin/scaner intern vs amenințare)"
        elif sig_out and atype(sig_out[0]) != "INFO":
            verdict = "activitate INIȚIATĂ de gazdă (%s) — atribuiți sursa" % clean(sig_out[0])[:28]
        else:
            verdict = "expus (%s), fără atac corelat → întărire proactivă" % ("/".join(sorted(exp)) or "servicii")
        caus.append({"ip": ip, "exp": "/".join(sorted(exp)) or "—", "sig": dom_sig, "c": amap[ip]["c"], "mx": mx, "verdict": verdict, "causal": real_causal})

def sevname(s): return "CRITIC" if s >= 8 else "ÎNALT" if s >= 6 else "MEDIU" if s >= 4 else "MIC"
ncaus = sum(1 for c in caus if c["causal"]); L = []
def w(s): L.append(s)
w("# %s — Raport complet de evaluare\n" % SCAN_BRAND)
w("## Descoperire autonomă + VAS + MATCH cauzal alerte ↔ scan\n")
w("**Senzor:** %s · **Client:** %s · **Data:** %s · **Profil:** %s · **Poziție:** inline\n" % (SENSOR, ORG, DATE, PROFILE))
w("**Întocmit de:** %s · %s\n\n---\n" % (SOC_NAME, SCAN_BRAND))
w("## 0. Rezumat executiv\n")
w("%s a cartografiat **autonom** rețeaua (fără IP-uri furnizate, fără agent) de pe senzorul inline `%s`, apoi a evaluat vulnerabilitățile gazdelor active și le-a corelat **cauzal** cu telemetria SOC.\n" % (SCAN_BRAND, SENSOR))
w("| Indicator | Valoare |\n|---|---|")
w("| Gazde active descoperite | %d |" % ds.get("hosts", 0))
w("| Subrețele | %d |" % len(ds.get("subnets", []) or []))
w("| Gazde cu servicii | %d |" % ds.get("with_services", 0))
w("| Constatări (C/Î/M/m) | %d (%d/%d/%d/%d) |" % (fsum.get("total", 0), fsum.get("critical", 0), fsum.get("high", 0), fsum.get("medium", 0), fsum.get("low", 0)))
w("| Alerte SOC de RETEA (%s) | %d |" % (ALERT_WINDOW_TXT, tot))
w("| — notă | doar alerte de rețea; evenimentele host ale senzorului (rootcheck/FIM) și propriul scan EXCLUSE |")
w("| Gazde MATCH (expuse ȘI alertate) | %d |" % len(match_ips))
w("| — din care corelație CAUZALĂ (expunere vizată activ din exterior) | %d |\n" % ncaus)
if hl_tot > 0:
    w("**Onestitate (alerte nivel ridicat):** %s\n" % HLV)
    w("\n**Anti-auto-alarmă:** din %d alerte de rețea nivel≥10 (%s), doar %d în fereastra scanului → **NU sunt generate de %s**. Sursele scanului + evenimentele host ale senzorului sunt EXCLUSE. Detalii la cap. 5.\n" % (hl_tot, ALERT_WINDOW_TXT, recent, SCAN_BRAND))
else:
    w("**Onestitate:** la momentul scanării **NU există dovezi de atac activ/compromitere** (nivel maxim %d = informațional). Constatările sunt **expuneri de închis preventiv**.\n" % maxlvl)
if BD: w("> **Client cu Bitdefender:** scanare low-and-slow (motor adaptiv) pentru a nu declanșa apărarea adaptivă.\n")
if NOTE: w("> %s\n" % NOTE)
w("\n---\n")
w("## 1. Acțiuni imediate (primele 72 de ore)\n")
crit = [f for f in findings if f["severity"] >= 8]
caus_hot = [c for c in caus if c["causal"]]
if caus_hot:
    w("**Prioritate MAXIMĂ — expuneri vizate ACTIV din exterior (corelație cauzală):**\n\n| IP | Expunere | Activitate | Nivel |\n|---|---|---|---|")
    for c in caus_hot[:12]: w("| %s | %s | %s | %d |" % (c["ip"], c["exp"], c["sig"][:36], c["mx"]))
    w("")
if crit:
    # R16 (doleanță ICISOC): anexă per-terminal — IP + nume/tip + expunere + serviciu vizat, marcând explicit „nedeterminabil".
    _hbip = {h.get("ip"): h for h in hosts}
    _WEB = {80, 443, 8080, 8443, 8006}
    w("**Constatări CRITICE — per terminal:**\n\n| IP | Terminal (nume / tip) | Expunere | Serviciu vizat | Constatare | Remediere |\n|---|---|---|---|---|---|")
    seen = set()
    for f in crit:
        k = (f["ip"], f["category"])
        if k in seen: continue
        seen.add(k)
        _h = _hbip.get(f["ip"], {})
        _nm = _h.get("hostname") or clean(_h.get("role")) or "nedeterminabil"
        _tp = clean(_h.get("vendor") or _h.get("role")) or "nedeterminabil"
        _term = _nm if _nm == _tp else ("%s / %s" % (_nm, _tp) if _nm != "nedeterminabil" else _tp)
        _svcs = set(_h.get("services", []) or [])
        _exp = "internă (segment) — expunerea publică nu e determinabilă de senzor" if priv(f["ip"]) else "PUBLICĂ"
        _sv = ", ".join(portname(p) for p in sorted(_svcs)) if _svcs else "nedeterminabil"
        w("| %s | %s | %s | %s | %s | %s |" % (f["ip"], _term[:34], _exp, _sv[:40], clean(f["title"])[:48], clean(f.get("remediation", ""))[:40]))
    w("")
    w("> **Precizare (context R16):** o constatare pe un serviciu web al unei gazde **NU** implică faptul că toate gazdele sunt vulnerabile — fiecare linie de mai sus e o expunere CONFIRMATĂ pe acea gazdă anume. Câmpurile pe care senzorul inline nu le poate determina (nume/tip/expunere publică) sunt marcate explicit „nedeterminabil”.\n")
if not crit and not caus_hot: w("Nu există constatări critice sau expuneri vizate activ. Igienă în cap. 6.\n")
w("\n---\n")
w("## 2. Metodologie și anti-fals-pozitiv\n")
w("Scanare **inline, non-distructivă**: descoperire pasivă (zero pachete) → ARP tag-uit → connect-scan fiabil → verificări VAS non-distructive (SMB1, SNMP, TLS, banner HTTP, CVE+KEV). **Fără teste de parole, fără exploit.** Verificare anti-FP în 3 trepte (protocol → vendor/port → excludere zgomot/scan propriu). MATCH-ul corelează **cauzal** tipul expunerii cu tipul atacului ȘI direcția (extern/intern) pe aceeași gazdă.\n\n---\n")
w("## 3. Descoperire autonomă de rețea\n")
w("Cartografiere **complet autonomă** — fără IP-uri sau documentație furnizate de client: descoperire pasivă (zero pachete) + ARP tag-uit 802.1Q (VLAN-home) + connect-scan. Întreaga topologie de mai jos e reconstituită de scaner.\n")
w("\n| Indicator | Valoare |\n|---|---|")
w("| Gazde active | %d |\n| MAC real (fizic confirmat) | %d |\n| Subrețele | %d |\n| VLAN-uri (802.1Q) | %d |\n| Gazde cu servicii expuse | %d |\n" % (ds.get("hosts", 0), ds.get("mac_real", 0), len(ds.get("subnets", []) or []), len(ds.get("vlans", []) or []), ds.get("with_services", 0)))
_sub = collections.Counter(".".join(h["ip"].split(".")[:3]) for h in hosts if h.get("ip"))
if _sub:
    w("\n### 3.1 Distribuție gazde pe subrețea\n| Subrețea | Gazde active |\n|---|---|")
    for k, n in _sub.most_common(24): w("| %s.0/24 | %d |" % (k, n))
_svc = collections.Counter()
for h in hosts:
    for p in h.get("services", []) or []: _svc[p] += 1
if _svc:
    _pn = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 102: "S7/OT", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB", 502: "Modbus/OT", 554: "RTSP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 8006: "Proxmox", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "Print"}
    w("\n### 3.2 Servicii expuse în rețea (nr. gazde)\n| Serviciu (port) | Gazde |\n|---|---|")
    for p, n in _svc.most_common(): w("| %s (%d) | %d |" % (_pn.get(p, "port"), p, n))
_rb = collections.Counter(clean(h.get("role")) or "—" for h in hosts)
if len([k for k in _rb if k != "—"]) >= 1:
    w("\n### 3.3 Distribuție pe tip de echipament (rol — euristic din vendor/porturi)\n| Tip / rol | Gazde |\n|---|---|")
    for k, n in _rb.most_common(15): w("| %s | %d |" % (k, n))
subs = ds.get("subnets", []) or []
if subs: w("\n**Toate subrețelele detectate (%d):** %s\n" % (len(subs), ", ".join(sorted(subs))))
w("\n---\n")
w("## 4. Evaluare de vulnerabilități (VAS)\n")
w("**%d constatări:** %d critice · %d înalte · %d medii · %d mici.\n" % (fsum.get("total", 0), fsum.get("critical", 0), fsum.get("high", 0), fsum.get("medium", 0), fsum.get("low", 0)))
if findings:
    bycat = collections.Counter(f["category"] for f in findings)
    w("\n| Categorie | Număr |\n|---|---|")
    for c, n in bycat.most_common(): w("| %s | %d |" % (c, n))
    w("")
    ch = [f for f in findings if f["severity"] >= 6]
    if ch:
        w("\n**Critice și înalte (per gazdă):**\n\n| IP | Sev | Categorie | Constatare |\n|---|---|---|---|")
        for f in sorted(ch, key=lambda x: -x["severity"])[:60]: w("| %s | %s | %s | %s |" % (f["ip"], sevname(f["severity"]), f["category"], clean(f["title"])[:52]))
        w("")
else: w("Nu au fost confirmate constatări active la acest scan (vezi nota din rezumat / cap. 5).\n")
w("\n---\n")
w("## 5. MATCH CAUZAL — alerte SOC ↔ scan, pe gazdă\n")
w("**Fereastră de alerte: %s** (senzor migrat recent pe SOC-ul CYBER3 — fereastră scurtă). Corelăm DOAR **alerte de rețea reale** (Suricata cu IP sursă/destinație); evenimentele HOST ale senzorului (rootcheck/FIM/PAM ale agentului) și sursele propriului scan (.250) sunt **EXCLUSE**. Legăm **tipul expunerii** de **tipul activității** ȘI **direcția** pe aceeași gazdă — nu suprapunere de IP. **%d alerte de rețea** analizate.\n" % (ALERT_WINDOW_TXT, tot))
if sigs:
    w("\n**Top signaturi (context):**\n\n| Signatură | Număr |\n|---|---|")
    for s, n in sigs[:10]: w("| %s | %d |" % (clean(s)[:68], n))
    w("")
w("\n**Distribuție nivel:** " + ", ".join("L%d=%d" % (k, levels[k]) for k in sorted(levels, reverse=True)) + ".\n")
if hl_tot > 0:
    w("\n### 5.1 Alerte de nivel ridicat — interpretare onestă\n")
    w("**%d alerte de rețea nivel≥10 (%s)** (%d din exterior, %d din interior). %s\n" % (hl_tot, ALERT_WINDOW_TXT, hl_ext, hl_intl, HLV))
    if hl_sigs:
        w("\n| Signatură nivel≥10 | Număr |\n|---|---|")
        for s, n in hl_sigs[:8]: w("| %s | %d |" % (clean(s)[:66], n))
        w("")
    if hl_dst: w("\n**Ținte principale:** %s\n" % ", ".join("%s (%d)" % (ip, n) for ip, n in hl_dst[:4]))
    w("\n**Verificat:** doar %d din %d alerte nivel≥10 sunt în fereastra scanului → **NU sunt generate de %s**.\n" % (recent, hl_tot, SCAN_BRAND))
w("\n### 5.2 Corelație cauzală pe gazdă\n")
if caus:
    w("| IP | Expunere (scan) | Activitate SOC (denumire integrală) | Nivel max | Verdict cauzal |\n|---|---|---|---|---|")
    for c in caus[:30]: w("| %s | %s | %s | %d | %s |" % (c["ip"], c["exp"], clean(c["sig"])[:80], c["mx"], c["verdict"]))
    w("")
    if ncaus: w("\n**%d gazde au corelație CAUZALĂ** (expunere de același tip cu atacul din EXTERIOR) — prioritate de remediere. Restul: expuse fără atac corelat (proactiv), administrare internă (FP) sau activitate de atribuit.\n" % ncaus)
    else: w("\n**Nicio corelație cauzală externă directă.** Suprapunerile sunt expuneri sub trafic informațional/administrare internă → întărire proactivă; activitățile interne de nivel ridicat se atribuie (admin/scaner vs amenințare).\n")
else:
    w("Nicio gazdă scanată nu apare și în alerte. **Atenție de acoperire:** alertele acoperă întreaga rețea, dar scanul atinge doar gazdele accesibile; ținta cea mai alertată poate fi în afara setului scanat (vezi 5.1).\n")
w("\n---\n")
w("## 6. Recomandări prioritizate\n")
if caus_hot: w("- **P0:** remediați imediat gazdele cu corelație cauzală (cap. 1) — expunere vizată activ din exterior.")
if crit: w("- **P1:** remediați constatările critice.")
w("- **P2:** servicii expuse (Telnet/SNMP/DB/RDP) → VPN/segmentare; SNMPv3.")
w("- **P3 igienă:** TLS de la CA, parole non-default, dezactivare SMBv1 prin GPO; restrângeți serverele web expuse la internet.")
# ── Capitol 7: Ghid STEP by STEP de remediere (detaliat, per tip de constatare PREZENT în scan) ──
REMEDY = {
 "SMBv1": ("🔴 SMBv1 / EternalBlue — execuție cod la distanță (vectorul WannaCry)", [
   "Windows (PowerShell ca administrator): `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart`",
   "Alternativ, prin registru: `Set-ItemProperty 'HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanmanServer\\\\Parameters' SMB1 -Type DWORD -Value 0 -Force`",
   "Pe tot domeniul (recomandat): GPO → Computer Configuration → Preferences → Windows Settings → Registry → creați valoarea `SMB1 = 0` (aplicată automat la toate stațiile).",
   "Reporniți fiecare stație afectată.",
   "Verificare: `Get-SmbServerConfiguration | Select EnableSMB1Protocol` → trebuie să afișeze `False`.",
   "La firewall/router: blocați porturile 139 și 445 dinspre internet.",
 ]),
 "S7": ("🔴 PLC Siemens S7 expus (OT/SCADA — control industrial)", [
   "Mutați PLC-ul într-un VLAN OT dedicat, separat de rețeaua de birou (model Purdue).",
   "Firewall: PERMITEȚI accesul la PLC (port 102) DOAR de la stația de inginerie/SCADA autorizată; blocați restul.",
   "ZERO acces direct dinspre internet sau rețeaua de birou către PLC.",
   "Dacă e posibil, activați protecția prin parolă în TIA Portal + nivelul de protecție „complet”.",
   "Monitorizare dedicată a traficului OT (senzorul CYBER3 inline).",
 ]),
 "Modbus": ("🔴 Dispozitiv Modbus expus (OT — control industrial)", [
   "Segmentați în VLAN OT separat; firewall strict.",
   "PERMITEȚI portul 502 DOAR de la stația de control autorizată.",
   "Blocați accesul dinspre birou/internet către dispozitiv.",
   "Unde e suportat, activați Modbus/TCP Security (TLS) sau un gateway cu autentificare.",
 ]),
 "MSSQL": ("🟠 Bază de date expusă în rețea", [
   "Firewall: restrângeți portul bazei de date (1433 MSSQL / 3306 MySQL / 5432 Postgres) DOAR la serverele-aplicație autorizate.",
   "NU expuneți baza de date la rețeaua generală sau la internet.",
   "Dezactivați/redenumiți conturile implicite (ex. `sa`), impuneți parole puternice.",
   "Activați auditarea conexiunilor și criptarea (TLS) pentru conexiunile la DB.",
 ]),
 "RDP": ("🟠 RDP (3389) expus — poartă frecventă de ransomware", [
   "NU expuneți 3389 la internet — accesul doar prin VPN sau RD Gateway.",
   "Firewall: permiteți 3389 DOAR din subrețeaua de administrare.",
   "Activați NLA: `sysdm.cpl` → Remote → „Allow connections only with Network Level Authentication”.",
   "Parole complexe + blocare cont după 5 încercări (GPO Account Lockout Policy).",
   "Ideal: autentificare cu doi factori (MFA) pe RDP.",
 ]),
 "TELNET": ("🟠 Telnet / protocol în clar — credențiale interceptabile", [
   "Dezactivați Telnet și folosiți SSH în loc.",
   "Pe echipamente de rețea (switch/router): `no service telnet` apoi activați SSH (`crypto key generate rsa` / `ip ssh version 2`).",
   "Pe FTP în clar: treceți la SFTP sau FTPS.",
 ]),
 "SNMP-PUBLIC": ("🟠 SNMP „public” activ — scurgere de informații", [
   "Pe fiecare echipament (imprimantă/switch/UPS): în interfața de administrare → secțiunea SNMP.",
   "Schimbați community string „public” într-una complexă, SAU dezactivați SNMP dacă nu e folosit de monitorizare.",
   "Preferați SNMPv3 (cu autentificare + criptare) în locul v1/v2c.",
   "Restrângeți accesul SNMP (ACL) doar la serverul de monitorizare autorizat.",
 ]),
 "TLS": ("🟡 TLS slab / certificat necorespunzător", [
   "Instalați certificate de la o autoritate de încredere (sau CA internă a organizației).",
   "Dezactivați TLS 1.0/1.1 și cifrurile slabe; activați doar TLS 1.2 și 1.3.",
   "Reînnoiți certificatele expirate; evitați certificatele auto-semnate pe servicii expuse.",
 ]),
 "WEB": ("🟡 Panou/aplicație web expusă", [
   "Restrângeți panourile de administrare la VPN sau la IP-uri interne (firewall/reverse-proxy).",
   "Impuneți autentificare puternică și aplicați actualizările de securitate.",
   "Ascundeți versiunile în bannere; adăugați un WAF unde e posibil.",
 ]),
 "CRED": ("🔴 Credențiale implicite / slabe pe un serviciu expus", [
   "Schimbați IMEDIAT parola implicită pe echipamentul/serviciul afectat (admin/admin, root, etc.).",
   "Impuneți parole lungi și unice (minim 14 caractere); dezactivați conturile implicite nefolosite.",
   "Unde e posibil, activați autentificarea cu doi factori (MFA).",
   "Restrângeți accesul la interfața de administrare doar din rețeaua internă / VPN.",
 ]),
 "CVE": ("🔴 Vulnerabilitate cunoscută (CVE) pe un serviciu expus", [
   "Identificați versiunea produsului din banner și aplicați actualizarea de securitate a producătorului.",
   "Prioritizați CVE-urile din catalogul CISA KEV (exploatate activ) — patch în regim de urgență.",
   "Dacă patch-ul nu e disponibil imediat: restrângeți accesul la serviciu (firewall) până la remediere.",
   "Reduceți suprafața: dezactivați serviciile și porturile neutilizate.",
 ]),
}
_REM_ORDER = ["SMBv1", "CVE", "S7", "Modbus", "CRED", "MSSQL", "RDP", "TELNET", "SNMP-PUBLIC", "TLS", "WEB"]

def _remedy_key(cat):
    """Normalizează categoria reală de constatare (cu sufixe -EXPUS/-SELF/-NEÎNCREZUT etc.) la cheia REMEDY.
    Fără asta, `RDP-EXPUS`, `TELNET-EXPUS`, `PANOU-WEB`, `TLS-SELF` etc. NU s-ar potrivi și capitolul ar fi gol."""
    c = (cat or "").upper()
    if "SMBV1" in c or "SMB1" in c: return "SMBv1"
    if c.startswith("S7") or "SIEMENS" in c: return "S7"
    if "MODBUS" in c: return "Modbus"
    if any(k in c for k in ("MSSQL", "MYSQL", "POSTGRES", "MONGO", "REDIS", "ELASTIC", "BAZA", "DB-EXPUS")): return "MSSQL"
    if "RDP" in c: return "RDP"
    if "TELNET" in c or c.startswith("FTP") or "-CLAR" in c: return "TELNET"
    if "SNMP" in c: return "SNMP-PUBLIC"
    if c.startswith("TLS") or c.startswith("SSL") or "CERT" in c: return "TLS"
    if "WEB" in c or "PANOU" in c or "HTTP" in c: return "WEB"
    if "CRED" in c or "DEFAULT" in c or "PAROL" in c: return "CRED"
    if c.startswith("CVE") or "KEV" in c: return "CVE"
    return None
w("\n---\n## 7. Ghid STEP by STEP de remediere\n")
w("Pași concreți de implementare pentru fiecare tip de problemă găsit în scan — de urmat de administratorul beneficiarului, simplu și clar. Ordonat după prioritate.\n")
_cats = {}
for _f in findings:
    _k = _remedy_key(_f.get("category", ""))
    if _k:
        _cats.setdefault(_k, []).append(_f.get("ip", "?"))
_n = 0
for _c in _REM_ORDER:
    if _c not in _cats:
        continue
    _n += 1
    _title, _steps = REMEDY[_c]
    _ips = sorted(set(_cats[_c]))
    w("\n### 7.%d %s\n" % (_n, _title))
    w("**Gazde afectate (%d):** %s\n" % (len(_ips), ", ".join(_ips[:24]) + (" …" if len(_ips) > 24 else "")))
    w("**Implementare pas cu pas:**\n")
    for _i, _s in enumerate(_steps, 1):
        w("%d. %s" % (_i, _s))
if _n == 0:
    w("\n_Nicio constatare care să necesite un ghid de remediere dedicat._\n")

w("\n---\n## 8. Inventar detaliat\n")
_sevn = {9: "CRITIC", 8: "CRITIC", 7: "ÎNALT", 6: "ÎNALT", 5: "MEDIU", 4: "MEDIU", 3: "MIC", 2: "MIC", 1: "MIC", 0: "—"}
_derole = lambda x: re.sub(r"^[^\x00-\x7F]+\s*", "", str(x or "")).strip() or "—"
# Anexa A — inventarul COMPLET al constatărilor (toate severitățile, nu doar C/Î)
w("\n### 8.1 Inventar complet al constatărilor (%d)\n" % len(findings))
if findings:
    w("| IP | VLAN | Severitate | Categorie | Constatare | Remediere |\n|---|---|---|---|---|---|")
    for f in sorted(findings, key=lambda x: (-x.get("severity", 0), x.get("ip", ""))):
        w("| %s | %s | %s | %s | %s | %s |" % (f.get("ip", "-"), (f.get("vlan") if f.get("vlan") is not None else "—"),
          _sevn.get(f.get("severity", 0), "-"), f.get("category", "-"), str(f.get("title", "-"))[:72], str(f.get("remediation", "-"))[:60]))
# Anexa B — inventarul gazdelor cu servicii (IP, VLAN, rol, porturi)
_hs = sorted([h for h in hosts if h.get("services")], key=lambda h: h.get("ip", ""))
w("\n### 8.2 Inventar gazde cu servicii (%d)\n" % len(_hs))
if _hs:
    w("| IP | VLAN | Rol / echipament | Porturi deschise |\n|---|---|---|---|")
    for h in _hs:
        w("| %s | %s | %s | %s |" % (h.get("ip", "-"), (h.get("home_vlan") if h.get("home_vlan") is not None else "—"),
          _derole(h.get("role")), ", ".join(str(p) for p in sorted(h.get("services", [])))))
# Anexa C — bannere de servicii capturate (dovezi brute, extras)
_ban = fnd.get("banners", {})
if _ban:
    w("\n### 8.3 Bannere de servicii capturate (extras)\n")
    w("| Serviciu | Banner |\n|---|---|")
    for k, v in list(_ban.items())[:50]:
        w("| %s | %s |" % (str(k)[:26], re.sub(r"\s+", " ", str(v))[:90].replace("|", "¦")))
# Anexa D — metodologie (text auto-conținut, FĂRĂ referiri la fișiere externe neatașate — cerință client ICI)
w("\n### 8.4 Metodologie\n")
w("- **Metodă:** descoperire autonomă (pasiv zero-pachete + ARP tag-uit + connect-scan **adaptiv cu santinelă**, low-and-slow), VAS non-distructiv (SMBv1/SNMP/TLS/banner HTTP/CVE-KEV). **Fără exploit, fără teste de parole.**")
w("- **Excluderi MATCH:** propriul scan CYBER3 (surse `.250`) + IP-uri senzor + unelte de apărare (AV) — pentru corelații reale, nu circulare.\n")
w("\n*%s · %s · %s. Evaluare autorizată, non-distructivă, inline. Tot ce nu a putut fi verificat activ este marcat explicit; raportul nu conține presupuneri ca fapte.*\n" % (SCAN_BRAND, SOC_SHORT, DATE))
open(os.path.join(OUT, "CYBER3_Scan_Raport_%s_%s.md" % (SENSOR, DATE_ISO)), "w", encoding="utf-8").write("\n".join(L))

# ---- MATCH report separat (sărit când SKIP_MATCH=1 — se completează separat, după rapoartele de alerte) ----
if not SKIP_MATCH:
    M = ["# %s — MATCH REPORT (cauzal)\n" % SCAN_BRAND, "## Descoperire ↔ Alerte SOC ↔ Vulnerabilități\n",
         "**Senzor:** %s · **Client:** %s · **Data:** %s · **Alerte de rețea (%s):** %d (host-events senzor + scan propriu excluse)\n\n---\n" % (SENSOR, ORG, DATE, ALERT_WINDOW_TXT, tot),
         "## 1. Rezumat\n| Indicator | Valoare |\n|---|---|", "| Gazde | %d |" % ds.get("hosts", 0),
         "| Gazde cu servicii | %d |" % ds.get("with_services", 0), "| Constatări | %d |" % fsum.get("total", 0),
         "| Gazde MATCH | %d (cauzale externe: %d) |\n" % (len(match_ips), ncaus),
         "\n## 2. Nivel ridicat\n**%d alerte nivel≥10** — %s\n" % (hl_tot, HLV), "\n## 3. Corelație cauzală pe gazdă\n"]
    if caus:
        M.append("| IP | Expunere | Activitate SOC | Nivel | Verdict |\n|---|---|---|---|---|")
        for c in caus[:30]: M.append("| %s | %s | %s | %d | %s |" % (c["ip"], c["exp"], c["sig"][:28], c["mx"], c["verdict"]))
    else: M.append("Nicio suprapunere expunere × alertă pe gazdele scanate.")
    M.append("\n## 4. Concluzii\n- %s\n- Propriul scan CYBER3 și uneltele de apărare (Bitdefender) sunt excluse din MATCH.\n" % ("%d gazde cu corelație cauzală externă — prioritate" % ncaus if ncaus else "Fără corelație cauzală externă directă; suprapunerile = expuneri sub trafic informațional/administrare internă (proactiv)"))
    M.append("\n*%s · MATCH REPORT · %s · %s.*\n" % (SCAN_BRAND, SOC_SHORT, DATE))
    open(os.path.join(OUT, "CYBER3_Scan_MATCH_REPORT_%s_%s.md" % (SENSOR, DATE_ISO)), "w", encoding="utf-8").write("\n".join(M))
json.dump(disc, open(os.path.join(OUT, "discovery.json"), "w"), indent=2, ensure_ascii=False)
json.dump(fnd, open(os.path.join(OUT, "findings.json"), "w"), indent=2, ensure_ascii=False)
print("OK %s: hosts=%d find=%d match=%d cauzale=%d maxlvl=%d" % (SENSOR, ds.get("hosts", 0), fsum.get("total", 0), len(match_ips), ncaus, maxlvl))
