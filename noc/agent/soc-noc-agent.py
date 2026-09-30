#!/usr/bin/env python3
"""NOC node agent — colecteaza health LOCAL, AUTO-REMEDIAZA (treapta 2, lista alba) si impinge la NOC edge.
Ruleaza ca root (systemd timer ~60s). Config: /etc/cyber3/noc-node.token + /etc/default/cyber3-noc-agent.
GARDA: doar actiuni idempotente/reversibile/blast-mic; NICIODATA pe calea de date a bridge-ului inline.
Rate-limit per actiune; raporteaza tot. Kill-switch: REMEDIATE=0 in /etc/default/cyber3-noc-agent. Vezi [[noc-design-spec]]."""
import json, os, re, socket, subprocess, time, urllib.request

CFG = {}
for p in ("/etc/default/cyber3-noc-agent",):
    if os.path.exists(p):
        for line in open(p):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1); CFG[k.strip()] = v.strip().strip('"')
NOC_URL = CFG.get("NOC_URL", "https://cyber3-noc.cyber3.workers.dev/v1/noc/report")
TOKFILE = CFG.get("NOC_TOKEN_FILE", "/etc/cyber3/noc-node.token")
TOKEN = open(TOKFILE).read().strip() if os.path.exists(TOKFILE) else os.environ.get("NOC_NODE_TOKEN", "")
REMEDIATE = CFG.get("REMEDIATE", "1") == "1"
STATE_FILE = "/var/lib/cyber3-noc/remediation.json"
SKIP_SERVICES = set(x.strip() for x in CFG.get("SKIP_SERVICES", "").split(",") if x.strip())
SWAP_MIN_MB = int(CFG.get("SWAP_MIN_MB", "256"))


def sh(cmd, t=20):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t).stdout.strip()
    except Exception:
        return ""


def active(svc):
    s = sh(f"systemctl is-active {svc}")
    return s if s else "missing"


def read(path):
    try:
        return open(path).read().strip()
    except Exception:
        return ""


def has_iface(n): return os.path.exists(f"/sys/class/net/{n}")
def carrier(n): return read(f"/sys/class/net/{n}/carrier") == "1"
def _cap_iface():
    # Interfata monitorizata de Suricata: br0 (senzori inline clasici) / bond0 (icisoc110 IDS 10G) etc.
    sock = "/var/run/suricata/suricata-command.socket"
    o = sh(f"suricatasc -c iface-list {sock} 2>/dev/null")
    try:
        ifs = json.loads(o).get("message", {}).get("ifaces", [])
        if ifs: return ifs[0]
    except Exception: pass
    for n in ("br0", "bond0"):
        if has_iface(n): return n
    return ""


CAPIF = _cap_iface()


def _eve_path():
    for f in ("/var/log/suricata/eve-alerts.json", "/var/log/suricata/eve.json"):
        if os.path.exists(f): return f
    return "/var/log/suricata/eve-alerts.json"


EVE_PATH = _eve_path()


def br_members():
    if not CAPIF: return []
    try: return os.listdir(f"/sys/class/net/{CAPIF}/brif")
    except Exception: return []


def suricata_capture():
    if not CAPIF: return {"ok": False}
    sock = "/var/run/suricata/suricata-command.socket"
    def stat():
        o = sh(f"suricatasc -c 'iface-stat {CAPIF}' {sock} 2>/dev/null")
        try:
            d = json.loads(o)["message"]; return d.get("pkts", 0), d.get("drop", 0)
        except Exception: return None, None
    p1, d1 = stat()
    if p1 is None: return {"ok": False}
    time.sleep(3)
    p2, d2 = stat()
    if p2 is None: return {"ok": False}
    dpk = p2 - p1
    return {"ok": True, "pps": int(dpk / 3),
            "drop_pct": round((d2 - d1) * 100 / dpk, 2) if dpk > 0 else 0.0, "drops_total": d2}


def wg_handshake_age():
    ifs = sh("wg show interfaces 2>/dev/null").split()
    wgif = ifs[0] if ifs else "wg1"
    o = sh(f"wg show {wgif} latest-handshakes 2>/dev/null"); now = int(time.time()); best = None
    for line in o.splitlines():
        p = line.split()
        if len(p) >= 2 and p[1].isdigit() and int(p[1]) > 0:
            age = now - int(p[1]); best = age if best is None else min(best, age)
    return best


def l2shield_status():
    """STRAT 3 (L2 Shield): ebtables anti-gateway-ARP-spoof. present/armed/mode/rules/drops.
    armed=1 doar daca chain-ul CYBER3_L2SHIELD exista + jump din FORWARD + mod DROP + >=1 regula."""
    lc = sh("ebtables -L CYBER3_L2SHIELD --Lc 2>/dev/null")
    if not lc or "CYBER3_L2SHIELD" not in lc:
        return {"present": 0, "armed": 0, "mode": "off", "rules": 0, "drops": 0}
    jump = 1 if "CYBER3_L2SHIELD" in (sh("ebtables -L FORWARD 2>/dev/null") or "") else 0
    rules = lc.count("--arp-ip-src")
    mode = "drop" if "-j DROP" in lc else ("count" if "-j CONTINUE" in lc else "off")
    drops = sum(int(x) for x in re.findall(r"pcnt = (\d+)", lc))
    return {"present": 1, "armed": (1 if (jump and mode == "drop" and rules > 0) else 0),
            "mode": mode, "rules": rules, "drops": drops, "jump": jump}


# ---------- TREAPTA 2: auto-remediere (lista alba) ----------
def _load_state():
    try: return json.load(open(STATE_FILE))
    except Exception: return {}
def _save_state(s):
    try:
        os.makedirs("/var/lib/cyber3-noc", exist_ok=True); json.dump(s, open(STATE_FILE, "w"))
    except Exception: pass
def _rate_ok(state, key, max_n, window=3600):
    now = time.time(); hist = [t for t in state.get(key, []) if now - t < window]
    if len(hist) >= max_n:
        state[key] = hist; return False
    hist.append(now); state[key] = hist; return True


def pull_approved(node):
    """Trage acțiunile sensibile APROBATE de om pentru acest nod (de la NOC)."""
    url = NOC_URL.replace("/report", "/commands") + "?node=" + node
    try:
        req = urllib.request.Request(url, headers={"authorization": "Bearer " + TOKEN, "user-agent": "cyber3-noc-agent/2.1"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode()).get("approved", [])
    except Exception:
        return []


def remediate(metrics, is_inline, node):
    """SAFE = auto. SENSITIVE = execută DOAR dacă aprobat-om; altfel propune. NICIODATĂ pe calea de date bridge."""
    if not REMEDIATE: return [], [], []
    done, executed, proposals = [], [], []
    st = _load_state(); approved = pull_approved(node); svc = metrics.get("services", {})

    # ---- SAFE (auto) ----
    for s in ("wazuh-agent", "cyber3-soc-receiver"):
        # doar servicii ENABLED (nu deranja ce e dezactivat deliberat, ex. receiver pe icisoc110)
        if svc.get(s) in ("inactive", "failed") and sh(f"systemctl is-enabled {s} 2>/dev/null") == "enabled":
            if _rate_ok(st, "r:" + s, 3): sh(f"systemctl restart {s}"); done.append(f"restart {s}")
            else: done.append(f"{s} jos — rate-limit (uman)")
    if metrics.get("host", {}).get("ntp") == "no":
        if _rate_ok(st, "ntp", 1): sh("systemctl restart systemd-timesyncd 2>/dev/null || systemctl restart chrony 2>/dev/null"); done.append("resync NTP")

    # ---- SENSITIVE (aprobare-om) ----
    def sensitive(action, label, reason, cmd):
        if action in approved:
            if _rate_ok(st, "ap:" + action, 3): sh(cmd); executed.append(action)
        else:
            proposals.append({"action": action, "label": label, "reason": reason})

    if svc.get("suricata") in ("inactive", "failed"):
        sensitive("restart-suricata", "restart Suricata (întrerupe IDS scurt)", "Suricata jos", "systemctl restart suricata")
    if is_inline and metrics.get("security", {}).get("br_netfilter_module") not in (1, "1") and metrics.get("security", {}).get("ar_method") != "ebtables":
        sensitive("enable-brnetfilter", "re-activează br_netfilter (filtrare bridge)", "br_netfilter OFF pe inline",
                  "modprobe br_netfilter; sysctl -w net.bridge.bridge-nf-call-iptables=1; sysctl -w net.bridge.bridge-nf-call-ip6tables=1")
    if metrics.get("host", {}).get("disk_pct", 0) >= 92:
        sensitive("disk-clean", "curăță disc (șterge loguri)", "disc ≥92%", "journalctl --vacuum-size=200M 2>/dev/null; apt-get clean 2>/dev/null")
    _save_state(st)
    return done, executed, proposals


def _inline_ok():
    try:
        mem = []
        for b in os.listdir("/sys/class/net"):
            brif = "/sys/class/net/" + b + "/brif"
            if os.path.isdir(brif):
                m = os.listdir(brif)
                if len(m) >= 2:
                    mem += m
        if not mem:
            return 0
        def _tx(n):
            v = read("/sys/class/net/" + n + "/statistics/tx_packets")
            return int(v) if v and v.strip().isdigit() else 0
        a = {m: _tx(m) for m in mem}
        time.sleep(2)
        b2 = {m: _tx(m) for m in mem}
        return 1 if sum(b2[m] - a[m] for m in mem) / 2.0 > 20 else 0
    except Exception:
        return -1

def collect():
    host = CFG.get("NODE_NAME") or socket.gethostname()
    is_sensor = bool(CAPIF)
    members = br_members() if is_sensor else []
    is_inline = len(members) >= 2
    cores = os.cpu_count() or 1
    load = float((read("/proc/loadavg").split() or ["0"])[0] or 0)
    mem = {}
    for line in read("/proc/meminfo").splitlines():
        m = re.match(r"(\w+):\s+(\d+)", line)
        if m: mem[m.group(1)] = int(m.group(2))
    mem_pct = round((1 - mem.get("MemAvailable", 0) / max(1, mem.get("MemTotal", 1))) * 100)
    swap_mb = round((mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)) / 1024)
    disk_pct = int((sh("df / | awk 'END{print $5}'") or "0").rstrip("%") or 0)
    ntp = "yes" if "synchronized: yes" in sh("timedatectl 2>/dev/null").lower() else "no"
    metrics = {"host": {"load": load, "cores": cores, "mem_pct": mem_pct, "swap_mb": swap_mb, "disk_pct": disk_pct,
                        "uptime_s": int(float((read("/proc/uptime").split() or ["0"])[0] or 0)), "ntp": ntp}}

    if is_sensor:
        ntype, group = "sensor", "sensors"
        metrics["inline"] = is_inline
        svc = {s: active(s) for s in ["suricata", "wazuh-agent", "wg-quick@wg1", "cyber3-soc-receiver"]}
        metrics["services"] = svc
        brnf = read("/proc/sys/net/bridge/bridge-nf-call-iptables") or "0"
        metrics["security"] = {"br_netfilter": int(brnf) if brnf.isdigit() else 0, "br_netfilter_module": (1 if "br_netfilter" in (sh("lsmod 2>/dev/null") or "") else 0), "ar_method": ("iptables+brnf" if ("br_netfilter" in (sh("lsmod 2>/dev/null") or "") and "CYBER3_BLOCK" in (sh("iptables -S FORWARD 2>/dev/null") or "")) else ("ebtables" if "-j DROP" in (sh("ebtables -L FORWARD 2>/dev/null") or "") else "none")), "can_block": (1 if (("CYBER3_BLOCK" in (sh("iptables -S FORWARD 2>/dev/null") or "") and "br_netfilter" in (sh("lsmod 2>/dev/null") or "") and ((read("/proc/sys/net/bridge/bridge-nf-call-iptables") or "0").strip()=="1")) or ("-j DROP" in (sh("ebtables -L FORWARD 2>/dev/null") or ""))) else 0), "inline_ok": _inline_ok()}
        cap = suricata_capture(); cap["br0_carrier"] = carrier(CAPIF); metrics["capture"] = cap
        metrics["l2shield"] = l2shield_status()
        metrics["wg_handshake_age_s"] = wg_handshake_age()
        eve = EVE_PATH
        metrics["eve_age_s"] = int(time.time() - os.path.getmtime(eve)) if os.path.exists(eve) else None
        metrics["eve_size_mb"] = int(os.path.getsize(eve) / 1048576) if os.path.exists(eve) else None
    else:
        ntype, group = "server", "soc-core"
        cand = ["wazuh-manager", "wazuh-indexer", "filebeat", "nginx", "gunicorn", "supervisor",
                "wg-quick@wg1", "wg-quick@wg0", "mariadb", "misp-workers", "pve-cluster", "pvedaemon"]
        svc = {s: active(s) for s in cand if sh(f"systemctl list-unit-files {s}.service 2>/dev/null | grep -c {s}.service") != "0"}
        metrics["services"] = svc
        # CYBER3 AI MULTI-SOURCE FUSION ENGINE (CyberBot prin wazuh-integratord) — doar pe manager
        if svc.get("wazuh-manager") == "active":
            wcs = sh("/var/ossec/bin/wazuh-control status 2>/dev/null")
            errs = sh("tail -400 /var/ossec/logs/integrations.log 2>/dev/null | grep -ci error")
            metrics["fusion_engine"] = {"integratord": "running" if "wazuh-integratord is running" in wcs else "down",
                                        "cyberbot_err_recent": int(errs or 0)}

    # ---- TREAPTA 2: remediază (auto) / propune (sensibil) ----
    done, executed, proposals = remediate(metrics, is_sensor and is_inline, host)
    if done or executed:  # re-citește ce s-a schimbat
        if is_sensor:
            metrics["services"] = {s: active(s) for s in ["suricata", "wazuh-agent", "wg-quick@wg1", "cyber3-soc-receiver"]}
            brnf = read("/proc/sys/net/bridge/bridge-nf-call-iptables") or "0"
            metrics["security"] = {"br_netfilter": int(brnf) if brnf.isdigit() else 0, "br_netfilter_module": (1 if "br_netfilter" in (sh("lsmod 2>/dev/null") or "") else 0), "ar_method": ("iptables+brnf" if ("br_netfilter" in (sh("lsmod 2>/dev/null") or "") and "CYBER3_BLOCK" in (sh("iptables -S FORWARD 2>/dev/null") or "")) else ("ebtables" if "-j DROP" in (sh("ebtables -L FORWARD 2>/dev/null") or "") else "none")), "can_block": (1 if (("CYBER3_BLOCK" in (sh("iptables -S FORWARD 2>/dev/null") or "") and "br_netfilter" in (sh("lsmod 2>/dev/null") or "") and ((read("/proc/sys/net/bridge/bridge-nf-call-iptables") or "0").strip()=="1")) or ("-j DROP" in (sh("ebtables -L FORWARD 2>/dev/null") or ""))) else 0), "inline_ok": _inline_ok()}
        else:
            metrics["services"] = {s: active(s) for s in metrics.get("services", {})}

    # ---- status ----
    reasons = []; status = "green"
    def amber(r):
        nonlocal status
        if status != "red": status = "amber"
        reasons.append(r)
    def red(r):
        nonlocal status; status = "red"; reasons.append(r)
    sv = metrics.get("services", {})
    if is_sensor:
        for s, lbl in [("suricata", "Suricata"), ("wazuh-agent", "wazuh-agent")]:
            if sv.get(s) != "active": red(f"{lbl} jos")
        # WireGuard: pe vechimea handshake-ului (interfata detectata), nu pe numele unit-ului
        hs = metrics.get("wg_handshake_age_s")
        if hs is None or hs > 300: red(f"tunel wg ({hs}s)")
        cap = metrics.get("capture", {})
        if not cap.get("br0_carrier"): amber(f"{CAPIF} fără carrier")
        if cap.get("ok") and cap.get("drop_pct", 0) > 1: amber(f"drops {cap['drop_pct']}%")
        if is_inline and metrics["security"].get("br_netfilter_module",0) != 1 and metrics["security"].get("ar_method") != "ebtables": amber("br_netfilter OFF (AR inefectiv)")
        # STRAT 3 L2 Shield: drops>0 = ARP-spoof activ prins la L2 (unghi mort al straturilor IP)
        l2s = metrics.get("l2shield", {})
        if l2s.get("drops", 0) > 0: amber(f"L2 Shield: {l2s['drops']} ARP-spoof blocate")
        # receiver: doar daca e ENABLED (icisoc110 nu-l foloseste -> nu alarma fals)
        if sv.get("cyber3-soc-receiver") != "active" and sh("systemctl is-enabled cyber3-soc-receiver 2>/dev/null") == "enabled":
            amber("CYBER3 receiver jos")
        # eve: fișier uriaș (rotație lipsă/ruptă) sau vechi (Suricata nu mai scrie)
        esz = metrics.get("eve_size_mb")
        # icisoc110 scrie eve full (~plafonat la 3G prin logrotate orar); red doar la runaway real
        if esz is not None and esz >= 6144: red(f"eve {esz}MB (rotație ruptă)")
        elif esz is not None and esz >= 4096: amber(f"eve {esz}MB (fără rotație?)")
        eag = metrics.get("eve_age_s")
        if eag is not None and eag > 3600: amber(f"eve vechi {eag}s (Suricata nu scrie?)")
    else:
        for s, stt in sv.items():
            if s in SKIP_SERVICES: continue
            if stt not in ("active", "missing"): red(f"{s} {stt}")
    dp = metrics["host"]["disk_pct"]
    if dp >= 90: red(f"disc {dp}%")
    elif dp >= 80: amber(f"disc {dp}%")
    # RAM — lipsea complet din status (de-asta icisoc108 la 71% era verde)
    mp = metrics["host"]["mem_pct"]
    if mp >= 93: red(f"RAM {mp}%")
    elif mp >= 85: amber(f"RAM {mp}%")
    sw = metrics["host"].get("swap_mb", 0)
    if sw >= SWAP_MIN_MB: amber(f"swap {sw}MB (presiune RAM)")
    if load > cores * 2: amber(f"load {load}")
    if metrics["host"]["ntp"] == "no": amber("NTP nesincronizat")

    rep = {"node": host, "type": ntype, "group": group, "ts": int(time.time()),
           "status": status, "reasons": reasons, "metrics": metrics}
    if done: rep["remediations"] = done
    if executed: rep["executed"] = executed
    if proposals: rep["proposals"] = proposals
    return rep


def push(report):
    req = urllib.request.Request(NOC_URL, data=json.dumps(report).encode(), method="POST",
                                 headers={"content-type": "application/json",
                                          "authorization": "Bearer " + TOKEN, "user-agent": "cyber3-noc-agent/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()[:120]
    except Exception as e:
        return 0, str(e)[:120]


if __name__ == "__main__":
    rep = collect()
    code, body = push(rep)
    print(f"[noc-agent] {rep['node']} status={rep['status']} auto={rep.get('remediations',[])} exec={rep.get('executed',[])} propuneri={[p['action'] for p in rep.get('proposals',[])]} -> HTTP {code}")
