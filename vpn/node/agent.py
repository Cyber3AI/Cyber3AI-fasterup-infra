#!/usr/bin/env python3
# CYBER3.AI VPN — agent nod exit (Pas 2). Mini-API control-plane -> nod.
# Doar stdlib. Ascultă pe 127.0.0.1 (expunere la Pas 3 via cloudflared). No-logs.
import json, os, re, subprocess, fcntl, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WG_IF   = "wg0"
WG_NET  = "10.3.0"
WG_PORT = 51820
DNS     = "10.3.0.1"
TOKEN_FILE = "/etc/cyber3/agent.token"
LOCK_FILE  = "/run/cyber3-agent.lock"
LISTEN  = ("0.0.0.0", 8080)  # port permis de Workers fetch; protejat de firewall Hetzner (doar IP-uri CF) + bearer token

def token():
    with open(TOKEN_FILE) as f:
        return f.read().strip()

def sh(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout

PUBLIC_IP_FILE = "/etc/cyber3/public_ip"

def public_ip():
    # nod în spatele unui router (ex. birou, port-forward UDP 51820): IP-ul public nu e pe interfață
    try:
        with open(PUBLIC_IP_FILE) as f:
            ip = f.read().strip()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
            return ip
    except OSError:
        pass
    out = sh("ip", "-4", "route", "get", "1.1.1.1")
    m = re.search(r"src (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else ""

def server_pubkey():
    return sh("wg", "show", WG_IF, "public-key").strip()

def used_octets():
    out = sh("wg", "show", WG_IF, "allowed-ips")
    return {int(m.group(1)) for m in re.finditer(rf"{WG_NET}\.(\d+)/32", out)}

def alloc_ip():
    used = used_octets()
    for o in range(2, 255):
        if o not in used:
            return f"{WG_NET}.{o}"
    raise RuntimeError("pool full")

def peer_ip(pub):
    out = sh("wg", "show", WG_IF, "allowed-ips")
    m = re.search(rf"{re.escape(pub)}\s+({WG_NET}\.\d+)/32", out)
    return m.group(1) if m else None

def peer_exists(pub):
    return pub in sh("wg", "show", WG_IF, "peers").split()

def peer_transfer():
    """Transfer per-peer (rx,tx octeti) via `wg show wg0 transfer`. Cumulativ de la adaugarea
    peer-ului; RAM-only => resetat la re-add / reboot (control-plane-ul acumuleaza deltele)."""
    res = {}
    for line in sh("wg", "show", WG_IF, "transfer").splitlines():
        p = line.split("\t")
        if len(p) == 3:
            res[p[0]] = {"rx": int(p[1]), "tx": int(p[2])}
    return res

ANCHORS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def default_iface():
    m = re.search(r"dev (\S+)", sh("ip", "-4", "route", "get", "1.1.1.1"))
    return m.group(1) if m else "eth0"

def link_speed(dev):
    """Viteza portului în Mbps; None pe interfețe virtuale (VPS) care nu o raportează."""
    try:
        v = int(open(f"/sys/class/net/{dev}/speed").read().strip())
        return v if v > 0 else None
    except (OSError, ValueError):
        return None

_CPU_LAST = {"t": 0.0, "tot": 0, "idle": 0}
def cpu_util(sample=1.0):
    """Ocuparea CPU ca MEDIE de la apelul anterior (între 5 s și 15 min); altfel o probă de 1 s.
    O fereastră de 0,3 s pe un nod cu 1 vCPU prindea orice proces scurt drept „100%” (alarmă falsă)."""
    def snap():
        v = [int(x) for x in open("/proc/stat").readline().split()[1:]]
        return sum(v), v[3] + (v[4] if len(v) > 4 else 0)
    now = time.time(); t2, i2 = snap(); last = dict(_CPU_LAST)
    _CPU_LAST.update(t=now, tot=t2, idle=i2)
    if 5 <= now - last["t"] <= 900 and t2 > last["tot"]:
        return round(100.0 * (1 - (i2 - last["idle"]) / max(1, t2 - last["tot"])), 1)
    t1, i1 = t2, i2; time.sleep(sample); t2, i2 = snap()
    return round(100.0 * (1 - (i2 - i1) / max(1, t2 - t1)), 1)

def ping_all(targets):
    """Latență medie (ms) spre ancore/noduri — ping-uri în paralel, fără logare."""
    procs = {t: subprocess.Popen(["ping", "-n", "-q", "-c", "3", "-i", "0.2", "-W", "1", t],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) for t in targets}
    out = {}
    for t, p in procs.items():
        try:
            txt = p.communicate(timeout=5)[0]
            m = re.search(r"= [\d.]+/([\d.]+)/", txt)
            loss = re.search(r"(\d+)% packet loss", txt)
            out[t] = {"ms": float(m.group(1)) if m else None, "loss": int(loss.group(1)) if loss else 100}
        except Exception:
            p.kill(); out[t] = {"ms": None, "loss": 100}
    return out

def metrics(targets, nolat=False):
    """Metrici nod, independente de furnizor (Hetzner / data center propriu). Read-only, no-logs:
    doar contoare agregate, nicio adresă de client și nicio destinație."""
    dev = default_iface()
    stat = lambda i, k: int(open(f"/sys/class/net/{i}/statistics/{k}").read())
    mem = {}
    for line in open("/proc/meminfo"):
        k, v = line.split(":", 1); mem[k] = int(v.split()[0])
    st = os.statvfs("/")
    now = int(time.time())
    hs = [int(l.split("\t")[1]) for l in sh("wg", "show", WG_IF, "latest-handshakes").splitlines() if "\t" in l]
    blk = "/etc/unbound/ioc.blocklist"
    try:
        ioc_lines = sum(1 for _ in open(blk)); ioc_mtime = int(os.path.getmtime(blk))
    except OSError:
        ioc_lines, ioc_mtime = None, None
    l1, l5, l15 = os.getloadavg()
    return {
        "host": os.uname().nodename, "uptime_s": int(float(open("/proc/uptime").read().split()[0])), "ts": now,
        "cpu": {"cores": os.cpu_count(), "util_pct": cpu_util(), "load1": round(l1, 2), "load5": round(l5, 2), "load15": round(l15, 2)},
        "mem": {"total_mb": mem["MemTotal"] // 1024, "avail_mb": mem.get("MemAvailable", 0) // 1024},
        "disk": {"total_gb": round(st.f_blocks * st.f_frsize / 1e9, 1), "free_gb": round(st.f_bavail * st.f_frsize / 1e9, 1)},
        "net": {"iface": dev, "rx_bytes": stat(dev, "rx_bytes"), "tx_bytes": stat(dev, "tx_bytes"), "speed_mbps": link_speed(dev)},
        "wg": {"iface": WG_IF, "port": WG_PORT, "pool_size": 253, "peers": len(hs),
               "active_3m": sum(1 for h in hs if h and now - h < 180), "active_15m": sum(1 for h in hs if h and now - h < 900),
               "rx_bytes": stat(WG_IF, "rx_bytes"), "tx_bytes": stat(WG_IF, "tx_bytes")},
        "lat": {} if nolat else ping_all(ANCHORS + [t for t in targets if IPV4_RE.match(t)][:12]),
        "ioc": {"blocklist_lines": ioc_lines, "mtime": ioc_mtime},
        "unbound": subprocess.run(["systemctl", "is-active", "unbound"], capture_output=True, text=True).stdout.strip(),
    }

# --- HEALTHCHECK v1 ---
# Verificări făcute de nod asupra lui însuși, la cererea portalului vpn.cyber3.ai. Read-only, no-logs:
# niciun client, nicio destinație — doar starea serviciilor de care depinde un tunel care MERGE.
def _run(args, timeout=6):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except Exception as e:
        return 255, str(e)

def _dig(name):
    """(status, are_răspuns) întrebând resolverul din tunel, exact cum îl întreabă un client."""
    rc, out = _run(["dig", "+time=2", "+tries=1", "@" + DNS, name, "A"])
    m = re.search(r"status: (\w+)", out)
    return (m.group(1) if m else "TIMEOUT"), bool(re.search(r"ANSWER: [1-9]", out))

def _first_blocked(path):
    """Primul domeniu din lista de blocare (pentru proba „un domeniu blocat chiar e blocat”)."""
    try:
        with open(path) as f:
            for line in f:
                m = re.search(r'local-zone:\s*"?([^"\s]+?)\.?"?\s+always_nxdomain', line)
                if m: return m.group(1)
    except OSError:
        pass
    return None

def _age_h(path):
    try: return round((time.time() - os.path.getmtime(path)) / 3600, 1)
    except OSError: return None

def health():
    c = []
    def add(cid, ok, sev, val, msg):
        c.append({"id": cid, "ok": bool(ok), "sev": "OK" if ok else sev, "val": val, "msg": msg})
    # 1. WireGuard: interfața există și ascultă
    rc, out = _run(["wg", "show", WG_IF, "listen-port"])
    add("wg", rc == 0 and out.strip() == str(WG_PORT), "CRIT", out.strip() or None, "WireGuard activ pe portul %d" % WG_PORT)
    # 2. DNS-ul din tunel răspunde (proba reală, nu doar „serviciul e pornit”)
    st, ans = _dig("example.com")
    add("dns_resolve", st == "NOERROR" and ans, "CRIT", st, "Resolverul din tunel răspunde la un nume obișnuit")
    # 3. Filtrarea: un domeniu din listă chiar e blocat
    for cid, path, label in (("ioc_block", "/etc/unbound/ioc.blocklist", "domenii periculoase"), ("ads_block", "/etc/unbound/ads.blocklist", "reclame și trackere")):
        d = _first_blocked(path)
        if d is None:
            add(cid, False, "WARN", None, "Lista de %s lipsește sau e goală" % label); continue
        st, _ = _dig(d)
        add(cid, st == "NXDOMAIN", "WARN", st, "Un domeniu din lista de %s e blocat efectiv" % label)
        age = _age_h(path)
        add(cid + "_age", age is not None and age < 24 * 8, "WARN", age, "Lista de %s e actualizată (vechime în ore)" % label)
    # 4. Ieșirea spre Internet: rutare + NAT + conectivitate
    try: fwd = open("/proc/sys/net/ipv4/ip_forward").read().strip()
    except OSError: fwd = "?"
    add("forward", fwd == "1", "CRIT", fwd, "Rutarea între tunel și Internet e pornită")
    nat = any("masquerade" in o.lower() for o in (_run(["nft", "list", "ruleset"])[1], _run(["iptables", "-t", "nat", "-S"])[1]))
    add("nat", nat, "CRIT", nat, "Regula NAT (masquerade) pentru clienți există")
    lat = ping_all(["1.1.1.1", "8.8.8.8"])
    worst = min(v["loss"] for v in lat.values())
    add("internet", worst < 100, "CRIT", worst, "Nodul ajunge în Internet (pierdere minimă de pachete, %)")
    # 5. Resurse — încărcare SUSȚINUTĂ, nu o citire de o clipă
    l1, l5, l15 = os.getloadavg(); cores = os.cpu_count() or 1
    add("load", l5 / cores < 1.5, "CRIT" if l15 / cores >= 2 else "WARN", round(l5 / cores, 2), "Încărcare pe 5 minute per nucleu")
    mem = {}
    for line in open("/proc/meminfo"):
        k, v = line.split(":", 1); mem[k] = int(v.split()[0])
    mp = round(100 * (1 - mem.get("MemAvailable", 0) / max(1, mem["MemTotal"])), 1)
    add("mem", mp < 90, "WARN", mp, "Memorie ocupată (%)")
    stv = os.statvfs("/"); dp = round(100 * (1 - stv.f_bavail / max(1, stv.f_blocks)), 1)
    add("disk", dp < 90, "CRIT" if dp >= 97 else "WARN", dp, "Disc ocupat (%)")
    try:
        cc = int(open("/proc/sys/net/netfilter/nf_conntrack_count").read()); cm = int(open("/proc/sys/net/netfilter/nf_conntrack_max").read())
        cp = round(100 * cc / max(1, cm), 1)
        add("conntrack", cp < 80, "CRIT" if cp >= 95 else "WARN", cp, "Tabela de conexiuni NAT ocupată (%)")
    except (OSError, ValueError):
        pass
    # 6. Sistem
    rc, out = _run(["systemctl", "--failed", "--no-legend", "--plain"])
    failed = [l.split()[0] for l in out.splitlines() if l.strip()]
    add("units", not failed, "WARN", failed[:5], "Niciun serviciu de sistem căzut")
    rc, out = _run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    add("ntp", out.strip() == "yes", "WARN", out.strip() or None, "Ceasul e sincronizat (NTP)")
    add("reboot", not os.path.exists("/var/run/reboot-required"), "INFO", os.path.exists("/var/run/reboot-required"), "Nu e nevoie de repornire după actualizări")
    bad = [x for x in c if not x["ok"] and x["sev"] != "INFO"]
    worst_sev = "CRIT" if any(x["sev"] == "CRIT" for x in bad) else ("WARN" if bad else "OK")
    return {"v": 1, "host": os.uname().nodename, "ts": int(time.time()), "status": worst_sev,
            "uptime_s": int(float(open("/proc/uptime").read().split()[0])), "checks": c}

class Lock:
    def __enter__(self):
        self.f = open(LOCK_FILE, "w"); fcntl.flock(self.f, fcntl.LOCK_EX); return self
    def __exit__(self, *a):
        fcntl.flock(self.f, fcntl.LOCK_UN); self.f.close()

class H(BaseHTTPRequestHandler):
    def _auth(self):
        return self.headers.get("Authorization", "") == "Bearer " + token()
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}
    def log_message(self, *a):
        pass  # no-logs

    def do_GET(self):
        if not self._auth(): return self._send(401, {"error": "unauthorized"})
        if self.path == "/stat":
            peers = sh("wg", "show", WG_IF, "peers").split()
            rx = int(open(f"/sys/class/net/{WG_IF}/statistics/rx_bytes").read())
            tx = int(open(f"/sys/class/net/{WG_IF}/statistics/tx_bytes").read())
            l1 = os.getloadavg()[0]
            return self._send(200, {
                "peers": len(peers), "rx_bytes": rx, "tx_bytes": tx,
                "load1": round(l1, 2), "cores": os.cpu_count(),
                "pubkey": server_pubkey(), "endpoint": f"{public_ip()}:{WG_PORT}",
            })
        if self.path == "/usage":
            # Consum per-peer (pt plafonarea free). Aditiv, read-only, no-logs.
            return self._send(200, {"transfer": peer_transfer()})
        if self.path == "/health":
            # Health Check funcțional al nodului (portalul vpn.cyber3.ai). Aditiv, read-only.
            try: return self._send(200, health())
            except Exception as e: return self._send(500, {"error": "health: " + str(e)[:200]})
        if self.path.startswith("/metrics"):
            # Pentru portalul operațional vpn.cyber3.ai. Aditiv, read-only. ?targets=ip1,ip2 = latență spre alte noduri.
            q = self.path.split("?", 1)[1] if "?" in self.path else ""
            targets, nolat = [], False
            for part in q.split("&"):
                if part.startswith("targets="):
                    targets = [t for t in part[8:].split(",") if t]
                if part == "nolat=1":
                    nolat = True  # mod rapid pentru graficele în timp real (fără ping-uri)
            return self._send(200, metrics(targets, nolat))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth(): return self._send(401, {"error": "unauthorized"})
        if self.path == "/peer":
            try: pub = self._body().get("pubkey", "").strip()
            except Exception: return self._send(400, {"error": "bad json"})
            if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", pub):
                return self._send(400, {"error": "bad pubkey"})
            with Lock():
                ip = peer_ip(pub) if peer_exists(pub) else None
                if ip is None:
                    ip = alloc_ip()
                    sh("wg", "set", WG_IF, "peer", pub, "allowed-ips", f"{ip}/32")
                    # RAM-only: NU salvam pe disc (wg-quick save) — peer-ul traieste doar in kernel,
                    # re-adaugat de control-plane la /connect; sters la reboot (zero date de user pe disc).
            return self._send(200, {
                "client_ip": f"{ip}/32", "server_pubkey": server_pubkey(),
                "endpoint": f"{public_ip()}:{WG_PORT}", "dns": DNS,
            })
        return self._send(404, {"error": "not found"})

    def do_DELETE(self):
        if not self._auth(): return self._send(401, {"error": "unauthorized"})
        if self.path == "/peer":
            try: pub = self._body().get("pubkey", "").strip()
            except Exception: return self._send(400, {"error": "bad json"})
            with Lock():
                if peer_exists(pub):
                    sh("wg", "set", WG_IF, "peer", pub, "remove")
                    # RAM-only: fara wg-quick save (vezi POST /peer).
            return self._send(200, {"removed": pub})
        return self._send(404, {"error": "not found"})

if __name__ == "__main__":
    ThreadingHTTPServer(LISTEN, H).serve_forever()
