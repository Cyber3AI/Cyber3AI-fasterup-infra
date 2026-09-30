#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CYBER3 Scan — descoperirea rețelei clientului de pe senzorul inline (br0). Stdlib, ca root.

PASIV (implicit): ascultă traficul → VLAN-uri, subrețele, hosturi (IP+MAC+producător+rol),
hostname-uri (DHCP/DNS/mDNS), servicii (port server pe SYN). Zero pachete trimise, zero input.

ACTIV (--active): injectează ARP-uri brute TAG-UITE per VLAN pe br0 → fiecare host viu răspunde
(tagged) → MAC REAL pe fiecare host din fiecare VLAN (inclusiv subrețele rutate) + hosturi tăcute.
Non-distructiv (doar ARP), rată controlată (--level bland|mediu|agresiv).

  sudo python3 c3scan.py --iface br0 --duration 45                      # doar pasiv
  sudo python3 c3scan.py --iface br0 --active --level mediu --out ...   # pasiv + sweep activ

CHANGELOG:
  2026-06-29 (icisoc106 / Apa Canal Pitești) — senzor inline pe UPLINK RUTAT L3 (fără tag-uri
    802.1Q, fără adiacență L2 la gazde; ruta default → firewall perimetral care BLOCHEAZĂ scanul).
    Adăugat, ADITIV (căile tagged & native-mgmt rămân neschimbate):
    1) detect_internal_gateway(): găsește routerul intern REAL (vecinul de pe subreteaua mgmt al
       cărui MAC e dominant printre gazdele rutate) → rutează țintele prin el, NU prin ruta default.
    2) connect_scan_adaptive(): connect-scan cu rate-limit + SANTINELĂ — dacă o gazdă sigur-deschisă
       devine 'filtered' (apărare adaptivă tip Bitdefender a blocat sursa), încetinește și așteaptă
       deblocarea (evită fals-negativele). Folosit automat de portscan_native.
"""
import argparse, ipaddress, json, os, re, socket, struct, subprocess, sys, threading, time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

PACKET_AUXDATA = 8
SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
TP_STATUS_VLAN_VALID = 1 << 4
PPS = {"bland": 60, "mediu": 250, "agresiv": 900}

def load_oui():
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(here, "oui.txt"), "/opt/cyber3/c3scan/oui.txt"):
        try:
            d = {}
            for ln in open(p, encoding="utf-8", errors="ignore"):
                k, _, v = ln.partition("\t")
                if k.strip(): d[k.strip()] = v.strip()
            if d: return d
        except Exception:
            pass
    return {}
OUI = load_oui()

ROLE_RULES = [
    (("hewlett", "canon", "kyocera", "brother", "epson", "lexmark", "xerox", "ricoh", "oki", "zebra"), "🖨️ imprimantă"),
    (("hikvision", "dahua", "axis", "hanwha", "uniview", "mobotix", "vivotek"), "📷 cameră IP"),
    (("mikrotik", "ubiquiti", "cisco", "tp-link", "tplink", "aruba", "fortinet", "juniper", "netgear", "zyxel", "ruckus", "extreme"), "🌐 echipament rețea"),
    (("synology", "qnap", "western", "segate", "seagate", "buffalo"), "💾 NAS/storage"),
    (("apple",), "🍎 Apple"),
    (("samsung", "xiaomi", "oppo", "vivo", "oneplus", "realme", "motorola"), "📱 telefon/mobil"),
    (("espressif", "tuya", "sonoff", "shelly", "raspberry", "particle"), "🔌 IoT/embedded"),
    (("vmware", "qemu", "virtualbox", "hyper-v", "docker", "parallels", "xensource"), "🖥️ VM/container"),
    (("dell", "lenovo", "gigabyte", "asustek", "asus", "micro-star", "intel", "realtek", "inventec",
      "wistron", "compal", "quanta", "pegatron", "hon hai", "foxconn", "liteon", "azurewave"), "🖥️ PC/laptop"),
]
def role_from_vendor(v):
    if not v: return None
    vl = v.lower()
    for subs, role in ROLE_RULES:
        if any(x in vl for x in subs): return role
    return None

ROLE_BY_PORT = {445: "🪟 Windows (SMB)", 3389: "🪟 Windows (RDP)", 139: "🪟 Windows",
                22: "🐧 Linux/SSH", 9100: "🖨️ imprimantă (RAW)", 631: "🖨️ imprimantă (IPP)",
                554: "📷 cameră (RTSP)", 1883: "🔌 IoT (MQTT)", 53: "🧭 DNS server",
                3306: "🗄️ MySQL", 5432: "🗄️ PostgreSQL", 1433: "🗄️ MSSQL", 6379: "🗄️ Redis",
                502: "🏭 OT (Modbus)", 47808: "🏭 OT (BACnet)", 102: "🏭 OT (Siemens S7)"}
SVC_PORTS = set(list(ROLE_BY_PORT) + [80, 443, 8080, 8443, 21, 23, 25, 110, 143, 161, 389, 636,
                873, 2049, 5900, 5985, 8000, 8888, 9200, 27017, 1521, 8006])

def fmt_mac(b): return ":".join("%02x" % x for x in b)
def fmt_ip(b): return ".".join(str(x) for x in b)
def mac_bytes(s): return bytes(int(x, 16) for x in s.split(":"))
def is_priv(ip):
    try: a, b = int(ip.split(".")[0]), int(ip.split(".")[1])
    except Exception: return False
    return a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)
def vendor_of(mac): return OUI.get(mac.replace(":", "")[:6].lower()) if mac else None

class Net:
    def __init__(self):
        self.hosts = {}; self.peers = defaultdict(set)
    def host(self, ip):
        h = self.hosts.get(ip)
        if not h:
            h = {"ip": ip, "mac": None, "mac_real": False, "vendor": None, "vlans": set(),
                 "home_vlan": None, "hostname": None, "services": set(), "talks_external": 0, "pkts": 0, "role": None}
            self.hosts[ip] = h
        return h

def parse_dhcp(p, net):
    if len(p) < 240 or p[236:240] != b"\x63\x82\x53\x63": return
    cmac = fmt_mac(p[28:34]); ciaddr = fmt_ip(p[12:16]); yiaddr = fmt_ip(p[16:20])
    hostname = None; reqip = None; i = 240
    while i < len(p) - 1:
        t = p[i]
        if t == 255: break
        if t == 0: i += 1; continue
        ln = p[i + 1]; val = p[i + 2:i + 2 + ln]
        if t == 12: hostname = val.decode("utf-8", "ignore")
        elif t == 50 and ln == 4: reqip = fmt_ip(val)
        i += 2 + ln
    ip = next((x for x in (yiaddr, reqip, ciaddr) if x and x != "0.0.0.0" and is_priv(x)), None)
    if ip:
        h = net.host(ip)
        if not h["mac_real"]: h["mac"] = cmac
        if hostname: h["hostname"] = h["hostname"] or hostname

def parse_dns_names(p):
    names = []
    if len(p) < 12: return names
    try:
        qd = struct.unpack("!H", p[4:6])[0]; i = 12
        for _ in range(min(qd, 4)):
            labels = []
            while i < len(p):
                ln = p[i]
                if ln == 0: i += 1; break
                if ln & 0xc0: i += 2; break
                labels.append(p[i + 1:i + 1 + ln].decode("utf-8", "ignore")); i += 1 + ln
            if labels: names.append(".".join(labels))
            i += 4
    except Exception:
        pass
    return names

def handle(frame, net, vlan_aux=None):
    if len(frame) < 14: return
    src = frame[6:12]; eth = struct.unpack("!H", frame[12:14])[0]; off = 14; vlan = vlan_aux
    if eth == 0x8100:
        if len(frame) < 18: return
        vlan = struct.unpack("!H", frame[14:16])[0] & 0x0fff
        eth = struct.unpack("!H", frame[16:18])[0]; off = 18
    smac = fmt_mac(src)
    if eth == 0x0806:  # ARP — sender (sip/smac) e host REAL din acel VLAN (inclusiv răspunsuri la sweep)
        a = frame[off:]
        if len(a) >= 28:
            sha = fmt_mac(a[8:14]); spa = fmt_ip(a[14:18])
            if is_priv(spa):
                h = net.host(spa); h["mac"] = sha; h["mac_real"] = True
                h["home_vlan"] = vlan
                if vlan is not None: h["vlans"].add(vlan)
        return
    if eth != 0x0800: return
    ih = frame[off:]
    if len(ih) < 20: return
    ihl = (ih[0] & 0x0f) * 4; proto = ih[9]
    sip = fmt_ip(ih[12:16]); dip = fmt_ip(ih[16:20])
    if is_priv(sip):
        h = net.host(sip)
        if not h["mac_real"]: h["mac"] = h["mac"] or smac
        h["pkts"] += 1
        if vlan is not None: h["vlans"].add(vlan)
        if not is_priv(dip): h["talks_external"] += 1
    if is_priv(dip) and vlan is not None: net.host(dip)["vlans"].add(vlan)
    if is_priv(sip) and is_priv(dip): net.peers[sip].add(dip); net.peers[dip].add(sip)
    if proto not in (6, 17): return
    l4 = ih[ihl:]
    if len(l4) < 4: return
    sport, dport = struct.unpack("!HH", l4[0:4])
    if proto == 6:
        if len(l4) >= 14:
            flags = l4[13]
            if (flags & 0x02) and not (flags & 0x10) and is_priv(dip):
                net.host(dip)["services"].add(dport)
            if (flags & 0x12) == 0x12 and is_priv(sip):   # SYN-ACK => sip are sport DESCHIS (răspuns la portscan)
                net.host(sip)["services"].add(sport)
        for ip, port in ((dip, dport), (sip, sport)):
            if is_priv(ip) and port in SVC_PORTS: net.host(ip)["services"].add(port)
    else:
        for ip, port in ((dip, dport), (sip, sport)):
            if is_priv(ip) and port in SVC_PORTS: net.host(ip)["services"].add(port)
        payload = l4[8:]
        if dport in (67, 68) or sport in (67, 68): parse_dhcp(payload, net)
        elif dport in (53, 5353) or sport in (53, 5353):
            for nm in parse_dns_names(payload):
                if nm.endswith(".local") and is_priv(sip):
                    h = net.host(sip); h["hostname"] = h["hostname"] or nm.rsplit(".local", 1)[0]

# ---- DESCOPERIRE ACTIVĂ: ARP brut tag-uit ----
def build_arp(vlan, src_mac, tpa):
    arp = (b"\x00\x01\x08\x00\x06\x04\x00\x01" + src_mac + b"\x00\x00\x00\x00"
           + b"\x00" * 6 + bytes(int(x) for x in tpa.split(".")))
    if vlan is None:
        return b"\xff" * 6 + src_mac + b"\x08\x06" + arp
    return b"\xff" * 6 + src_mac + b"\x81\x00" + struct.pack("!H", vlan & 0x0fff) + b"\x08\x06" + arp

def count_real(net, pref, vlan):
    return sum(1 for ip, h in net.hosts.items()
               if ip.startswith(pref + ".") and h["mac_real"] and h.get("home_vlan") == vlan)

PROBE = [1, 254, 2, 10, 100, 50, 200, 150, 20, 5]
def smart_sweep(iface, net, prefs, vlans, src_mac, pps, stop):
    # Faza 1: probă TOATE (subnet×vlan) deodată; pauză; Faza 2: full DOAR pe VLAN-ul care a răspuns (acasă)
    try:
        ss = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); ss.bind((iface, 0))
    except Exception:
        return
    delay = 1.0 / max(1, pps)
    def snd(vlan, ip):
        try: ss.send(build_arp(vlan, src_mac, ip))
        except Exception: pass
        time.sleep(delay)
    for pref in prefs:
        for v in vlans:
            for i in PROBE:
                if stop.is_set(): return
                snd(v, f"{pref}.{i}")
    time.sleep(2.0)
    for pref in prefs:
        for v in [x for x in vlans if count_real(net, pref, x) > 0]:
            for i in range(1, 255):
                if stop.is_set(): return
                snd(v, f"{pref}.{i}")
    ss.close()

def recv_one(s):
    try:
        data, anc, _, _ = s.recvmsg(65535, socket.CMSG_SPACE(64))
    except socket.timeout:
        return None, None
    except Exception:
        return b"", None
    vlan = None
    for lvl, typ, cdata in anc:
        if lvl == SOL_PACKET and typ == PACKET_AUXDATA and len(cdata) >= 18:
            try:
                status = struct.unpack_from("I", cdata, 0)[0]; tci = struct.unpack_from("H", cdata, 16)[0]
                if (status & TP_STATUS_VLAN_VALID) or tci: vlan = tci & 0x0fff
            except Exception: pass
    return data, vlan

def capture(s, net):
    data, vlan = recv_one(s)
    if data is None: return False
    if data:
        try: handle(data, net, vlan)
        except Exception: pass
    return True

# ---- PORTSCAN ACTIV (connect-scan, fiabil chiar prin SYN-proxy/firewall) ----
# SYN-scan brut e NESIGUR prin gateway-uri cu SYN-proxy (UniFi/firewall → toate porturile par deschise).
# Soluție: interfață VLAN temporară pe br0 + IP liber + connect() din kernel (proxy-ul dă RST la ACK-ul
# real → porturile false dispar). Curățare subif în finally.
PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554, 993, 995,
         1433, 3306, 3389, 8080, 8443, 9100, 161, 8006, 502, 102]
SCAN_WORKERS = {"bland": 40, "mediu": 120, "agresiv": 300}

def _ipcmd(args):
    try: subprocess.run(["ip"] + args.split(), capture_output=True, timeout=8)
    except Exception: pass

def pick_free(net, pref):
    used = {int(x.split(".")[3]) for x in net.hosts if x.startswith(pref + ".")}
    return f"{pref}." + str(next((i for i in range(250, 200, -1) if i not in used), 251))

# ---- SUPORT LINK NETAGUIT (native VLAN): scanare din interfața de management, FĂRĂ atingerea bridge-ului ----
_EGRESS_CACHE = {}

def detect_mgmt_src(iface):
    """Sursă L3 pt scanare pe link NETAGUIT: un IP RFC1918 pe o interfață care NU e bridge-ul,
    nu lo, nu wg*, nu o sub-interfață VLAN. Dacă senzorul NU e inline (bridge-ul poartă chiar IP-ul
    de management — ex. icisoc107 pe port de router), cade înapoi pe IP-ul bridge-ului.
    Întoarce (src_ip, mgmt_iface) sau (None, None)."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, timeout=8).stdout.decode("latin1", "ignore")
    except Exception:
        return None, None
    bridge_fallback = None
    for ln in out.splitlines():
        p = ln.split()
        if len(p) < 4:
            continue
        dev = p[1]
        if dev == "lo" or dev.startswith("wg") or "." in dev:
            continue
        ip = p[3].split("/")[0]
        if not is_priv(ip):
            continue
        if dev == iface:
            if bridge_fallback is None:      # senzor NON-inline: bridge-ul are IP-ul de management
                bridge_fallback = (ip, dev)
            continue
        return ip, dev
    return bridge_fallback or (None, None)

def route_egress(ip):
    """Interfața prin care iese efectiv traficul către ip (ip route get), cache per /24."""
    pref = ".".join(ip.split(".")[:3])
    if pref in _EGRESS_CACHE:
        return _EGRESS_CACHE[pref]
    dev = None
    try:
        out = subprocess.run(["ip", "route", "get", ip], capture_output=True, timeout=4).stdout.decode("latin1", "ignore")
        # FIX icisoc107 (27 aug 2026): adresa PROPRIE a senzorului (ex. IP-ul br0 pe senzor non-inline) da
        # "local ... dev lo" -> NU reprezinta /24-ul si NU se cache-uieste (altfel tot /24-ul devenea "lo" -> 0 gazde scanate).
        if out.startswith("local") or re.search(r"\bdev\s+lo\b", out):
            return "lo"
        m = re.search(r"\bdev\s+(\S+)", out)
        if m:
            dev = m.group(1)
    except Exception:
        return None                    # eroare tranzitorie: nu otravi cache-ul
    _EGRESS_CACHE[pref] = dev
    return dev

# Interval între connect-uri pe calea ADAPTIVĂ (uplink rutat L3 / apărare adaptivă). conn/s ≈ 1/interval.
SLOW_INTERVAL = {"bland": 0.18, "mediu": 0.06, "agresiv": 0.015}

def detect_internal_gateway(net, mgmt_src):
    """Pe link rutat L3: routerul intern REAL = vecinul de pe subreteaua mgmt al cărui MAC e dominant
    printre gazdele RUTATE (alt subnet, MAC = gateway). Întoarce IP-ul routerului intern sau None.
    Datorită lui ocolim ruta default (care poate merge spre un firewall perimetral ce blochează)."""
    from collections import Counter
    mgmt_pref = ".".join(mgmt_src.split(".")[:3])
    macs = Counter(); local_by_mac = {}
    for ip, h in net.hosts.items():
        mac = h.get("mac")
        if not mac:
            continue
        pref = ".".join(ip.split(".")[:3])
        if pref == mgmt_pref:
            if h.get("mac_real") and ip != mgmt_src:
                local_by_mac[mac] = ip
        else:
            macs[mac] += 1
    if not macs:
        return None
    gw_mac, n = macs.most_common(1)[0]
    gw_ip = local_by_mac.get(gw_mac)
    # gateway intern valid doar dacă MAC-ul lui chiar rutează multe gazde (≥3) și e pe subreteaua mgmt
    return gw_ip if (gw_ip and n >= 3) else None

def _conn_once(ip, port, src, to=1.0):
    so = socket.socket()
    try:
        so.bind((src, 0)); so.settimeout(to)
        ok = (so.connect_ex((ip, port)) == 0); so.close(); return ok
    except Exception:
        try: so.close()
        except Exception: pass
        return False

def connect_scan_adaptive(ips, ports, src_ip, level, stop=None):
    """connect-scan secvenţial cu rate-limit + SANTINELĂ. Prima gazdă găsită deschisă devine santinelă;
    dacă santinela devine 'filtered' (apărarea adaptivă a blocat sursa), pauză 180s până la deblocare —
    previne fals-negativele. Folosit pe calea rutată/nativă (sensibilă la Bitdefender). Întoarce {ip:{ports}}."""
    opened = defaultdict(set); interval = SLOW_INTERVAL.get(level, 0.18)
    canary = None; last = [0.0]; n = 0; blocks = 0
    def pace():
        w = last[0] + interval - time.time()
        if w > 0: time.sleep(w)
        last[0] = time.time()
    for ip in ips:
        for p in ports:
            if stop is not None and stop.is_set(): return opened
            pace()
            if _conn_once(ip, p, src_ip):
                opened[ip].add(p)
                if canary is None: canary = (ip, p)
            n += 1
            if canary and n % 60 == 0 and not _conn_once(canary[0], canary[1], src_ip, to=1.6):
                blocks += 1
                print(f"[c3scan] apărare adaptivă: sursă blocată — pauză 180s (#{blocks})", flush=True)
                time.sleep(180)
    if blocks:
        print(f"[c3scan] adaptiv: {blocks} reblocări tratate (low-and-slow)", flush=True)
    return opened

def portscan_native(net, iface, level, ips=None):
    """Port-scan pe link NETAGUIT / UPLINK RUTAT L3: connect() din interfața de MANAGEMENT.
    Dacă gazdele țintă sunt RUTATE (în spatele unui router intern), rutează prin routerul intern REAL
    descoperit (nu prin ruta default → firewall perimetral). Connect-scan ADAPTIV (santinelă). Zero atingere bridge."""
    src, mgmt = detect_mgmt_src(iface)
    if not src:
        print("[c3scan] portscan NATIV: niciun IP de management — sar portscan"); return False
    cand = [ip for ip in (ips if ips is not None else [ip for ip in net.hosts if is_priv(ip)]) if ip != src]   # fara IP-ul propriu
    # GATEWAY INTERN ÎNVĂȚAT (icisoc108, 27 aug 2026): dacă există /etc/cyber3/scan-gateway (IP), se folosește EL, nu
    # euristica (care a ales un proxy transparent .18 în loc de routerul real .181 → mii de porturi false). Se persistă
    # gateway-ul folosit în /etc/cyber3/scan-gateway.last pentru scanul următor ("învață din scanul precedent").
    gw_forced = None
    try:
        gw_forced = open("/etc/cyber3/scan-gateway").read().split("#")[0].strip() or None
    except Exception:
        pass
    gw = gw_forced or detect_internal_gateway(net, src)
    if gw_forced:
        print(f"[c3scan] gateway intern din fișierul învățat /etc/cyber3/scan-gateway: {gw}")
    if gw:
        try:
            open("/etc/cyber3/scan-gateway.last", "w").write(f"{gw} # folosit {time.strftime('%Y-%m-%d %H:%M')} ({'fișier' if gw_forced else 'euristic'})\n")
        except Exception:
            pass
    added = []
    # FIX bug untagged+rutat: PARALEL by default (rapid), adaptiv-secvenţial DOAR opt-in pt rețele cu apărare
    # adaptivă (Bitdefender/pf) marcate cu /etc/cyber3/scan-adaptive. Altfel un /23 rula ~1h secvențial (bugul icisoc101).
    adaptive = os.path.exists("/etc/cyber3/scan-adaptive")
    mode = "ADAPTIV low-and-slow (Bitdefender)" if adaptive else "PARALEL rapid"
    try:
        if gw:
            # rutează explicit fiecare /24 țintă prin routerul intern (ocolește ruta default/firewall)
            subs = sorted({".".join(ip.split(".")[:3]) for ip in cand if ".".join(ip.split(".")[:3]) != ".".join(src.split(".")[:3])})
            for s in subs:
                _ipcmd(f"route add {s}.0/24 via {gw} dev {mgmt}"); added.append(s)
            sel = cand
            print(f"[c3scan] PORTSCAN RUTAT prin gateway intern {gw} (dev {mgmt}, src {src}): "
                  f"{len(sel)} gazde × {len(PORTS)} porturi, {len(added)} subrețele, nivel {level} ({mode})")
        else:
            sel = [ip for ip in cand if route_egress(ip) == mgmt]
            if not sel:
                print(f"[c3scan] portscan NATIV: nicio gazdă rutată prin {mgmt} ({src})"); return False
            print(f"[c3scan] PORTSCAN NATIV (link netaguit) din {mgmt} {src}: {len(sel)} gazde × {len(PORTS)} porturi, nivel {level} ({mode})")
        scanned = connect_scan_adaptive(sel, PORTS, src, level) if adaptive else connect_scan(sel, PORTS, src, SCAN_WORKERS[level])
        scanned = strip_proxy_artifacts(scanned, net)
        for ip, ports in scanned.items():
            net.host(ip)["services"].update(ports)
    finally:
        for s in added:
            _ipcmd(f"route del {s}.0/24 via {gw} dev {mgmt}")
    return True

PROXY_ARTIFACTS = []   # [{"subnet":..., "ports":[...], "hosts_affected":n}] — porturi răspunse de un proxy/firewall transparent pentru ORICE IP

def strip_proxy_artifacts(scanned, net):
    """GARDĂ ANTI-PROXY (icisoc108, 27 aug 2026): un proxy/firewall transparent (ex. 192.168.1.18) completează
    handshake-ul TCP pentru ORICE IP pe anumite porturi (21/80/110/143/993/995) → clase întregi apar „cu servicii".
    Semnătură: același set de porturi pe ≥200 IP-uri (sau ≥90% din cele scanate) dintr-un /24. Porturile din set se
    ELIMINĂ din toate gazdele acelui /24 (nu putem ști dacă vreo gazdă le are real) și se raportează ONEST ca
    „ne-evaluabile prin proxy" în discovery.json (summary.proxy_artifacts)."""
    from collections import Counter, defaultdict as _dd
    by24 = _dd(dict)
    for ip, ports in scanned.items():
        if ports:
            by24[".".join(ip.split(".")[:3])][ip] = frozenset(ports)
    for pref, hosts in by24.items():
        if len(hosts) < 30:
            continue
        cnt = Counter(hosts.values())
        for pset, n in cnt.most_common(3):
            if n >= 200 or n >= 0.9 * len(hosts) and n >= 30:
                bad = set(pset)
                affected = 0
                for ip in list(hosts):
                    before = scanned[ip]
                    scanned[ip] = set(before) - bad
                    if before != scanned[ip]:
                        affected += 1
                PROXY_ARTIFACTS.append({"subnet": pref + ".0/24", "ports": sorted(bad), "hosts_affected": affected})
                print(f"[c3scan] ⚠ ARTEFACT PROXY în {pref}.0/24: porturile {sorted(bad)} răspund identic pe {n} IP-uri "
                      f"(handshake completat de un proxy/firewall transparent) → eliminate de la {affected} gazde; "
                      f"ne-evaluabile pe această cale. Setează gateway-ul real în /etc/cyber3/scan-gateway.")
    # GLOBAL (icisoc108, a 2-a rulare): semnătura proxy apare și în clase incomplete/IP-uri răzlețe → porturile-semnătură
    # se elimină de la TOATE gazdele FĂRĂ MAC real (posibil inexistente); gazdele cu MAC real le păstrează (răspund ele).
    if PROXY_ARTIFACTS:
        sig = set().union(*[set(a["ports"]) for a in PROXY_ARTIFACTS])
        n = 0
        for ip, ports in list(scanned.items()):
            h = net.hosts.get(ip) if net is not None else None
            if (set(ports) & sig) and not (h and h.get("mac_real")):
                scanned[ip] = set(ports) - sig; n += 1
        if n:
            PROXY_ARTIFACTS.append({"subnet": "GLOBAL", "ports": sorted(sig), "hosts_affected": n})
            print(f"[c3scan] ⚠ ARTEFACT PROXY global: porturile {sorted(sig)} eliminate de la {n} gazde fără MAC real (posibil inexistente)")
    return scanned

def connect_scan(ips, ports, src_ip, workers):
    opened = defaultdict(set); lock = threading.Lock()
    def probe(t):
        ip, port = t
        try:
            so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            so.bind((src_ip, 0)); so.settimeout(1.0)
            if so.connect_ex((ip, port)) == 0:
                with lock: opened[ip].add(port)
            so.close()
        except Exception: pass
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(probe, [(ip, p) for ip in ips for p in ports]))
    return opened

def portscan(net, iface, level):
    groups = defaultdict(list)
    for ip, h in net.hosts.items():
        if h["mac_real"] and h.get("home_vlan") is not None:
            groups[(h["home_vlan"], ".".join(ip.split(".")[:3]))].append(ip)
    if not groups:
        # Link NETAGUIT (native VLAN): niciun tag 802.1Q învățat → scanare din interfața de management.
        if portscan_native(net, iface, level):
            return
        print("[c3scan] portscan: niciun host L2 cu VLAN cunoscut"); return
    total = sum(len(v) for v in groups.values())
    print(f"[c3scan] PORTSCAN connect (fiabil prin SYN-proxy): {total} hosturi × {len(PORTS)} porturi, "
          f"{len(groups)} (VLAN,subrețea), nivel {level}")
    workers = SCAN_WORKERS[level]
    for (vlan, pref), ips in sorted(groups.items()):
        free = pick_free(net, pref); subif = f"{iface}.{vlan}"
        _ipcmd(f"link del {subif}")
        _ipcmd(f"link add link {iface} name {subif} type vlan id {vlan}")
        _ipcmd(f"addr add {free}/24 dev {subif}")
        _ipcmd(f"link set {subif} up")
        time.sleep(0.3)
        try:
            for ip, ports in connect_scan(ips, PORTS, free, workers).items():
                net.host(ip)["services"].update(ports)
        finally:
            _ipcmd(f"link del {subif}")
    # FIX icisoc109 (27 aug 2026): pe trunk cu VLAN NATIV, gazdele care au raspuns la ARP FARA tag (home_vlan=None)
    # sau cele vazute doar pasiv/rutate nu intrau in niciun grup taguit -> NU erau port-scanate deloc (275 MAC reale,
    # doar 32 scanate). Restul se scaneaza NATIV din interfata de management (rutat prin gateway-ul intern invatat).
    grouped = {ip for ips in groups.values() for ip in ips}
    rest = [ip for ip, h in net.hosts.items() if is_priv(ip) and ip not in grouped]
    if rest:
        print(f"[c3scan] gazde in VLAN nativ / fara VLAN-acasa / rutate: {len(rest)} -> port-scan NATIV din management")
        portscan_native(net, iface, level, ips=rest)

def parse_targets(raw, cap=8192):   # cap 1024→4096→8192 (27 aug 2026): 20×/24 = 5080 gazde (icisoc101) intra intreg; la 4096 se taiau ultimele subretele
    # ADD TARGET: IP-uri/subrețele explicite (RFC1918). Subrețelele se extind în hosturi (cap).
    ips = []
    for t in re.split(r"[,\s]+", raw or ""):
        t = t.strip()
        if not t:
            continue
        try:
            n = ipaddress.ip_network(t, strict=False)
        except ValueError:
            continue
        if not n.is_private:
            continue
        if n.num_addresses == 1:
            ips.append(str(n.network_address))
        else:
            for h in n.hosts():
                ips.append(str(h))
                if len(ips) >= cap:
                    break
        if len(ips) >= cap:
            break
    # dedup păstrând ordinea
    seen = set(); out = []
    for ip in ips:
        if ip not in seen and is_priv(ip):
            seen.add(ip); out.append(ip)
    return out[:cap]

def portscan_targets(net, iface, level, targets):
    # Scanează IP-uri EXPLICITE. Subif VLAN cu IP în subrețeaua țintei; ținta răspunde DOAR în VLAN-ul
    # ei real (connect din kernel) → zero FP. VLAN cunoscut din descoperire (rapid) altfel toate VLAN-urile.
    bysub = defaultdict(list)
    for ip in targets:
        bysub[".".join(ip.split(".")[:3])].append(ip)
    known = {}
    for h in net.hosts.values():
        if h.get("home_vlan") is not None:
            known.setdefault(".".join(h["ip"].split(".")[:3]), h["home_vlan"])
    all_vlans = sorted({v for v in known.values()}) or \
                sorted({v for h in net.hosts.values() for v in h["vlans"] if v})
    workers = SCAN_WORKERS[level]
    if not all_vlans:
        # Link NETAGUIT: scanează țintele explicite din interfața de management (fără sub-interfață VLAN).
        for ip in targets:
            net.host(ip)["explicit"] = True
        if portscan_native(net, iface, level, ips=targets):
            return
        print("[c3scan] ȚINTE: niciun VLAN și nicio interfață de management — doar listate"); return
    print(f"[c3scan] PORTSCAN ȚINTE explicite: {len(targets)} IP în {len(bysub)} subrețele "
          f"(VLAN-uri candidate: {all_vlans or '—'})")
    for pref, ips in sorted(bysub.items()):
        for ip in ips:
            net.host(ip)["explicit"] = True
        vlans = [known[pref]] if pref in known else all_vlans
        if not vlans:
            print(f"[c3scan]   {pref}.0/24: niciun VLAN candidat (off-trunk?) — doar listat"); continue
        for vlan in vlans:
            free = pick_free(net, pref); subif = f"{iface}.{vlan}"
            _ipcmd(f"link del {subif}")
            _ipcmd(f"link add link {iface} name {subif} type vlan id {vlan}")
            _ipcmd(f"addr add {free}/24 dev {subif}")
            _ipcmd(f"link set {subif} up"); time.sleep(0.3)
            try:
                for ip, ports in connect_scan(ips, PORTS, free, workers).items():
                    if ports:
                        net.host(ip)["services"].update(ports)
                        net.host(ip)["home_vlan"] = vlan
            finally:
                _ipcmd(f"link del {subif}")

def finalize(net):
    for h in net.hosts.values():
        h["vendor"] = vendor_of(h["mac"])
        h["role"] = None
        for port, role in ROLE_BY_PORT.items():
            if port in h["services"]: h["role"] = role; break
        if not h["role"]: h["role"] = role_from_vendor(h["vendor"])
    gw = {}
    for ip, peers in net.peers.items():
        h = net.hosts.get(ip)
        if not h: continue
        score = len(peers) + h["talks_external"]
        for v in (h["vlans"] or {None}):
            if v not in gw or score > gw[v][1]: gw[v] = (ip, score)
    for v, (ip, _) in gw.items():
        if net.hosts[ip]["role"] in (None, "🌐 echipament rețea"):
            net.hosts[ip]["role"] = "🚪 probabil GATEWAY"

def subnet(ip): return ".".join(ip.split(".")[:3]) + ".0/24"

def report(net, dur, frames, active):
    hosts = [h for h in net.hosts.values() if is_priv(h["ip"])]
    out = {"tool": "CYBER3 Scan", "phase": "active+passive" if active else "passive",
           "duration_s": dur, "frames": frames,
           "summary": {"hosts": len(hosts), "vlans": sorted({v for h in hosts for v in h["vlans"]}),
                       "subnets": sorted({subnet(h["ip"]) for h in hosts}),
                       "mac_real": sum(1 for h in hosts if h["mac_real"]),
                       "with_vendor": sum(1 for h in hosts if h["vendor"]),
                       "with_role": sum(1 for h in hosts if h["role"]),
                       "with_hostname": sum(1 for h in hosts if h["hostname"]),
                       "with_services": sum(1 for h in hosts if h["services"]),
                       "proxy_artifacts": PROXY_ARTIFACTS}, "hosts": []}
    for h in sorted(hosts, key=lambda x: tuple(int(p) for p in x["ip"].split("."))):
        out["hosts"].append({"ip": h["ip"], "mac": h["mac"], "mac_real": h["mac_real"], "vendor": h["vendor"],
            "vlan": sorted(h["vlans"]) or None, "hostname": h["hostname"],
            "services": sorted(h["services"]), "role": h["role"], "home_vlan": h.get("home_vlan")})
    return out

def print_summary(out):
    s = out["summary"]
    print("\n" + "=" * 72)
    print("CYBER3 Scan — DESCOPERIRE " + ("ACTIVĂ+PASIVĂ" if out["phase"].startswith("active") else "PASIVĂ"))
    print("=" * 72)
    print(f"Hosturi: {s['hosts']} | VLAN-uri: {s['vlans']} | subrețele: {len(s['subnets'])}")
    print(f"MAC real: {s['mac_real']}/{s['hosts']} · {s['with_vendor']} producători · {s['with_role']} roluri · "
          f"{s['with_hostname']} hostname · {s['with_services']} servicii")
    by_vlan = defaultdict(list)
    for h in out["hosts"]: by_vlan[h.get("home_vlan") if h.get("home_vlan") is not None else (h["vlan"] or [None])[0]].append(h)
    for v in sorted(by_vlan, key=lambda x: (x is None, x)):
        print(f"\n── VLAN {v if v is not None else 'nativ'} ── ({len(by_vlan[v])} hosturi)")
        for h in by_vlan[v][:25]:
            svc = ",".join(str(p) for p in h["services"][:6])
            print(f"  {h['ip']:<15} {(h['mac'] or '?'):<17} {(h['vendor'] or '?')[:13]:<13} "
                  f"{(h['role'] or ''):<19} {(h['hostname'] or '')[:16]:<16} [{svc}]")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="br0")
    ap.add_argument("--duration", type=int, default=40, help="durata fază pasivă (s)")
    ap.add_argument("--active", action="store_true")
    ap.add_argument("--level", choices=list(PPS), default="mediu")
    ap.add_argument("--drain", type=int, default=20, help="ascultare răspunsuri după sweep (s)")
    ap.add_argument("--ports", action="store_true", help="portscan activ TCP SYN după descoperire (necesită --active)")
    ap.add_argument("--targets", default="", help="ADD TARGET: IP-uri/subrețele explicite RFC1918 (virgulă/spațiu)")
    ap.add_argument("--out", default="/var/log/cyber3/discovery.json")
    a = ap.parse_args()
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1); s.bind((a.iface, 0)); s.settimeout(2)
    except PermissionError:
        print("EROARE: rulează ca root."); sys.exit(1)
    except OSError as e:
        print(f"EROARE interfață {a.iface}: {e}"); sys.exit(1)
    net = Net(); frames = 0
    print(f"[c3scan] OUI={len(OUI)} | pasiv pe {a.iface} {a.duration}s ...")
    t0 = time.time()
    while time.time() - t0 < a.duration:
        if capture(s, net): frames += 1
    if a.active:
        try: smac = mac_bytes(open(f"/sys/class/net/{a.iface}/address").read().strip())
        except Exception: smac = b"\x02\xc3\x5c\xa1\x00\x01"
        prefs = sorted({".".join(h["ip"].split(".")[:3]) for h in net.hosts.values() if is_priv(h["ip"])})[:64]
        vlans = sorted({v for h in net.hosts.values() for v in h["vlans"]}) + [None]
        print(f"[c3scan] sweep ACTIV inteligent: {len(prefs)} subrețele × {len(vlans)} VLAN-uri (probă→full), nivel {a.level}")
        stop = threading.Event()
        th = threading.Thread(target=smart_sweep, args=(a.iface, net, prefs, vlans, smac, PPS[a.level], stop)); th.start()
        t1 = time.time()
        while th.is_alive() or time.time() - t1 < a.drain:
            if capture(s, net): frames += 1
            if not th.is_alive() and time.time() - t1 > a.drain: break
        stop.set(); th.join(timeout=2)
        if a.ports:
            portscan(net, a.iface, a.level)
        if a.targets:
            tips = parse_targets(a.targets)
            if tips:
                portscan_targets(net, a.iface, a.level, tips)
            else:
                print("[c3scan] --targets: niciun IP RFC1918 valid")
    finalize(net)
    out = report(net, a.duration, frames, a.active)
    print_summary(out)
    try:
        os.makedirs(os.path.dirname(a.out), exist_ok=True)
        json.dump(out, open(a.out, "w"), indent=2, ensure_ascii=False)
        print(f"\n[c3scan] {frames} cadre → {out['summary']['hosts']} hosturi (MAC real: {out['summary']['mac_real']}) → {a.out}")
    except Exception as e:
        print(f"[c3scan] nu am putut scrie {a.out}: {e}")

if __name__ == "__main__":
    main()
