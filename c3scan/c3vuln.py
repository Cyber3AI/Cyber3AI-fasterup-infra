#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CYBER3 Scan — verificări de vulnerabilități (#3a + #3b). Rulează ca root, pe senzor.

Citește discovery.json (de la c3scan), se conectează la porturile deschise prin interfață VLAN
temporară pe br0 + IP liber (același mecanism fiabil prin SYN-proxy) și rulează verificări
NON-DISTRUCTIVE.

#3a: fingerprint serviciu/versiune (banner + HTTP Server), servicii periculoase expuse, SMBv1
     (EternalBlue), TLS expirat/self-signed, panouri admin/login web expuse.
#3b: CVE pe versiuni din banner îmbogățit cu CISA KEV (exploatat-în-lume), SNMP community „public"
     (UDP 161, info-leak + sysDescr), credențiale DEFAULT pe panouri web (opt-in, NON-fragile).

  sudo python3 c3vuln.py --iface br0 --in /var/log/cyber3/discovery.json --out /var/log/cyber3/findings.json
  ... --snmp            (probă SNMP public — implicit ACTIV)
  ... --creds           (default-creds pe panouri web — OPT-IN, exclude OT/cameră/IoT)
"""
import argparse, collections, json, os, re, socket, ssl, struct, subprocess, time
from base64 import b64encode
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

# port -> (eticheta, severitate, titlu, remediere) — DOAR servicii riscante chiar și intern
EXPOSED = {
    23:   ("TELNET", 7, "Telnet expus — autentificare în CLAR", "Dezactivează Telnet; folosește SSH"),
    21:   ("FTP", 4, "FTP expus — posibil în clar", "Folosește SFTP/FTPS; dezactivează anonymous"),
    5900: ("VNC", 6, "VNC expus", "Parolă tare + tunel VPN; nu expune VNC"),
    6379: ("REDIS", 8, "Redis expus (frecvent FĂRĂ autentificare)", "Activează auth + bind local; firewall"),
    1433: ("MSSQL", 4, "MS SQL Server expus", "Nu expune baza de date; restricționează pe firewall"),
    3306: ("MYSQL", 4, "MySQL expus", "Nu expune baza de date; restricționează pe firewall"),
    5432: ("POSTGRES", 4, "PostgreSQL expus", "Nu expune baza de date; restricționează pe firewall"),
    502:  ("MODBUS", 7, "Modbus/OT expus", "Segmentare OT strictă; fără rută din IT"),
    102:  ("S7", 7, "Siemens S7/OT expus", "Segmentare OT strictă; fără rută din IT"),
    47808:("BACNET", 6, "BACnet/OT expus", "Segmentare OT"),
    3389: ("RDP", 3, "RDP expus (risc brute-force / BlueKeep)", "Acces doar prin VPN; NLA; parole tari + MFA"),
}
BANNER_PORTS = {21, 22, 23, 25, 110, 143}
HTTP_PORTS = {80, 8080, 8000, 8888}
TLS_PORTS = {443, 8443, 8006, 9443, 993, 995}

# --- #3b: reguli CVE pe versiune din banner. „exact" = regex match; „lt" = versiunea capturată < prag.
#     Toate sunt detectabile sigur din banner (FP mic). KEV adaugă flag „exploatat-în-lume" + ridică sev.
CVE_RULES = [
    {"re": r"Apache/2\.4\.49\b",       "cve": "CVE-2021-41773", "sev": 9, "name": "Apache httpd 2.4.49",
     "title": "Apache 2.4.49 — path traversal → RCE", "rem": "Upgrade Apache httpd ≥ 2.4.51"},
    {"re": r"Apache/2\.4\.50\b",       "cve": "CVE-2021-42013", "sev": 9, "name": "Apache httpd 2.4.50",
     "title": "Apache 2.4.50 — path traversal → RCE", "rem": "Upgrade Apache httpd ≥ 2.4.51"},
    {"re": r"vsftpd 2\.3\.4\b",        "cve": "CVE-2011-2523", "sev": 9, "name": "vsftpd 2.3.4", "ci": True,
     "title": "vsftpd 2.3.4 — backdoor (port 6200)", "rem": "Reinstalează vsftpd dintr-o sursă curată"},
    {"re": r"ProFTPD 1\.3\.5\b",       "cve": "CVE-2015-3306", "sev": 8, "name": "ProFTPD 1.3.5", "ci": True,
     "title": "ProFTPD 1.3.5 — mod_copy RCE", "rem": "Upgrade ProFTPD ≥ 1.3.5a; dezactivează mod_copy"},
    {"re": r"OpenSSH[_/ ](\d+\.\d+(?:p\d+)?(?:\.\d+)?)", "lt": (7, 7), "cve": "CVE-2018-15473", "sev": 4,
     "name": "OpenSSH <7.7", "title": "OpenSSH <7.7 — enumerare utilizatori", "rem": "Upgrade OpenSSH ≥ 7.7"},
    {"re": r"Exim[ /](\d+\.\d+(?:\.\d+)?)", "lt": (4, 92), "cve": "CVE-2019-10149", "sev": 8, "ci": True,
     "name": "Exim <4.92", "title": "Exim <4.92 — RCE (Return of the WIZard)", "rem": "Upgrade Exim ≥ 4.92"},
]

# default-creds: doar Basic-auth, listă mică, non-distructiv, oprire la prima reușită. Opt-in.
DEFAULT_CREDS = [("admin", "admin"), ("admin", "password"), ("admin", ""), ("root", "root"),
                 ("admin", "admin123"), ("admin", "1234"), ("user", "user")]
FRAGILE = ("🏭", "📷", "🔌")   # OT / cameră IP / IoT — niciodată default-cred

def vtup(s): return tuple(int(x) for x in re.findall(r"\d+", s)[:4])

def load_kev(path):
    try:
        d = json.load(open(path))
        return {k: v for k, v in d.items() if k != "_meta"}, d.get("_meta", {})
    except Exception:
        return {}, {}

def ipcmd(a):
    try: subprocess.run(["ip"] + a.split(), capture_output=True, timeout=8)
    except Exception: pass

def purge(iface):
    # șterge orice subif VLAN rămas (siguranță: nu lăsa IP-uri în VLAN-urile clientului)
    try:
        out = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, timeout=8).stdout.decode("latin1", "ignore")
    except Exception:
        return
    for name in sorted(set(re.findall(re.escape(iface) + r"\.\d+", out))):
        ipcmd(f"link set {name} down"); ipcmd(f"link del {name}")

# ---- SUPORT LINK NETAGUIT (native VLAN): probe din interfața de management, fără sub-interfață VLAN pe bridge ----
_EGRESS_CACHE = {}

def _is_priv(ip):
    try:
        a, b = int(ip.split(".")[0]), int(ip.split(".")[1])
    except Exception:
        return False
    return a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)

def detect_mgmt_src(iface):
    """IP RFC1918 pe o interfață care NU e bridge-ul/lo/wg*/sub-interfață VLAN → (src, mgmt_iface).
    Dacă senzorul NU e inline (bridge-ul poartă chiar IP-ul de management — ex. icisoc107 pe port de
    router), cade înapoi pe IP-ul bridge-ului. Întoarce (src, mgmt_iface) sau (None, None)."""
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
        if not _is_priv(ip):
            continue
        if dev == iface:
            if bridge_fallback is None:      # senzor NON-inline: bridge-ul are IP-ul de management
                bridge_fallback = (ip, dev)
            continue
        return ip, dev
    return bridge_fallback or (None, None)

def route_egress(ip):
    pref = ".".join(ip.split(".")[:3])
    if pref in _EGRESS_CACHE:
        return _EGRESS_CACHE[pref]
    dev = None
    try:
        out = subprocess.run(["ip", "route", "get", ip], capture_output=True, timeout=4).stdout.decode("latin1", "ignore")
        m = re.search(r"\bdev\s+(\S+)", out)
        if m:
            dev = m.group(1)
    except Exception:
        pass
    _EGRESS_CACHE[pref] = dev
    return dev

def detect_internal_gateway(hosts, mgmt_src):
    """Routerul intern REAL (pe uplink rutat L3): vecinul de pe subreteaua mgmt al cărui MAC e dominant
    printre gazdele rutate. Întoarce IP sau None. Identic cu logica din c3scan — rutăm prin el ca să
    ocolim ruta default (firewall perimetral care blochează scanul). Vezi CHANGELOG c3scan 2026-06-29."""
    import collections
    mgmt_pref = ".".join(mgmt_src.split(".")[:3])
    macs = collections.Counter(); local_by_mac = {}
    for h in hosts:
        mac = h.get("mac"); ip = h.get("ip")
        if not mac or not ip:
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
    return gw_ip if (gw_ip and n >= 3) else None

# Timeout adaptiv de probă: ținte locale = rapid; ținte RUTATE L3 / cu latență = timeout MĂRIT.
# Fix incident f003 (30 iun 2026): negocierea SMB1 nu se finaliza în 2.2s peste o cale rutată-mgmt → fals-negativ.
PROBE_TO = 2.2
def adaptive_timeout(host, ports, src):
    """Măsoară RTT-ul printr-un connect la un port (probabil) deschis și scalează timeout-ul probelor.
    Ținte locale (RTT mic) → ~PROBE_TO; ținte rutate/latente → mai mult. Clamp [PROBE_TO, 8.0]."""
    for p in (sorted(ports)[:3] if ports else [445, 80, 443]):
        try:
            t0 = time.time()
            so = socket.create_connection((host, p), timeout=3, source_address=(src, 0)); so.close()
            return max(PROBE_TO, min(8.0, (time.time() - t0) * 10 + 1.5))
        except Exception:
            continue
    return PROBE_TO

def grab(host, port, src, to=None):
    to = to or PROBE_TO
    try:
        so = socket.create_connection((host, port), timeout=to, source_address=(src, 0)); so.settimeout(to)
        try: d = so.recv(400)
        except Exception: d = b""
        so.close(); return d.decode("latin1", "ignore").strip()
    except Exception: return ""

def http_probe(host, port, src, tls, to=None):
    to = to or PROBE_TO
    server = title = None; fnd = []; auth = False
    try:
        raw = socket.create_connection((host, port), timeout=to, source_address=(src, 0))
        sk = ssl._create_unverified_context().wrap_socket(raw, server_hostname=host) if tls else raw
        sk.settimeout(to)
        sk.sendall(("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: CYBER3-Scan\r\nConnection: close\r\n\r\n" % host).encode())
        resp = b""
        while len(resp) < 16384:
            try: c = sk.recv(4096)
            except Exception: break
            if not c: break
            resp += c
        sk.close()
        head, _, body = resp.partition(b"\r\n\r\n")
        head = head.decode("latin1", "ignore"); body = body.decode("latin1", "ignore")
        status = head.split("\r\n", 1)[0]
        auth = " 401" in status or "www-authenticate: basic" in head.lower()
        for ln in head.split("\r\n"):
            if ln.lower().startswith("server:"): server = ln.split(":", 1)[1].strip()[:60]
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m: title = re.sub(r"\s+", " ", m.group(1)).strip()[:60]
        low = ((title or "") + " " + body[:1200]).lower()
        if auth or any(k in low for k in ("login", "sign in", "log in", "admin", "router", "camera", "unifi",
                                  "printer", "synology", "qnap", "dashboard", "password", "webui", "management")):
            fnd.append((3, "PANOU-WEB", f"Panou admin/login web pe {port}" + (f" — „{title}”" if title else ""),
                        "Restricționează (VPN/allowlist); parolă tare + MFA; verifică credențiale default"))
    except Exception:
        pass
    return server, title, fnd, auth

def basic_auth_creds(host, port, src, tls, to=None):
    to = to or PROBE_TO
    # OPT-IN: doar pe servere ce cer HTTP Basic (401). Non-distructiv, oprire la prima reușită.
    hits = []
    for user, pw in DEFAULT_CREDS:
        try:
            raw = socket.create_connection((host, port), timeout=to, source_address=(src, 0))
            sk = ssl._create_unverified_context().wrap_socket(raw, server_hostname=host) if tls else raw
            sk.settimeout(to)
            tok = b64encode(f"{user}:{pw}".encode()).decode()
            sk.sendall(("GET / HTTP/1.0\r\nHost: %s\r\nAuthorization: Basic %s\r\n"
                        "User-Agent: CYBER3-Scan\r\nConnection: close\r\n\r\n" % (host, tok)).encode())
            resp = b""
            while len(resp) < 2048:
                try: c = sk.recv(1024)
                except Exception: break
                if not c: break
                resp += c
            sk.close()
            status = resp.split(b"\r\n", 1)[0].decode("latin1", "ignore")
            if " 200" in status or " 302" in status or " 301" in status:
                hits.append((9, "DEFAULT-CRED", f"Credențiale DEFAULT acceptate pe {port}: {user}/{pw or '(gol)'}",
                             "Schimbă imediat parola; dezactivează contul default"))
                break
        except Exception:
            continue
    return hits

def tls_probe(host, port, src, to=None):
    to = to or PROBE_TO
    fnd = []
    try: raw = socket.create_connection((host, port), timeout=to, source_address=(src, 0))
    except Exception: return fnd
    try:
        ssl.create_default_context().wrap_socket(raw, server_hostname=host).close()
    except ssl.SSLCertVerificationError as e:
        m = str(e).lower()
        if "expired" in m: fnd.append((5, "TLS-EXPIRAT", f"Certificat TLS EXPIRAT pe {port}", "Reînnoiește certificatul"))
        elif "self" in m: fnd.append((2, "TLS-SELF", f"Certificat self-signed pe {port}", "Certificat de la o CA recunoscută"))
        else: fnd.append((2, "TLS-NEÎNCREZUT", f"Certificat TLS neîncrezut pe {port}", "Verifică lanțul de certificate"))
    except Exception:
        try: raw.close()
        except Exception: pass
    return fnd

def smb_v1(host, src, to=None):
    to = to or PROBE_TO
    dialects = b"".join(b"\x02" + d + b"\x00" for d in
                        [b"PC NETWORK PROGRAM 1.0", b"LANMAN1.0", b"Windows for Workgroups 3.1a",
                         b"LM1.2X002", b"LANMAN2.1", b"NT LM 0.12"])
    hdr = b"\xffSMB" + b"\x72" + b"\x00\x00\x00\x00" + b"\x18" + b"\x01\x28" + b"\x00" * 12 \
          + b"\x00\x00" + b"\xfe\xff" + b"\x00\x00" + b"\x00\x00"
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
    smb = hdr + body
    pkt = b"\x00\x00" + struct.pack(">H", len(smb)) + smb
    try:
        so = socket.create_connection((host, 445), timeout=to, source_address=(src, 0)); so.settimeout(to)
        so.sendall(pkt); r = so.recv(1024); so.close()
        # SMBv1 REAL = raspuns SMBv1 (0xffSMB) SI un dialect efectiv ACCEPTAT.
        #   0xfeSMB = SMB2+ (SMBv1 dezactivat). DialectIndex 0xFFFF = serverul raspunde SMBv1 dar
        #   REFUZA toate dialectele => SMBv1 dezactivat. (Fix fals-pozitiv Termo .38/.39/.40, 7 aug 2026:
        #   NAS-uri care raspund pe 445 dar nu accepta niciun dialect SMBv1 erau marcate gresit „SMBv1 ACTIV".)
        if len(r) < 39 or r[4:8] != b"\xffSMB":
            return False
        if r[36] == 0:                                   # WordCount 0 = raspuns de eroare, niciun dialect
            return False
        return struct.unpack("<H", r[37:39])[0] != 0xFFFF   # 0xFFFF = toate dialectele refuzate
    except Exception:
        return False

def _ber_len(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big"); return bytes([0x80 | len(b)]) + b

def _tlv(tag, val): return bytes([tag]) + _ber_len(len(val)) + val

def snmp_get_sysdescr(host, src, community, to=None):
    to = to or PROBE_TO
    # SNMPv1 GET sysDescr (1.3.6.1.2.1.1.1.0). Întoarce textul sysDescr dacă comunitatea e validă, altfel None.
    oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"               # 1.3.6.1.2.1.1.1.0
    vb = _tlv(0x30, _tlv(0x06, oid) + _tlv(0x05, b""))       # varbind: OID + NULL
    pdu = _tlv(0xa0, _tlv(0x02, b"\x26\x4f") + _tlv(0x02, b"\x00") + _tlv(0x02, b"\x00") + _tlv(0x30, vb))
    msg = _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x04, community.encode()) + pdu)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((src, 0)); s.settimeout(max(1.6, to * 0.7)); s.sendto(msg, (host, 161))
        data, _ = s.recvfrom(2048); s.close()
    except Exception:
        return None
    # extrage prima OCTET STRING de după OID-ul sysDescr din răspuns
    i = data.find(oid)
    if i < 0: return ""
    j = i + len(oid)
    while j < len(data) - 1:
        if data[j] == 0x04:   # OCTET STRING
            ln = data[j + 1]
            if ln & 0x80:
                k = ln & 0x7f; ln = int.from_bytes(data[j + 2:j + 2 + k], "big"); off = j + 2 + k
            else:
                off = j + 2
            return data[off:off + ln].decode("latin1", "ignore").strip()
        j += 1
    return ""

def match_cve(banners, kev):
    fnd = []
    for src in banners.values():
        for r in CVE_RULES:
            m = re.search(r["re"], src, re.I if r.get("ci") else 0)
            if not m: continue
            if "lt" in r:
                if not m.groups() or vtup(m.group(1)) >= r["lt"]: continue
            sev, title = r["sev"], r["title"]; cve = r["cve"]
            k = kev.get(cve)
            cat = "CVE"
            if k:
                cat = "CVE-KEV"; sev = max(sev, 8)
                extra = " — EXPLOATAT-ÎN-LUME (CISA KEV"
                if k.get("added"): extra += f", din {k['added']}"
                extra += ", RANSOMWARE" if k.get("ransomware") else ""
                title = f"{title} [{cve}{extra})]"
            else:
                title = f"{title} [{cve}]"
            fnd.append((sev, cat, title, r["rem"]))
    return fnd

def vuln_host(ip, ports, src, role, kev, do_snmp, do_creds, timeout=None):
    f = []; banners = {}
    # timeout adaptiv per gazdă: măsurat o dată din RTT (ținte rutate/latente primesc mai mult). Vezi PROBE_TO.
    to = timeout or adaptive_timeout(ip, ports, src)
    for p in sorted(ports):
        if p in EXPOSED:
            et, sev, titlu, rem = EXPOSED[p]; f.append((sev, et + "-EXPUS", titlu, rem))
        if p in BANNER_PORTS:
            b = grab(ip, p, src, to)
            if b: banners[str(p)] = b[:120]
        if p in HTTP_PORTS:
            srv, ttl, hf, auth = http_probe(ip, p, src, False, to)
            if srv: banners[str(p)] = srv
            f += hf
            if do_creds and auth and not (role and role.startswith(FRAGILE)):
                f += basic_auth_creds(ip, p, src, False, to)
        if p in TLS_PORTS:
            srv, ttl, hf, auth = http_probe(ip, p, src, True, to)
            if srv: banners[str(p)] = srv
            f += hf + tls_probe(ip, p, src, to)
            if do_creds and auth and not (role and role.startswith(FRAGILE)):
                f += basic_auth_creds(ip, p, src, True, to)
    if 445 in ports and smb_v1(ip, src, to):
        f.append((9, "SMBv1", "SMBv1 ACTIV (EternalBlue/WannaCry — CVE-2017-0144)", "Dezactivează SMBv1 URGENT (regedit/GPO)"))
    if do_snmp:
        sd = snmp_get_sysdescr(ip, src, "public", to)
        if sd is not None:
            if sd: banners["161"] = sd[:120]
            f.append((6, "SNMP-PUBLIC", "SNMP community „public” activă (info-leak)"
                      + (f" — {sd[:60]}" if sd else ""), "Schimbă community-ul; SNMPv3 cu auth; restricționează 161/udp"))
    f += match_cve(banners, kev)
    return f, banners

def sevname(s): return "CRITIC" if s >= 8 else "ÎNALT" if s >= 6 else "MEDIU" if s >= 4 else "MIC"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="br0")
    ap.add_argument("--in", dest="inp", default="/var/log/cyber3/discovery.json")
    ap.add_argument("--out", default="/var/log/cyber3/findings.json")
    ap.add_argument("--kev", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "kev.json"))
    ap.add_argument("--snmp", dest="snmp", action="store_true", default=True, help="probă SNMP public (implicit ON)")
    ap.add_argument("--no-snmp", dest="snmp", action="store_false")
    ap.add_argument("--creds", action="store_true", help="default-creds pe panouri web (OPT-IN, exclude OT/cameră/IoT)")
    ap.add_argument("--workers", type=int, default=60)
    a = ap.parse_args()
    kev, kmeta = load_kev(a.kev)
    if kev: print(f"[c3vuln] KEV încărcat: {len(kev)} CVE exploatate-în-lume (catalog {kmeta.get('released','?')})")
    else:   print(f"[c3vuln] ATENȚIE: kev.json lipsă/gol ({a.kev}) — fără îmbogățire exploatat-în-lume")
    d = json.load(open(a.inp)); hosts = d["hosts"]
    bypref = defaultdict(set)
    for h in hosts: bypref[".".join(h["ip"].split(".")[:3])].add(int(h["ip"].split(".")[3]))
    groups = defaultdict(list)
    for h in hosts:
        if h.get("services") and h.get("home_vlan") is not None:
            groups[(h["home_vlan"], ".".join(h["ip"].split(".")[:3]))].append(h)
    total_hosts = sum(len(v) for v in groups.values())
    print(f"[c3vuln] {total_hosts} hosturi cu servicii în {len(groups)} (VLAN,subrețea); "
          f"SNMP={'on' if a.snmp else 'off'} creds={'ON' if a.creds else 'off'}; verific ...")
    purge(a.iface)   # curăță eventuale subif-uri rămase dintr-o rulare anterioară
    findings = []; scanned = 0; banners_all = {}
    for (vlan, pref), hs in sorted(groups.items()):
        free = f"{pref}." + str(next((i for i in range(250, 200, -1) if i not in bypref[pref]), 251))
        subif = f"{a.iface}.{vlan}"
        ipcmd(f"link del {subif}"); ipcmd(f"link add link {a.iface} name {subif} type vlan id {vlan}")
        ipcmd(f"addr add {free}/24 dev {subif}"); ipcmd(f"link set {subif} up"); time.sleep(0.3)
        try:
            def work(h):
                fl, bn = vuln_host(h["ip"], h["services"], free, h.get("role"), kev, a.snmp, a.creds)
                return h["ip"], fl, bn
            with ThreadPoolExecutor(max_workers=a.workers) as ex:
                for ip, fl, bn in ex.map(work, hs):
                    scanned += 1
                    if bn: banners_all[ip] = bn
                    for sev, cat, titlu, rem in fl:
                        findings.append({"ip": ip, "vlan": vlan, "severity": sev, "category": cat,
                                         "title": titlu, "remediation": rem})
        finally:
            ipcmd(f"link set {subif} down"); ipcmd(f"link del {subif}")
    # Link NETAGUIT (native VLAN): gazde cu servicii dar fără VLAN învățat → probe din interfața de management.
    native = [h for h in hosts if h.get("services") and h.get("home_vlan") is None]
    if native:
        src, mgmt = detect_mgmt_src(a.iface)
        if src:
            # UPLINK RUTAT L3: rutează țintele prin routerul intern REAL (nu prin ruta default → firewall).
            gw = detect_internal_gateway(hosts, src); added = []
            nworkers = min(a.workers, 8) if gw else a.workers  # mai blând când mergem prin router intern
            try:
                if gw:
                    nsel = native
                    subs = sorted({".".join(h["ip"].split(".")[:3]) for h in nsel
                                   if ".".join(h["ip"].split(".")[:3]) != ".".join(src.split(".")[:3])})
                    for s in subs:
                        ipcmd(f"route add {s}.0/24 via {gw} dev {mgmt}"); added.append(s)
                    print(f"[c3vuln] {len(nsel)} hosturi RUTATE prin gateway intern {gw} ({mgmt}, src {src}); verific ...")
                else:
                    nsel = [h for h in native if route_egress(h["ip"]) == mgmt]
                    print(f"[c3vuln] {len(nsel)} hosturi NATIVE (link netaguit) din {mgmt} {src}; verific ...")
                def nwork(h):
                    fl, bn = vuln_host(h["ip"], h["services"], src, h.get("role"), kev, a.snmp, a.creds)
                    return h["ip"], fl, bn
                with ThreadPoolExecutor(max_workers=nworkers) as ex:
                    for ip, fl, bn in ex.map(nwork, nsel):
                        scanned += 1
                        if bn: banners_all[ip] = bn
                        for sev, cat, titlu, rem in fl:
                            findings.append({"ip": ip, "vlan": None, "severity": sev, "category": cat,
                                             "title": titlu, "remediation": rem})
            finally:
                for s in added:
                    ipcmd(f"route del {s}.0/24 via {gw} dev {mgmt}")
        else:
            print(f"[c3vuln] {len(native)} hosturi native dar fără interfață de management — sărite")
    purge(a.iface)   # plasă de siguranță finală
    findings.sort(key=lambda x: -x["severity"])
    summ = {"total": len(findings),
            "critical": sum(1 for f in findings if f["severity"] >= 8),
            "high": sum(1 for f in findings if 6 <= f["severity"] < 8),
            "medium": sum(1 for f in findings if 4 <= f["severity"] < 6),
            "low": sum(1 for f in findings if f["severity"] < 4),
            "kev": sum(1 for f in findings if f["category"] == "CVE-KEV")}
    out = {"tool": "CYBER3 Scan", "phase": "vuln", "hosts_scanned": scanned, "kev_catalog": kmeta.get("released", ""),
           "summary": summ, "findings": findings, "banners": banners_all}
    print("\n" + "=" * 68 + "\nCYBER3 Scan — VULNERABILITĂȚI\n" + "=" * 68)
    print(f"Hosturi scanate: {scanned} | Findings: {summ['total']}  "
          f"(CRITIC {summ['critical']} · ÎNALT {summ['high']} · MEDIU {summ['medium']} · MIC {summ['low']} "
          f"· exploatat-în-lume {summ['kev']})")
    print("Pe categorie:", dict(collections.Counter(f["category"] for f in findings)))
    print("\nTop findings:")
    for f in findings[:22]:
        print(f"  [{f['severity']} {sevname(f['severity']):<6}] {f['category']:<12} {f['ip']:<15} {f['title']}")
    try:
        json.dump(out, open(a.out, "w"), indent=2, ensure_ascii=False)
        print(f"\n[c3vuln] {scanned} hosturi → {len(findings)} findings → {a.out}")
    except Exception as e:
        print(f"[c3vuln] nu pot scrie {a.out}: {e}")

if __name__ == "__main__":
    main()
