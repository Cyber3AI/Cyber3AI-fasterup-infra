#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CYBER3 Scan — ÎNVĂȚARE INCREMENTALĂ A REȚELEI la nivel de DISPOZITIVE (operator, 27 aug 2026).

Algoritm: 1) inventarul învățat la scanul anterior (/etc/cyber3/inventory.json) → 2) scanul curent descoperă
schimbări/adăugiri → 3) delta (gazde NOI / NEVĂZUTE / SERVICII SCHIMBATE; vulnerabilități NOI / REMEDIATE)
se salvează per rulare (scans/<id>.delta.json, .delta-vuln.json) și inventarul se actualizează → 4) următorul
scan pleacă de la noul inventar. Pur stdlib; apelat de c3-engage.sh (root). NU atinge rețeaua.

  c3delta.py disc --disc discovery.json --inv /etc/cyber3/inventory.json --out <id>.delta.json --scan <id>
  c3delta.py vuln --findings findings.json --base /etc/cyber3/findings-baseline.json --out <id>.delta-vuln.json --scan <id>
"""
import argparse, json, os, sys, time

TS = time.strftime("%Y-%m-%d %H:%M")


def _load(p, default):
    try:
        return json.load(open(p))
    except Exception:
        return default


def _save(p, obj):
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = p + ".tmp"
    json.dump(obj, open(tmp, "w"), indent=1, ensure_ascii=False)
    os.replace(tmp, p)
    try:
        os.chmod(p, 0o644)
    except Exception:
        pass


def _real(h):
    """Gazdă REALĂ = are servicii, MAC REAL (răspuns ARP propriu, nu MAC-ul gateway-ului văzut pasiv) sau hostname.
    FIX icisoc108 (27 aug 2026): pe scan rutat, gateway-ul răspunde RST pentru IP-uri inexistente → MAC=gateway pe
    mii de IP-uri enumerate; fără mac_real inventarul se umfla (3565 „gazde")."""
    return bool(h.get("services")) or bool(h.get("mac_real")) or bool(h.get("hostname"))


def _clean(v):
    return None if v in (None, "", "?") else v


def _scope(a, d):
    """Clasele ACOPERITE de această rulare: --scope (țintele wrapper-ului) sau, în lipsă, subrețelele enumerate
    complet (≥200 IP în discovery). Doar gazdele/constatările din scope pot fi declarate nevăzute/remediate."""
    import ipaddress
    nets = []
    for t in (getattr(a, "scope", "") or "").replace(" ", ",").split(","):
        t = t.strip()
        if not t:
            continue
        try:
            nets.append(ipaddress.ip_network(t, strict=False))
        except ValueError:
            pass
    if not nets:
        cnt = {}
        for h in d.get("hosts", []):
            ip = h.get("ip", "")
            if ip.count(".") == 3:
                p = ".".join(ip.split(".")[:3]) + ".0/24"
                cnt[p] = cnt.get(p, 0) + 1
        nets = [ipaddress.ip_network(p) for p, n in cnt.items() if n >= 200]
    def inside(ip):
        if not nets:
            return True  # scope necunoscut → presupunem rulare completă
        try:
            a_ = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a_ in n for n in nets)
    return nets, inside


def run_disc(a):
    d = _load(a.disc, {})
    nets, in_scope = _scope(a, d)
    inv = _load(a.inv, {"created": TS, "updated": None, "scans": [], "hosts": {}})
    hosts = inv.setdefault("hosts", {})
    first = not hosts
    seen_now = set()
    new, changed = [], []
    for h in d.get("hosts", []):
        ip = h.get("ip")
        if not ip or not _real(h):
            continue
        seen_now.add(ip)
        cur = {"mac": _clean((h.get("mac") or "").lower()), "vendor": _clean(h.get("vendor")), "role": _clean(h.get("role")),
               "hostname": _clean(h.get("hostname")), "services": sorted(set(h.get("services") or [])),
               "vlans": sorted(v for v in (h.get("vlans") or []) if v is not None)}
        old = hosts.get(ip)
        if old is None:
            hosts[ip] = dict(cur, first_seen=TS, last_seen=TS, seen_count=1, missed=0)
            new.append(dict(ip=ip, **cur))
            continue
        diff = {}
        sa = sorted(set(cur["services"]) - set(old.get("services") or []))
        sr = sorted(set(old.get("services") or []) - set(cur["services"]))
        if sa: diff["services_added"] = sa
        if sr: diff["services_removed"] = sr
        for k in ("mac", "hostname", "vendor", "role"):
            if cur.get(k) and old.get(k) and cur[k] != old[k]:
                diff[k + "_old"], diff[k + "_new"] = old[k], cur[k]
        if diff:
            changed.append(dict(ip=ip, **diff))
        # actualizează (păstrează valorile vechi dacă cele noi lipsesc)
        for k in ("mac", "vendor", "role", "hostname"):
            if cur.get(k):
                old[k] = cur[k]
        old["services"] = cur["services"]
        old["vlans"] = sorted(set(old.get("vlans") or []) | set(cur["vlans"]))
        old["last_seen"] = TS
        old["seen_count"] = old.get("seen_count", 0) + 1
        old["missed"] = 0
    gone = []
    for ip, old in hosts.items():
        if ip not in seen_now and in_scope(ip):
            old["missed"] = old.get("missed", 0) + 1
            gone.append({"ip": ip, "mac": old.get("mac"), "vendor": old.get("vendor"), "role": old.get("role"),
                         "hostname": old.get("hostname"), "last_seen": old.get("last_seen"), "missed_scans": old["missed"]})
    inv["updated"] = TS
    inv.setdefault("scans", []).append({"scan": a.scan, "ts": TS, "hosts_seen": len(seen_now), "new": len(new),
                                        "changed": len(changed), "unseen": len(gone)})
    _save(a.inv, inv)
    delta = {"scan": a.scan, "ts": TS, "baseline_initial": first, "scope": [str(n) for n in nets],
             "summary": {"hosts_seen": len(seen_now), "inventory_total": len(hosts), "new": len(new), "changed": len(changed),
                         "unseen": len(gone), "scope_subnets": len(nets)},
             "new_hosts": sorted(new, key=lambda x: x["ip"]), "changed_hosts": sorted(changed, key=lambda x: x["ip"]),
             "unseen_hosts": sorted(gone, key=lambda x: x["ip"])}
    _save(a.out, delta)
    s = delta["summary"]
    if first:
        print("[c3delta] inventar INIȚIAL creat: %d gazde reale → %s" % (len(hosts), a.inv))
    else:
        print("[c3delta] DISPOZITIVE vs inventarul învățat: văzute=%d | NOI=%d | schimbate=%d | nevăzute acum=%d (inventar total %d) → %s"
              % (s["hosts_seen"], s["new"], s["changed"], s["unseen"], s["inventory_total"], a.out))
        for x in delta["new_hosts"][:15]:
            print("   + NOU %-15s %s %s %s" % (x["ip"], x.get("mac") or "-", (x.get("vendor") or "")[:18], x.get("services")))
        for x in delta["changed_hosts"][:10]:
            print("   ~ SCHIMBAT %-15s %s" % (x["ip"], {k: v for k, v in x.items() if k != "ip"}))


def run_vuln(a):
    f = _load(a.findings, {})
    d = _load(a.disc, {}) if getattr(a, "disc", None) else {}
    nets, in_scope = _scope(a, d)
    base = _load(a.base, {"created": TS, "updated": None, "findings": {}})
    bf = base.setdefault("findings", {})
    first = not bf
    now = {}
    for x in f.get("findings", []):
        k = "%s|%s|%s" % (x.get("ip"), x.get("category"), x.get("title"))
        now[k] = {"ip": x.get("ip"), "category": x.get("category"), "title": x.get("title"), "severity": x.get("severity")}
    new = [v for k, v in now.items() if k not in bf]
    resolved = [dict(v, last_seen=v.get("last_seen")) for k, v in bf.items()
                if k not in now and v.get("active", True) and in_scope(v.get("ip") or "")]
    for k, v in now.items():
        e = bf.get(k)
        if e is None:
            bf[k] = dict(v, first_seen=TS, last_seen=TS, active=True)
        else:
            e.update(last_seen=TS, active=True, severity=v.get("severity"))
    for k, v in bf.items():
        if k not in now and v.get("active", True) and in_scope(v.get("ip") or ""):
            v["active"] = False
            v["resolved_seen"] = TS
    base["updated"] = TS
    _save(a.base, base)
    def bycat(lst):
        c = {}
        for v in lst:
            c[v.get("category")] = c.get(v.get("category"), 0) + 1
        return c
    delta = {"scan": a.scan, "ts": TS, "baseline_initial": first,
             "summary": {"findings_now": len(now), "new": len(new), "resolved": len(resolved),
                         "new_by_category": bycat(new), "resolved_by_category": bycat(resolved),
                         "new_critical": sum(1 for v in new if int(v.get("severity") or 0) >= 8)},
             "new_findings": sorted(new, key=lambda v: (-int(v.get("severity") or 0), v.get("ip") or "")),
             "resolved_findings": sorted(resolved, key=lambda v: (-int(v.get("severity") or 0), v.get("ip") or ""))}
    _save(a.out, delta)
    s = delta["summary"]
    if first:
        print("[c3delta] bază VULNERABILITĂȚI inițială: %d constatări → %s" % (len(now), a.base))
    else:
        print("[c3delta] VULNERABILITĂȚI vs scanul anterior: acum=%d | NOI=%d (critice %d) %s | REMEDIATE=%d %s → %s"
              % (s["findings_now"], s["new"], s["new_critical"], s["new_by_category"], s["resolved"], s["resolved_by_category"], a.out))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    p1 = sub.add_parser("disc"); p1.add_argument("--disc", required=True); p1.add_argument("--inv", required=True)
    p1.add_argument("--out", required=True); p1.add_argument("--scan", default="-"); p1.add_argument("--scope", default="")
    p2 = sub.add_parser("vuln"); p2.add_argument("--findings", required=True); p2.add_argument("--base", required=True)
    p2.add_argument("--out", required=True); p2.add_argument("--scan", default="-"); p2.add_argument("--scope", default="")
    p2.add_argument("--disc", default="")
    a = ap.parse_args()
    try:
        run_disc(a) if a.mode == "disc" else run_vuln(a)
    except Exception as e:  # niciodată nu oprește scanul
        print("[c3delta] eroare (ignorată): %s" % e)
        sys.exit(0)


if __name__ == "__main__":
    main()
