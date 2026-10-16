#!/bin/bash
# READ-ONLY: clasifică FIECARE IP blocat pe senzor (CYBER3_BLOCK + DROP directe iptables; nft pe icisoc110)
# după cum apare în alertele Suricata (zile disponibile): serviciu folosit de client vs atacator.
export LC_ALL=C
EVEDIR=/var/log/suricata
# DOAR blocări reale: iptables DROP -s (INPUT/FORWARD/CYBER3_BLOCK). Pe icisoc110 (hostname fasterup) + elementele seturilor nft de blocare.
BL=$( { iptables -S 2>/dev/null | grep -oE '^-A (INPUT|FORWARD|CYBER3_BLOCK) -s [0-9.]+(/32)? -j DROP' | awk '{print $4}';
        if [ "$(hostname)" = fasterup ]; then for st in $(nft list sets bridge 2>/dev/null | grep -oE 'set [a-z0-9_]+' | awk '{print $2}'); do nft list set bridge filter $st 2>/dev/null | sed -n '/elements/,/}/p' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'; done; fi ; } | sed 's#/32##' | sort -u)
NBL=$(echo "$BL" | grep -c .)
FILES="$EVEDIR/eve-alerts.json $(ls -t $EVEDIR/eve-alerts.json-* 2>/dev/null | head -4)"
echo "$BL" > /tmp/c3_bl.txt
nice -n 19 ionice -c3 python3 - /tmp/c3_bl.txt /etc/cyber3/ar-allowlist.txt $FILES <<'PY'
import sys, json, gzip, ipaddress, collections, socket
bl = set(l.strip() for l in open(sys.argv[1]) if l.strip())
try: allow = set(l.split()[0] for l in open(sys.argv[2]) if l.strip() and not l.startswith('#'))
except Exception: allow = set()
files = sys.argv[3:]
PROT = [ipaddress.ip_network(c) for c in ("8.8.4.0/24 8.8.8.0/24 142.250.0.0/15 172.217.0.0/16 216.58.192.0/19 172.253.0.0/16 74.125.0.0/16 64.233.160.0/19 209.85.128.0/17 173.194.0.0/16 108.177.0.0/17 13.64.0.0/11 13.104.0.0/14 20.0.0.0/8 40.64.0.0/10 52.96.0.0/12 52.112.0.0/14 204.79.197.0/24 131.253.0.0/16 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 23.0.0.0/12 23.32.0.0/11 23.64.0.0/14 104.64.0.0/10 2.16.0.0/13 92.122.0.0/15 95.100.0.0/15 184.24.0.0/13 151.101.0.0/16 199.232.0.0/16 217.156.52.0/24").split()]
def priv(ip):
    try: return ipaddress.ip_address(ip).is_private
    except ValueError: return False
st = collections.defaultdict(lambda: {"out":0, "in":0, "sport":collections.Counter(), "dport":collections.Counter(), "sig":collections.Counter(), "first":"", "last":""})
for f in files:
    try:
        fh = gzip.open(f, 'rt', errors='replace') if f.endswith('.gz') else open(f, errors='replace')
        for l in fh:
            if '"src_ip"' not in l: continue
            try: e = json.loads(l)
            except Exception: continue
            s, d = e.get("src_ip"), e.get("dest_ip")
            for ip, role in ((d, "out"), (s, "in")):
                if ip in bl:
                    x = st[ip]; other = s if role == "out" else d
                    if priv(other): x[role] += 1
                    if role == "in": x["sport"][e.get("src_port")] += 1
                    else: x["dport"][e.get("dest_port")] += 1
                    x["sig"][(e.get("alert") or {}).get("signature", "")[:55]] += 1
                    t = e.get("timestamp", "")[:16]; x["first"] = x["first"] or t; x["last"] = t
    except Exception as ex:
        print("  (fișier ilizibil %s: %s)" % (f, ex))
host = socket.gethostname()
flag = []
for ip in sorted(bl):
    x = st.get(ip); reasons = []
    a = ipaddress.ip_address(ip)
    if a.is_private: reasons.append("ADRESĂ PRIVATĂ")
    if ip in allow: reasons.append("ÎN ALLOWLIST")
    if any(a in n for n in PROT): reasons.append("REȚEA PROTEJATĂ (CDN/cloud/ANAF)")
    if x:
        if x["sport"] and set(p for p, _ in x["sport"].most_common(3)) & {53, 853, 123}: reasons.append("RĂSPUNDE DIN PORT 53/853/123 (rezolver/NTP)")
        if x["out"] > 0 and x["out"] >= x["in"]: reasons.append("CLIENTUL O CONTACTEAZĂ (out=%d ≥ in=%d)" % (x["out"], x["in"]))
    if reasons:
        flag.append(ip)
        top = "; ".join("%dx %s" % (n, s) for s, n in (x["sig"].most_common(2) if x else []))
        print("  ⚠ %-16s %s | out=%s in=%s sport=%s dport=%s | %s" % (ip, " + ".join(reasons), x["out"] if x else 0, x["in"] if x else 0,
              dict(x["sport"].most_common(2)) if x else {}, dict(x["dport"].most_common(2)) if x else {}, top))
print("%s | blocate=%d | fără urme în alerte=%d | SEMNALATE=%d" % (host, len(bl), sum(1 for ip in bl if ip not in st), len(flag)))
PY
rm -f /tmp/c3_bl.txt
