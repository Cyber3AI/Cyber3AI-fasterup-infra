#!/bin/bash
# CYBER3 Scan — wrapper privilegiat declanșat de portal (SSH socadmin → sudo NOPASSWD).
# Rulează descoperire rețea (pasiv+activ+portscan) apoi vulnerabilități (KEV+SNMP). NON-distructiv.
# Args: <scan_id> [level]   level ∈ {bland,mediu,agresiv} (implicit mediu). Root-owned, NEscriibil de socadmin.
set -u
DIR=/opt/cyber3/c3scan
LOG=/var/log/cyber3
SCANS="$LOG/scans"
IFACE=br0
# interfața de captură: override /etc/cyber3/scan-iface; altfel br0, iar dacă br0 lipsește dar există bond0 (ex. ICISOC110/ANRE) → bond0
[ -s /etc/cyber3/scan-iface ] && IFACE=$(tr -cd 'a-z0-9.-' < /etc/cyber3/scan-iface)
[ -e "/sys/class/net/$IFACE" ] || { [ -e /sys/class/net/bond0 ] && IFACE=bond0; }
SID=$(printf '%s' "${1:-}" | tr -cd 'A-Za-z0-9_-' | cut -c1-40)
LVL=$(printf '%s' "${2:-mediu}" | tr -cd 'a-z')
TGT=$(printf '%s' "${3:-}" | tr -cd '0-9./, ' | cut -c1-4000)   # ADD TARGET: IP-uri/subrețele explicite
case "$LVL" in bland|mediu|agresiv) ;; *) LVL=mediu ;; esac
[ -z "$SID" ] && { echo "bad scan_id"; exit 2; }
mkdir -p "$SCANS"; chmod 755 "$LOG" "$SCANS" 2>/dev/null
ST="$SCANS/$SID.status"
write_st(){ printf '%s\n' "$1" > "$ST"; chmod 644 "$ST"; }

# Ținte implicite PER SENZOR (operator, 27 aug 2026): dacă ADD TARGET din portal e GOL, se citesc
# clasele salvate în /etc/cyber3/scan-targets.txt (un IP/subrețea RFC1918 pe linie, # = comentariu).
DEFT=/etc/cyber3/scan-targets.txt
TSRC=portal
# Per senzor: /etc/cyber3/scan-targets.disabled = NU folosi clasele din fișier (mod AUTO: doar gazde văzute pasiv+ARP).
# Motiv (icisoc108, 27 aug 2026): clasele enumerate produc mii de gazde fantomă printr-un proxy transparent.
if [ -z "$TGT" ] && [ -s "$DEFT" ] && [ ! -e /etc/cyber3/scan-targets.disabled ]; then
    TGT=$(sed 's/#.*//' "$DEFT" | tr -cd '0-9./,\n ' | tr '\n ' ',,' | tr -s ',' | sed 's/^,//;s/,$//' | cut -c1-4000)
    TSRC=file
fi
[ -z "$TGT" ] && TSRC=none
TGN=$(printf '%s' "$TGT" | tr ',' '\n' | grep -c .)

# TRUNK TAGUIT (VLAN-uri 802.1Q văzute la scanul anterior): ARP sweep-ul per VLAN enumerează deja fiecare IP din
# fiecare subrețea×VLAN → clasele din FIȘIER nu se mai trimit ca ținte explicite (altfel c3scan le încearcă în
# TOATE VLAN-urile = ×11 timp; icisoc104 27 aug: 1h în loc de 3 min). Rămân SCOPE pentru delta (c3delta).
# ADD TARGET explicit din portal (src=portal) se respectă întotdeauna.
TAGGED=$(python3 -c "import json;d=json.load(open('$LOG/discovery.json'));print(1 if [v for v in (d.get('summary',{}).get('vlans') or []) if v is not None] else 0)" 2>/dev/null || echo 0)
[ "$(cat /sys/class/net/$IFACE/carrier 2>/dev/null)" = 1 ] || TAGGED=0   # bridge fără carrier (ex. F003 scos din inline) → ținte din fișier, din mgmt
TGT_ARG=()
if [ -n "$TGT" ] && { [ "$TSRC" = portal ] || [ "$TAGGED" != 1 ]; }; then
    TGT_ARG=(--targets "$TGT")
elif [ -n "$TGT" ]; then
    TSRC="file-scope(trunk-taguit,auto-descoperire)"
fi

write_st "running phase=discovery level=$LVL targets=$TGN src=$TSRC started=$(date +%s)"
# 1) descoperire: pasiv + ARP tag-uit (VLAN-home) + connect-scan porturi (+ ținte explicite ADD TARGET)
python3 "$DIR/c3scan.py" --iface "$IFACE" --active --level "$LVL" --ports "${TGT_ARG[@]}" \
    --out "$LOG/discovery.json" >"$SCANS/$SID.discovery.log" 2>&1
RC1=$?
if [ $RC1 -ne 0 ] || [ ! -s "$LOG/discovery.json" ]; then
    write_st "done total=0 error=discovery rc=$RC1 ended=$(date +%s)"; exit 1
fi
# GARDĂ (icisoc107, 27 aug): discovery fără NICIO gazdă cu servicii = port-scan eșuat/neaplicabil → scan EȘUAT;
# nu se rulează delta (altfel toate constatările anterioare ar fi marcate greșit „remediate") și nu se continuă cu vuln.
WSVC=$(python3 -c "import json;print(json.load(open('$LOG/discovery.json')).get('summary',{}).get('with_services',0))" 2>/dev/null || echo 0)
if [ "${WSVC:-0}" = 0 ]; then
    write_st "done total=0 error=no-services-found hosts=0 ended=$(date +%s)"; exit 1
fi

# 1b) COMPLETARE INCREMENTALĂ a structurii claselor (operator, 27 aug 2026): subrețelele nou descoperite
#     (cu gazde vii sau MAC real) se adaugă în $DEFT; nu se adaugă cele rutate prin VPN-ul SOC (wg) sau marcate „# EXCLUS".
python3 - "$LOG/discovery.json" "$DEFT" >>"$SCANS/$SID.discovery.log" 2>&1 <<'PY'
import json, sys, os, re, time, collections, subprocess
disc, deft = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(disc))
except Exception:
    sys.exit(0)
live, mac = collections.Counter(), collections.Counter()
for h in d.get("hosts", []):
    ip = h.get("ip", "")
    if ip.count(".") != 3 or not ip.startswith(("10.", "192.168.", "172.")):
        continue
    p = ".".join(ip.split(".")[:3]) + ".0/24"
    if h.get("services"): live[p] += 1
    if h.get("mac_real"): mac[p] += 1     # doar MAC REAL (ARP propriu), nu MAC-ul gateway-ului vazut pasiv (fix icisoc108)
existing, excluded = set(), set()
if os.path.exists(deft):
    for l in open(deft).read().splitlines():
        s = l.strip()
        mm = re.match(r"#\s*EXCLUS\s+(\S+)", s)
        if mm: excluded.add(mm.group(1)); continue
        if s and not s.startswith("#"): existing.add(s.split()[0])
def via_wg(p):
    try:
        r = subprocess.run(["ip", "route", "get", p.split("/")[0].rsplit(".", 1)[0] + ".1"],
                           capture_output=True, text=True, timeout=3).stdout
        return " dev wg" in r
    except Exception:
        return False
cand = sorted(set(live) | set(mac), key=lambda p: (-live[p], -mac[p]))
new = [p for p in cand if (live[p] > 0 or mac[p] > 0) and p not in existing and p not in excluded and not via_wg(p)]
if new:
    ts = time.strftime("%Y-%m-%d")
    first = not os.path.exists(deft)
    with open(deft, "a") as f:
        if first:
            f.write("# CYBER3 Scan - tinte implicite (citite de c3-engage.sh cand ADD TARGET din portal e GOL); # = comentariu, '# EXCLUS x' = nu se re-adauga\n")
        for p in new:
            f.write("%s   # adaugat %s (descoperit: vii=%d mac=%d)\n" % (p, ts, live[p], mac[p]))
    os.chmod(deft, 0o644)
    print("[c3-engage] structura claselor completata incremental: +%d subretele -> %s (%s)" % (len(new), deft, ", ".join(new)))
else:
    print("[c3-engage] structura claselor: nimic nou de adaugat in %s" % deft)
# istoric TOPOLOGIE per rulare (pasul 3 al algoritmului: actualizezi, salvezi, avansezi)
try:
    s = d.get("summary", {})
    vl = sorted(v for v in (s.get("vlans") or []) if v is not None)
    with open(deft, "a") as f:
        f.write("# topologie %s: gazde=%s mac_real=%s subretele=%s vlans=%s (%s)\n" % (
            time.strftime("%Y-%m-%d %H:%M"), s.get("hosts", 0), s.get("mac_real", 0),
            len(s.get("subnets") or []), vl if vl else "netaguit/rutat", d.get("phase", "?")))
except Exception:
    pass
PY

# 1c) ÎNVĂȚARE DISPOZITIVE (operator 27 aug): delta gazde NOI/schimbate/nevăzute față de inventarul învățat
#     (/etc/cyber3/inventory.json) + actualizarea inventarului → următorul scan pleacă de la el.
[ -f "$DIR/c3delta.py" ] && python3 "$DIR/c3delta.py" disc --disc "$LOG/discovery.json" --inv /etc/cyber3/inventory.json \
    --out "$SCANS/$SID.delta.json" --scan "$SID" --scope "$TGT" >>"$SCANS/$SID.discovery.log" 2>&1

write_st "running phase=vuln level=$LVL"
# 2) vulnerabilități: servicii expuse/SMBv1/TLS/panouri + CVE-KEV + SNMP public (FĂRĂ --creds din portal)
python3 "$DIR/c3vuln.py" --iface "$IFACE" --in "$LOG/discovery.json" \
    --out "$LOG/findings.json" >"$SCANS/$SID.vuln.log" 2>&1
RC2=$?
if [ $RC2 -ne 0 ] || [ ! -s "$LOG/findings.json" ]; then
    write_st "done total=0 error=vuln rc=$RC2 ended=$(date +%s)"; exit 1
fi

cp -f "$LOG/findings.json" "$SCANS/$SID.json" 2>/dev/null; chmod 644 "$SCANS/$SID.json"
cp -f "$LOG/discovery.json" "$SCANS/$SID.discovery.json" 2>/dev/null; chmod 644 "$SCANS/$SID.discovery.json"
# 2b) ÎNVĂȚARE VULNERABILITĂȚI: constatări NOI / REMEDIATE față de scanul anterior (baza /etc/cyber3/findings-baseline.json)
[ -f "$DIR/c3delta.py" ] && python3 "$DIR/c3delta.py" vuln --findings "$LOG/findings.json" --base /etc/cyber3/findings-baseline.json \
    --out "$SCANS/$SID.delta-vuln.json" --scan "$SID" --scope "$TGT" --disc "$LOG/discovery.json" >>"$SCANS/$SID.vuln.log" 2>&1
DELTA=$(python3 - "$SCANS/$SID.delta.json" "$SCANS/$SID.delta-vuln.json" <<'PY'
import json,sys
try:
    a=json.load(open(sys.argv[1]))["summary"]; b=json.load(open(sys.argv[2]))["summary"]
    print("hosts_new=%d hosts_changed=%d hosts_unseen=%d vuln_new=%d vuln_resolved=%d"%(a["new"],a["changed"],a["unseen"],b["new"],b["resolved"]))
except Exception:
    print("")
PY
)
SUM=$(python3 - "$LOG/findings.json" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1])); s=d.get("summary",{})
    print("total=%d critical=%d high=%d medium=%d low=%d kev=%d hosts=%d"%(
        s.get("total",0),s.get("critical",0),s.get("high",0),s.get("medium",0),
        s.get("low",0),s.get("kev",0),d.get("hosts_scanned",0)))
except Exception:
    print("total=0 error=parse")
PY
)
write_st "done $SUM ${DELTA:+$DELTA }ended=$(date +%s)"
exit 0
