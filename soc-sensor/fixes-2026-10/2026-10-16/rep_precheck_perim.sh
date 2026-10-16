#!/bin/bash
# READ-ONLY. Înainte de armarea DROP pe reputație: verifică dacă vreo adresă folosită de client (allowlist, rezolvere DNS,
# destinațiile contactate de stații în 60 s) se află în rețelele listate de regulile Spamhaus/DShield/CINS.
# Dacă da -> armarea pe acest senzor NU se face până la analiză. Nu modifică nimic.
export LC_ALL=C
EXP="${1:-}"; H=$(hostname); [ "$H" = "$EXP" ] || { echo "[$H] ABORT hostname"; exit 3; }
R=/var/lib/suricata/rules/suricata.rules; REP='(Spamhaus (DROP|EDROP) Listed|Dshield Block Listed|CINS Active Threat Intelligence Poor Reputation)'
BR=$(ls -d /sys/class/net/*/bridge 2>/dev/null | head -1 | cut -d/ -f5)
grep -E "^(alert|drop) .*$REP" $R | grep -oE '\[[^]]+\]' | tr -d '[]' | tr ',' '\n' | grep -E '^[0-9.]+(/[0-9]+)?$' | sort -u > /tmp/c3_rep_nets.txt
grep -vE '^\s*#|^\s*$' /etc/cyber3/ar-allowlist.txt | awk '{print $1}' > /tmp/c3_allow.txt
timeout 60 tcpdump -i "$BR" -nn -q -c 30000 ip 2>/dev/null | awk '{s=$3; d=$5; sub(/\.[0-9]+$/,"",s); sub(/\.[0-9]+:?$/,"",d); print s, d}' \
  | awk -v own="$OWN" 'BEGIN{n=split(own,o," "); for(i=1;i<=n;i++) m[o[i]]=1} (m[$1] || $1 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) && !($2 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) && !m[$2] {c[$2]++} END{for(k in c) print c[k], k}' | sort -rn > /tmp/c3_dst.txt
python3 - <<'PY'
import ipaddress, socket
nets = [ipaddress.ip_network(l.strip(), strict=False) for l in open('/tmp/c3_rep_nets.txt') if l.strip()]
def hit(x):
    try:
        n = ipaddress.ip_network(x, strict=False)
    except ValueError:
        return []
    return [str(r) for r in nets if r.overlaps(n)]
allow = [l.strip() for l in open('/tmp/c3_allow.txt') if l.strip()]
dst = [l.split() for l in open('/tmp/c3_dst.txt') if l.strip()]
ah = [(a, hit(a)) for a in allow if hit(a)]
dh = [(ip, int(c), hit(ip)) for c, ip in dst if hit(ip)]
tot = sum(int(c) for c, _ in dst)
host = socket.gethostname()
print(f"[{host}] rețele în listele de reputație: {len(nets)} | allowlist verificate: {len(allow)} -> pe liste: {len(ah)} | destinații contactate de clienți (60 s): {len(dst)} adrese / {tot} pachete -> pe liste: {len(dh)} adrese / {sum(c for _,c,_ in dh)} pachete")
for a, r in ah: print(f"   ⚠ ALLOWLIST {a} în {r[:3]}")
for ip, c, r in sorted(dh, key=lambda x: -x[1])[:10]: print(f"   ⚠ DESTINAȚIE CLIENT {ip} ({c} pachete) în {r[:3]}")
print(f"[{host}] VERDICT: {'SIGUR pentru armare' if not ah and not dh else 'NU arma încă — analiză necesară'}")
PY
rm -f /tmp/c3_rep_nets.txt /tmp/c3_allow.txt /tmp/c3_dst.txt
