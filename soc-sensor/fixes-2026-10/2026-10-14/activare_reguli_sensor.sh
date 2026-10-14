#!/bin/bash
# Rulează PE SENZOR ca root. Activează regulile CYBER3 (cyber3-local.rules) + MISP IOC (cyber3-misp.rules)
# în rule-files, ordinea canonică f001: suricata.rules, cyber3-misp.rules, cyber3-local.rules (+ ce mai există).
# Gărzi: precheck --queue-bypass + suricata activă, backup, UN restart controlat (NICIODATĂ suricata -T / reload-rules
# pe senzor inline viu), verificare „3+ rule files processed” + 0 failed + 4 cozi + trafic, auto-revert.
set -u
H=$(hostname); TS=$(date -u +%Y%m%d-%H%M%S)
Y=/etc/suricata/suricata.yaml; RP=/var/lib/suricata/rules; L=/var/log/suricata/suricata.log
say(){ echo "[$H $(date -u +%T)] $*"; }
nfq(){ awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null; }

iptables -S FORWARD | grep NFQUEUE | grep -q -- --queue-bypass || { say "ABORT: NFQUEUE fără --queue-bypass"; exit 3; }
systemctl is-active --quiet suricata || { say "ABORT: suricata nu rulează"; exit 3; }
test -s $RP/cyber3-local.rules || { say "ABORT: lipsește cyber3-local.rules"; exit 3; }
BEFORE=$(grep -E 'rules successfully loaded' $L | tail -1 | grep -oE '[0-9]+ rule files processed. [0-9]+ rules successfully loaded')
say "înainte: $BEFORE | cozi=$(nfq)"

cp -a $Y $Y.bak-activare-$TS
if [ ! -s $RP/cyber3-misp.rules ]; then
  install -m 640 -o suricata -g suricata /tmp/cyber3-misp.rules $RP/cyber3-misp.rules && say "cyber3-misp.rules instalat (referința f001, sha $(sha256sum $RP/cyber3-misp.rules | cut -c1-12))"
  NEWMISP=1
else NEWMISP=0; fi
test -s /etc/suricata/datasets/misp-domains.lst || { say "ABORT: lipsește datasetul MISP"; cp -a $Y.bak-activare-$TS $Y; exit 3; }

python3 - "$Y" <<'PY'
import sys, re
p = sys.argv[1]; s = open(p).read()
m = re.search(r"^rule-files:\n((?:[ \t]+- .*\n)+)", s, re.M)
cur = [x.strip()[2:].strip() for x in m.group(1).splitlines()]
want = ['suricata.rules', 'cyber3-misp.rules', 'cyber3-local.rules']
new = want + [x for x in cur if x not in want]
s = s[:m.start()] + "rule-files:\n" + "".join(f"  - {x}\n" for x in new) + s[m.end():]
open(p, "w").write(s)
print("rule-files:", " ".join(new))
PY

revert(){
  say "AUTO-REVERT: $1"
  cp -a $Y.bak-activare-$TS $Y; [ "$NEWMISP" = 1 ] && rm -f $RP/cyber3-misp.rules
  systemctl restart suricata; sleep 40
  say "revert: suricata=$(systemctl is-active suricata) cozi=$(nfq)"; exit 2
}

N0=$(wc -l < $L); T0=$(date +%s)
systemctl restart suricata
OK=0
for i in $(seq 1 50); do
  sleep 4
  tail -n +$N0 $L | grep -q "Engine started" && [ "$(nfq)" = 4 ] && { OK=1; break; }
  systemctl is-failed --quiet suricata && break
done
LOAD=$(tail -n +$N0 $L | grep -E 'rules successfully loaded' | tail -1 | grep -oE '[0-9]+ rule files processed. [0-9]+ rules successfully loaded, [0-9]+ rules failed')
ERR=$(tail -n +$N0 $L | grep -c '<Error>')
[ "$OK" = 1 ] || revert "motorul nu a pornit cu 4 cozi în 200 s"
echo "$LOAD" | grep -qE '^[3-9] rule files processed' || revert "nu se încarcă 3 fișiere ($LOAD)"
echo "$LOAD" | grep -q ', 0 rules failed' || revert "reguli eșuate ($LOAD)"
[ "$ERR" = 0 ] || revert "$ERR erori în suricata.log"
iptables -Z FORWARD 2>/dev/null; sleep 8
PK=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{print $1}')
QD=$(awk '{s+=$6} END{print s+0}' /proc/net/netfilter/nfnetlink_queue)
systemctl restart wazuh-agent
say "DUPĂ ($(( $(date +%s)-T0 )) s): $LOAD | cozi=$(nfq) | trafic NFQUEUE 8 s=$PK pachete | qdrop=$QD | erori=0 | wazuh-agent=$(systemctl is-active wazuh-agent)"
say "OK — backup $Y.bak-activare-$TS"
