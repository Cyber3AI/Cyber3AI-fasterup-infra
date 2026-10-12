#!/bin/bash
# Rulează PE SENZOR ca root. Armare DROP pe reputație (Spamhaus DROP/EDROP, DShield, CINS) — aceeași procedură ca f001 (7.10.2026).
# Gărzi: precheck --queue-bypass, backup, sanity după suricata-update, regulile locale CYBER3 păstrate, un singur restart controlat,
# verificare că cele 4 cozi NFQUEUE sunt reluate, auto-revert. NICIODATĂ suricata -T pe senzorul inline viu.
set -o pipefail
H=$(hostname)
DC=/etc/suricata/drop.conf
RULES=/var/lib/suricata/rules/suricata.rules
TS=$(date -u +%Y%m%d-%H%M%S)
REP='(Spamhaus (DROP|EDROP) Listed|Dshield Block Listed|CINS Active Threat)'
say(){ echo "[$H] $*"; }
localsids(){ cat /var/lib/suricata/rules/*.rules /etc/suricata/rules/*.rules 2>/dev/null | grep -v '^#' | grep -oE 'sid: ?9[0-9]{6}' | sort -u | wc -l; }
nfq(){ awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null; }

QB=$(iptables -S FORWARD 2>/dev/null | grep NFQUEUE | grep -c -- --queue-bypass)
[ "$QB" -ge 1 ] || { say "ABORT: NFQUEUE fără --queue-bypass"; exit 3; }
grep -q "armare drop reputatie" "$DC" && { say "SKIP: drop pe reputație deja armat"; exit 0; }
systemctl is-active --quiet suricata || { say "ABORT: suricata nu rulează"; exit 3; }
DROP0=$(grep -c '^drop ' "$RULES"); RA0=$(grep -cE "^alert .*$REP" "$RULES"); LS0=$(localsids); Q0=$(nfq)
say "înainte: drop=$DROP0 reputatie_alert=$RA0 reguli_locale_CYBER3=$LS0 cozi_NFQ=$Q0"

cp -a "$DC" "$DC.bak-rep-drop-$TS" && cp -a "$RULES" "$RULES.bak-rep-drop-$TS" || { say "ABORT: backup"; exit 1; }
revert(){
  say "AUTO-REVERT"; cp -a "$RULES.bak-rep-drop-$TS" "$RULES"; cp -a "$DC.bak-rep-drop-$TS" "$DC"
  systemctl restart suricata; sleep 20; say "revert: suricata=$(systemctl is-active suricata) cozi_NFQ=$(nfq)"
}
cat >> "$DC" <<EOF
# CYBER3 12oct2026 armare drop reputatie INBOUND la perimetru $H (operator)
re:Spamhaus (DROP|EDROP) Listed
re:Dshield Block Listed
re:CINS Active Threat Intelligence Poor Reputation
EOF
say "drop.conf actualizat; suricata-update --no-test --no-reload ..."
suricata-update --no-test --no-reload 2>&1 | tail -3

DN=$(grep -cE "^drop .*$REP" "$RULES"); AN=$(grep -cE "^alert .*$REP" "$RULES"); TOT=$(wc -l < "$RULES"); DROP1=$(grep -c '^drop ' "$RULES"); LS1=$(localsids)
say "după update: reputatie DROP=$DN alert_rămas=$AN drop_total=$DROP0→$DROP1 total_reguli=$TOT reguli_locale=$LS0→$LS1"
if [ "$DN" -lt 300 ] || [ "$AN" -ne 0 ] || [ "$TOT" -lt 50000 ] || [ "$LS1" -lt "$LS0" ] || [ "$DROP1" -lt "$DROP0" ]; then
  say "SANITY EȘUAT"; cp -a "$RULES.bak-rep-drop-$TS" "$RULES"; cp -a "$DC.bak-rep-drop-$TS" "$DC"; say "fișiere restaurate, suricata NErepornit"; exit 4
fi

systemctl restart suricata
OK=0
for i in $(seq 1 36); do sleep 5; [ "$(systemctl is-active suricata)" = active ] && [ "$(nfq)" -ge "${Q0:-4}" ] && { OK=1; break; }; done
[ $OK = 1 ] || { say "suricata nu a reluat cozile NFQ în 180 s (stare=$(systemctl is-active suricata), cozi=$(nfq))"; revert; exit 5; }
sleep 15
systemctl is-active --quiet suricata || { say "suricata a căzut după pornire"; revert; exit 5; }
systemctl restart wazuh-agent
QB2=$(iptables -S FORWARD 2>/dev/null | grep NFQUEUE | grep -c -- --queue-bypass)
say "OK: suricata=$(systemctl is-active suricata) agent=$(systemctl is-active wazuh-agent) cozi_NFQ=$(nfq) queue-bypass=$QB2 reputatie_DROP=$DN"
say "ROLLBACK: cp -a $RULES.bak-rep-drop-$TS $RULES; cp -a $DC.bak-rep-drop-$TS $DC; systemctl restart suricata"
