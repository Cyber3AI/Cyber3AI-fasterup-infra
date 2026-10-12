#!/bin/bash
# icisoc107 — verificare READ-ONLY a vizibilității (oglindirea SPAN). Nu modifică nimic, nu repornește nimic.
# De rulat după ce clientul configurează oglindirea portului de uplink spre senzor; măsoară 120 s de trafic.
set -u
IF=enp2s0; OWN=192.168.0.199; T=120
c(){ suricatasc -c dump-counters 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin)['message']; print(d['decoder']['pkts'], d['decoder']['tcp'], d['decoder']['arp'], d['tcp']['sessions'], d['detect']['alert'])"; }
read P0 TCP0 ARP0 S0 A0 < <(c); L0=$(wc -l < /var/log/suricata/eve-alerts.json)
echo "== icisoc107 $(date -u +%FT%TZ): măsor ${T}s pe $IF =="
F=$(mktemp); timeout $T tcpdump -i "$IF" -nn -q -c 200000 "tcp and not host $OWN" 2>/dev/null | awk '{print $3">"$5}' | sed 's/\.[0-9]*>/>/;s/\.[0-9]*:$//' > "$F"
read P1 TCP1 ARP1 S1 A1 < <(c); L1=$(wc -l < /var/log/suricata/eve-alerts.json)
DP=$((P1-P0)); DT=$((TCP1-TCP0)); DA=$((ARP1-ARP0)); DS=$((S1-S0))
PAIRS=$(sort -u "$F" | wc -l); EXT=$(grep -vcE '^(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9.]*>(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01]))\.' "$F")
echo "pachete: $DP ($((DP/T))/s) | TCP: $DT ($(( DP>0 ? DT*100/DP : 0 ))%) | ARP: $DA ($(( DP>0 ? DA*100/DP : 0 ))%)"
echo "sesiuni TCP noi (fără senzor): $DS | perechi TCP terțe distincte: $PAIRS | pachete TCP intern<->Internet: $EXT"
echo "alerte noi: detect.alert +$((A1-A0)), eve-alerts.json +$((L1-L0)) linii"
if [ "$DT" -gt $((DP/5)) ] && [ "$EXT" -gt 100 ]; then echo "VERDICT: OGLINDIREA FUNCȚIONEAZĂ (trafic unicast al clientului vizibil)"; else echo "VERDICT: SENZOR ORB — vede doar broadcast/multicast și propriul trafic; oglindirea SPAN lipsește sau e greșită"; fi
rm -f "$F"
