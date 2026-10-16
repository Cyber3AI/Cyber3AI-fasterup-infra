#!/bin/bash
# READ-ONLY. Sănătatea senzorului după modificările 15–16.10. Nu scrie nimic, nu repornește nimic.
export LC_ALL=C
H=$(hostname); EXP="${1:-}"; [ -z "$EXP" ] || [ "$H" = "$EXP" ] || { echo "[$H] ABORT hostname (aștept $EXP)"; exit 3; }
L=/var/log/suricata/suricata.log; W=""
SA=$(systemctl is-active suricata); SINCE=$(systemctl show suricata -p ActiveEnterTimestamp --value | awk '{print $2,$3}')
N0=$(grep -n 'This is Suricata version' $L 2>/dev/null | tail -1 | cut -d: -f1); N0=${N0:-1}
LOAD=$(tail -n +$N0 $L 2>/dev/null | grep -oE '[0-9]+ rule files processed. [0-9]+ rules successfully loaded, [0-9]+ rules failed' | tail -1)
ERR=$(tail -n +$N0 $L 2>/dev/null | grep -c '<Error>')
Q=$(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null)
qd(){ awk '{s+=$6+$7} END{print s+0}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null; }
nf(){ iptables -L FORWARD -v -n -x 2>/dev/null | awk '/NFQUEUE/{s+=$1} END{print s+0}'; }
BR=$(ls -d /sys/class/net/*/bridge 2>/dev/null | head -1 | cut -d/ -f5)
PORTS=$(ls /sys/class/net/$BR/brif 2>/dev/null | tr '\n' ' ')
rx(){ for p in $PORTS; do echo -n "$(cat /sys/class/net/$p/statistics/rx_packets) "; done; }
Q0=$(qd); F0=$(nf); R0=($(rx)); sleep 10; Q1=$(qd); F1=$(nf); R1=($(rx))
i=0; PT=""; for p in $PORTS; do d=$(( ${R1[$i]} - ${R0[$i]} )); PT="$PT$p:+$d "; [ "$d" -gt 0 ] || W="$W port_${p}_fără_trafic"; i=$((i+1)); done
CNT=$(suricatasc -c dump-counters 2>/dev/null | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)['message']; i=d.get('ips',{}); a=i.get('accepted',0); b=i.get('blocked',0); r=i.get('drop_reason',{})
  print(f\"blocat={100*b/max(a+b,1):.2f}% (reguli={r.get('rules',0)} stream_err={r.get('stream_error',0)} flow={r.get('flow_drop',0)}) uptime={d.get('uptime')}s\")
except Exception: print('contoare=NA')" 2>/dev/null)
A=/etc/cyber3/ar-allowlist.txt
AB=0; for ip in $(grep -vE '^\s*#|^\s*$' $A 2>/dev/null | awk '{print $1}' | grep -E '^[0-9.]+$'); do iptables -S 2>/dev/null | grep -q -- "-s $ip/32 -j DROP" && { AB=$((AB+1)); W="$W allowlist_${ip}_BLOCAT"; }; done
TN=$(iptables -S 2>/dev/null | grep -c '192.0.2.234'); [ "$TN" = 0 ] || W="$W IP_test_rămas"
AG=$(systemctl is-active wazuh-agent); AGC=$(grep -oE "status='[a-z]+'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null | cut -d"'" -f2)
HS=$(wg show wg1 latest-handshakes 2>/dev/null | awk '{print $2}' | head -1); HSA=$(( $(date +%s) - ${HS:-0} ))
FU=$(systemctl --failed --no-legend 2>/dev/null | grep -vc 'wg-quick@wg0')
[ "$SA" = active ] || W="$W suricata_$SA"
[ -z "$LOAD" ] || echo "$LOAD" | grep -q ', 0 rules failed' || [ "$H" = f002 ] || [ "$H" = f005 ] || W="$W reguli_eșuate"
[ "$ERR" = 0 ] || W="$W erori_log=$ERR"
[ "$Q" = 4 ] || [ "$H" = icisoc107 ] || [ "$H" = fasterup ] || W="$W cozi=$Q"
[ $((Q1-Q0)) = 0 ] || W="$W qdrop+$((Q1-Q0))"
[ "$AG" = active ] && [ "$AGC" = connected ] || W="$W agent_${AG}_${AGC}"
[ "$HSA" -lt 180 ] || W="$W wg_handshake_${HSA}s"
[ "$FU" = 0 ] || W="$W unități_eșuate=$FU"
echo "[$H] suricata=$SA din $SINCE | ${LOAD:-reguli NA} | erori=$ERR | cozi=$Q qdrop+$((Q1-Q0)) | NFQ+$((F1-F0))/10s | punte $PT| $CNT | allowlist_blocate=$AB | test_IP=$TN | agent=$AGC | wg=${HSA}s | VERDICT: ${W:-OK}"
