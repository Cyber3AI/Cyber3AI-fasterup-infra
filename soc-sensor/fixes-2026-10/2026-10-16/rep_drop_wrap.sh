#!/bin/bash
# Pe senzor (root): $1 = hostname așteptat. Măsoară traficul înainte/după și rulează scriptul canonic rep_drop_sensor.sh.
EXP="$1"; H=$(hostname); [ "$H" = "$EXP" ] || { echo "[$H] ABORT: hostname diferit de $EXP — nimic modificat"; exit 3; }
m(){ a=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{print $1}'); qa=$(awk '{s+=$6} END{print s+0}' /proc/net/netfilter/nfnetlink_queue); sleep 10
     b=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{print $1}'); qb=$(awk '{s+=$6} END{print s+0}' /proc/net/netfilter/nfnetlink_queue); echo "$((b-a)) $((qb-qa))"; }
read P0 D0 < <(m); echo "[$H] ÎNAINTE: trafic NFQUEUE 10 s=+$P0 pachete, qdrop +$D0"
bash /tmp/rds.sh; RC=$?
sleep 5; read P1 D1 < <(m)
echo "[$H] DUPĂ: trafic NFQUEUE 10 s=+$P1 pachete, qdrop +$D1 | suricata=$(systemctl is-active suricata) cozi=$(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue) | drop reputație încărcate=$(grep -cE '^drop .*(Spamhaus (DROP|EDROP) Listed|Dshield Block Listed|CINS Active Threat)' /var/lib/suricata/rules/suricata.rules) | erori log de la pornire=$(tail -n +$(grep -n 'This is Suricata version' /var/log/suricata/suricata.log | tail -1 | cut -d: -f1) /var/log/suricata/suricata.log | grep -c '<Error>')"
if [ "$RC" != 0 ]; then echo "[$H] REZULTAT: rc=$RC (scriptul canonic a revenit / a sărit)"; exit $RC; fi
if [ "$P0" -gt 50 ] && [ "$P1" -eq 0 ]; then echo "[$H] ALARMĂ: traficul nu mai trece prin NFQUEUE după restart — STOP"; exit 9; fi
echo "[$H] REZULTAT: OK"
