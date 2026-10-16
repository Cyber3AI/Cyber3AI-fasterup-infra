#!/bin/bash
# READ-ONLY. După armarea reputației: trafic pe 4 intervale de 10 s (NFQUEUE vs punte), contoare de drop Suricata, qdrop.
EXP="$1"; H=$(hostname); [ "$H" = "$EXP" ] || { echo "[$H] ABORT hostname"; exit 3; }
BR=$(ls -d /sys/class/net/*/bridge 2>/dev/null | head -1 | cut -d/ -f5)
for i in 1 2 3 4; do
  a=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{s+=$1} END{print s+0}'); ra=$(cat /sys/class/net/$BR/statistics/rx_packets)
  sleep 10
  b=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{s+=$1} END{print s+0}'); rb=$(cat /sys/class/net/$BR/statistics/rx_packets)
  echo "[$H] interval $i: NFQUEUE +$((b-a)) | punte $BR rx +$((rb-ra))"
done
echo "[$H] cozi (id pachete_în_coadă dropped_user):"; awk '{print "   ", $1, $3, $5, $6}' /proc/net/netfilter/nfnetlink_queue
echo "[$H] suricata activ din: $(systemctl show suricata -p ActiveEnterTimestamp --value)"
S=/var/log/suricata/stats.log
[ -f $S ] && { echo "[$H] contoare drop (ultimul bloc stats.log):"; tac $S | awk '/^Date:/{exit} {print}' | grep -E 'ips\.(accepted|blocked|rejected|replaced|drop_reason)' | awk -F'|' '{gsub(/ /,"",$1); gsub(/ /,"",$3); print "   ", $1, $3}' | sort -u; }
