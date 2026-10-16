#!/bin/bash
# f010 după cablarea inline: verificare carrier + forwarding → UN restart Suricata (obligatoriu: pornit fără carrier) →
# verificare 4 cozi / trafic / 0 pierderi → descoperire READ-ONLY a adresei publice dominante (pentru allowlist, cu confirmare).
# Nu modifică iptables/allowlist. Fără suricata -T / reload-rules.
set -u
[ "$(hostname)" = f010 ] || { echo "ABORT: nu sunt pe f010 ($(hostname))"; exit 3; }
L=/var/log/suricata/suricata.log
P="$(ls /sys/class/net/br0/brif | tr '\n' ' ')"
for p in $P; do echo "$p carrier=$(cat /sys/class/net/$p/carrier) speed=$(cat /sys/class/net/$p/speed 2>/dev/null)"; done
for p in $P; do [ "$(cat /sys/class/net/$p/carrier)" = 1 ] || { echo "ABORT: $p fără carrier — verificați cablul; Suricata NU a fost repornit"; exit 4; }; done
c(){ for p in $P; do printf '%s ' $(( $(cat /sys/class/net/$p/statistics/rx_packets) + $(cat /sys/class/net/$p/statistics/tx_packets) )); done; }
a=$(c); sleep 5; b=$(c); echo "trafic pe punte în 5 s (rx+tx per port): înainte [$a] după [$b]"
iptables -S FORWARD | grep NFQUEUE | grep -q -- --queue-bypass || { echo "ABORT: NFQUEUE fără --queue-bypass"; exit 3; }
N0=$(wc -l < $L); T0=$(date +%s)
systemctl restart suricata
for i in $(seq 1 50); do sleep 4; tail -n +$N0 $L | grep -q "Engine started" && [ "$(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue)" = 4 ] && break; done
echo "Suricata repornit în $(( $(date +%s)-T0 )) s: $(systemctl is-active suricata) | $(tail -n +$N0 $L | grep -oE '[0-9]+ rule files processed. [0-9]+ rules successfully loaded, [0-9]+ rules failed') | erori=$(tail -n +$N0 $L | grep -c '<Error>') | cozi=$(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue)"
q1=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{print $1}'); d1=$(awk '{s+=$6} END{print s+0}' /proc/net/netfilter/nfnetlink_queue); sleep 10
q2=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{print $1}'); d2=$(awk '{s+=$6} END{print s+0}' /proc/net/netfilter/nfnetlink_queue)
echo "NFQUEUE în 10 s: +$((q2-q1)) pachete | qdrop +$((d2-d1)) | VLAN în trafic: $(timeout 6 tcpdump -i br0 -nn -e -c 200 2>/dev/null | grep -c 802.1Q)/200"
echo "== adrese PUBLICE dominante pe punte (30 s, doar citire) — candidați pentru adresa proprie a instituției:"
timeout 30 tcpdump -i br0 -nn -q -c 20000 ip 2>/dev/null | awk '{print $3; print $5}' | sed -E 's/\.[0-9]+:?$//' | grep -vE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|224\.|239\.|255\.)' | sort | uniq -c | sort -rn | head -6
echo "allowlist actuală: $(grep -v '^#' /etc/cyber3/ar-allowlist.txt | grep -vE '^(8\.8|1\.|9\.9|149\.|208\.|142\.|172\.|216\.|74\.|64\.|209\.|108\.)' | tr '\n' ' ')"
