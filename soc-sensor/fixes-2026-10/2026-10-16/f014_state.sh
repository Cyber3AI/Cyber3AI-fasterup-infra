H=$(hostname); [ "$H" = f014 ] || { echo "[$H] ABORT hostname"; exit 3; }
echo "[$H] uptime: $(uptime -p) | ora UTC $(date -u +%H:%M)"
ip -br link | sed 's/^/   /'; ip -br -4 a | grep -v '^lo' | sed 's/^/   addr /'
for i in /sys/class/net/*/brif/*; do echo "   port punte: $(basename $(dirname $(dirname $i)))/$(basename $i) carrier=$(cat /sys/class/net/$(basename $i)/carrier 2>/dev/null)"; done
echo "   ruta implicită: $(ip r | grep default)"
a=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{s+=$1} END{print s+0}'); sleep 10; b=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{s+=$1} END{print s+0}')
echo "[$H] NFQUEUE reguli=$(iptables -S FORWARD | grep -c NFQUEUE) bypass=$(iptables -S FORWARD | grep -c queue-bypass) | trafic 10 s=+$((b-a)) | cozi=$(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue)"
echo "[$H] suricata=$(systemctl is-active suricata) agent=$(systemctl is-active wazuh-agent) wg=$(systemctl is-active wg-quick@wg0 2>/dev/null) l2shield=$(systemctl is-active cyber3-l2shield 2>/dev/null)"
echo "[$H] relay-2 în supresii: $(grep -ci relay /etc/suricata/threshold.config)"
echo "[$H] ultimele alerte (5 min): $(awk -v s=$(date -u -d '-5 min' +%Y-%m-%dT%H:%M:%S) -F'"timestamp":"' '{split($2,a,"\""); if (a[1]>=s) n++} END{print n+0}' /var/log/suricata/eve-alerts.json)"
