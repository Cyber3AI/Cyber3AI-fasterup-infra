EXP="$1"; H=$(hostname); [ "$H" = "$EXP" ] || { echo "[$H] ABORT hostname"; exit 3; }
OUT=$(suricatasc -c dump-counters 2>/dev/null)
echo "$OUT" | python3 -c "
import json,sys
d=json.load(sys.stdin)['message']
ips=d.get('ips',{}); print('[$H] uptime s:', d.get('uptime'), '| ips:', json.dumps(ips))
fl=d.get('flow',{}); print('[$H] flow total:', fl.get('total'), 'tcp:', fl.get('tcp'), 'udp:', fl.get('udp'))
dec=d.get('decoder',{}); print('[$H] pachete decodate:', dec.get('pkts'), 'bytes:', dec.get('bytes'))
"
# drop-uri vizibile în eve (non-reputație) de la pornire
ST=$(date -u -d "$(systemctl show suricata -p ActiveEnterTimestamp --value)" +%Y-%m-%dT%H:%M:%S)
awk -v s="$ST" -F'"timestamp":"' '{split($2,a,"\""); if (a[1]>=s && index($0,"\"action\":\"blocked\"")) n++} END{print "['$H'] blocări vizibile în eve de la pornire:", n+0}' /var/log/suricata/eve-alerts.json
