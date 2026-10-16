export LC_ALL=C
SINCE=$(date -u -d '-24 hours' +%Y-%m-%dT%H:%M); SINCE_AR=$(date -u -d '-24 hours' '+%Y/%m/%d %H:%M')
E=/var/log/suricata/eve-alerts.json; F="$E $(ls -t /var/log/suricata/eve-alerts.json-* 2>/dev/null | head -1)"
ips=$(for f in $F; do zcat -f $f 2>/dev/null; done | awk -v s="$SINCE" -F'"timestamp":"' '{split($2,a,"\""); if (a[1]>=s && index($0,"\"action\":\"blocked\"")) n++} END{print n+0}')
alerts=$(for f in $F; do zcat -f $f 2>/dev/null; done | awk -v s="$SINCE" -F'"timestamp":"' '{split($2,a,"\""); if (a[1]>=s) n++} END{print n+0}')
ar=$(awk -v s="$SINCE_AR" 'substr($0,1,16)>=s' /var/ossec/logs/active-responses.log 2>/dev/null | grep -c 'firewall-drop-real.*"command": *"add"')
arskip=$(awk -v s="$SINCE_AR" 'substr($0,1,16)>=s' /var/ossec/logs/active-responses.log 2>/dev/null | grep -c 'SKIP')
l2=$(ebtables -L CYBER3_L2SHIELD --Lc 2>/dev/null | grep -oE 'pcnt = [0-9]+' | awk '{s+=$3} END{print s+0}')
ext=$(timeout 15 tcpdump -i br0 -nn -q -c 3000 ip 2>/dev/null | awk '{print $3}' | sed -E 's/\.[0-9]+:?$//' | awk '{ if ($1 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) p++; else q++ } END{ t=p+q; printf "%d%% surse externe (%d pachete)", (t? 100*q/t:0), t }')
echo "$(hostname) | alerte 24h=$alerts | IPS blocked 24h=$ips | AR add 24h=$ar (SKIP=$arskip) | L2 drops=$l2 | CYBER3_BLOCK=$(iptables -S CYBER3_BLOCK 2>/dev/null | grep -c '^-A') | trafic: $ext | suricata=$(systemctl is-active suricata) AR=$(grep -A1 '<active-response>' /var/ossec/etc/ossec.conf | grep -c '<disabled>yes')"
