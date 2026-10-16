# READ-ONLY: IP-uri blocate (CYBER3_BLOCK + DROP directe) care sunt folosite de client ca servere DNS (dest_port 53 în eve-alerts, 7 zile)
BL=$(iptables -S 2>/dev/null | grep -oE '^-A (INPUT|FORWARD|CYBER3_BLOCK) -s [0-9.]+(/32)? -j DROP' | awk '{print $4}' | sed 's#/32##' | sort -u)
DNS=$(for f in /var/log/suricata/eve-alerts.json $(ls -t /var/log/suricata/eve-alerts.json-* 2>/dev/null | head -6); do zcat -f $f 2>/dev/null; done | grep -oE '"dest_ip":"[0-9.]+","dest_port":(53|853)[,}]' | cut -d'"' -f4 | sort | uniq -c | sort -rn)
HIT=""; for ip in $BL; do n=$(echo "$DNS" | awk -v x="$ip" '$2==x{print $1}'); [ -n "$n" ] && HIT="$HIT $ip($n interogări DNS)"; done
PUB=$(for ip in $BL; do case $ip in 8.8.8.8|8.8.4.4|1.1.1.1|1.0.0.1|9.9.9.9|149.112.112.112|208.67.222.222|208.67.220.220|193.231.*|81.12.*|213.154.124.1|96.45.45.45|96.45.46.46|94.140.14.*|84.116.46.*|193.226.*|194.102.*|212.*.*.53) echo -n "$ip ";; esac; done)
echo "$(hostname) | blocate=$(echo "$BL" | grep -c .) | REZOLVERE ALE CLIENTULUI BLOCATE:${HIT:- niciunul} | rezolvere publice cunoscute blocate: ${PUB:-niciunul} | top DNS client: $(echo "$DNS" | head -3 | awk '{printf "%s(%s) ",$2,$1}')"
