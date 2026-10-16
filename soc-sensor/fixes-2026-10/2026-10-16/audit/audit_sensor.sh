#!/bin/bash
# AUDIT READ-ONLY senzor (14.10.2026 seara). NU modifică nimic: fără restart, fără reload, fără iptables/ebtables scrieri.
# Măsurători empirice: contoare citite de 2 ori la interval (trafic, cozi, pierderi), nu doar existența fișierelor.
export LC_ALL=C
H=$(hostname); L=/var/log/suricata/suricata.log; Y=/etc/suricata/suricata.yaml; RP=/var/lib/suricata/rules
P(){ printf '%s|%s\n' "$1" "$2"; }
nf(){ awk '{q+=$6; u+=$7} END{print NR, q+0, u+0}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null; }
fwd(){ iptables -L FORWARD -v -n -x 2>/dev/null | awk '/NFQUEUE/{print $1}'; }
BR=$(ls -d /sys/class/net/*/bridge 2>/dev/null | head -1 | cut -d/ -f5)
PORTS=$(ls /sys/class/net/$BR/brif 2>/dev/null | tr '\n' ' ')
cnt(){ for p in $PORTS; do printf '%s:%s:%s ' $p $(cat /sys/class/net/$p/statistics/rx_packets) $(cat /sys/class/net/$p/statistics/tx_packets); done; }

P host "$H"
P suricata "$(systemctl is-active suricata) sub=$(systemctl show suricata -p SubState --value) start=$(systemctl show suricata -p ActiveEnterTimestamp --value) NRestarts=$(systemctl show suricata -p NRestarts --value)"
START_EPOCH=$(date -d "$(systemctl show suricata -p ActiveEnterTimestamp --value)" +%s 2>/dev/null)
P rulefiles_yaml "$(awk '/^rule-files:/{f=1;next} f&&/^[[:space:]]*-/{printf "%s ",$2;next} f{exit}' $Y)"
P loaded "$(grep -E 'rules successfully loaded' $L | tail -1 | grep -oE '[0-9]+ rule files processed. [0-9]+ rules successfully loaded, [0-9]+ rules failed, [0-9]+ rules skipped')"
P threshold "$(grep -oE 'Threshold config parsed: [0-9]+' $L | tail -1)"
# erori/avertismente DOAR din pornirea curentă
NSTART=$(grep -n 'This is Suricata version' $L | tail -1 | cut -d: -f1); NSTART=${NSTART:-1}
P err_since_start "$(tail -n +$NSTART $L | grep -c '<Error>')"
P warn_since_start "$(tail -n +$NSTART $L | grep -c '<Warning>')"
P err_lines "$(tail -n +$NSTART $L | grep -E '<Error>|<Warning>' | sed 's/^.*<\(Error\|Warning\)> - //' | sort | uniq -c | sort -rn | head -4 | tr '\n' ';')"
P badb64 "$(tail -n +$NSTART $L | grep -ci 'bad base64')"
P execstart "$(systemctl show suricata -p ExecStart --value | grep -oE '\-q [0-9]' | tr '\n' ' ')"
P failopen "$(grep -cE '^[[:space:]]+fail-open:[[:space:]]*yes' $Y) runmode=$(grep -E '^runmode:' $Y | awk '{print $2}')"
P forward_chain "$(iptables -S FORWARD | tail -n +2 | tr '\n' ' ')"
P socket "$(timeout 8 suricatasc -c uptime 2>/dev/null | grep -oE '"message": ?[0-9]+' | grep -oE '[0-9]+')s"
P rulestats "$(timeout 10 suricatasc -c ruleset-stats 2>/dev/null | tr -d ' \n' | cut -c1-160)"
# EMPIRIC: trafic + cozi pe 20 s
A1=$(fwd); N1=$(nf); C1=$(cnt); sleep 20; A2=$(fwd); N2=$(nf); C2=$(cnt)
P bridge "$BR ports=[$PORTS] carrier=$(cat /sys/class/net/$BR/carrier 2>/dev/null)"
P nfqueue_20s "pachete +$(( ${A2:-0} - ${A1:-0} )) | cozi=$(echo $N2 | awk '{print $1}') qdrop +$(( $(echo $N2|awk '{print $2}') - $(echo $N1|awk '{print $2}') )) udrop +$(( $(echo $N2|awk '{print $3}') - $(echo $N1|awk '{print $3}') )) (total qdrop=$(echo $N2|awk '{print $2}'))"
P ports_20s "$(for p in $PORTS; do r1=$(echo "$C1" | tr ' ' '\n' | grep "^$p:" | cut -d: -f2); r2=$(echo "$C2" | tr ' ' '\n' | grep "^$p:" | cut -d: -f2); t1=$(echo "$C1" | tr ' ' '\n' | grep "^$p:" | cut -d: -f3); t2=$(echo "$C2" | tr ' ' '\n' | grep "^$p:" | cut -d: -f3); printf '%s rx+%s tx+%s; ' $p $((r2-r1)) $((t2-t1)); done)"
# blocări IPS (eve) — ultimele 6 h, pe semnătură; + cele 3 SID CYBER3 / MISP de la ora activării
E=/var/log/suricata/eve-alerts.json
SINCE=$(date -u -d '-6 hours' +%Y-%m-%dT%H:%M)
P blocked_6h "$(awk -v s="$SINCE" -F'"timestamp":"' '{split($2,a,"\""); if (a[1] >= s && index($0,"\"action\":\"blocked\"")) print}' $E 2>/dev/null | grep -oE '"signature":"[^"]{0,60}' | sort | uniq -c | sort -rn | head -5 | sed 's/"signature":"//' | tr '\n' ';')"
P blocked_6h_total "$(awk -v s="$SINCE" -F'"timestamp":"' '{split($2,a,"\""); if (a[1] >= s && index($0,"\"action\":\"blocked\"")) n++} END{print n+0}' $E 2>/dev/null)"
P cyber3_misp_alerts_6h "$(awk -v s="$SINCE" -F'"timestamp":"' '{split($2,a,"\""); if (a[1] >= s) print}' $E 2>/dev/null | grep -oE '"signature_id":(390000[123]|310001[0-2]|91009[0-9]{2})' | sort | uniq -c | tr '\n' ' ')"
P blocked_internal_dst_6h "$(awk -v s="$SINCE" -F'"timestamp":"' '{split($2,a,"\""); if (a[1] >= s && index($0,"\"action\":\"blocked\"")) print}' $E 2>/dev/null | grep -oE '"dest_ip":"(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)[^"]*","dest_port":[0-9]+' | sort | uniq -c | sort -rn | head -3 | tr '\n' ';')"
# AR / permaban / allowlist
P ar_wrapper "$(md5sum /var/ossec/active-response/bin/firewall-drop | cut -c1-8) real=$(test -x /var/ossec/active-response/bin/firewall-drop-real && echo DA || echo NU)"
P cyber3_block "$(iptables -S CYBER3_BLOCK 2>/dev/null | grep -c '^-A') reguli; jump INPUT=$(iptables -S INPUT | grep -c 'CYBER3_BLOCK') FORWARD=$(iptables -S FORWARD | grep -c 'CYBER3_BLOCK')"
BL=$(iptables -S 2>/dev/null | grep -oE '^-A (INPUT|FORWARD|CYBER3_BLOCK) -s [0-9.]+(/32)? -j DROP' | awk '{print $4}' | sed 's#/32##' | sort -u)
P blocked_private "$(echo "$BL" | grep -cE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)')"
P blocked_in_allowlist "$(for ip in $BL; do grep -qxF "$ip" /etc/cyber3/ar-allowlist.txt 2>/dev/null && echo $ip; done | tr '\n' ' ')"
P temp_ar_blocks_now "$(iptables -S INPUT | grep -cE '^-A INPUT -s [0-9.]+/32 -j DROP')"
P permaban_timer "$(systemctl is-active cyber3-permaban.timer) list=$(wc -l < /etc/cyber3/permaban.list 2>/dev/null)"
P ar_log_last "$(tail -1 /var/ossec/logs/active-responses.log 2>/dev/null | cut -c1-110)"
# MLEO / L2
P mleo "$(test -x /usr/local/sbin/cyber3-mleo-contain && /usr/local/sbin/cyber3-mleo-contain status 2>&1 | tail -1) state=$(wc -l < /var/lib/cyber3/mleo-contain.state 2>/dev/null)"
P l2shield "$(grep -E '^(MODE|PINS)=' /etc/cyber3/l2shield.conf 2>/dev/null | tr '\n' ' ') timer=$(systemctl is-active cyber3-l2shield.timer) rules=$(ebtables -L CYBER3_L2SHIELD 2>/dev/null | grep -c -- '-j') drops=$(ebtables -L CYBER3_L2SHIELD --Lc 2>/dev/null | grep -oE 'pcnt = [0-9]+' | awk '{s+=$3} END{print s+0}')"
# IOC dataset + wrapper
P dataset_disk "$(sha256sum /etc/suricata/datasets/misp-domains.lst | cut -c1-12) $(wc -l < /etc/suricata/datasets/misp-domains.lst) linii mtime=$(stat -c %y /etc/suricata/datasets/misp-domains.lst | cut -c1-16)"
P dataset_loaded_before_disk "$( [ -n "$START_EPOCH" ] && [ $(stat -c %Y /etc/suricata/datasets/misp-domains.lst) -gt $START_EPOCH ] && echo 'DA (lista nouă intră la următorul restart)' || echo 'NU (lista de pe disc e cea încărcată)')"
P misp_rules "$(sha256sum $RP/cyber3-misp.rules 2>/dev/null | cut -c1-12) local=$(sha256sum $RP/cyber3-local.rules | cut -c1-12) local_sids=$(grep -oE 'sid:[0-9]+' $RP/cyber3-local.rules | cut -d: -f2 | tr '\n' ',')"
P apply_wrapper "reload_active=$(grep -v '^#' /usr/local/sbin/cyber3-apply-domains 2>/dev/null | grep -c reload-rules) sudoers=$(test -f /etc/sudoers.d/cyber3-domains && echo OK)"
# Wazuh agent + timere + sistem
P agent "$(systemctl is-active wazuh-agent) $(grep -E '^status' /var/ossec/var/run/wazuh-agentd.state 2>/dev/null | tr -d "'") last_ack=$(grep -E '^last_ack' /var/ossec/var/run/wazuh-agentd.state 2>/dev/null | cut -d"'" -f2) msg_sent=$(grep -E '^msg_sent' /var/ossec/var/run/wazuh-agentd.state | cut -d"'" -f2)"
P eve_growing "$(s1=$(stat -c %s /var/log/suricata/eve.json 2>/dev/null); sleep 5; s2=$(stat -c %s /var/log/suricata/eve.json 2>/dev/null); echo +$((s2-s1)) octeți/5s)"
P wg1 "$(wg show wg1 latest-handshakes 2>/dev/null | awk '{print systime()-$2"s"}')"
P failed_units "$(systemctl list-units --failed --no-legend | awk '{print $1}' | tr '\n' ' ')"
P timers "$(for t in cyber3-permaban cyber3-noc-agent cyber3-suricata-update suricata-healthcheck cyber3-mleo-expire cyber3-traffic cyber3-ueba; do printf '%s=%s ' ${t#cyber3-} $(systemctl is-active $t.timer 2>/dev/null); done)"
P noc_last "$(journalctl -u cyber3-noc-agent --since -15min --no-pager -o cat 2>/dev/null | grep -oE 'HTTP [0-9]+' | tail -1)"
P hold "$(apt-mark showhold | tr '\n' ' ')"
P resources "load=$(cut -d' ' -f1-3 /proc/loadavg) mem_avail=$(awk '/MemAvailable/{printf "%.1fG",$2/1048576}' /proc/meminfo) suricata_rss=$(ps -o rss= -C Suricata-Main | awk '{s+=$1} END{printf "%.0fM", s/1024}') disk_root=$(df -h / | awk 'END{print $5}') disk_varlog=$(df -h /var/log | awk 'END{print $5}')"
P logrotate "$(grep -c 'su suricata suricata' /etc/logrotate.d/suricata 2>/dev/null) postrotate_restart=$(grep -c 'systemctl restart suricata' /etc/logrotate.d/suricata 2>/dev/null)"
P suricata_update_last "$(tail -1 /var/log/cyber3/suricata-update.log 2>/dev/null | cut -c1-100)"
