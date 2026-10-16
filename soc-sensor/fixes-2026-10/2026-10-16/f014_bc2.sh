H=$(hostname); [ "$H" = f014 ] || exit 3
echo "== CYBER3_BLOCK live: $(iptables -S CYBER3_BLOCK | grep -c DROP) DROP | rules.v4: $(grep -c 'CYBER3_BLOCK.*DROP' /etc/iptables/rules.v4)"
for ip in 192.168.1.1 192.168.1.131 89.167.112.95 10.0.0.100 10.0.0.101 10.0.0.1; do
 echo "   $ip: blocat_live=$(iptables -S | grep -c -- "-s $ip/32 -j DROP") blocat_rules.v4=$(grep -c -- "-s $ip/32 -j DROP" /etc/iptables/rules.v4) permaban=$(grep -c "^$ip " /etc/cyber3/permaban.list 2>/dev/null) allowlist=$(grep -cxF $ip /etc/cyber3/ar-allowlist.txt)"; done
echo "   allowlist conține 192.168.0.0/16 sau 192.168.1.0/24: $(grep -cE '^192\.168\.(0\.0/16|1\.0/24)' /etc/cyber3/ar-allowlist.txt)"
echo "== suricata-healthcheck"; systemctl cat suricata-healthcheck.service | grep -E 'ExecStart|br0' ; E=$(systemctl show suricata-healthcheck -p ExecStart --value | grep -oE 'path=[^ ;]+' | cut -d= -f2); [ -f "$E" ] && grep -nE 'br0|ip link|netplan|reboot|networkctl' $E | head
echo "== cyber3-iptables-restore"; systemctl cat cyber3-iptables-restore.service | grep -E 'ExecStart|After|Before'
