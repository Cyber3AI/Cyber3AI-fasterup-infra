#!/bin/bash
# Test de acceptanță §10 (read-only) pe f014.
L=/var/log/suricata/suricata.log
echo "1. servicii: suricata=$(systemctl is-active suricata) sub=$(systemctl show suricata -p SubState --value) agent=$(systemctl is-active wazuh-agent) wg1=$(systemctl is-active wg-quick@wg1) failed=$(systemctl list-units --failed --no-legend | wc -l)"
systemctl list-units --failed --no-legend | sed 's/^/   FAILED: /'
echo "2. strat 1: $(grep -oE '[0-9]+ rules successfully loaded, [0-9]+ rules failed' $L | tail -1) | $(grep -oE 'Threshold config parsed: [0-9]+ rule' $L | tail -1)"
echo "   threads W-NFQ: $(grep -oE 'Threads created -> W: [0-9]+' $L | tail -1) | cozi kernel: $(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue) | qdrop: $(awk '{s+=$6} END{print s+0}' /proc/net/netfilter/nfnetlink_queue)"
echo "   runmode=$(grep -E '^runmode:' /etc/suricata/suricata.yaml | awk '{print $2}') fail-open=$(grep -cE '^[[:space:]]+fail-open:[[:space:]]*yes' /etc/suricata/suricata.yaml) bad-base64=$(grep -ci 'bad base64' $L) erori=$(grep -c '<Error>' $L)"
grep '<Error>' $L | tail -3 | sed 's/^/   ERR: /'
echo "   FORWARD: $(iptables -S FORWARD | tail -n +2 | tr '\n' ' ')"
echo "3. VLAN/bridge: vlan-tagged=$(sysctl -n net.bridge.bridge-nf-filter-vlan-tagged) call-iptables=$(sysctl -n net.bridge.bridge-nf-call-iptables) br_netfilter=$(lsmod | grep -c ^br_netfilter) br0=$(ip -br link show br0 | awk '{print $2}') stp=$(cat /sys/class/net/br0/bridge/stp_state)"
echo "4. strat 2: firewall-drop=$(md5sum /var/ossec/active-response/bin/firewall-drop | cut -c1-8) real=$(test -x /var/ossec/active-response/bin/firewall-drop-real && echo DA) CYBER3_BLOCK în INPUT=$(iptables -S INPUT | grep -c CYBER3_BLOCK) FORWARD=$(iptables -S FORWARD | grep -c CYBER3_BLOCK)"
echo "5. strat 3: l2shield $(tr '\n' ' ' < /etc/cyber3/l2shield.conf) timer=$(systemctl is-active cyber3-l2shield.timer) ebtables_drop=$(ebtables -L 2>/dev/null | grep -c DROP)"
echo "6. agent: $(grep -E '^status' /var/ossec/var/run/wazuh-agentd.state) | client.keys=$(awk '{print $1,$2}' /var/ossec/etc/client.keys)"
echo "8. persistență: iptables-restore=$(systemctl is-enabled cyber3-iptables-restore) DefDeps=$(systemctl show cyber3-iptables-restore -p DefaultDependencies --value) modules=$(ls /etc/modules-load.d | grep -c cyber3) sysctl.d=$(ls /etc/sysctl.d | grep -c cyber3) suricata=$(systemctl is-enabled suricata) agent=$(systemctl is-enabled wazuh-agent) wg1=$(systemctl is-enabled wg-quick@wg1)"
echo "   hold: $(apt-mark showhold | tr '\n' ' ') unattended=$(systemctl is-enabled unattended-upgrades) tmpfiles=$(test -S /run/suricata/suricata-command.socket && echo socket-OK || echo socket-lipsă) logrotate=$(grep -c 'su suricata suricata' /etc/logrotate.d/suricata)"
echo "10. livrare: eve-alerts=$(stat -c '%U:%G %s' /var/log/suricata/eve-alerts.json 2>/dev/null) | /var/log/cyber3=$(stat -c %U /var/log/cyber3) | noc: $(journalctl -u cyber3-noc-agent --since -10min --no-pager -o cat | grep -oE 'HTTP [0-9]+' | tail -1) | ops: $(journalctl -u cyber3-ops-agent --since -10min --no-pager -o cat | tail -1 | cut -c1-90)"
echo "   gai.conf=$(grep -c '^precedence ::ffff:0:0/96 100' /etc/gai.conf) suricatasc uptime: $(timeout 10 suricatasc -c uptime 2>/dev/null | grep -oE '"message": [0-9]+')"
echo "   MLEO: $(/usr/local/sbin/cyber3-mleo-contain status 2>&1 | tail -1)"
