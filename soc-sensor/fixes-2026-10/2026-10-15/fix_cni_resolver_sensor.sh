#!/bin/bash
# Rulează PE icisoc109 (CNI) ca root. 15.10.2026: rezolverul DNS 193.231.252.1 (folosit de serverele DNS ale CNI
# 192.168.100.100/.101) a fost blocat 90 de zile de permaban pe 14.10 11:37 UTC. Deblocare + allowlist + persistență.
# Atinge DOAR acest IP. Nu repornește nimic (Suricata, Wazuh, rețea neatinse).
set -u
IP=193.231.252.1; TS=$(date -u +%Y%m%d-%H%M%S)
H=$(hostname); [ "$H" = icisoc109 ] || { echo "ABORT: nu sunt pe icisoc109 ($H)"; exit 3; }
iptables-save > /root/iptables.bak-cni-resolver-$TS
cp -a /etc/cyber3/permaban.list /etc/cyber3/permaban.list.bak-cni-resolver-$TS
cp -a /etc/cyber3/ar-allowlist.txt /etc/cyber3/ar-allowlist.txt.bak-cni-resolver-$TS
echo "înainte: CYBER3_BLOCK=$(iptables -S CYBER3_BLOCK | grep -c "$IP") INPUT/FORWARD directe=$(iptables -S | grep -E '^-A (INPUT|FORWARD) -s' | grep -c "$IP") permaban.list=$(grep -c "^$IP " /etc/cyber3/permaban.list) allowlist=$(grep -cxF "$IP" /etc/cyber3/ar-allowlist.txt)"
while iptables -C CYBER3_BLOCK -s $IP/32 -j DROP 2>/dev/null; do iptables -D CYBER3_BLOCK -s $IP/32 -j DROP; done
for ch in INPUT FORWARD; do while iptables -C $ch -s $IP/32 -j DROP 2>/dev/null; do iptables -D $ch -s $IP/32 -j DROP; done; done
sed -i "/^$(echo $IP | sed 's/\./\\./g') /d" /etc/cyber3/permaban.list
grep -qxF "$IP" /etc/cyber3/ar-allowlist.txt || printf '# 15.10.2026: rezolver DNS folosit de serverele DNS CNI (192.168.100.100/.101) — blocat greșit de permaban 14.10\n%s\n' "$IP" >> /etc/cyber3/ar-allowlist.txt
iptables-save > /etc/iptables/rules.v4
echo "$(date -u +%FT%TZ) UNBLOCK $IP motiv=rezolver-DNS-al-clientului (incident cni.ro 15.10.2026)" >> /var/log/cyber3/permaban-audit.log
echo "după:    CYBER3_BLOCK=$(iptables -S CYBER3_BLOCK | grep -c "$IP") INPUT/FORWARD directe=$(iptables -S | grep -E '^-A (INPUT|FORWARD) -s' | grep -c "$IP") permaban.list=$(grep -c "^$IP " /etc/cyber3/permaban.list) allowlist=$(grep -cxF "$IP" /etc/cyber3/ar-allowlist.txt) rules.v4=$(grep -c "$IP" /etc/iptables/rules.v4)"
echo "lanțuri neatinse: CYBER3_BLOCK rămase=$(iptables -S CYBER3_BLOCK | grep -c '^-A') | FORWARD: $(iptables -S FORWARD | tail -n +2 | tr '\n' ' ')"
echo "suricata=$(systemctl is-active suricata) agent=$(systemctl is-active wazuh-agent)"
echo "permaban — simulare: îl mai poate re-bloca? $(bash -c 'source <(sed -n "/^whitelisted()/,/^}/p" /usr/local/bin/cyber3-permaban.sh); DNS_NTP=""; PENDING_DECIZIE=""; PROT=""; in_protected_cidr(){ return 1; }; whitelisted 193.231.252.1 && echo "NU (whitelisted)" || echo "DA — PROBLEMĂ"')"
