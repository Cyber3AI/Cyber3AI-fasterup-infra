#!/bin/bash
# READ-ONLY. Verifică dacă f014 revine singur pe VPN după reboot (mgmt pe br0/enp0s25 DHCP).
H=$(hostname); [ "$H" = f014 ] || { echo "[$H] ABORT hostname"; exit 3; }
echo "== 1. netplan (toate fișierele)"; ls -l /etc/netplan/; for f in /etc/netplan/*.yaml; do echo "--- $f"; cat $f; done
echo "== 2. fișiere networkd generate (ce se aplică la boot)"; for f in /run/systemd/network/*; do echo "--- $f"; grep -vE '^\s*$' $f; done
ls /etc/systemd/network/ 2>/dev/null | sed 's/^/   etc-networkd: /'
echo "== 3. stare networkd"; networkctl list --no-pager 2>/dev/null
networkctl status br0 --no-pager 2>/dev/null | grep -E 'State|Address|Gateway|DHCP|Network File|Online' | sed 's/^/   /'
echo "   rute: $(ip r | tr '\n' ';')"
echo "   lease networkd: $(ls /run/systemd/netif/leases/ 2>/dev/null | tr '\n' ' ')"
echo "   procese dhclient/dhcpcd: $(pgrep -a 'dhclient|dhcpcd' | tr '\n' ';')"
echo "== 4. wait-online / ordinea la boot"
systemctl is-enabled systemd-networkd systemd-networkd-wait-online 2>&1 | tr '\n' ' '; echo
systemctl cat systemd-networkd-wait-online 2>/dev/null | grep -E '^ExecStart|^#.*conf' | sed 's/^/   /'
echo "   ultimul boot wait-online: $(journalctl -b -u systemd-networkd-wait-online --no-pager -o cat 2>/dev/null | tail -3 | tr '\n' ' ')"
echo "== 5. WireGuard"
systemctl is-enabled wg-quick@wg1; systemctl show wg-quick@wg1 -p After -p Wants --value | tr ' ' '\n' | grep -E 'network' | tr '\n' ' '; echo
grep -E '^\s*(Address|Endpoint|PersistentKeepalive|AllowedIPs|DNS|PostUp|PreUp|Table)' /etc/wireguard/wg1.conf | sed 's/^/   /'
wg show wg1 | grep -E 'endpoint|handshake|transfer' | sed 's/^/   /'
ls /etc/wireguard/ | sed 's/^/   fișier: /'; systemctl list-unit-files 'wg-quick@*' --no-pager 2>/dev/null | grep wg-quick | sed 's/^/   /'
echo "   wg0 boot: $(journalctl -b -u wg-quick@wg0 --no-pager -o cat 2>/dev/null | tail -2 | tr '\n' ' ')"
echo "== 6. agent Wazuh -> manager"; grep -oE '<address>[^<]+' /var/ossec/etc/ossec.conf | sed 's/^/   /'; systemctl is-enabled wazuh-agent
echo "== 7. firewall persistat (aplicat la boot)"
systemctl is-enabled netfilter-persistent iptables 2>/dev/null | tr '\n' ' '; echo
[ -f /etc/iptables/rules.v4 ] && { echo "   rules.v4 INPUT/OUTPUT:"; grep -E '^:(INPUT|OUTPUT)|^-A (INPUT|OUTPUT)' /etc/iptables/rules.v4 | head -25 | sed 's/^/     /'; }
echo "   live INPUT/OUTPUT policy: $(iptables -S | grep -E '^-P (INPUT|OUTPUT)' | tr '\n' ' ')"
echo "   ebtables: $(ebtables -L 2>/dev/null | grep -cE '^-') reguli | nft bridge tables: $(nft list tables 2>/dev/null | grep -c bridge)"
[ -f /etc/ebtables.rules ] || ls /etc/cyber3/*ebt* /etc/cyber3/*l2* 2>/dev/null | sed 's/^/   l2 fișier: /'
echo "== 8. unități CYBER3 care pornesc la boot / timere care ating rețeaua"
systemctl list-unit-files --no-pager --state=enabled 2>/dev/null | grep -iE 'cyber3|l2|bridge|watchdog|netw' | sed 's/^/   /'
systemctl list-timers --all --no-pager 2>/dev/null | grep -iE 'cyber3|l2|watchdog' | sed 's/^/   /'
grep -rlE 'br0|netplan|enp0s25|eno1|ip link' /usr/local/sbin /etc/cron.d /etc/systemd/system/*.service 2>/dev/null | sed 's/^/   referă rețeaua: /'
echo "== 9. modules-load (br_netfilter / nfqueue)"; cat /etc/modules-load.d/*.conf 2>/dev/null | grep -v '^#' | sed 's/^/   /'
echo "== 10. ultimul boot a fost curat? (erori networkd)"; journalctl -b -u systemd-networkd --no-pager -o cat 2>/dev/null | grep -iE 'fail|error|timeout' | tail -5 | sed 's/^/   /'
