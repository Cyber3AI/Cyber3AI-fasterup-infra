#!/bin/bash
# f014 — PAS 2+3 canonic: golden f012 → f014, identitate, curățarea valorilor f012/f010, br0, servicii.
# Rulează ca root pe f014 (staging). Arhivele golden sunt în /tmp/golden/.
set -u
TS=$(date -u +%Y%m%d-%H%M%S)
say(){ echo "[f014 $(date -u +%T)] $*"; }
G=/tmp/golden

# 0) backup a ce există din pachete (yaml stock etc.)
cd /
tar czf /root/pre-golden-$TS.tgz etc/suricata var/ossec/etc/ossec.conf 2>/dev/null && say "backup pre-golden /root/pre-golden-$TS.tgz"

# 1) despachetare golden
for a in g_a g_b g_c; do tar xzf $G/$a.tgz -C / && say "despachetat $a ($(tar tzf $G/$a.tgz | grep -vc '/$') fișiere)"; done

# 2) proprietari/permisiuni (uid-urile diferă între cutii)
chown root:root /etc/suricata/suricata.yaml; chmod 644 /etc/suricata/suricata.yaml
chown -R root:suricata /var/lib/suricata/rules; chown suricata:suricata /var/lib/suricata/rules/cyber3-local.rules; chmod 640 /var/lib/suricata/rules/cyber3-local.rules
chown root:wazuh /var/ossec/etc/ossec.conf /var/ossec/etc/local_internal_options.conf; chmod 640 /var/ossec/etc/ossec.conf /var/ossec/etc/local_internal_options.conf
chown root:wazuh /var/ossec/active-response/bin/firewall-drop /var/ossec/active-response/bin/firewall-drop-real
chmod 750 /var/ossec/active-response/bin/firewall-drop /var/ossec/active-response/bin/firewall-drop-real
chown -R socadmin:socadmin /home/socadmin/cyber3-ops
chmod 440 /etc/sudoers.d/cyber3-mleo /etc/sudoers.d/cyber3-scan; visudo -c >/dev/null && say "sudoers valid" || say "EROARE sudoers"
chmod 755 /usr/local/bin/cyber3-*.sh /usr/local/bin/mleo_q.sh /usr/local/bin/suricata-healthcheck.sh /usr/local/sbin/cyber3-ips-fix.sh /usr/local/sbin/cyber3-mleo-contain

# 3) identitate
sed -i 's|<agent_name>f012</agent_name>|<agent_name>f014</agent_name>|' /var/ossec/etc/ossec.conf
say "ossec agent_name: $(grep -oE '<agent_name>[^<]+' /var/ossec/etc/ossec.conf | cut -d'>' -f2); manageri: $(grep -oE '<address>[^<]+' /var/ossec/etc/ossec.conf | cut -d'>' -f2 | tr '\n' ' ')"
grep -c f012 /var/ossec/etc/ossec.conf | xargs -I{} say "rămășițe f012 în ossec.conf: {}"

# 4) L2 Shield LIVRAT DEZARMAT (incident f012: pin moștenit = blackhole la cablare)
printf 'MODE=observe\nPINS=""\n' > /etc/cyber3/l2shield.conf
say "l2shield: $(tr '\n' ' ' < /etc/cyber3/l2shield.conf)"

# 5) ar-allowlist: scoase valorile f012/f008 (IP staging vechi, wg f008, rezolverele DNS ale spitalului); + wg f014
sed -i -e '/^192\.168\.0\.176$/d' -e '/^10\.1\.8\.1$/d' -e '/^# rezolvere DNS folosite de client/d' -e '/^193\.231\.100\.13[04]$/d' /etc/cyber3/ar-allowlist.txt
grep -q '^10\.1\.14\.1$' /etc/cyber3/ar-allowlist.txt || sed -i '3a 10.1.14.1' /etc/cyber3/ar-allowlist.txt
say "ar-allowlist: $(grep -vc '^#' /etc/cyber3/ar-allowlist.txt) intrări (gamele clinicii se adaugă la client)"

# 6) threshold: scoase self-scan f010 (192.168.0.136, 10.228.0.110, 10.1.10.1); self-scan f014 = wg + mgmt staging
T=/etc/suricata/threshold.config
sed -i -e '/track by_src, ip 192\.168\.0\.136$/d' -e '/track by_src, ip 10\.228\.0\.110$/d' -e '/track by_src, ip 10\.1\.10\.1$/d' $T
sed -i 's|^# threshold.config STANDARD.*|# threshold.config STANDARD flotă — f014 (din golden f012, 14.10.2026)|' $T
sed -i '/^# === Self-scan senzor/a suppress gen_id 0, sig_id 0, track by_src, ip 10.1.14.1\nsuppress gen_id 0, sig_id 0, track by_src, ip 192.168.0.135' $T
say "threshold: $(grep -c '^suppress' $T) suppress; self-scan: $(grep -A3 '^# === Self-scan' $T | grep -oE 'ip [0-9.]+' | tr '\n' ' ')"

# 7) stare CYBER3 fresh (NU moștenită)
: > /etc/cyber3/permaban.list; chmod 600 /etc/cyber3/permaban.list
printf '# f014 — țintele de scan se stabilesc la client (gamele clinicii)\n' > /etc/cyber3/scan-targets.txt
mkdir -p /var/lib/cyber3 /var/log/cyber3 /var/log/suricata; chown socadmin:socadmin /var/log/cyber3
chown suricata:suricata /var/log/suricata
say "stare fresh: fără findings-baseline/inventory/noc-token; /var/log/cyber3 = $(stat -c %U /var/log/cyber3)"

# 8) module + sysctl (br_netfilter, nfqueue, vlan-tagged)
modprobe br_netfilter; modprobe nfnetlink_queue; modprobe nfnetlink
sysctl --system >/dev/null 2>&1
say "sysctl bridge: call-iptables=$(sysctl -n net.bridge.bridge-nf-call-iptables) vlan-tagged=$(sysctl -n net.bridge.bridge-nf-filter-vlan-tagged)"

# 9) br0 = eno1 + enp0s25 (stp false, fwd-delay 0) + mgmt enp2s0 DHCP la staging
cp -a /etc/netplan/50-cyber3.yaml /root/50-cyber3.yaml.bak-$TS
cat > /etc/netplan/50-cyber3.yaml <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    enp2s0:
      dhcp4: true
    eno1:
      dhcp4: false
      optional: true
    enp0s25:
      dhcp4: false
      optional: true
  bridges:
    br0:
      interfaces: [eno1, enp0s25]
      dhcp4: false
      optional: true
      parameters:
        stp: false
        forward-delay: 0
EOF
chmod 600 /etc/netplan/50-cyber3.yaml
netplan generate && say "netplan br0 valid"

# 10) iptables canonic: CYBER3_BLOCK gol + NFQUEUE 4 cozi cu bypass
iptables-restore < /etc/iptables/rules.v4 && iptables -F CYBER3_BLOCK && iptables-save > /etc/iptables/rules.v4
say "FORWARD: $(iptables -S FORWARD | tr '\n' ' ')"

# 11) systemd
systemctl daemon-reload
systemctl disable --now suricata-update.timer >/dev/null 2>&1
systemd-tmpfiles --create /etc/tmpfiles.d/suricata.conf
for u in cyber3-iptables-restore.service netfilter-persistent.service cyber3-soc-receiver.service \
         cyber3-permaban.timer cyber3-traffic.timer cyber3-ueba.timer cyber3-suricata-update.timer \
         cyber3-mleo-expire.timer suricata-healthcheck.timer suricata.service; do systemctl enable $u >/dev/null 2>&1; done
systemctl disable --now cyber3-l2shield.timer >/dev/null 2>&1   # dezarmat până la client
say "systemd-analyze verify iptables-restore: $(systemd-analyze verify cyber3-iptables-restore.service 2>&1 | grep -ci cycle) cicluri"
nohup sh -c "sleep 3; netplan apply" >/dev/null 2>&1 &
say "netplan apply programat (br0)"
say "PAS 2+3 gata (ops-agent + noc-agent așteaptă tokenurile; wg1 + înrolare = PAS 4-5)"
