#!/bin/bash
# Rulat de operator pe Acer: ! bash <acest fișier> — PREVENTIV icisoc101 (Spitalul Schuler Ploiești): rezolverul DNS
# 193.231.252.1 (folosit de client, 218 interogări în 7 zile) în ar-allowlist, ca permaban să nu-l poată bloca (cazul CNI 15.10).
# Doar un rând adăugat în /etc/cyber3/ar-allowlist.txt (backup). Nimic repornit.
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
export SSH_ASKPASS=$S/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0
O="-o PubkeyAuthentication=no -o ConnectTimeout=20 -o ProxyJump=socadmin@10.0.0.22"
ssh $O socadmin@10.1.22.1 'sudo -S -p "" bash -c "
  [ \$(hostname) = icisoc101 ] || { echo ABORT host; exit 3; }
  A=/etc/cyber3/ar-allowlist.txt; cp -a \$A \$A.bak-resolver-\$(date -u +%Y%m%d-%H%M%S)
  grep -qxF 193.231.252.1 \$A || printf \"# 15.10.2026: rezolver DNS al clientului (preventiv, incidentul CNI)\n193.231.252.1\n\" >> \$A
  echo \"\$(hostname): allowlist 193.231.252.1=\$(grep -cxF 193.231.252.1 \$A) | blocat acum=\$(iptables -S | grep -c 193.231.252.1) | suricata=\$(systemctl is-active suricata)\"
"' < $S/.fleetpw
