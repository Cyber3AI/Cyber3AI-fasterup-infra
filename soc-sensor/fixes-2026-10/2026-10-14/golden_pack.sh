#!/bin/bash
# Rulează pe golden f012 ca root. DOAR citește configurația și scrie 3 arhive în /tmp (le șterg după copiere).
# Excluse (stare/identitate f012): *.bak*, __pycache__, findings-baseline/inventory/scan-targets, noc-node.token,
# permaban.list, agent.conf.json/agent.log, client.keys, authd.pass, /var/lib/cyber3, loguri, wireguard, netplan.
set -e
cd /
X="--exclude=*.bak* --exclude=*bak-* --exclude=__pycache__"
tar czf /tmp/g_a.tgz $X \
  etc/suricata \
  var/lib/suricata/rules/suricata.rules var/lib/suricata/rules/cyber3-local.rules var/lib/suricata/rules/classification.config \
  var/ossec/etc/ossec.conf var/ossec/etc/local_internal_options.conf \
  var/ossec/active-response/bin/firewall-drop var/ossec/active-response/bin/firewall-drop-real
tar czf /tmp/g_b.tgz $X \
  etc/default/cyber3-soc-receiver etc/iptables/rules.v4 \
  etc/modules-load.d/cyber3-br_netfilter.conf etc/modules-load.d/cyber3-brnf.conf etc/modules-load.d/cyber3-nfqueue.conf \
  etc/sysctl.d/99-cyber3-bridge-nf.conf etc/sysctl.d/99-cyber3-brnf.conf etc/gai.conf \
  opt/cyber3 etc/cyber3/ar-allowlist.txt etc/cyber3/l2shield.conf \
  home/socadmin/cyber3-ops/allowlist.json home/socadmin/cyber3-ops/ops_agent.py \
  usr/local/bin/cyber3-l2shield.sh usr/local/bin/cyber3-permaban.sh usr/local/bin/cyber3-suricata-update.sh \
  usr/local/bin/mleo_q.sh usr/local/bin/suricata-healthcheck.sh \
  usr/local/sbin/cyber3-ips-fix.sh usr/local/sbin/cyber3-mleo-contain \
  etc/sudoers.d/cyber3-mleo etc/sudoers.d/cyber3-scan \
  etc/tmpfiles.d/suricata.conf etc/logrotate.d/suricata
tar czf /tmp/g_c.tgz $X \
  $(ls -d etc/systemd/system/cyber3-*.service etc/systemd/system/cyber3-*.timer etc/systemd/system/cyber3-*.d | grep -v bak) \
  etc/systemd/system/suricata.service.d etc/systemd/system/suricata-healthcheck.service etc/systemd/system/suricata-healthcheck.timer \
  etc/systemd/system/netfilter-persistent.service.d etc/systemd/system/systemd-networkd-wait-online.service.d
chmod 644 /tmp/g_[abc].tgz
for f in /tmp/g_[abc].tgz; do echo "$f $(du -h $f | cut -f1) fișiere=$(tar tzf $f | grep -vc '/$') sha=$(sha256sum $f | cut -c1-12)"; done
