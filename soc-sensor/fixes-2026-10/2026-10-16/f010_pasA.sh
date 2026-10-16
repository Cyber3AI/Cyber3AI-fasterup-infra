#!/bin/bash
# f010 PAS A — DOAR FIȘIERE, FĂRĂ RESTART, fără iptables: wrapper apply fără reload (+sudoers/cheie), dataset 597k pe disc
# (se încarcă la restartul din pasul B), allowlist curățat de reziduurile f008. Backup la tot.
set -u
[ "$(hostname)" = f010 ] || { echo "ABORT: nu sunt pe f010 ($(hostname))"; exit 3; }
TS=$(date -u +%Y%m%d-%H%M%S); ST0=$(systemctl show suricata -p ActiveEnterTimestamp --value)
bash /tmp/dfs.sh | sed 's/^/   /'                       # wrapper fără reload + sudoers + cheie portal (domains_fix_sensor.sh)
install -m 644 /tmp/c3-ds.lst /tmp/cyber3-domains-staged.lst; rm -f /tmp/c3-ds.lst
echo "   apply: $(/usr/local/sbin/cyber3-apply-domains)"
echo "   dataset pe disc: $(sha256sum /etc/suricata/datasets/misp-domains.lst | cut -c1-12) $(wc -l < /etc/suricata/datasets/misp-domains.lst) linii"
A=/etc/cyber3/ar-allowlist.txt; cp -a $A $A.bak-standard-$TS
sed -i -e '/^192\.168\.0\.176$/d' -e '/^10\.1\.8\.1$/d' $A
grep -qxF 10.1.10.1 $A || sed -i '3a 10.1.10.1' $A
echo "   allowlist: 192.168.0.176=$(grep -cxF 192.168.0.176 $A) 10.1.8.1=$(grep -cxF 10.1.8.1 $A) 10.1.10.1=$(grep -cxF 10.1.10.1 $A) rezolvere 8.8.8.8=$(grep -cxF 8.8.8.8 $A) 1.1.1.1=$(grep -cxF 1.1.1.1 $A) | intrări=$(grep -vc '^#' $A)"
ST1=$(systemctl show suricata -p ActiveEnterTimestamp --value)
echo "   Suricata NEATINS: $([ "$ST0" = "$ST1" ] && echo DA || echo NU) ($ST1) | FORWARD: $(iptables -S FORWARD | tail -n +2 | tr '\n' ' ')"
