#!/bin/bash
# Rulează PE MANAGER ca root: instalează reîmprospătarea lunară a listei AWS (CyberBot) + cron + rulare de probă. Idempotent.
set -u
P=/usr/local/sbin/cyber3-refresh-aws.py; A=/var/ossec/integrations/aws-ipv4.txt
/usr/bin/python3 -m py_compile /tmp/cyber3-refresh-aws.py || { echo "ABORT: compilare"; exit 2; }
install -o root -g root -m 755 /tmp/cyber3-refresh-aws.py $P; rm -f /tmp/cyber3-refresh-aws.py
LINE='30 4 1 * * /usr/bin/python3 /usr/local/sbin/cyber3-refresh-aws.py >/dev/null 2>&1'
( crontab -l -u root 2>/dev/null | grep -v 'cyber3-refresh-aws.py'; echo "$LINE" ) | crontab -u root -
echo "cron: $(crontab -l -u root | grep cyber3-refresh-aws)"
echo "cron domenii MISP intact: $(crontab -l -u root | grep -c cyber3-refresh-domains)"
echo "înainte: $(grep -vc '^#' $A 2>/dev/null) rețele, sha $(sha256sum $A 2>/dev/null | cut -c1-12)"
/usr/bin/python3 $P >/dev/null; echo "rulare de probă rc=$? | jurnal: $(tail -1 /var/log/cyber3-aws-refresh.log)"
echo "după: $(grep -vc '^#' $A) rețele, sha $(sha256sum $A | cut -c1-12), $(stat -c '%U:%G %a' $A) | $(head -1 $A | cut -c1-90)"
sudo -u wazuh test -r $A && echo "lizibil de wazuh (CyberBot): DA" || echo "lizibil de wazuh: NU — PROBLEMĂ"
