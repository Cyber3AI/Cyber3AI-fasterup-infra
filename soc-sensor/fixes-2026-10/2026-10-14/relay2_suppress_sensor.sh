#!/bin/bash
# Rulează PE SENZOR ca root. Adaugă relay-2 (46.62.221.30, DR portal Hetzner) la infrastructura SOC:
# supresie în threshold.config (lângă hub) + 2 reguli pass în cyber3-local.rules (sid 9100930/9100931).
# Backup înainte. NU face reload/restart (pe senzorii vii intră la restartul de noapte din logrotate); argument „restart” = doar pentru staging.
set -u
H=$(hostname); TS=$(date -u +%Y%m%d-%H%M%S)
T=/etc/suricata/threshold.config; R=/var/lib/suricata/rules/cyber3-local.rules
cp -a $T $T.bak-relay2-$TS; cp -a $R $R.bak-relay2-$TS
if ! grep -q 'ip 46.62.221.30$' $T; then
  sed -i '/track by_dst, ip 89\.167\.112\.95$/a suppress gen_id 0, sig_id 0, track by_src, ip 46.62.221.30\nsuppress gen_id 0, sig_id 0, track by_dst, ip 46.62.221.30' $T
fi
if ! grep -q 'sid:9100930;' $R; then
  cat >> $R <<'P'
# CYBER3 14 oct 2026: relay-2 46.62.221.30 = DR portal (infra SOC). Sincronizarea portal->relay-2 pe SSH era blocată de 2003068 când un senzor stă inline la sediu.
pass ip $HOME_NET any -> 46.62.221.30 any (msg:"CYBER3 PASS infra SOC relay-2 (DR portal)"; classtype:not-suspicious; sid:9100930; rev:1;)
pass ip 46.62.221.30 any -> $HOME_NET any (msg:"CYBER3 PASS infra SOC relay-2 (DR portal) retur"; classtype:not-suspicious; sid:9100931; rev:1;)
P
fi
chown suricata:suricata $R; chmod 640 $R
echo "[$H] threshold: $(grep -c 'ip 46.62.221.30$' $T) linii relay-2, $(grep -c '^suppress' $T) suppress total | local: $(grep -cE 'sid:91009(30|31);' $R) reguli pass relay-2"
if [ "${1:-}" = restart ]; then
  systemctl restart suricata; for i in $(seq 1 40); do sleep 5; grep -q "$(date -u +%H:%M)" /dev/null; [ "$(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue)" = 4 ] && [ "$(systemctl show suricata -p SubState --value)" = running ] && tail -n 30 /var/log/suricata/suricata.log | grep -q "Engine started" && break; done
  echo "[$H] restart: $(systemctl show suricata -p SubState --value); $(grep -oE '[0-9]+ rules successfully loaded, [0-9]+ rules failed' /var/log/suricata/suricata.log | tail -1); $(grep -oE 'Threshold config parsed: [0-9]+ rule' /var/log/suricata/suricata.log | tail -1); cozi=$(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue)"
fi
