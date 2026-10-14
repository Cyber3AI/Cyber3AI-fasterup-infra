#!/bin/bash
# f014 — PAS 6 canonic: pornire servicii (Suricata --no-block, suita CYBER3, timere) + executor MLEO (installer canonic).
set -u
say(){ echo "[f014 $(date -u +%T)] $*"; }
systemctl daemon-reload
systemctl enable --now cyber3-soc-receiver.service cyber3-ops-agent.service >/dev/null 2>&1
for t in cyber3-noc-agent cyber3-permaban cyber3-traffic cyber3-ueba cyber3-suricata-update suricata-healthcheck; do
  systemctl enable --now $t.timer >/dev/null 2>&1
done
systemctl enable suricata >/dev/null 2>&1; systemctl start --no-block suricata
say "Suricata pornește în fundal (ruleset mare, 1-3 min)"
bash /tmp/mleo_exec_sensor.sh 2>&1 | tail -3
say "servicii: receiver=$(systemctl is-active cyber3-soc-receiver) ops=$(systemctl is-active cyber3-ops-agent) agent=$(systemctl is-active wazuh-agent) wg1=$(systemctl is-active wg-quick@wg1)"
say "timere: $(systemctl list-timers 'cyber3-*' 'suricata-*' --no-legend | awk '{print $NF}' | tr '\n' ' ')"
say "l2shield timer (trebuie inactiv): $(systemctl is-active cyber3-l2shield.timer)"
