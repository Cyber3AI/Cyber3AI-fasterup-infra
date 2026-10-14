#!/bin/bash
# f014 — PAS 4 (wg1) + PAS 5 (înrolare Wazuh CU PAROLĂ, agent_name fix) + tokenuri ops/NOC. Rulează ca root pe f014.
# Secretele vin în /tmp/f014sec/ (șterse la final). Nu afișează secrete.
set -u
say(){ echo "[f014 $(date -u +%T)] $*"; }
K=/tmp/f014sec

# PAS 4 — wg1
systemctl enable --now wg-quick@wg1 >/dev/null 2>&1
for i in $(seq 1 15); do ping -c1 -W2 10.0.0.100 >/dev/null 2>&1 && break; sleep 2; done
say "wg1: handshake=$(wg show wg1 latest-handshakes | awk '{print ($2>0)?"DA":"NU"}') ping manager=$(ping -c1 -W2 10.0.0.100 >/dev/null && echo OK || echo EȘEC)"

# PAS 5 — parola de înrolare + agent-auth cu numele f014
install -m 640 -o root -g wazuh $K/authd.pass /var/ossec/etc/authd.pass
grep -q '<authorization_pass_path>etc/authd.pass</authorization_pass_path>' /var/ossec/etc/ossec.conf && say "ossec.conf: bloc <enrollment> cu agent_name f014 + pass_path OK" || say "ATENȚIE: lipsește pass_path în ossec.conf"
systemctl stop wazuh-agent 2>/dev/null
OUT=$(/var/ossec/bin/agent-auth -m 10.0.0.100 -A f014 2>&1); echo "$OUT" | grep -E "Valid key|ERROR|INFO: Using agent name" | sed 's/^/   /'
grep -oE '^[0-9]+ f014' /var/ossec/etc/client.keys | sed 's/^/[f014] client.keys: /'
systemctl enable --now wazuh-agent >/dev/null 2>&1; sleep 8
say "wazuh-agent: $(systemctl is-active wazuh-agent); stare: $(grep -E '^status' /var/ossec/var/run/wazuh-agentd.state 2>/dev/null)"

# ops-agent (token de flotă, identitate f014) + NOC (token partajat)
python3 - "$K/ops.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); d['node_label']='f014'
json.dump(d,open('/home/socadmin/cyber3-ops/agent.conf.json','w'),indent=2)
print('[f014] ops agent.conf.json: node_label=%s dry_run=%s' % (d['node_label'], d.get('dry_run')))
PY
chown socadmin:socadmin /home/socadmin/cyber3-ops/agent.conf.json; chmod 600 /home/socadmin/cyber3-ops/agent.conf.json
install -m 600 -o root -g root $K/noc-node.token /etc/cyber3/noc-node.token
rm -rf $K
say "secretele temporare șterse"
