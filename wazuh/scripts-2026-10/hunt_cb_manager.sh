#!/bin/bash
# Rulează PE MANAGERUL WAZUH (10.0.0.100) ca root. Fișierul cb_hunt_patch.py vine pe stdin după acest script (vezi lansatorul).
# 1) regula 100260 (grup cyber3_threat_hunt, nivel 8) pentru evenimentele CYBER3 Threat Hunt;
# 2) CyberBot: ramura handle_threat_hunt (notificare, fără blocare/AI);
# 3) teste: wazuh-analysisd -t, wazuh-logtest, CyberBot dry-run; restart manager; auto-revert.
set -u
TS=$(date -u +%Y%m%d-%H%M%S)
R=/var/ossec/etc/rules/local_rules.xml; CB=/var/ossec/integrations/cyberbot.py; LT=/var/ossec/bin/wazuh-logtest
ok(){ echo "[OK]  $*"; }; fail(){ echo "[ERR] $*"; }
echo "== manager $(date -u +%FT%TZ) =="
systemctl is-active --quiet wazuh-manager || { fail "wazuh-manager inactiv — ABORT"; exit 1; }
AG0=$(/var/ossec/bin/agent_control -l | grep -c Active)
cp -a $R $R.bak-hunt-$TS && cp -a $CB $CB.bak-hunt-$TS || { fail "backup"; exit 1; }
ok "backup .bak-hunt-$TS (local_rules.xml, cyberbot.py)"
revert(){ echo "[REV] restaurare"; cp -a $R.bak-hunt-$TS $R; cp -a $CB.bak-hunt-$TS $CB; systemctl restart wazuh-manager; sleep 20; echo "[REV] manager=$(systemctl is-active wazuh-manager)"; }

# 1) regula
if ! grep -q 'id="100260"' $R; then
cat >> $R <<'EOF'

<!-- CYBER3 10.10.2026: constatari CYBER3 Threat Hunt (portal), injectate prin API (PUT /events); notificate de CyberBot -->
<group name="cyber3_threat_hunt,">
  <rule id="100260" level="8">
    <decoded_as>json</decoded_as>
    <field name="cyber3_hunt.id">\S+</field>
    <description>CYBER3 Threat Hunt [$(cyber3_hunt.severity)] $(cyber3_hunt.agent) $(cyber3_hunt.host): $(cyber3_hunt.title)</description>
    <group>cyber3_threat_hunt,threat_hunting,</group>
  </rule>
</group>
EOF
fi
chown root:wazuh $R; chmod 660 $R
OUT=$(/var/ossec/bin/wazuh-analysisd -t 2>&1) || { fail "analysisd -t: $(echo "$OUT" | tail -2)"; revert; exit 2; }
ok "configurație validă"
SAMPLE='{"cyber3_hunt":{"id":"test0000test","hunt":"H3","severity":"CRITIC","agent":"icisoc109","agent_id":"015","host":"192.168.103.88","title":"TEST Stager PowerShell urmat de C2","detail":"test","first_seen":"2026-09-24T08:24:55Z","last_seen":"2026-09-24T08:25:03Z","count":3}}'
RES=$(echo "$SAMPLE" | timeout 40 $LT 2>&1 | awk -F"'" '/^\tid: /{id=$2} /^\tlevel: /{lv=$2} END{print id"/"lv}')
[ "$RES" = "100260/8" ] || { fail "logtest: $RES (așteptat 100260/8)"; revert; exit 2; }
ok "logtest: eveniment Threat Hunt → regula 100260, nivel 8"

# 2) CyberBot
python3 /tmp/cb_hunt_patch.py $CB || { fail "patch cyberbot"; revert; exit 2; }
python3 -m py_compile $CB || { fail "cyberbot.py nu compilează"; revert; exit 2; }
chown root:wazuh $CB; chmod 750 $CB
# dry-run: alertă Threat Hunt completă, cum o primește CyberBot de la Wazuh — doar jurnal, fără mesaje
cat > /tmp/hunt_alert_test.json <<'EOF'
{"timestamp":"2026-10-10T12:00:00.000+0000","rule":{"level":8,"description":"CYBER3 Threat Hunt [CRITIC] icisoc109 192.168.103.88: TEST","id":"100260","groups":["cyber3_threat_hunt","threat_hunting"]},"agent":{"id":"000","name":"wazuh-server"},"manager":{"name":"wazuh-server"},"id":"1","decoder":{"name":"json"},"data":{"cyber3_hunt":{"id":"dryrun0000aa","hunt":"H3","severity":"CRITIC","agent":"icisoc109","agent_id":"015","host":"192.168.103.88","title":"TEST dry-run","detail":"test","first_seen":"2026-09-24T08:24:55Z","last_seen":"2026-09-24T08:25:03Z","count":3}},"location":"API"}
EOF
L0=$(wc -l < /var/ossec/logs/cyberbot.log)
sudo -u wazuh env HUNT_DRY_RUN=1 python3 $CB /tmp/hunt_alert_test.json 2>&1 | tail -3
rm -f /tmp/hunt_alert_test.json /tmp/cb_hunt_patch.py
NEWLOG=$(tail -n +$((L0+1)) /var/ossec/logs/cyberbot.log | grep -E "dryrun0000aa|process_alert exception|traceback")
echo "$NEWLOG" | tail -3
echo "$NEWLOG" | grep -qF "[HUNT_DRYRUN] id=dryrun0000aa" || { fail "dry-run CyberBot: linia HUNT_DRYRUN lipsește"; revert; exit 2; }
echo "$NEWLOG" | grep -qE "process_alert exception|traceback" && { fail "excepție în CyberBot la dry-run"; revert; exit 2; }
ok "CyberBot dry-run: constatare recunoscută, destinatari rezolvați, ZERO mesaje trimise"

# 3) restart manager (regula nouă)
systemctl restart wazuh-manager
for i in $(seq 1 24); do sleep 5; systemctl is-active --quiet wazuh-manager && break; done
systemctl is-active --quiet wazuh-manager || { fail "manager nu a repornit"; revert; exit 2; }
sleep 60; AG1=$(/var/ossec/bin/agent_control -l | grep -c Active)
ok "manager repornit; agenți activi $AG1 (înainte $AG0)"
echo "ROLLBACK: cp -a $R.bak-hunt-$TS $R; cp -a $CB.bak-hunt-$TS $CB; systemctl restart wazuh-manager"
