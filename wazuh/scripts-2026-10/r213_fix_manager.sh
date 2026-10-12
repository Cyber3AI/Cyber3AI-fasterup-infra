#!/bin/bash
# Rulează PE MANAGERUL WAZUH (10.0.0.100), ca root (primit pe stdin prin sudo -S ... bash -s).
# Corectare: alertele Suricata din categoriile „Misc activity” (100213, nivel 2) și „Potential Corporate Privacy Violation”
# (100214, nivel 1) nu ajung în index (log_alert_level = 3). Se adaugă reguli-copil care ridică doar semnalele relevante:
#   100250 (nivel 7)  — instrumente de acces la distanță (AnyDesk, TeamViewer, RustDesk, ScreenConnect etc.)
#   100251 (nivel 12) — honeytoken / canary token (Thinkst, o3n.io)
#   100252 (nivel 8)  — semnale C2 / ClickFix / stealer / phishing căzute în categoria „Misc activity”
# Restul „Misc activity” rămâne la nivelul 2 (zgomot). Nivelurile 7 și 8 nu declanșează Active Response / CyberBot (prag 10).
# Gărzi: backup, test de configurație (wazuh-analysisd -t), wazuh-logtest pe 4 mostre, restart controlat, verificare agenți, auto-revert.
set -u
TS=$(date -u +%Y%m%d-%H%M%S)
F=/var/ossec/etc/rules/local_rules.xml
B="$F.bak-r213-$TS"
ok(){ echo "[OK]  $*"; }; fail(){ echo "[ERR] $*"; }
LT=/var/ossec/bin/wazuh-logtest

echo "== manager Wazuh $(date -u +%FT%TZ) =="
systemctl is-active --quiet wazuh-manager || { fail "wazuh-manager nu e activ — ABORT"; exit 1; }
AG0=$(/var/ossec/bin/agent_control -l | grep -c "Active")
ok "wazuh-manager activ; agenți activi acum: $AG0"
grep -q 'id="100250"' "$F" && { ok "regulile 100250-100252 există deja — nimic de făcut"; exit 0; }
grep -q 'P2 — Suricata anomaly events' "$F" || { fail "ancora de inserare lipsă — ABORT"; exit 1; }

cp -a "$F" "$B" || { fail "backup"; exit 1; }
ok "backup $B"

revert(){
  echo "[REV] restaurare $B"; cp -a "$B" "$F"; chown root:wazuh "$F"; chmod 660 "$F"
  systemctl restart wazuh-manager; sleep 20
  echo "[REV] wazuh-manager=$(systemctl is-active wazuh-manager)"
}

BLOCK=$(mktemp)
cat > "$BLOCK" <<'EOF'
  <!-- CYBER3 10.10.2026: semnale relevante scoase din 100213 (Misc activity, nivel 2) si 100214 (Corporate Privacy, nivel 1) -->
  <rule id="100250" level="7">
    <if_sid>100213, 100214</if_sid>
    <field name="alert.signature" type="pcre2">(?i)REMOTE_ACCESS|AnyDesk|TeamViewer|RustDesk|ScreenConnect|Splashtop|NetSupport|Atera|RemotePC|Supremo|Ammyy</field>
    <description>Suricata: instrument de acces la distanta — $(alert.signature)</description>
    <mitre>
      <id>T1219</id>
    </mitre>
    <group>ids,remote_access,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_11.4,tsc_CC7.2,</group>
  </rule>
  <rule id="100251" level="12">
    <if_sid>100213, 100214</if_sid>
    <field name="alert.signature" type="pcre2">(?i)honey ?token|canary ?token|thinkst|o3n \.io|canarytokens</field>
    <description>Suricata: HONEYTOKEN declansat — posibil acces neautorizat la date-capcana — $(alert.signature)</description>
    <mitre>
      <id>T1083</id>
    </mitre>
    <group>ids,honeytoken,attack,gdpr_IV_35.7.d,gdpr_IV_32.2,nist_800_53_SI.4,pci_dss_11.4,tsc_CC7.2,</group>
  </rule>
  <rule id="100252" level="8">
    <if_sid>100213</if_sid>
    <field name="alert.signature" type="pcre2">(?i)\bCnC\b|\bC2\b|Command and Control|ClickFix|Stealer|Phishing|Exvicy|Malicious</field>
    <description>Suricata: semnal de compromitere in categoria Misc activity — $(alert.signature)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>ids,suspicious,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_11.4,tsc_CC7.2,</group>
  </rule>
EOF
awk -v blk="$BLOCK" '/P2 — Suricata anomaly events/ && !done { while ((getline l < blk) > 0) print l; done=1 } { print }' "$B" > "$F.tmp-r213" \
  && cat "$F.tmp-r213" > "$F" && rm -f "$F.tmp-r213" "$BLOCK"
chown root:wazuh "$F"; chmod 660 "$F"
[ "$(grep -c 'id="10025[012]"' "$F")" = 3 ] || { fail "inserare incompletă"; revert; exit 2; }
ok "3 reguli inserate (100250-100252)"

# test de configurație
OUT=$(/var/ossec/bin/wazuh-analysisd -t 2>&1); RC=$?
[ $RC -eq 0 ] || { fail "wazuh-analysisd -t rc=$RC: $(echo "$OUT" | tail -3 | tr '\n' ' ')"; revert; exit 2; }
ok "wazuh-analysisd -t: configurație validă"

# logtest pe 4 mostre (sesiune nouă = reguli citite de pe disc)
mk(){ printf '{"timestamp":"2026-10-10T10:00:00.000000+0000","flow_id":%s,"in_iface":"br0","event_type":"alert","src_ip":"192.168.103.88","src_port":50000,"dest_ip":"192.0.2.10","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":%s,"rev":1,"signature":"%s","category":"%s","severity":3}}\n' "$1" "$2" "$3" "$4"; }
lt(){ mk "$@" | timeout 40 $LT 2>&1 | awk -F"'" '/^\tid: /{id=$2} /^\tlevel: /{lv=$2} END{print id"/"lv}'; }
R1=$(lt 1 2025003 "ET REMOTE_ACCESS AnyDesk Remote Desktop Software User-Agent" "Misc activity")
R2=$(lt 2 2033467 "ET INFO Observed DNS Query to Thinkst Canary Token Domain (o3n .io)" "Misc activity")
R3=$(lt 3 2016149 "ET INFO Session Traversal Utilities for NAT (STUN Binding Request)" "Misc activity")
R4=$(lt 4 2054168 "ET REMOTE_ACCESS TeamViewer RMM Domain in DNS Lookup" "Potential Corporate Privacy Violation")
echo "logtest: AnyDesk=$R1 (așteptat 100250/7) · honeytoken=$R2 (100251/12) · STUN=$R3 (100213/2) · TeamViewer=$R4 (100250/7)"
if [ "$R1" = "100250/7" ] && [ "$R2" = "100251/12" ] && [ "$R3" = "100213/2" ] && [ "$R4" = "100250/7" ]; then
  ok "logtest: clasificare corectă, zgomotul rămâne la nivel 2"
else
  fail "logtest nu dă rezultatul așteptat"; revert; exit 2
fi

# restart controlat
systemctl restart wazuh-manager
for i in $(seq 1 24); do sleep 5; systemctl is-active --quiet wazuh-manager && break; done
systemctl is-active --quiet wazuh-manager || { fail "wazuh-manager nu a repornit"; revert; exit 2; }
sleep 60
AG1=$(/var/ossec/bin/agent_control -l | grep -c "Active")
ok "wazuh-manager repornit; agenți activi: $AG1 (înainte $AG0)"
[ "$AG1" -ge $((AG0 - 1)) ] || echo "[ATENȚIE] mai puțini agenți activi decât înainte — se reconectează de obicei în 1–3 minute; reverifică: agent_control -l"
echo "ROLLBACK: cp -a $B $F && systemctl restart wazuh-manager"
