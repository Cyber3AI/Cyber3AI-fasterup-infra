#!/bin/bash
# Rulează PE MANAGERUL WAZUH (10.0.0.100), ca root (primit pe stdin prin sudo -S ... bash -s).
# Flood 10-11.10.2026: regula 100250 (acces la distanță, nivel 7) a ridicat în index și interogările DNS / TLS SNI de fundal
# ale clienților AnyDesk/TeamViewer (≈25.000/zi, 26 de stații icisoc110). Se adaugă copilul 100254 (nivel 2 = nu se indexează)
# DOAR pentru semnăturile „… in DNS Lookup / in TLS SNI”. Rămân la nivel 7 sesiunile reale (REMOTE_ACCESS / User-Agent).
# Gărzi: backup, analysisd -t, logtest pe 5 mostre, restart controlat, verificare agenți, auto-revert.
set -u
TS=$(date -u +%Y%m%d-%H%M%S)
F=/var/ossec/etc/rules/local_rules.xml
B="$F.bak-r250flood-$TS"
LT=/var/ossec/bin/wazuh-logtest
ok(){ echo "[OK]  $*"; }; fail(){ echo "[ERR] $*"; }

echo "== manager Wazuh $(date -u +%FT%TZ) =="
systemctl is-active --quiet wazuh-manager || { fail "wazuh-manager nu e activ — ABORT"; exit 1; }
AG0=$(/var/ossec/bin/agent_control -l | grep -c "Active")
grep -q 'id="100254"' "$F" && { ok "100254 există deja — nimic de făcut"; exit 0; }
grep -q 'id="100252"' "$F" || { fail "100252 lipsă — ABORT"; exit 1; }
cp -a "$F" "$B" || { fail backup; exit 1; }
ok "backup $B"
revert(){ echo "[REV] restaurare $B"; cp -a "$B" "$F"; chown root:wazuh "$F"; chmod 660 "$F"; systemctl restart wazuh-manager; sleep 20; echo "[REV] wazuh-manager=$(systemctl is-active wazuh-manager)"; }

BLOCK=$(mktemp)
cat > "$BLOCK" <<'EOF'
  <!-- CYBER3 11.10.2026: zgomot de fundal al clientilor de acces la distanta (DNS / TLS SNI) — nu se indexeaza -->
  <rule id="100254" level="2">
    <if_sid>100250</if_sid>
    <field name="alert.signature" type="pcre2">(?i)(in DNS Lookup|in TLS SNI)</field>
    <description>Suricata: acces la distanta — trafic de fundal (DNS/SNI) — $(alert.signature)</description>
    <group>ids,remote_access,remote_access_background,</group>
  </rule>
EOF
# inserare imediat după închiderea regulii 100252
awk -v blk="$BLOCK" '{ print } /<rule id="100252"/ { inr=1 } inr && /<\/rule>/ { while ((getline l < blk) > 0) print l; inr=0 }' "$B" > "$F.tmp" && cat "$F.tmp" > "$F" && rm -f "$F.tmp" "$BLOCK"
chown root:wazuh "$F"; chmod 660 "$F"
[ "$(grep -c 'id="100254"' "$F")" = 1 ] || { fail "inserare"; revert; exit 2; }
OUT=$(/var/ossec/bin/wazuh-analysisd -t 2>&1) || { fail "analysisd -t: $(echo "$OUT" | tail -2 | tr '\n' ' ')"; revert; exit 2; }
ok "configurație validă"

mk(){ printf '{"timestamp":"2026-10-11T10:00:00.000000+0000","flow_id":%s,"in_iface":"br0","event_type":"alert","src_ip":"192.168.3.115","src_port":50000,"dest_ip":"192.0.2.10","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":%s,"rev":1,"signature":"%s","category":"%s","severity":3}}\n' "$1" "$2" "$3" "$4"; }
lt(){ mk "$@" | timeout 40 $LT 2>&1 | awk -F"'" '/^\tid: /{id=$2} /^\tlevel: /{lv=$2} END{print id"/"lv}'; }
R1=$(lt 1 2060507 "ET INFO Anydesk Relay Domain (net .anydesk .com) in DNS Lookup" "Potential Corporate Privacy Violation")
R2=$(lt 2 2060508 "ET INFO Observed Anydesk Relay Domain (net .anydesk .com) in TLS SNI" "Misc activity")
R3=$(lt 3 2027762 "ET REMOTE_ACCESS AnyDesk Remote Desktop Software User-Agent" "Misc activity")
R4=$(lt 4 2009475 "ET POLICY TeamViewer Dyngate User-Agent" "Potential Corporate Privacy Violation")
R5=$(lt 5 2033467 "ET INFO Observed DNS Query to Thinkst Canary Token Domain (o3n .io)" "Misc activity")
echo "logtest: DNS AnyDesk=$R1 | SNI AnyDesk=$R2 | UA AnyDesk=$R3 | TeamViewer UA=$R4 | honeytoken=$R5"
[ "$R1" = "100254/2" ] && [ "$R2" = "100254/2" ] && [ "$R3" = "100250/7" ] && [ "$R4" = "100250/7" ] && [ "$R5" = "100251/12" ] \
  || { fail "logtest diferit de așteptări (100254/2, 100254/2, 100250/7, 100250/7, 100251/12)"; revert; exit 2; }
ok "logtest 5/5"

systemctl restart wazuh-manager
for i in $(seq 1 24); do sleep 5; systemctl is-active --quiet wazuh-manager && break; done
systemctl is-active --quiet wazuh-manager || { fail "manager nu a repornit"; revert; exit 2; }
sleep 60; AG1=$(/var/ossec/bin/agent_control -l | grep -c "Active")
ok "manager repornit; agenți activi $AG1 (înainte $AG0)"
[ "$AG1" -ge $((AG0-1)) ] || { fail "agenți pierduți"; revert; exit 2; }
echo "ROLLBACK: cp -a $B $F; systemctl restart wazuh-manager"
