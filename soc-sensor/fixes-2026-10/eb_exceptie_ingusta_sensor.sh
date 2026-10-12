#!/bin/bash
# Rulează PE SENZORUL icisoc103 (Elbi), ca root (primit pe stdin prin sudo -S ... bash -s).
# Înlocuiește excepția prea largă sid 9100902 (pass http 192.168.2.9 80 -> $HOME_NET any) cu tratare îngustă:
#   - 2061633 (zgRAT/PureLogs GZIP) dezactivată din sursa ET prin /etc/suricata/disable.conf (rezistă la update-ul zilnic);
#   - 9100903 = aceeași semnătură, DOAR ALERTĂ, numai pentru serverul 192.168.2.9;
#   - 9100904 = aceeași semnătură, DROP, pentru orice ALT server (comportamentul ET păstrat).
# Restul inspecției/blocării pentru 192.168.2.9 revine la normal (fără pass).
# Gărzi: precheck, backup, UN restart controlat, verificare, auto-revert. NICIODATĂ `suricata -T` / reload.
set -u
TS=$(date -u +%Y%m%d-%H%M%S)
R=/var/lib/suricata/rules
RULES=$R/suricata.rules
LOCAL=$R/cyber3-local.rules
DIS=/etc/suricata/disable.conf
SLOG=/var/log/suricata/suricata.log
ok(){ echo "[OK]  $*"; }; fail(){ echo "[ERR] $*"; }

echo "== icisoc103 $(date -u +%FT%TZ) =="
# ---- 0. precheck ----
[ "$(iptables -S FORWARD | grep -c 'NFQUEUE.*--queue-bypass')" -ge 1 ] || { fail "queue-bypass lipsă pe FORWARD — ABORT"; exit 1; }
ok "queue-bypass prezent"
AVAIL=$(free -m | awk '/^Mem:/{print $7}'); [ "$AVAIL" -gt 3000 ] || { fail "memorie disponibilă $AVAIL MB < 3000 — ABORT"; exit 1; }
ok "memorie disponibilă ${AVAIL} MB"
systemctl is-active --quiet suricata || { fail "suricata inactiv — ABORT"; exit 1; }
exec 9>/run/cyber3-suricata-update.lock; flock -w 300 9 || { fail "update-ul zilnic rulează (lock) — ABORT"; exit 1; }
ok "lock update obținut (update-ul automat nu poate rula în paralel)"
grep -q "sid:9100903;" "$LOCAL" && { ok "9100903 există deja — nimic de făcut"; exit 0; }

DROP_ET0=$(grep -c '^drop ' "$RULES"); DROP_LOC0=$(grep -c '^drop ' "$LOCAL")
echo "drop înainte: ET=$DROP_ET0 local=$DROP_LOC0"

# ---- 1. backup ----
for f in "$RULES" "$LOCAL" "$DIS"; do cp -a "$f" "$f.bak-eb-$TS" || { fail "backup $f"; exit 1; }; done
ok "backup-uri .bak-eb-$TS (suricata.rules, cyber3-local.rules, disable.conf)"

revert(){
  echo "[REV] restaurare backup-uri .bak-eb-$TS"
  for f in "$RULES" "$LOCAL" "$DIS"; do cp -a "$f.bak-eb-$TS" "$f"; done
  systemctl restart suricata
  for i in $(seq 1 60); do sleep 4; tail -40 "$SLOG" | grep -qa 'Engine started' && systemctl is-active --quiet suricata && break; done
  echo "[REV] după revert: suricata=$(systemctl is-active suricata), drop ET=$(grep -c '^drop ' "$RULES")"
}

# ---- 2. disable.conf: 2061633 scoasă din sursa ET (citit de suricata-update la fiecare rulare) ----
grep -qE '^2061633([[:space:]]|$)' "$DIS" || printf '# CYBER3 %s: 2061633 dezactivat global; inlocuit cu 9100903 (alert 192.168.2.9) + 9100904 (drop restul) in cyber3-local.rules\n2061633\n' "$(date -u +%F)" >> "$DIS"
ok "2061633 în disable.conf"

# ---- 3. cyber3-local.rules: scoate pass 9100902 (+ comentariul lui), adaugă 9100903/9100904 ----
awk '/^# CYBER3 25 sep 2026: icisoc103 aplicatie interna 192.168.2.9:80/ {next} /sid:9100902;/ {next} {print}' "$LOCAL" > "$LOCAL.tmp-eb" || { fail "editare local"; revert; exit 2; }
cat >> "$LOCAL.tmp-eb" <<'EOF'
# CYBER3 10.10.2026: inlocuieste pass-ul larg 9100902. 2061633 (ET, dezactivat in disable.conf) copiat exact:
#   - 9100903 DOAR ALERTA pentru serverul intern 192.168.2.9 (portal Elbi / xTrack WMS, FP probabil - incident EB, ICI);
#   - 9100904 DROP pentru orice alt server (comportamentul ET pastrat).
alert tcp 192.168.2.9 any -> $HOME_NET any (msg:"ET MALWARE zgRAT / PureLogs CnC Backdoor Server GZIP Traffic [CYBER3 alert-only 192.168.2.9, incident EB]"; flow:established,to_client; byte_extract:4,0,size; content:"|1f 8b 08 00 00 00 00 00 04 00|"; offset:4; depth:10; byte_jump:0,0,from_end,post_offset -4; byte_test:4,=,size,0,relative; reference:url,app.any.run/tasks/8c40a9d2-dc92-48ba-b75e-616f1a230000; classtype:trojan-activity; sid:9100903; rev:1; metadata:original_sid 2061633, malware_family PureLogs; target:dest_ip;)
drop tcp !192.168.2.9 any -> $HOME_NET any (msg:"ET MALWARE zgRAT / PureLogs CnC Backdoor Server GZIP Traffic [CYBER3 copie 2061633]"; flow:established,to_client; byte_extract:4,0,size; content:"|1f 8b 08 00 00 00 00 00 04 00|"; offset:4; depth:10; byte_jump:0,0,from_end,post_offset -4; byte_test:4,=,size,0,relative; reference:url,app.any.run/tasks/8c40a9d2-dc92-48ba-b75e-616f1a230000; classtype:trojan-activity; sid:9100904; rev:1; metadata:original_sid 2061633, malware_family PureLogs; target:dest_ip;)
EOF
cat "$LOCAL.tmp-eb" > "$LOCAL" && rm -f "$LOCAL.tmp-eb"
chown suricata:suricata "$LOCAL" 2>/dev/null; chmod 640 "$LOCAL"
if grep -q "sid:9100902;" "$LOCAL" || ! grep -q "sid:9100903;" "$LOCAL" || ! grep -q "sid:9100904;" "$LOCAL"; then fail "local rules incorecte"; revert; exit 2; fi
ok "9100902 scos; 9100903 (alert) + 9100904 (drop) adăugate"

# ---- 4. regenerare ruleset prin mecanismul existent (fără test, fără reload) ----
OUT=$(suricata-update --no-test --no-reload 2>&1); RC=$?
if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -qiE 'no such option|unrecognized|invalid choice'; then OUT=$(suricata-update --no-test 2>&1); RC=$?; fi
[ "$RC" -eq 0 ] || { fail "suricata-update rc=$RC: $(printf '%s' "$OUT" | tail -3 | tr '\n' ' ')"; revert; exit 2; }
N=$(wc -l < "$RULES"); [ "$N" -ge 1000 ] || { fail "ruleset prea mic ($N)"; revert; exit 2; }
grep -qE '^(drop|alert) .*sid:2061633;' "$RULES" && { fail "2061633 încă activ în suricata.rules după update"; revert; exit 2; }
DROP_ET1=$(grep -c '^drop ' "$RULES"); DROP_LOC1=$(grep -c '^drop ' "$LOCAL")
D=$((DROP_ET0 - DROP_ET1))
echo "drop după update: ET=$DROP_ET1 (−$D) local=$DROP_LOC1 (+$((DROP_LOC1-DROP_LOC0)))"
# toleranță: sursa ET se poate schimba zilnic; verificăm doar că nu s-a pierdut conversia (regresia 22.09)
[ "$DROP_ET1" -ge $((DROP_ET0 - 50)) ] && [ "$DROP_ET1" -ge 10000 ] || { fail "drop ET a scăzut anormal ($DROP_ET0 → $DROP_ET1) — posibilă regresie drop.conf"; revert; exit 2; }
ok "ruleset regenerat: $N linii, 2061633 dezactivat, conversia drop intactă"

# ---- 5. UN restart controlat ----
MARK=$(wc -l < "$SLOG")
MP0=$(systemctl show suricata -p MainPID --value)
systemctl restart suricata
STARTED=0; W=0
while [ $W -lt 240 ]; do
  sleep 5; W=$((W+5))
  if [ "$(systemctl show suricata -p MainPID --value)" != "$MP0" ] && tail -n +"$((MARK+1))" "$SLOG" | grep -qa 'Engine started'; then
    Q=$(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null); [ "${Q:-0}" -ge 4 ] && { STARTED=1; break; }
  fi
done
LOADED=$(tail -n +"$((MARK+1))" "$SLOG" | grep -oE '[0-9]+ rules successfully loaded, [0-9]+ rules failed' | tail -1)
FAILED=$(echo "$LOADED" | grep -oE '[0-9]+ rules failed' | grep -oE '^[0-9]+')
if [ "$STARTED" = 1 ] && systemctl is-active --quiet suricata && [ "${FAILED:-1}" = 0 ]; then
  ok "Suricata repornit în ${W}s: $LOADED; cozi NFQ: $Q"
else
  fail "restart nereușit (activ=$(systemctl is-active suricata), '$LOADED', cozi=${Q:-?})"
  tail -n +"$((MARK+1))" "$SLOG" | grep -iE 'error|9100903|9100904' | head -8
  revert; exit 2
fi

# ---- 6. verificare finală ----
sleep 20
echo "== VERIFICARE =="
echo "pass 9100902:        $(grep -c 'sid:9100902;' "$LOCAL") (trebuie 0)"
echo "9100903 / 9100904:   $(grep -c '^alert .*sid:9100903;' "$LOCAL") alert / $(grep -c '^drop .*sid:9100904;' "$LOCAL") drop"
echo "2061633 în ET:       $(grep -cE '^(drop|alert) .*sid:2061633;' "$RULES") activ (trebuie 0)"
echo "drop total:          ET $DROP_ET0 → $DROP_ET1 · local $DROP_LOC0 → $DROP_LOC1"
echo "queue-bypass:        $(iptables -S FORWARD | grep -c queue-bypass)"
echo "qdrop/udrop cozi:    $(awk '{q+=$6; u+=$7} END{print q"/"u}' /proc/net/netfilter/nfnetlink_queue)"
echo "suricata / wazuh:    $(systemctl is-active suricata) / $(systemctl is-active wazuh-agent)"
echo "ROLLBACK: for f in $RULES $LOCAL $DIS; do cp -a \$f.bak-eb-$TS \$f; done; systemctl restart suricata"
