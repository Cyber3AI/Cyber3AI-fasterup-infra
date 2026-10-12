#!/bin/bash
# Rulează PE SENZORUL icisoc108 (Primăria Pitești), ca root (primit pe stdin prin sudo -S ... bash -s).
# Protecție de urgență pentru incidentul PPI: oprește accesul DIN INTERNET la interfața web (WebMC) a centralei
# Panasonic KX-NS1000 192.168.1.159 (publicată prin 5.2.164.82:8087 -> 192.168.1.159:80), până închide clientul redirecționarea.
# Telefonia NU e atinsă: se blochează doar TCP 80/443 spre centrală din $EXTERNAL_NET (SIP/RTP/trunchiuri folosesc alte porturi);
# accesul din LAN nu trece prin senzor și rămâne neschimbat.
# Gărzi: precheck queue-bypass + memorie, backup, UN restart Suricata, auto-revert. NICIODATĂ `suricata -T` / reload pe senzorul viu.
set -u
TS=$(date -u +%Y%m%d-%H%M%S)
LOCAL=/var/lib/suricata/rules/cyber3-local.rules
SLOG=/var/log/suricata/suricata.log
ok(){ echo "[OK]  $*"; }; fail(){ echo "[ERR] $*"; }

echo "== icisoc108 $(date -u +%FT%TZ) =="
[ "$(iptables -S FORWARD | grep -c 'NFQUEUE.*--queue-bypass')" -ge 1 ] || { fail "queue-bypass lipsă — ABORT"; exit 1; }
ok "queue-bypass prezent (traficul Primăriei trece în timpul restartului)"
AVAIL=$(free -m | awk '/^Mem:/{print $7}'); [ "$AVAIL" -gt 4000 ] || { fail "memorie disponibilă $AVAIL MB < 4000 — ABORT"; exit 1; }
ok "memorie disponibilă ${AVAIL} MB"
systemctl is-active --quiet suricata || { fail "suricata nu e activ — ABORT"; exit 1; }

if grep -q "sid:9100920;" "$LOCAL"; then
  ok "regulile 9100920-9100921 există deja — nimic de făcut"; exit 0
fi
cp -a "$LOCAL" "$LOCAL.bak-ppi-$TS"
cat >> "$LOCAL" <<'EOF'
# CYBER3 10.10.2026: incident PPI — centrala KX-NS1000 192.168.1.159 publicată din Internet (8087->80); WebMC vulnerabil (traversal + upload)
drop tcp $EXTERNAL_NET any -> 192.168.1.159 [80,443] (msg:"CYBER3 BLOCK acces din Internet la WebMC centrala KX-NS1000 192.168.1.159 (incident PPI)"; flow:to_server; classtype:attempted-admin; sid:9100920; rev:1;)
drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"CYBER3 BLOCK cerere WebMC Panasonic din Internet (incident PPI)"; flow:established,to_server; http.uri; content:"/WebMC/"; nocase; classtype:attempted-admin; sid:9100921; rev:1;)
EOF
chown suricata:suricata "$LOCAL" 2>/dev/null; chmod 640 "$LOCAL"
ok "2 reguli adăugate în cyber3-local.rules (backup .bak-ppi-$TS)"

MARK=$(wc -l < "$SLOG")
systemctl restart suricata
WAITED=0; STARTED=0
while [ $WAITED -lt 240 ]; do
  sleep 5; WAITED=$((WAITED+5))
  if tail -n +"$((MARK+1))" "$SLOG" | grep -q "rules successfully loaded"; then
    Q=$(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null)
    [ "${Q:-0}" -ge 4 ] && { STARTED=1; break; }
  fi
done
LOADED=$(tail -n +"$((MARK+1))" "$SLOG" | grep -oE "[0-9]+ rules successfully loaded, [0-9]+ rules failed" | tail -1)
FAILED=$(echo "$LOADED" | grep -oE "[0-9]+ rules failed" | grep -oE "^[0-9]+")
if [ "$STARTED" = 1 ] && systemctl is-active --quiet suricata && [ "${FAILED:-1}" = 0 ]; then
  ok "Suricata repornit în ${WAITED}s: $LOADED; cozi NFQ legate: $Q"
else
  fail "restart nereușit (activ=$(systemctl is-active suricata), $LOADED, cozi=${Q:-?}) — REVERT"
  tail -n +"$((MARK+1))" "$SLOG" | grep -iE "error|9100920|9100921" | head -10
  cp -a "$LOCAL.bak-ppi-$TS" "$LOCAL"; systemctl restart suricata; sleep 60
  echo "după revert: suricata=$(systemctl is-active suricata)"; exit 2
fi

echo "== VERIFICARE =="
echo "reguli PPI în fișier: $(grep -c 'sid:910092[01];' "$LOCAL") din 2"
echo "queue-bypass:         $(iptables -S FORWARD | grep -c queue-bypass)"
echo "qdrop/udrop cozi:     $(awk '{q+=$6; u+=$7} END{print q"/"u}' /proc/net/netfilter/nfnetlink_queue)"
echo "suricata / wazuh:     $(systemctl is-active suricata) / $(systemctl is-active wazuh-agent)"
echo "ROLLBACK: cp -a $LOCAL.bak-ppi-$TS $LOCAL && systemctl restart suricata"
