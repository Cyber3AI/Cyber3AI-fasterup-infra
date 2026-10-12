#!/bin/bash
# Rulează PE SENZORUL icisoc109 (CNI), ca root (primit pe stdin prin sudo -S ... bash -s).
# Blocare PERMANENTĂ C2 OnionDrop din incidentul CN (24.09.2026): IP 91.92.33.76 + domeniul astroznenekey.com.
# Gărzi: precheck queue-bypass + memorie, backup, restart Suricata o singură dată, auto-revert la eroare.
# NU rulează niciodată `suricata -T` / reload pe senzorul inline viu.
set -u
TS=$(date -u +%Y%m%d-%H%M%S)
IP=91.92.33.76
LIST=/etc/cyber3/permaban.list
LOCAL=/var/lib/suricata/rules/cyber3-local.rules
SLOG=/var/log/suricata/suricata.log
FOREVER=4102444800   # 01.01.2100 — intrarea nu mai expiră (EXPIRE_DAYS compară epoch < cutoff)
ok(){ echo "[OK]  $*"; }; fail(){ echo "[ERR] $*"; }

echo "== icisoc109 $(date -u +%FT%TZ) =="
# 0. precheck
[ "$(iptables -S FORWARD | grep -c 'NFQUEUE.*--queue-bypass')" -ge 1 ] || { fail "queue-bypass lipsă pe FORWARD — ABORT (restartul ar tăia traficul)"; exit 1; }
ok "queue-bypass prezent (traficul CNI trece în timpul restartului)"
AVAIL=$(free -m | awk '/^Mem:/{print $7}'); [ "$AVAIL" -gt 4000 ] || { fail "memorie disponibilă $AVAIL MB < 4000 — ABORT"; exit 1; }
ok "memorie disponibilă ${AVAIL} MB"
systemctl is-active --quiet suricata || { fail "suricata nu e activ — ABORT"; exit 1; }

# 1. IP permanent în permaban (mecanismul existent îl reaplică în CYBER3_BLOCK la fiecare rulare și după reboot)
cp -a "$LIST" "$LIST.bak-cn-perm-$TS"
if awk -v x="$IP" '$1==x{f=1} END{exit !f}' "$LIST"; then
  awk -v x="$IP" -v e="$FOREVER" '$1==x{$2=e} {print $1" "$2}' "$LIST" > "$LIST.tmp" && cat "$LIST.tmp" > "$LIST" && rm -f "$LIST.tmp"
else
  echo "$IP $FOREVER" >> "$LIST"
fi
iptables -C CYBER3_BLOCK -s "$IP" -j DROP 2>/dev/null || iptables -A CYBER3_BLOCK -s "$IP" -j DROP
echo "$(date -u +%FT%TZ) PERMANENT $IP incident-CN-24.09 (fara expirare)" >> /var/log/cyber3/permaban-audit.log 2>/dev/null
grep -q "^$IP $FOREVER$" "$LIST" && iptables -C CYBER3_BLOCK -s "$IP" -j DROP && ok "$IP permanent în permaban.list (epoch $FOREVER) + CYBER3_BLOCK" || { fail "permaban nu s-a aplicat"; cp -a "$LIST.bak-cn-perm-$TS" "$LIST"; exit 1; }

# 2. reguli Suricata: IP în ambele sensuri + domeniu (DNS, TLS SNI, HTTP Host)
if grep -q "sid:9100910;" "$LOCAL"; then
  ok "regulile 9100910-9100914 există deja — fără restart"
  RESTART=0
else
  cp -a "$LOCAL" "$LOCAL.bak-cn-perm-$TS"
  cat >> "$LOCAL" <<'EOF'
# CYBER3 10.10.2026: incident CN (24.09) — C2 OnionDrop, blocare permanentă (ICI, pct. 7.3)
drop ip $HOME_NET any -> 91.92.33.76 any (msg:"CYBER3 BLOCK C2 OnionDrop 91.92.33.76 iesire (incident CN 24.09)"; classtype:trojan-activity; sid:9100910; rev:1;)
drop ip 91.92.33.76 any -> $HOME_NET any (msg:"CYBER3 BLOCK C2 OnionDrop 91.92.33.76 intrare (incident CN 24.09)"; classtype:trojan-activity; sid:9100911; rev:1;)
drop dns $HOME_NET any -> any any (msg:"CYBER3 BLOCK DNS C2 OnionDrop astroznenekey.com (incident CN 24.09)"; dns.query; dotprefix; content:".astroznenekey.com"; nocase; endswith; classtype:trojan-activity; sid:9100912; rev:1;)
drop tls $HOME_NET any -> any any (msg:"CYBER3 BLOCK TLS SNI C2 OnionDrop astroznenekey.com (incident CN 24.09)"; flow:established,to_server; tls.sni; dotprefix; content:".astroznenekey.com"; nocase; endswith; classtype:trojan-activity; sid:9100913; rev:1;)
drop http $HOME_NET any -> any any (msg:"CYBER3 BLOCK HTTP Host C2 OnionDrop astroznenekey.com (incident CN 24.09)"; flow:established,to_server; http.host; dotprefix; content:".astroznenekey.com"; endswith; classtype:trojan-activity; sid:9100914; rev:1;)
EOF
  chown suricata:suricata "$LOCAL" 2>/dev/null; chmod 640 "$LOCAL"
  ok "5 reguli adăugate în cyber3-local.rules (backup .bak-cn-perm-$TS)"
  RESTART=1
fi

# 3. restart controlat o singură dată + verificare + auto-revert
if [ "$RESTART" = 1 ]; then
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
    fail "restart nereușit (activ=$(systemctl is-active suricata), $LOADED, cozi=${Q:-?}) — REVERT reguli"
    tail -n +"$((MARK+1))" "$SLOG" | grep -iE "error|9100910|9100911|9100912|9100913|9100914" | head -10
    cp -a "$LOCAL.bak-cn-perm-$TS" "$LOCAL"; systemctl restart suricata; sleep 60
    echo "după revert: suricata=$(systemctl is-active suricata). Blocarea IP din CYBER3_BLOCK rămâne activă."
    exit 2
  fi
fi

# 4. verificare finală
echo "== VERIFICARE =="
echo "permaban.list:       $(grep "^$IP " "$LIST")"
echo "CYBER3_BLOCK:        $(iptables -S CYBER3_BLOCK | grep "$IP")"
echo "reguli locale CN:    $(grep -c 'sid:91009[1][0-4];' "$LOCAL") din 5"
echo "drop total:          $(grep -c '^drop ' /var/lib/suricata/rules/suricata.rules) (ET) + $(grep -c '^drop ' "$LOCAL") (locale)"
echo "queue-bypass:        $(iptables -S FORWARD | grep -c queue-bypass)"
echo "qdrop/udrop cozi:    $(awk '{q+=$6; u+=$7} END{print q"/"u}' /proc/net/netfilter/nfnetlink_queue)"
echo "suricata / wazuh:    $(systemctl is-active suricata) / $(systemctl is-active wazuh-agent)"
echo "ROLLBACK (dacă e nevoie): cp -a $LOCAL.bak-cn-perm-$TS $LOCAL && systemctl restart suricata ; cp -a $LIST.bak-cn-perm-$TS $LIST"
