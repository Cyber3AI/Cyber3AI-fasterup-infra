#!/usr/bin/env bash
# CYBER3 SOC — rollout idempotent al receiver-ului pe un senzor (Faza 2, calea PRIMARĂ).
#
# SIGURANȚĂ: instalează DOAR un serviciu userspace (soc-receiver.py) care ascultă 8765/8766 și
# scrie /var/log/cyber3/events.json. NU atinge Suricata, bridge-ul inline, forwarding-ul sau
# rutarea — deci NU poate bloca internetul clientului. Idempotent: se poate rula de oricâte ori.
#
# Firewall: doar dacă INPUT NU e ACCEPT, adaugă reguli ACCEPT *scoped pe interfața LAN* pentru
# 8765/8766; altfel nu schimbă nimic în firewall.
#
# Folosire (se rulează PE senzor, ca root/sudo):
#   CYBER3_ORG=NUME_ORG LAN_IF=br0 bash rollout-receiver.sh /cale/catre/soc-receiver.py
#
set -euo pipefail

SRC="${1:-/tmp/soc-receiver.py}"
ORG="${CYBER3_ORG:?Setează CYBER3_ORG=<organizație> (eticheta evenimentelor)}"
HTTP_PORT="${CYBER3_HTTP_PORT:-8765}"
UDP_PORT="${CYBER3_UDP_PORT:-8766}"
LAN_IF="${LAN_IF:-}"
SVC_USER="${SVC_USER:-socadmin}"

[ -f "$SRC" ] || { echo "EROARE: sursa $SRC lipsește"; exit 1; }
id "$SVC_USER" >/dev/null 2>&1 || { echo "EROARE: userul $SVC_USER nu există"; exit 1; }

echo "==> Instalez binarul + dirul de log"
install -d -o root -g root -m 0755 /opt/cyber3
install -o "$SVC_USER" -g "$SVC_USER" -m 0755 "$SRC" /opt/cyber3/soc-receiver.py
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 /var/log/cyber3

echo "==> Scriu /etc/default/cyber3-soc-receiver (ORG=$ORG)"
cat >/etc/default/cyber3-soc-receiver <<EOF
CYBER3_ORG=$ORG
CYBER3_HTTP_PORT=$HTTP_PORT
CYBER3_UDP_PORT=$UDP_PORT
EOF

echo "==> Scriu unit systemd"
cat >/etc/systemd/system/cyber3-soc-receiver.service <<EOF
[Unit]
Description=CYBER3 SOC receiver — evenimente EDR/XDR de la endpoint-uri din LAN -> Wazuh
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
EnvironmentFile=/etc/default/cyber3-soc-receiver
ExecStart=/usr/bin/python3 /opt/cyber3/soc-receiver.py
Restart=on-failure
RestartSec=5
Nice=10

[Install]
WantedBy=multi-user.target
EOF

echo "==> (opțional) Firewall — doar dacă INPUT nu e ACCEPT"
POLICY="$(iptables -S INPUT 2>/dev/null | head -1 || true)"
if [ "$POLICY" = "-P INPUT ACCEPT" ] || [ -z "$POLICY" ]; then
  echo "    INPUT=ACCEPT (sau iptables indisponibil) -> nicio regulă necesară"
else
  echo "    INPUT restrictiv -> adaug ACCEPT scoped (${LAN_IF:-orice LAN}) pt $HTTP_PORT/tcp, $UDP_PORT/udp"
  IFARG=""; [ -n "$LAN_IF" ] && IFARG="-i $LAN_IF"
  # idempotent: -C verifică, adaugă doar dacă lipsește
  iptables -C INPUT $IFARG -p tcp --dport "$HTTP_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT $IFARG -p tcp --dport "$HTTP_PORT" -j ACCEPT
  iptables -C INPUT $IFARG -p udp --dport "$UDP_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT $IFARG -p udp --dport "$UDP_PORT" -j ACCEPT
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
fi

echo "==> Pornesc serviciul"
systemctl daemon-reload
systemctl enable --now cyber3-soc-receiver >/dev/null 2>&1
systemctl restart cyber3-soc-receiver
sleep 2

echo "==> Verificare receiver"
systemctl is-active cyber3-soc-receiver
curl -s --max-time 5 "http://127.0.0.1:$HTTP_PORT/v1/soc/health" || { echo "HEALTH FAIL"; exit 1; }
echo

echo "==> Asigur că agentul Wazuh citește events.json (localfile json)"
OSSEC=/var/ossec/etc/ossec.conf
if grep -q "/var/log/cyber3/events.json" "$OSSEC" 2>/dev/null; then
  echo "    OK: localfile deja prezent (nicio modificare)"
else
  echo "    Adaug localfile (backup + insert înainte de </ossec_config>)"
  cp -a "$OSSEC" "$OSSEC.bak-cyber3-$(date +%Y%m%d%H%M%S)"
  python3 - "$OSSEC" <<'PY'
import sys
f = sys.argv[1]
txt = open(f, encoding='utf-8').read()
block = ("  <!-- CYBER3 SOC bridge: evenimente EDR/XDR de la endpoint-uri din LAN -->\n"
         "  <localfile>\n"
         "    <log_format>json</log_format>\n"
         "    <location>/var/log/cyber3/events.json</location>\n"
         "  </localfile>\n")
i = txt.rfind('</ossec_config>')
assert i != -1, 'lipsește </ossec_config>'
open(f, 'w', encoding='utf-8').write(txt[:i] + block + txt[i:])
print('    localfile inserat')
PY
  echo "    Restart wazuh-agent"
  systemctl restart wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
  sleep 3
  systemctl is-active wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control status 2>/dev/null | head -3
  # dacă agentul nu pornește, semnalează puternic (config greșit) — dar bridge-ul/internetul nu sunt afectate
  tail -2 /var/ossec/logs/ossec.log 2>/dev/null | grep -i "error\|critical" && echo "    !!! verifică ossec.log" || true
fi
echo "==> GATA pe $(hostname) — org=$ORG"
