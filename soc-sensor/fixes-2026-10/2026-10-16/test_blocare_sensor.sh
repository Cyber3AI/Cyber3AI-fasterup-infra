#!/bin/bash
# TEST FUNCȚIONAL DE BLOCARE (rulează pe senzor ca root; argument: hostname așteptat).
# Adresa de test 192.0.2.234 (TEST-NET-1, RFC 5737): rezervată documentației, nerutată pe internet, nu o folosește niciun client.
# Pași: AR real (binarul Wazuh firewall-drop-real) ADD -> verific regula DROP în INPUT+FORWARD -> DELETE -> verific 0 reziduuri.
# Durata: câteva secunde. Nu atinge Suricata, NFQUEUE sau alt trafic.
set -u
EXP="${1:-}"; H=$(hostname); [ "$H" = "$EXP" ] || { echo "[$H] ABORT: hostname diferit de $EXP"; exit 3; }
IP=192.0.2.234; R=/var/ossec/active-response/bin/firewall-drop-real
[ -x "$R" ] || { echo "[$H] ABORT: lipsește $R"; exit 3; }
cnt(){ iptables -S 2>/dev/null | grep -c -- "-s $IP/32 -j DROP"; }
[ "$(cnt)" = 0 ] || { echo "[$H] ABORT: $IP există deja în iptables ($(cnt))"; exit 3; }
dlg(){ printf '%s\n' "{\"version\":1,\"origin\":{\"name\":\"c3-test\",\"module\":\"wazuh-execd\"},\"command\":\"$1\",\"parameters\":{\"extra_args\":[],\"alert\":{\"data\":{\"srcip\":\"$IP\"}},\"program\":\"active-response/bin/firewall-drop\"}}"; sleep 2
       printf '%s\n' '{"version":1,"origin":{"name":"c3-test","module":"wazuh-execd"},"command":"continue","parameters":{}}'; sleep 1; }
Q1=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{print $1}')
dlg add | timeout 20 $R >/dev/null 2>&1; A=$(cnt); WHERE=$(iptables -S | grep -- "-s $IP/32 -j DROP" | awk '{print $2}' | tr '\n' ',')
dlg delete | timeout 20 $R >/dev/null 2>&1; D=$(cnt)
[ "$D" = 0 ] || { iptables -S | grep -- "-s $IP/32 -j DROP" | sed 's/^-A/-D/' | while read -r r; do iptables $r; done; }
Q2=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{print $1}')
if [ "$A" -ge 1 ] && [ "$(cnt)" = 0 ]; then V="PASS"; else V="EȘEC"; fi
echo "[$H] TEST BLOCARE: $V | add -> $A reguli DROP ($WHERE) | delete -> $D rămase (final $(cnt)) | AR activ în ossec.conf: $(grep -A1 '<active-response>' /var/ossec/etc/ossec.conf | grep -c '<disabled>no') | trafic NFQUEUE în timpul testului: +$(( ${Q2:-0} - ${Q1:-0} )) | suricata=$(systemctl is-active suricata)"
