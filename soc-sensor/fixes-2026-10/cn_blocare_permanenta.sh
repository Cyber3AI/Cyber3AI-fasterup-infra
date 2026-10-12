#!/bin/bash
# Lansator — rulat de operator cu `!`: trimite scriptul pe icisoc109 (CNI) și îl execută ca root.
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
PW="$(cat "$S/.fleetpw")"
{ printf '%s\n' "$PW"; cat "$S/cn_blocare_permanenta_sensor.sh"; } | \
  ssh -o ConnectTimeout=15 -J socadmin@10.0.0.22 socadmin@10.1.32.1 'sudo -S -p "" bash -s' 2>&1 | grep -v '^\[sudo\]'
echo; echo "Verificare externă: ping senzor CNI"; ping -c 2 -W 3 10.1.32.1 >/dev/null && echo "icisoc109 răspunde pe VPN" || echo "ATENȚIE: icisoc109 nu răspunde pe VPN"
