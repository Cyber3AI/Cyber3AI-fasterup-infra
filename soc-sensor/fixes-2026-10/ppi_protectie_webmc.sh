#!/bin/bash
# Lansator — rulat de operator cu `!`: protecția WebMC pe icisoc108 (Primăria Pitești) + test din exterior.
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
PW="$(cat "$S/.fleetpw")"
{ printf '%s\n' "$PW"; cat "$S/ppi_protectie_webmc_sensor.sh"; } | \
  ssh -o ConnectTimeout=15 -J socadmin@10.0.0.22 socadmin@10.1.31.1 'sudo -S -p "" bash -s' 2>&1 | grep -v '^\[sudo\]'
echo; echo "== Test din Internet (după ~10 s): WebMC prin 5.2.164.82:8087 trebuie să NU mai răspundă cu HTTP =="
sleep 10
CODE=$(curl -s -m 12 -o /dev/null -w "%{http_code}" "http://5.2.164.82:8087/WebMC/" 2>/dev/null)
if [ "$CODE" = "000" ]; then echo "OK: nu mai răspunde din Internet (conexiune oprită de senzor)"; else echo "ATENȚIE: răspunde încă (HTTP $CODE) — verifică"; fi
ping -c 2 -W 3 10.1.31.1 >/dev/null && echo "icisoc108 răspunde pe VPN" || echo "ATENȚIE: icisoc108 nu răspunde pe VPN"
