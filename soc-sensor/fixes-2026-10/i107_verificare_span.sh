#!/bin/bash
# Lansator — rulat de operator cu `!`: verificare read-only a oglindirii SPAN pe icisoc107 (Turnu Măgurele).
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
PW="$(cat "$S/.fleetpw")"
{ printf '%s\n' "$PW"; cat "$S/i107_verificare_span_sensor.sh"; } | \
  ssh -o ConnectTimeout=15 -J socadmin@10.0.0.22 socadmin@10.1.30.1 'sudo -S -p "" bash -s' 2>&1 | grep -v '^\[sudo\]'
