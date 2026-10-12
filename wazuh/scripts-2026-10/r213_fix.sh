#!/bin/bash
# Lansator — rulat de operator cu `!`: corectarea regulii 100213 pe managerul Wazuh (10.0.0.100).
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
PW="$(cat "$S/.fleetpw")"
{ printf '%s\n' "$PW"; cat "$S/r213_fix_manager.sh"; } | \
  ssh -o ConnectTimeout=15 -J socadmin@10.0.0.22 socadmin@10.0.0.100 'sudo -S -p "" bash -s' 2>&1 | grep -v '^\[sudo\]'
