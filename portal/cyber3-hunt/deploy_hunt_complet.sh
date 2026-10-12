#!/bin/bash
# Lansator unic — rulat de operator cu `!`: CYBER3 Threat Hunt complet.
#   Pas 1: managerul Wazuh (10.0.0.100) — regula 100260 + CyberBot (notificări), teste + auto-revert.
#   Pas 2: portalul (10.0.0.22) — motor, API, buton ▸ HUNT, timer la 6 ore cu notificări.
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad/hunt
PW="$(cat /tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad/.fleetpw)"
echo "################ PAS 1 — manager Wazuh + CyberBot ################"
scp -q -J socadmin@10.0.0.22 $S/cb_hunt_patch.py socadmin@10.0.0.100:/tmp/cb_hunt_patch.py || { echo "[ERR] copiere patch CyberBot"; exit 1; }
OUT1=$({ printf '%s\n' "$PW"; cat $S/hunt_cb_manager.sh; } | ssh -o ConnectTimeout=15 -J socadmin@10.0.0.22 socadmin@10.0.0.100 'sudo -S -p "" bash -s' 2>&1 | grep -v '^\[sudo\]')
echo "$OUT1"
echo "$OUT1" | grep -q "manager repornit" || { echo; echo "[STOP] pasul 1 nu s-a încheiat cu succes — portalul NU se instalează."; exit 2; }
echo; echo "################ PAS 2 — portal (▸ HUNT) ################"
bash $S/deploy_hunt.sh
