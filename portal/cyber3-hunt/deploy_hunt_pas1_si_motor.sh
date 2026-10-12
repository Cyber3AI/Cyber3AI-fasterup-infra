#!/bin/bash
# Lansator — rulat de operator cu `!`:
#   A) managerul Wazuh: regula 100260 + CyberBot (notificări Threat Hunt), cu teste și auto-revert;
#   B) portal: actualizează motorul (H4 cloud → INFO, H7 fără istoric → INFO) și reface referința (fără notificări).
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad/hunt
PW="$(cat /tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad/.fleetpw)"
echo "################ A — manager Wazuh + CyberBot ################"
scp -q -J socadmin@10.0.0.22 $S/cb_hunt_patch.py socadmin@10.0.0.100:/tmp/cb_hunt_patch.py || { echo "[ERR] copiere patch CyberBot"; exit 1; }
OUT1=$({ printf '%s\n' "$PW"; cat $S/hunt_cb_manager.sh; } | ssh -o ConnectTimeout=15 -J socadmin@10.0.0.22 socadmin@10.0.0.100 'sudo -S -p "" bash -s' 2>&1 | grep -v '^\[sudo\]')
echo "$OUT1"
echo "$OUT1" | grep -q "manager repornit" || { echo; echo "[STOP] pasul A nu s-a încheiat cu succes."; exit 2; }
echo; echo "################ B — motor actualizat pe portal ################"
scp -q $S/threat_hunt.py socadmin@10.0.0.22:/tmp/threat_hunt.py && ssh -o ConnectTimeout=15 socadmin@10.0.0.22 'sudo bash -s' <<'EOS'
set -u
F=/opt/cyber3/hunt/threat_hunt.py; L=/opt/fasterup-portal/data/threat_hunt/latest.json
cp -a $F $F.bak-$(date -u +%Y%m%d-%H%M%S)
install -o socadmin -g socadmin -m 644 /tmp/threat_hunt.py $F && rm -f /tmp/threat_hunt.py
mv $L $L.referinta-veche 2>/dev/null
sudo -u socadmin /opt/fasterup-portal/venv/bin/python $F --days 7 --notify --out $L
python3 - <<PY
import json, collections
d = json.load(open("$L", encoding="utf-8"))
print("constatări 7 zile:", dict(collections.Counter(f["severity"] for f in d["findings"] if f["hunt"] != "ERR")), "| erori:", sum(1 for f in d["findings"] if f["hunt"] == "ERR"))
for f in d["findings"]:
    if f["severity"] in ("CRITIC", "ÎNALT", "MEDIU"):
        print("  %-6s %-3s %-10s %-16s %s" % (f["severity"], f["hunt"], f["agent"], f["host"], f["title"][:75]))
PY
echo "timer: $(systemctl is-active cyber3-threat-hunt.timer), următoarea rulare: $(systemctl show cyber3-threat-hunt.timer -p NextElapseUSecRealtime --value)"
EOS
