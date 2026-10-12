#!/bin/bash
# Lansator — rulat de operator cu `!`: armare DROP pe reputație, întâi icisoc102, apoi icisoc108 (doar dacă primul a reușit).
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
PW="$(cat "$S/.fleetpw")"
run(){
  { printf '%s\n' "$PW"; cat "$S/rep_drop_sensor.sh"; } | \
    timeout 420 ssh -o ConnectTimeout=15 -J socadmin@10.0.0.22 socadmin@$1 'sudo -S -p "" bash -s' 2>&1 | grep -v '^\[sudo\]'
}
probe(){ ssh -o ConnectTimeout=10 socadmin@10.0.0.22 "ping -c 3 -W 2 $1 >/dev/null && echo 'VPN OK' || echo 'VPN NU RĂSPUNDE'" </dev/null; }
for e in icisoc102:10.1.25.1 icisoc108:10.1.31.1; do
  n=${e%%:*}; ip=${e#*:}
  echo "================ $n ($ip) ================"
  OUT=$(run $ip); echo "$OUT"
  echo "[$n] legătura după: $(probe $ip)"
  echo "$OUT" | grep -qE "\] OK: suricata=active|SKIP: drop" || { echo "!!! $n nu a reușit — opresc aici, al doilea senzor NU se modifică"; exit 1; }
  sleep 20
done
echo "GATA: reputația e blocată la perimetru pe icisoc102 și icisoc108."
