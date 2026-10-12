#!/bin/bash
# Lansator — rulat de operator cu `!`: MLEO etapa 2 (carantină doar la aprobarea supervisorului).
# Pas 1: executorul pe 18 senzori (autotest pe adresă fictivă, nimic activ). Pas 2: portal.
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
H=$S/hunt
PW="$(cat "$S/.fleetpw")"
SENS="f001:10.1.1.1 f002:10.1.2.1 f005:10.1.5.1 f007:10.1.7.1 f008:10.1.8.1 f009:10.1.9.1 f010:10.1.10.1 f011:10.1.11.1 f012:10.1.12.1 icisoc101:10.1.22.1 icisoc102:10.1.25.1 icisoc103:10.1.26.1 icisoc104:10.1.27.1 icisoc105:10.1.28.1 icisoc106:10.1.29.1 icisoc107:10.1.30.1 icisoc108:10.1.31.1 icisoc109:10.1.32.1"
OKN=0; BAD=""
echo "== PAS 1: senzori =="
for e in $SENS; do
  n=${e%%:*}; ip=${e#*:}
  R=$( { printf '%s\n' "$PW"; cat "$H/mleo_exec_sensor.sh"; } | timeout 90 ssh -o ConnectTimeout=12 -J socadmin@10.0.0.22 socadmin@$ip 'sudo -S -p "" bash -s' 2>&1 | grep -v '^\[sudo\]' | tail -2)
  echo "$n: $R"
  echo "$R" | grep -q "OK]  executor instalat" && OKN=$((OKN+1)) || BAD="$BAD $n"
done
echo "senzori OK: $OKN / 18${BAD:+ — de reluat:$BAD}"
echo; echo "== PAS 2: portal =="
ssh -o ConnectTimeout=15 socadmin@10.0.0.22 'rm -rf /tmp/mleo_deploy; mkdir -p /tmp/mleo_deploy' && \
scp -q $H/mleo.py $H/api_hunt.py $H/patch_contain2.py socadmin@10.0.0.22:/tmp/mleo_deploy/ && \
ssh -o ConnectTimeout=15 socadmin@10.0.0.22 'sudo bash -s' < $H/install_mleo_etapa2.sh
