#!/bin/bash
# Rulat de operator: ! bash <acest fișier> — HOME_NET cu adresele publice proprii pe icisoc101, apoi icisoc105 (oprire la eroare).
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
export SSH_ASKPASS=$S/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0
O="-o PubkeyAuthentication=no -o ConnectTimeout=15 -o ProxyJump=socadmin@10.0.0.22"
for e in "icisoc101|10.1.22.1|5.2.180.41" "icisoc105|10.1.28.1|213.177.4.186,213.177.4.187,213.177.4.188,213.177.4.189,213.177.4.190"; do
  IFS='|' read n ip own <<< "$e"; echo "================ $n $(date -u +%T) UTC"
  for i in 1 2; do scp -q $O $S/homenet_sensor.sh socadmin@$ip:/tmp/hn.sh 2>/dev/null && break; sleep 4; done
  ssh $O socadmin@$ip "sudo -S -p '' bash /tmp/hn.sh $n $own; rc=\$?; rm -f /tmp/hn.sh; exit \$rc" < $S/.fleetpw 2>/dev/null; rc=$?
  ssh $O socadmin@$ip 'echo "[accesibil după] $(hostname)"' </dev/null 2>/dev/null || { echo "!!! $n INACCESIBIL — STOP"; exit 4; }
  [ $rc = 0 ] || { echo "!!! $n rc=$rc — STOP"; exit $rc; }
  sleep 20
done
echo GATA
