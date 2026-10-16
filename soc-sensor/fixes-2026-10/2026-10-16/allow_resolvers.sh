#!/bin/bash
# Rulat de operator pe Acer: ! bash <acest fișier> — adaugă 5 rezolvere DNS publice verificate în allowlist (doar fișier, fără restart).
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
export SSH_ASKPASS=$S/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0
O="-o PubkeyAuthentication=no -o ConnectTimeout=15"; J="-o ProxyJump=socadmin@10.0.0.22"
run(){ n=$1; ip=$2; X="$3"; r=$4; d="$5"
  for i in 1 2; do scp -q $O $X $S/allow_resolver_sensor.sh socadmin@$ip:/tmp/ars1.sh 2>/dev/null && break; sleep 4; done
  ssh $O $X socadmin@$ip "sudo -S -p '' bash /tmp/ars1.sh $n $r '$d'; rm -f /tmp/ars1.sh" < $S/.fleetpw 2>/dev/null || echo "[$n] EROARE / inaccesibil"; }
run f007      10.1.7.1  ""   1.1.1.3      "Cloudflare filtrare familie"
run f008      10.1.8.1  ""   94.140.14.14 "AdGuard DNS"
run icisoc103 10.1.26.1 "$J" 94.140.14.14 "AdGuard DNS"
run icisoc104 10.1.27.1 "$J" 94.140.15.15 "AdGuard DNS"
run icisoc109 10.1.32.1 "$J" 94.140.14.14 "AdGuard DNS"
echo GATA
