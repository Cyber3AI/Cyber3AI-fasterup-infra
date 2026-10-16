#!/bin/bash
# Rulat de operator pe Acer: ! bash <acest fișier> — deblochează rezolverul DNS 193.231.252.1 pe icisoc109 (CNI).
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
export SSH_ASKPASS=$S/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0
O="-o PubkeyAuthentication=no -o ConnectTimeout=20 -o ProxyJump=socadmin@10.0.0.22"
for i in 1 2 3; do scp -q $O $S/fix_cni_resolver_sensor.sh socadmin@10.1.32.1:/tmp/fcr.sh && break; sleep 3; done
ssh $O socadmin@10.1.32.1 'sudo -S -p "" bash /tmp/fcr.sh; rc=$?; rm -f /tmp/fcr.sh; exit $rc' < $S/.fleetpw
echo "rc=$?"
