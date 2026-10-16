#!/bin/bash
# Rulat de operator pe Acer: ! bash <acest fișier> — test funcțional de blocare pe TOȚI senzorii activi, unul câte unul.
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
export SSH_ASKPASS=$S/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0
O="-o PubkeyAuthentication=no -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new"
J="-o ProxyJump=socadmin@10.0.0.22"
# senzor:ip:acces
LIST="f001:10.1.1.1: f002:10.1.2.1: f005:10.1.5.1: f007:10.1.7.1: f008:10.1.8.1: f009:10.1.9.1: f010:10.1.10.1: f011:10.1.11.1: f012:10.1.12.1: f014:10.1.14.1:
icisoc101:10.1.22.1:J icisoc102:10.1.25.1:J icisoc103:10.1.26.1:J icisoc104:10.1.27.1:J icisoc105:10.1.28.1:J icisoc106:10.1.29.1:J icisoc107:10.1.30.1:J icisoc108:10.1.31.1:J icisoc109:10.1.32.1:J fasterup:10.1.33.1:J"
for e in $LIST; do
  n=${e%%:*}; r=${e#*:}; ip=${r%%:*}; a=${r#*:}; X=""; [ "$a" = J ] && X="$J"
  for i in 1 2; do scp -q $O $X $S/test_blocare_sensor.sh socadmin@$ip:/tmp/tb.sh 2>/dev/null && break; sleep 4; done
  ssh $O $X socadmin@$ip "sudo -S -p '' bash /tmp/tb.sh $n; rm -f /tmp/tb.sh" < $S/.fleetpw 2>/dev/null || echo "[$n] inaccesibil / eroare"
done
echo GATA
