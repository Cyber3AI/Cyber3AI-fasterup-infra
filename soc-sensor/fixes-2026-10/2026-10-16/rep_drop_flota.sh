#!/bin/bash
# Rulat de operator pe Acer: ! bash <acest fișier> — DROP pe reputație pe 13 senzori, UNUL câte UNUL, oprire la prima problemă.
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
export SSH_ASKPASS=$S/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0
O="-o PubkeyAuthentication=no -o ConnectTimeout=15"; J="-o ProxyJump=socadmin@10.0.0.22"
LIST="${1:-f014:14: f009:9: f011:11: icisoc104:27:J icisoc106:29:J icisoc103:26:J f007:7: f010:10: f008:8: f012:12: f002:2: f005:5: icisoc109:32:J}"
for e in $LIST; do
  n=${e%%:*}; r=${e#*:}; ip=10.1.${r%%:*}.1; X=""; [ "${r#*:}" = J ] && X="$J"
  echo "================ $n ($ip) $(date -u +%T) UTC"
  for i in 1 2; do scp -q $O $X $S/rep_drop_sensor.sh socadmin@$ip:/tmp/rds.sh 2>/dev/null && scp -q $O $X $S/rep_drop_wrap.sh socadmin@$ip:/tmp/rdw.sh 2>/dev/null && break; sleep 4; done
  ssh $O $X socadmin@$ip "sudo -S -p '' bash /tmp/rdw.sh $n; rc=\$?; rm -f /tmp/rds.sh /tmp/rdw.sh; exit \$rc" < $S/.fleetpw 2>/dev/null; rc=$?
  ssh $O $X socadmin@$ip 'echo "[accesibil după] $(hostname)"' </dev/null 2>/dev/null || { echo "!!! $n INACCESIBIL după — STOP"; exit 4; }
  [ $rc = 0 ] || { echo "!!! $n rc=$rc — STOP, senzorii următori NEATINȘI"; exit $rc; }
  sleep 30
done
echo "GATA — reputația armată pe: $LIST"
