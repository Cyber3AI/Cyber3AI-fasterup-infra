#!/bin/bash
# Lansator pe Acer: activează regulile CYBER3 + MISP pe f009, f008, f007, f011, f012 — UNUL câte UNUL,
# oprire la primul eșec. Argument opțional: lista de senzori (ex. "9" sau "9 8").
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
export SSH_ASKPASS=$S/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0
O="-o PubkeyAuthentication=no -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new"
for n in ${1:-9 8 7 11 12}; do
  h=socadmin@10.1.$n.1
  echo "================ f0$(printf %02d $n) ($h)"
  scp -q $O $S/activare_reguli_sensor.sh $h:/tmp/ars.sh && scp -q $O $S/cyber3-misp.rules.f001 $h:/tmp/cyber3-misp.rules || { echo "EROARE copiere — STOP"; exit 1; }
  ssh $O $h 'sudo -S -p "" bash /tmp/ars.sh; rc=$?; rm -f /tmp/ars.sh /tmp/cyber3-misp.rules; exit $rc' < $S/.fleetpw
  rc=$?
  [ $rc = 0 ] || { echo "rc=$rc — STOP (ceilalți senzori NEATINȘI)"; exit $rc; }
  ssh $O $h 'echo "accesibil după: $(hostname) uptime $(uptime -p)"' < /dev/null || { echo "senzor inaccesibil după — STOP"; exit 4; }
done
echo "GATA"
