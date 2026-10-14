#!/bin/bash
# Rulat de operator pe Acer: ! bash <acest fișier>
# (1) manager: generatorul MISP fără limita de 60 pagini + rulare + verificare; (2) DOAR dacă (1) e OK: distribuire manuală
# de pe portal (serviciul existent, ca socadmin) -> fișierul ajunge pe disc la senzori, încărcat la restartul de noapte (fără reload).
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
echo "== (1) manager"
scp -q -o BatchMode=yes $S/misp_gen_fix_manager.sh socadmin@10.0.0.100:/tmp/mgf.sh || { echo "EROARE copiere"; exit 1; }
ssh -o BatchMode=yes -o ServerAliveInterval=30 socadmin@10.0.0.100 'sudo -S -p "" bash /tmp/mgf.sh; rc=$?; rm -f /tmp/mgf.sh; exit $rc' < $S/.fleetpw
rc=$?; [ $rc = 0 ] || { echo "rc=$rc — STOP, nu distribui"; exit $rc; }
echo "== (2) portal: distribuire manuală"
ssh -o BatchMode=yes -o ServerAliveInterval=30 socadmin@10.0.0.22 '
  L=/var/log/cyber3-domains-distribute.log; N0=$(wc -l < $L)
  sudo systemctl start cyber3-distribute-domains.service; echo "serviciu: $(systemctl show cyber3-distribute-domains.service -p Result --value)"
  tail -n +$((N0+1)) $L'
echo GATA
