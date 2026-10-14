#!/bin/bash
# Rulat de operator pe Acer: ! bash <acest fișier> — reîmprospătarea lunară a listei AWS pentru CyberBot (manager).
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
scp -q -o BatchMode=yes $S/cyber3-refresh-aws.py socadmin@10.0.0.100:/tmp/cyber3-refresh-aws.py && scp -q -o BatchMode=yes $S/cyberbot_aws_refresh_manager.sh socadmin@10.0.0.100:/tmp/c3awsr.sh || { echo "EROARE copiere"; exit 1; }
ssh -o BatchMode=yes socadmin@10.0.0.100 'sudo -S -p "" bash /tmp/c3awsr.sh; rc=$?; rm -f /tmp/c3awsr.sh; exit $rc' < $S/.fleetpw
echo "rc=$?"
