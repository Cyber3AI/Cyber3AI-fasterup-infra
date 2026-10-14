#!/bin/bash
# Rulat de operator pe Acer: ! bash <acest fișier>  — adaugă AWS la excepțiile IOC din CyberBot (manager 10.0.0.100).
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
scp -q -o BatchMode=yes $S/cyberbot_iocaws_manager.sh socadmin@10.0.0.100:/tmp/c3aws.sh && scp -q -o BatchMode=yes $S/aws/aws-ipv4.txt socadmin@10.0.0.100:/tmp/aws-ipv4.txt || { echo "EROARE copiere"; exit 1; }
ssh -o BatchMode=yes socadmin@10.0.0.100 'sudo -S -p "" bash /tmp/c3aws.sh; rc=$?; rm -f /tmp/c3aws.sh; exit $rc' < $S/.fleetpw
echo "rc=$?"
