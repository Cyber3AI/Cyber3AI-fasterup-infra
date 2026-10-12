#!/bin/bash
# Deploy watchdog v2 pe icisoc104 (10.1.27.1) — cu backup si validare. Rulat de operator cu !
# NU atinge suricata/bridge/iptables. Rollback: vezi comanda afisata la final.
set -eu
SCRATCH="/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad"
PW="$(cat "$SCRATCH/.fleetpw")"
TS="$(date +%Y%m%d-%H%M%S)"
J="-J socadmin@10.0.0.22"

echo "[1/4] copiez v2 pe senzor (/tmp)..."
scp -o ConnectTimeout=12 $J "$SCRATCH/usb-mgmt-watchdog-v2.sh" socadmin@10.1.27.1:/tmp/usb-mgmt-watchdog-v2.sh

echo "[2/4] backup v1 + instalare v2..."
printf '%s\n' "$PW" | ssh $J socadmin@10.1.27.1 "sudo -S -p '' bash -c '
  cp -a /usr/local/sbin/usb-mgmt-watchdog.sh /usr/local/sbin/usb-mgmt-watchdog.sh.bak-v1-$TS
  install -m 755 -o root -g root /tmp/usb-mgmt-watchdog-v2.sh /usr/local/sbin/usb-mgmt-watchdog.sh
  rm -f /tmp/usb-mgmt-watchdog-v2.sh
  echo backup: /usr/local/sbin/usb-mgmt-watchdog.sh.bak-v1-$TS
'"

echo "[3/4] rulare de validare (sanatos => tacut, exit 0)..."
printf '%s\n' "$PW" | ssh $J socadmin@10.1.27.1 "sudo -S -p '' bash -c '
  systemctl start usb-mgmt-watchdog.service && echo rulare_OK
  systemctl is-active usb-mgmt-watchdog.timer
  tail -3 /var/log/usb-mgmt-watchdog.log
'"

echo "[4/4] verific ca senzorul e tot verde (ping VPN)..."
ping -c 2 -W 3 10.1.27.1 >/dev/null && echo "VPN OK — deploy incheiat."
echo
echo "ROLLBACK daca e nevoie:"
echo "  ssh $J socadmin@10.1.27.1 apoi: sudo cp -a /usr/local/sbin/usb-mgmt-watchdog.sh.bak-v1-$TS /usr/local/sbin/usb-mgmt-watchdog.sh"
