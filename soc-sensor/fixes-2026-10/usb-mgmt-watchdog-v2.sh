#!/bin/bash
# FasterUp icisoc104 — watchdog adaptor USB-Ethernet de management. v2 (8 oct 2026).
# v1 verifica doar exists+carrier+IP -> ORB la incidentul din 8 oct (r8152 "Tx timeout":
# interfata exista, avea carrier si IP, dar NU transmitea; 5h fara legatura).
# v2 adauga test END-TO-END (ping gateway SAU handshake wg proaspat) + scara de recuperare
# mai adanca (link flap -> rebind driver -> reset USB via authorized) + anti-flap (2 esecuri
# consecutive inainte de actiune). NU atinge NICIODATA br0/enp6s0/enp7s0/suricata/iptables.
set -u
IFACE="$(ls /sys/class/net/ 2>/dev/null | grep -m1 '^enx' || echo enx00133ba91417)"
EXPECT_IP="192.168.99.100"
GW="192.168.99.1"
HUB_WG="10.0.0.1"
LOG="/var/log/usb-mgmt-watchdog.log"
STATE="/run/usb-mgmt-watchdog.failcount"
HS_MAX=150   # handshake wg mai vechi de atat (sec) = tunel cazut (keepalive e 25s)
log(){ echo "$(date -u +%FT%TZ) [usb-wd v2] $*" >> "$LOG"; }
[ -f "$LOG" ] && [ "$(stat -c%s "$LOG" 2>/dev/null || echo 0)" -gt 1000000 ] && { tail -n 500 "$LOG" > "$LOG.t" && mv "$LOG.t" "$LOG"; }

exists(){ [ -d "/sys/class/net/$IFACE" ]; }
carrier(){ [ "$(cat /sys/class/net/$IFACE/carrier 2>/dev/null)" = "1" ]; }
hasip(){ ip -4 addr show "$IFACE" 2>/dev/null | grep -q "inet $EXPECT_IP"; }
wg_fresh(){  # handshake-ul wg1 mai nou de HS_MAX secunde?
  local hs now
  hs="$(wg show wg1 latest-handshakes 2>/dev/null | awk '{print $2; exit}')"
  [ -n "${hs:-}" ] && [ "$hs" -gt 0 ] || return 1
  now="$(date +%s)"
  [ $((now - hs)) -le "$HS_MAX" ]
}
e2e_ok(){  # transmite REAL? gateway raspunde SAU tunelul wg e viu
  ping -c1 -W2 -I "$IFACE" "$GW" >/dev/null 2>&1 && return 0
  wg_fresh && return 0
  ping -c1 -W2 -I "$IFACE" "$GW" >/dev/null 2>&1
}
healthy(){ exists && carrier && hasip && e2e_ok; }

if healthy; then rm -f "$STATE" 2>/dev/null; exit 0; fi

# anti-flap: actioneaza abia la al 2-lea esec consecutiv
FAILS=$(( $(cat "$STATE" 2>/dev/null || echo 0) + 1 ))
echo "$FAILS" > "$STATE"
if [ "$FAILS" -lt 2 ]; then
  log "nesanatos (1/2): iface=$IFACE exists=$(exists&&echo y||echo n) carrier=$(carrier&&echo y||echo n) ip=$(hasip&&echo y||echo n) e2e=n — astept confirmarea la urmatoarea rulare"
  exit 0
fi
log "MANAGEMENT JOS confirmat (${FAILS} esecuri): exists=$(exists&&echo y||echo n) carrier=$(carrier&&echo y||echo n) ip=$(hasip&&echo y||echo n) -> recuperare in trepte"

refresh_iface(){ IFACE="$(ls /sys/class/net/ 2>/dev/null | grep -m1 '^enx' || echo "$IFACE")"; }
try_net(){  # reaplica IP/ruta si reporneste tunelul, apoi retesteaza
  ip link set "$IFACE" up 2>/dev/null; sleep 1
  netplan apply 2>/dev/null; sleep 3
  systemctl restart wg-quick@wg1 2>/dev/null; sleep 4
  healthy
}

# Treapta 1: link flap + netplan + wg
if exists; then
  log "treapta 1: link down/up + netplan + wg1"
  ip link set "$IFACE" down 2>/dev/null; sleep 2
  if try_net; then log "RECUPERAT la treapta 1"; rm -f "$STATE"; exit 0; fi
fi

# Treapta 2: rebind driver r8152 (reseteaza ringurile Tx — cazul "Tx timeout")
log "treapta 2: unbind/bind r8152"
for d in /sys/bus/usb/drivers/r8152/[0-9]*; do
  [ -e "$d" ] || continue; id="$(basename "$d")"
  echo "$id" > /sys/bus/usb/drivers/r8152/unbind 2>/dev/null; sleep 1
  echo "$id" > /sys/bus/usb/drivers/r8152/bind 2>/dev/null
done
sleep 3; refresh_iface
if exists && try_net; then log "RECUPERAT la treapta 2 ($IFACE)"; rm -f "$STATE"; exit 0; fi

# Treapta 3: reset dispozitiv USB (authorized 0/1) — echivalent scos/bagat din port
log "treapta 3: reset USB via authorized"
for dev in /sys/bus/usb/devices/*/; do
  [ -f "$dev/idVendor" ] || continue
  drv="$(ls "$dev" 2>/dev/null | grep -m1 ':1\.0$')"
  [ -n "$drv" ] && [ -d "$dev/$drv/net" ] || continue
  if ls "$dev/$drv/net" 2>/dev/null | grep -q '^enx'; then
    log "reset USB: $(basename "$dev")"
    echo 0 > "$dev/authorized" 2>/dev/null; sleep 3
    echo 1 > "$dev/authorized" 2>/dev/null; sleep 5
  fi
done
refresh_iface
if exists && try_net; then log "RECUPERAT la treapta 3 ($IFACE)"; rm -f "$STATE"; exit 0; fi

log "ESEC toate treptele — adaptor probabil mort fizic; necesita interventie on-site (schimbare adaptor USB / power-cycle)"
exit 0
