#!/bin/bash
# MLEO C1 — executor de carantină pe senzor (L2 ebtables drop pe MAC + L3 iptables drop pe IP).
# VLAN-agnostic: MAC-ul e in header-ul Ethernet, inaintea tag-ului 802.1Q -> `-s <MAC>` prinde si trafic VLAN.
# Reversibil (rollback). Refuza MAC gateway/broadcast/multicast/allowlist. NU shutdown — doar izolare reversibila.
# usage: mleo_q.sh add <MAC> <txid> [ip1,ip2,...] | remove <MAC> <txid> | status
set -u
CHAIN=CYBER3_MLEO_Q
AUDIT=/var/log/cyber3/mleo-quarantine.log
ALLOW=/etc/cyber3/mleo-mac-allowlist.txt
mkdir -p /var/log/cyber3 /etc/cyber3 2>/dev/null
lc(){ echo "$1" | tr 'A-Z' 'a-z'; }
ensure(){ ebtables -L $CHAIN >/dev/null 2>&1 || ebtables -N $CHAIN; ebtables -L FORWARD 2>/dev/null | grep -q "\-j $CHAIN" || ebtables -I FORWARD 1 -j $CHAIN; }

case "${1:-}" in
 add)
   MAC=$(lc "${2:-}"); TX="${3:-}"; IPS="${4:-}"
   [ -z "$MAC" ] || [ -z "$TX" ] && { echo "REFUSE args"; exit 2; }
   case "$MAC" in ff:ff:ff:ff:ff:ff|01:*|33:33:*|00:00:00:00:00:00|"") echo "REFUSE bad/broadcast/multicast MAC=$MAC"; exit 2;; esac
   GWMAC=$(lc "$(grep -oE 'GWMAC=[^ ]+' /etc/cyber3/l2shield.conf 2>/dev/null | cut -d= -f2)")
   [ -n "$GWMAC" ] && [ "$MAC" = "$GWMAC" ] && { echo "REFUSE gateway MAC=$MAC"; exit 3; }
   grep -qixF "$MAC" "$ALLOW" 2>/dev/null && { echo "REFUSE allowlisted MAC=$MAC"; exit 4; }
   ensure
   ebtables -C $CHAIN -s "$MAC" -j DROP 2>/dev/null || ebtables -A $CHAIN -s "$MAC" -j DROP
   for ip in ${IPS//,/ }; do [ -n "$ip" ] && { iptables -C CYBER3_BLOCK -s "$ip" -j DROP 2>/dev/null || iptables -I CYBER3_BLOCK 1 -s "$ip" -j DROP; }; done
   echo "$(date -u +%FT%TZ) ADD tx=$TX mac=$MAC ips=$IPS" >> "$AUDIT"
   echo "QUARANTINED mac=$MAC tx=$TX l2_rules=$(ebtables -L $CHAIN 2>/dev/null | grep -c DROP)"
   ;;
 remove)
   MAC=$(lc "${2:-}"); TX="${3:-}"; IPS="${4:-}"
   ebtables -D $CHAIN -s "$MAC" -j DROP 2>/dev/null
   for ip in ${IPS//,/ }; do [ -n "$ip" ] && iptables -D CYBER3_BLOCK -s "$ip" -j DROP 2>/dev/null; done
   echo "$(date -u +%FT%TZ) REMOVE tx=$TX mac=$MAC" >> "$AUDIT"
   if [ "$(ebtables -L $CHAIN 2>/dev/null | grep -c DROP)" = "0" ]; then ebtables -D FORWARD -j $CHAIN 2>/dev/null; ebtables -X $CHAIN 2>/dev/null; fi
   echo "ROLLBACK done mac=$MAC tx=$TX remaining=$(ebtables -L $CHAIN 2>/dev/null | grep -c DROP)"
   ;;
 status)
   echo "chain_exists=$(ebtables -L $CHAIN >/dev/null 2>&1 && echo 1 || echo 0) jump=$(ebtables -L FORWARD 2>/dev/null | grep -c "\-j $CHAIN") drops=$(ebtables -L $CHAIN 2>/dev/null | grep -c DROP)"
   ebtables -L $CHAIN --Lc 2>/dev/null | grep DROP
   ;;
 *) echo "usage: add|remove|status";;
esac
