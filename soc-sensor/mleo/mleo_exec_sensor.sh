#!/bin/bash
# Rulează PE SENZOR ca root. Instalează executorul MLEO de carantină (inactiv până la o aprobare de supervisor în ▸ HUNT).
# Aprobat de operator (Mihai Bătrîneanu) pe 10.10.2026: socadmin poate rula ca root DOAR acest executor.
set -u
H=$(hostname); TS=$(date -u +%Y%m%d-%H%M%S)
X=/usr/local/sbin/cyber3-mleo-contain; SUD=/etc/sudoers.d/cyber3-mleo
ok(){ echo "[$H OK]  $*"; }; fail(){ echo "[$H ERR] $*"; }
iptables -C FORWARD -j NFQUEUE --queue-balance 0:3 --queue-bypass 2>/dev/null && Q=1 || Q=0
undo(){
  iptables -D FORWARD -j CYBER3_MLEO_C 2>/dev/null; iptables -F CYBER3_MLEO_C 2>/dev/null; iptables -X CYBER3_MLEO_C 2>/dev/null
  systemctl disable --now cyber3-mleo-expire.timer >/dev/null 2>&1
  rm -f $X $SUD /etc/systemd/system/cyber3-mleo-expire.service /etc/systemd/system/cyber3-mleo-expire.timer; systemctl daemon-reload
  echo "[$H REV] executor scos, senzor ca înainte"
}

cat > $X.new <<'XEOF'
#!/bin/bash
# CYBER3 MLEO — carantină de IEȘIRE pentru o stație internă compromisă (aprobată de supervisor în ▸ HUNT).
# Stația păstrează rețeaua internă (RFC1918, DHCP, multicast); tot traficul spre Internet e oprit.
# Reguli iptables în lanțul CYBER3_MLEO_C (primul în FORWARD), marcate cu comentariul mleo:<txid>; expirare automată.
# usage: cyber3-mleo-contain add <txid> <ip> <ore_ttl> [mac] | remove <txid> | expire | status
set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
CH=CYBER3_MLEO_C
ST=/var/lib/cyber3/mleo-contain.state      # txid ip mac expira_epoch
AUD=/var/log/cyber3/mleo-contain.log
MAXACTIVE=5
mkdir -p /var/lib/cyber3 /var/log/cyber3; touch "$ST"
exec 9>/run/cyber3-mleo-contain.lock; flock -w 20 9 || { echo "REFUZ: blocaj ocupat"; exit 9; }
aud(){ echo "$(date -u +%FT%TZ) $*" >> "$AUD"; }
ensure(){
  iptables -nL $CH >/dev/null 2>&1 || iptables -N $CH
  iptables -C FORWARD -j $CH 2>/dev/null || iptables -I FORWARD 1 -j $CH
}
del_tx(){
  local tx="$1" n=0 rules
  rules=$(iptables -S $CH 2>/dev/null | grep -F "\"mleo:$tx\"")
  while read -r rule; do
    [ -n "$rule" ] || continue
    eval "iptables ${rule/-A /-D }" 2>/dev/null && n=$((n+1))
  done <<< "$rules"
  sed -i "/^$tx /d" "$ST"
  echo $n
}
private(){ [[ "$1" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; }

case "${1:-}" in
 add)
  TX="${2:-}"; IP="${3:-}"; TTL="${4:-}"; MAC="$(echo "${5:-}" | tr 'A-F' 'a-f')"
  [[ "$TX" =~ ^[a-z0-9-]{4,64}$ ]] || { echo "REFUZ: txid invalid"; exit 2; }
  [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && private "$IP" || { echo "REFUZ: IP invalid sau public ($IP)"; exit 2; }
  [[ "$TTL" =~ ^[0-9]+$ ]] && [ "$TTL" -ge 1 ] && [ "$TTL" -le 168 ] || { echo "REFUZ: ore TTL 1..168"; exit 2; }
  case "${IP##*.}" in 0|1|254|255) echo "REFUZ: adresă de tip gateway/rețea ($IP)"; exit 3;; esac
  ip -4 -o addr show | grep -qw "inet $IP" && { echo "REFUZ: adresa senzorului"; exit 3; }
  grep -qxF "$IP" /etc/cyber3/ar-allowlist.txt 2>/dev/null && { echo "REFUZ: IP în ar-allowlist ($IP)"; exit 4; }
  if [ -n "$MAC" ]; then
    [[ "$MAC" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || { echo "REFUZ: MAC invalid"; exit 2; }
    case "$MAC" in ff:ff:ff:ff:ff:ff|00:00:00:00:00:00|01:*|33:33:*) echo "REFUZ: MAC broadcast/multicast"; exit 2;; esac
    ip -o link | grep -qi "$MAC" && { echo "REFUZ: MAC-ul senzorului"; exit 3; }
  fi
  grep -q "^$TX " "$ST" && { echo "DEJA ACTIV tx=$TX"; exit 0; }
  [ "$(wc -l < "$ST")" -ge $MAXACTIVE ] && { echo "REFUZ: deja $MAXACTIVE carantine active pe acest senzor"; exit 5; }
  ensure
  C="-m comment --comment mleo:$TX"
  for SEL in "-s $IP" ${MAC:+"-m mac --mac-source $MAC"}; do
    for NET in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 255.255.255.255/32; do
      iptables -A $CH $SEL -d $NET $C -j RETURN
    done
    iptables -A $CH $SEL $C -j DROP
  done
  EXP=$(( $(date +%s) + TTL*3600 ))
  echo "$TX $IP ${MAC:--} $EXP" >> "$ST"
  aud "ADD tx=$TX ip=$IP mac=${MAC:--} ttl=${TTL}h"
  echo "CARANTINĂ ACTIVĂ tx=$TX ip=$IP mac=${MAC:--} expiră=$(date -u -d @$EXP +%FT%TZ) reguli=$(iptables -S $CH | grep -cF "\"mleo:$TX\"")"
  ;;
 remove)
  TX="${2:-}"; [[ "$TX" =~ ^[a-z0-9-]{4,64}$ ]] || { echo "REFUZ: txid invalid"; exit 2; }
  N=$(del_tx "$TX"); aud "REMOVE tx=$TX reguli=$N"
  echo "ELIBERAT tx=$TX reguli_sterse=$N"
  ;;
 expire)
  NOW=$(date +%s)
  while read -r TX IP MAC EXP; do
    [ -n "${TX:-}" ] && [ "${EXP:-0}" -le "$NOW" ] && { N=$(del_tx "$TX"); aud "EXPIRE tx=$TX ip=$IP reguli=$N"; echo "EXPIRAT tx=$TX"; }
  done < <(cat "$ST")
  for TX in $(iptables -S $CH 2>/dev/null | grep -oE 'mleo:[a-z0-9-]+' | sort -u | cut -d: -f2); do
    grep -q "^$TX " "$ST" || { N=$(del_tx "$TX"); aud "ORPHAN tx=$TX reguli=$N"; }
  done
  ;;
 status)
  while read -r TX IP MAC EXP; do [ -n "${TX:-}" ] && echo "ACTIV tx=$TX ip=$IP mac=$MAC expiră=$(date -u -d @$EXP +%FT%TZ)"; done < "$ST"
  echo "reguli=$(iptables -S $CH 2>/dev/null | grep -c mleo:) salt_forward=$(iptables -C FORWARD -j $CH 2>/dev/null && echo da || echo nu)"
  ;;
 *) echo "usage: add <txid> <ip> <ore> [mac] | remove <txid> | expire | status"; exit 1;;
esac
XEOF
bash -n $X.new || { fail "sintaxă executor"; rm -f $X.new; exit 2; }
install -o root -g root -m 755 $X.new $X && rm -f $X.new

echo "socadmin ALL=(root) NOPASSWD: $X" > $SUD.new; chmod 440 $SUD.new
visudo -cf $SUD.new >/dev/null || { fail "sudoers invalid"; rm -f $SUD.new; undo; exit 2; }
mv $SUD.new $SUD

cat > /etc/systemd/system/cyber3-mleo-expire.service <<'U'
[Unit]
Description=CYBER3 MLEO - expirare carantine
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cyber3-mleo-contain expire
U
cat > /etc/systemd/system/cyber3-mleo-expire.timer <<'U'
[Unit]
Description=CYBER3 MLEO - expirare carantine la 5 minute
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
U
systemctl daemon-reload; systemctl enable --now cyber3-mleo-expire.timer >/dev/null 2>&1

# autotest pe o adresă fictivă (10.255.255.77 nu există la niciun client), exact cum o va rula portalul
T=mleotest-$TS
OUT=$(sudo -u socadmin sudo -n $X add $T 10.255.255.77 1 2>&1)
echo "$OUT" | grep -q "CARANTINĂ ACTIVĂ" && echo "$OUT" | grep -q "reguli=6" || { fail "autotest add: $OUT"; undo; exit 2; }
iptables -S FORWARD | sed -n 2p | grep -q "CYBER3_MLEO_C" || { fail "saltul FORWARD nu e primul"; $X remove $T >/dev/null; undo; exit 2; }
OUT2=$(sudo -u socadmin sudo -n $X remove $T 2>&1)
echo "$OUT2" | grep -q "reguli_sterse=6" || { fail "autotest remove: $OUT2"; undo; exit 2; }
[ "$(iptables -S CYBER3_MLEO_C | grep -c mleo:)" = 0 ] || { fail "reguli rămase după autotest"; undo; exit 2; }
R=$(sudo -u socadmin sudo -n $X add t-refuz 192.168.1.1 1 2>&1); echo "$R" | grep -q REFUZ || { fail "nu refuză gateway: $R"; undo; exit 2; }
if [ $Q = 1 ]; then iptables -C FORWARD -j NFQUEUE --queue-balance 0:3 --queue-bypass 2>/dev/null || { fail "NFQUEUE dispărut!"; undo; exit 2; }; fi
ok "executor instalat; autotest add/remove/refuz gateway OK; NFQUEUE neatins ($Q); timer expirare $(systemctl is-active cyber3-mleo-expire.timer)"
