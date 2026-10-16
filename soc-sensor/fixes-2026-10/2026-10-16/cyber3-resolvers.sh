#!/bin/bash
# CYBER3 — protecția rezolverelor DNS ale clientului (lecția CNI, 15.10.2026).
# Identifică serverele DNS PUBLICE interogate EFECTIV de rețeaua clientului (captură pe puntea inline, porturile 53/853,
# sursă = adresă privată a clientului) și le pune în /etc/cyber3/ar-allowlist.txt, pe care îl citesc atât wrapper-ul AR
# (firewall-drop SMART), cât și permaban → un rezolver folosit de client nu mai poate fi blocat (nici 10 min, nici 90 zile).
# Dacă un astfel de rezolver e DEJA blocat, îl deblochează (exact cazul CNI). Un atacator NU poate intra pe listă: ar trebui
# ca rețeaua clientului să-l interogheze ca server DNS de cel puțin MIN_Q ori în fereastra de captură.
# Moduri: (implicit) dry-run = doar raport;  --aplica = scrie allowlist + deblochează.  Jurnal: /var/log/cyber3/resolvers.log
set -u
export LC_ALL=C
MODE=${1:-dry-run}; SECS=${SECS:-120}; MIN_Q=${MIN_Q:-10}
A=/etc/cyber3/ar-allowlist.txt; P=/etc/cyber3/permaban.list; LOG=/var/log/cyber3/resolvers.log; H=$(hostname)
BR=$(ls -d /sys/class/net/*/bridge 2>/dev/null | head -1 | cut -d/ -f5)
[ -n "$BR" ] || { echo "[$H] fără punte — nimic de făcut"; exit 0; }
CAP=$(timeout $SECS tcpdump -i "$BR" -nn -l '(udp dst port 53 or tcp dst port 53 or tcp dst port 853) or (vlan and (udp dst port 53 or tcp dst port 53 or tcp dst port 853))' 2>/dev/null)
RES=$(echo "$CAP" | awk '{s=$3; d=$5; sub(/\.[0-9]+$/,"",s); sub(/\.(53|853):?$/,"",d); print s, d}' \
      | awk '$1 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/ && $2 !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|22[4-9]\.|23[0-9]\.)/ {q[$2]++; c[$2" "$1]=1}
             END{for (k in c){split(k,a," "); n[a[1]]++} for (ip in q) print ip, q[ip], n[ip]}' | sort -k2 -rn)
echo "[$H] captură ${SECS}s pe $BR: $(echo "$CAP" | grep -c .) interogări DNS; rezolvere publice (IP interogări clienți_distincți):"
[ -n "$RES" ] && echo "$RES" | sed 's/^/   /' || echo "   niciunul"
NEW=""; UNB=""
while read -r ip q n; do
  [ -n "$ip" ] || continue; [ "$q" -ge "$MIN_Q" ] || continue
  grep -qxF "$ip" $A 2>/dev/null || NEW="$NEW $ip"
  iptables -S 2>/dev/null | grep -q -- "-s $ip/32 -j DROP" && UNB="$UNB $ip"
done <<< "$RES"
echo "[$H] de adăugat în allowlist (≥$MIN_Q interogări):${NEW:- niciunul} | blocate acum și de deblocat:${UNB:- niciunul}"
[ "$MODE" = "--aplica" ] || { echo "[$H] DRY-RUN: nimic scris"; exit 0; }
TS=$(date -u +%Y%m%d-%H%M%S); mkdir -p /var/log/cyber3
if [ -n "$NEW$UNB" ]; then cp -a $A $A.bak-resolvers-$TS; cp -a $P $P.bak-resolvers-$TS 2>/dev/null; fi
for ip in $NEW; do
  printf '# auto cyber3-resolvers %s: rezolver DNS interogat de rețeaua clientului\n%s\n' "$TS" "$ip" >> $A
  echo "$(date -u +%FT%TZ) ALLOW $ip (rezolver DNS al clientului)" >> $LOG
done
for ip in $UNB; do
  for ch in CYBER3_BLOCK INPUT FORWARD; do while iptables -C $ch -s $ip/32 -j DROP 2>/dev/null; do iptables -D $ch -s $ip/32 -j DROP; done; done
  sed -i "/^$(echo $ip | sed 's/\./\\./g') /d" $P 2>/dev/null
  echo "$(date -u +%FT%TZ) UNBLOCK $ip (rezolver DNS al clientului era blocat)" >> $LOG
  echo "$(date -u +%FT%TZ) UNBLOCK $ip motiv=rezolver-DNS-al-clientului (cyber3-resolvers)" >> /var/log/cyber3/permaban-audit.log
done
[ -n "$UNB" ] && iptables-save > /etc/iptables/rules.v4
echo "[$H] APLICAT: adăugate=${NEW:- 0} deblocate=${UNB:- 0}"
