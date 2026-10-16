#!/bin/bash
# Rulează pe senzor ca root. Argumente: <hostname așteptat> <ip rezolver> <descriere>
# Adaugă UN rezolver DNS public verificat în /etc/cyber3/ar-allowlist.txt. DOAR fișier: fără restart, fără iptables, fără Suricata.
set -u
EXP="$1"; IP="$2"; DESC="$3"; H=$(hostname); A=/etc/cyber3/ar-allowlist.txt; TS=$(date -u +%Y%m%d-%H%M%S)
[ "$H" = "$EXP" ] || { echo "[$H] ABORT: hostname diferit de $EXP — nimic modificat"; exit 3; }
[[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "[$H] ABORT: IP invalid"; exit 3; }
ST0=$(systemctl show suricata -p ActiveEnterTimestamp --value); F0=$(iptables -S | md5sum | cut -c1-8)
if grep -qxF "$IP" $A; then echo "[$H] $IP deja în allowlist — nimic de făcut"; exit 0; fi
cp -a $A $A.bak-resolver-$TS
printf '# 16.10.2026: rezolver DNS folosit de rețeaua clientului (%s), verificat în trafic\n%s\n' "$DESC" "$IP" >> $A
ADDED=$(diff $A.bak-resolver-$TS $A | grep -c '^>'); REMOVED=$(diff $A.bak-resolver-$TS $A | grep -c '^<')
if [ "$ADDED" != 2 ] || [ "$REMOVED" != 0 ]; then cp -a $A.bak-resolver-$TS $A; echo "[$H] ABORT: diferență neașteptată (+$ADDED/-$REMOVED) — restaurat"; exit 2; fi
ST1=$(systemctl show suricata -p ActiveEnterTimestamp --value); F1=$(iptables -S | md5sum | cut -c1-8)
echo "[$H] OK: $IP adăugat ($DESC) | diff: +1 rând IP +1 comentariu, 0 șterse | Suricata neatins: $([ "$ST0" = "$ST1" ] && echo DA || echo NU) | iptables neatins: $([ "$F0" = "$F1" ] && echo DA || echo NU) | permaban îl vede ca protejat: $(grep -cxF "$IP" $A)"
