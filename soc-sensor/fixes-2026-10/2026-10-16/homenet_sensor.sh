#!/bin/bash
# Pe senzor (root). $1 = hostname așteptat, $2 = adresele publice proprii (separate prin virgulă).
# Adaugă adresele publice proprii ale clientului în HOME_NET (lecția ANRE, manifest §4). Backup, validare YAML (python, NU suricata -T),
# UN restart, verificare motor/cozi/trafic, auto-revert; apoi 3 minute de observare a blocărilor noi.
set -u
EXP="$1"; OWN="$2"; H=$(hostname); [ "$H" = "$EXP" ] || { echo "[$H] ABORT: hostname diferit de $EXP — nimic modificat"; exit 3; }
Y=/etc/suricata/suricata.yaml; L=/var/log/suricata/suricata.log; E=/var/log/suricata/eve-alerts.json; TS=$(date -u +%Y%m%d-%H%M%S)
iptables -S FORWARD | grep NFQUEUE | grep -q -- --queue-bypass || { echo "[$H] ABORT: NFQUEUE fără --queue-bypass"; exit 3; }
CUR=$(grep -E '^[[:space:]]*HOME_NET:' $Y | head -1); echo "[$H] HOME_NET înainte: $CUR"
echo "$CUR" | grep -q "${OWN%%,*}" && { echo "[$H] deja conține adresele proprii — nimic de făcut"; exit 0; }
m(){ a=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{print $1}'); sleep 10; b=$(iptables -L FORWARD -v -n -x | awk '/NFQUEUE/{print $1}'); echo $((b-a)); }
P0=$(m); echo "[$H] trafic NFQUEUE înainte: +$P0 / 10 s"
cp -a $Y $Y.bak-homenet-$TS
sed -i -E "0,/^([[:space:]]*HOME_NET:[[:space:]]*\"\[)([^]]*)(\]\")/s//\1\2,$OWN\3/" $Y
NEW=$(grep -E '^[[:space:]]*HOME_NET:' $Y | head -1); echo "[$H] HOME_NET după:   $NEW"
python3 -c "import yaml,sys; d=yaml.safe_load(open('$Y').read().replace('%YAML 1.1','',1)); print('[$H] YAML valid; HOME_NET =', d['vars']['address-groups']['HOME_NET'])" 2>&1 || { cp -a $Y.bak-homenet-$TS $Y; echo "[$H] ABORT: YAML invalid — restaurat, Suricata NErepornit"; exit 2; }
revert(){ echo "[$H] AUTO-REVERT: $1"; cp -a $Y.bak-homenet-$TS $Y; systemctl restart suricata; sleep 40; echo "[$H] revert: suricata=$(systemctl is-active suricata) cozi=$(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue)"; exit 2; }
N0=$(wc -l < $L); systemctl restart suricata
OK=0; for i in $(seq 1 50); do sleep 4; tail -n +$N0 $L | grep -q "Engine started" && [ "$(awk 'END{print NR}' /proc/net/netfilter/nfnetlink_queue)" = 4 ] && { OK=1; break; }; done
[ $OK = 1 ] || revert "motorul nu a pornit cu 4 cozi"
LOAD=$(tail -n +$N0 $L | grep -oE '[0-9]+ rule files processed. [0-9]+ rules successfully loaded, [0-9]+ rules failed' | tail -1)
ERR=$(tail -n +$N0 $L | grep -c '<Error>')
echo "$LOAD" | grep -q ', 0 rules failed' || revert "reguli eșuate: $LOAD"
[ "$ERR" = 0 ] || revert "$ERR erori în log"
P1=$(m); [ "$P0" -gt 50 ] && [ "$P1" -eq 0 ] && revert "traficul nu mai trece prin NFQUEUE"
systemctl restart wazuh-agent
echo "[$H] DUPĂ RESTART: $LOAD | erori=0 | cozi=4 | trafic NFQUEUE +$P1 / 10 s | agent=$(systemctl is-active wazuh-agent)"
T0=$(date -u +%Y-%m-%dT%H:%M:%S); echo "[$H] observ 3 minute blocările noi..."; sleep 180
NB=$(awk -v s="$T0" -F'"timestamp":"' '{split($2,a,"\""); if (a[1]>=s && index($0,"\"action\":\"blocked\"")) print}' $E)
OWNRE=$(echo "$OWN" | sed 's/\./\\./g; s/,/|/g')
echo "[$H] în 3 min: blocări IPS=$(echo "$NB" | grep -c .) | cu SURSA adresă proprie (trafic al instituției spre internet)=$(echo "$NB" | grep -cE "\"src_ip\":\"($OWNRE)\"") | alerte noi=$(awk -v s="$T0" -F'"timestamp":"' '{split($2,a,"\""); if (a[1]>=s) n++} END{print n+0}' $E)"
echo "$NB" | grep -oE '"signature":"[^"]{0,60}|"src_ip":"[^"]+' | paste - - | sort | uniq -c | sort -rn | head -6 | sed 's/^/   /'
echo "[$H] trafic final NFQUEUE: +$(m) / 10 s | ROLLBACK: cp -a $Y.bak-homenet-$TS $Y && systemctl restart suricata"
