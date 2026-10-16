#!/bin/bash
# f010 — punctele 1–4 ale standardului (DOAR FIȘIERE, fără restart, fără iptables). Supresiile se încarcă la următorul restart Suricata (nocturn).
set -u
[ "$(hostname)" = f010 ] || { echo "ABORT: nu sunt pe f010 ($(hostname))"; exit 3; }
TS=$(date -u +%Y%m%d-%H%M%S); T=/etc/suricata/threshold.config; ST0=$(systemctl show suricata -p ActiveEnterTimestamp --value)
cp -a $T $T.bak-standard-$TS
# 1) blocul de 367 supresii de reputație (identic cu flota, din golden f012)
if grep -q 'supresie zgomot reputatie INBOUND' $T; then echo "1) bloc reputație deja prezent"; else
  N=$(grep -cE '^suppress gen_id 1, sig_id 24[0-9]{5}$' /tmp/rep.block)
  [ "$N" = 367 ] || { echo "ABORT: blocul nu are 367 supresii ($N)"; exit 2; }
  printf '\n' >> $T; cat /tmp/rep.block >> $T; echo "1) adăugat blocul de reputație: $N supresii"; fi
# 2) self-scan de la birou (192.168.0.136) scos; rămâne 10.228.0.110 (mgmt real) — + wg 10.1.10.1 dacă lipsește
sed -i '/track by_src, ip 192\.168\.0\.136$/d' $T
grep -q 'track by_src, ip 10.1.10.1$' $T || sed -i '/^# === Self-scan senzor/a suppress gen_id 0, sig_id 0, track by_src, ip 10.1.10.1' $T
echo "2) self-scan: $(grep -A4 '^# === Self-scan' $T | grep -oE 'ip [0-9.]+' | tr '\n' ' ')| 192.168.0.136 rămase: $(grep -c '192\.168\.0\.136' $T)"
BAD=$(grep -vE '^\s*$|^#|^suppress gen_id [0-9]+, sig_id [0-9]+(, track by_(src|dst), ip [0-9./]+)?\s*$|^threshold |^event_filter |^rate_filter ' $T | head -3)
[ -z "$BAD" ] || { cp -a $T.bak-standard-$TS $T; echo "ABORT: linie neașteptată în threshold — restaurat: $BAD"; exit 2; }
echo "   threshold: $(grep -c '^suppress' $T) supresii (era $(grep -c '^suppress' $T.bak-standard-$TS)), sintaxă linii OK"
# 3) modulul NFQUEUE la boot
printf 'nfnetlink_queue\nnfnetlink\n' > /etc/modules-load.d/cyber3-nfqueue.conf; echo "3) modules-load: $(tr '\n' ' ' < /etc/modules-load.d/cyber3-nfqueue.conf)"
# 4) wait-online --any (boot robust)
mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d
printf '[Service]\nExecStart=\nExecStart=/lib/systemd/systemd-networkd-wait-online --any\n' > /etc/systemd/system/systemd-networkd-wait-online.service.d/10-c3-any.conf
systemctl daemon-reload; echo "4) wait-online: $(systemctl show systemd-networkd-wait-online -p ExecStart --value | grep -oE 'wait-online [^;]*' | head -1)"
ST1=$(systemctl show suricata -p ActiveEnterTimestamp --value)
echo "Suricata NEATINS: $([ "$ST0" = "$ST1" ] && echo DA || echo NU) | FORWARD: $(iptables -S FORWARD | tail -n +2 | tr '\n' ' ')| failed: $(systemctl list-units --failed --no-legend | wc -l)"
echo "Supresiile noi se încarcă la următorul restart Suricata: logrotate $(systemctl list-timers logrotate.timer --no-legend --no-pager | awk '{print $1,$2,$3}')"
rm -f /tmp/rep.block
