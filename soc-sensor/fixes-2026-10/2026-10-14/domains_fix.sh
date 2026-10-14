#!/bin/bash
# Rulat de operator pe Acer: ! bash <acest fișier>
# Pasul 1 (distribuitorul MISP): (A) pe fiecare senzor, unul câte unul: wrapper cyber3-apply-domains FĂRĂ reload-rules
# + sudoers + cheia portalului (doar fișiere; Suricata/Wazuh/rețea neatinse); (B) pe portal: f011, f012, f014 adăugați
# în lista distribuitorului (backup + verificare sintaxă + auto-revert); (C) test read-only portal -> senzorii noi.
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
export SSH_ASKPASS=$S/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0
O="-o PubkeyAuthentication=no -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new"
J="-o ProxyJump=socadmin@10.0.0.22"
DIRECT="1 2 5 7 8 9 11 12 14"            # f0xx prin VPN
VIAPORTAL="22 25 26 27 28 29 30 31 32 33" # icisoc101-110 prin portal
echo "== (A) senzori"
for n in $DIRECT $VIAPORTAL; do
  h=socadmin@10.1.$n.1; X=""; case " $VIAPORTAL " in *" $n "*) X="$J";; esac
  if ! scp -q $O $X $S/domains_fix_sensor.sh $h:/tmp/dfs.sh 2>/dev/null; then echo "10.1.$n.1: inaccesibil — sărit"; continue; fi
  ssh $O $X $h 'sudo -S -p "" bash /tmp/dfs.sh; rc=$?; rm -f /tmp/dfs.sh; exit $rc' < $S/.fleetpw 2>/dev/null || { echo "10.1.$n.1: EROARE — STOP"; exit 1; }
done

echo "== (B) portal: lista distribuitorului"
ssh -o ConnectTimeout=15 socadmin@10.0.0.22 'bash -s' <<'REMOTE'
F=/usr/local/sbin/cyber3-distribute-domains.sh; TS=$(date -u +%Y%m%d-%H%M%S)
sudo cp -a $F $F.bak-f011f012f014-$TS
for ip in 10.1.11.1 10.1.12.1 10.1.14.1; do
  grep -q "SENSORS=.*$ip" $F || sudo sed -i "s|^\(SENSORS=\"[^\"]*\)\"|\1 $ip\"|" $F
done
bash -n $F || { sudo cp -a $F.bak-f011f012f014-$TS $F; echo "REVERT: sintaxă"; exit 1; }
grep '^SENSORS=' $F | tr ' ' '\n' | grep -c '10\.1\.' | sed 's/^/senzori în listă: /'
grep -oE '10\.1\.1[124]\.1' $F | tr '\n' ' '; echo
echo "== (C) test read-only portal -> senzorii noi (cheie + sudo pe wrapper, fără a aplica nimic)"
for ip in 10.1.11.1 10.1.12.1 10.1.14.1; do
  ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new socadmin@$ip 'echo "$(hostname): ssh OK; sudo wrapper: $(sudo -n -l /usr/local/sbin/cyber3-apply-domains >/dev/null 2>&1 && echo DA || echo NU)"' </dev/null || echo "$ip: ssh EȘEC"
done
REMOTE
echo GATA
