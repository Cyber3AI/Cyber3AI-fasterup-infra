#!/bin/bash
# Rulat de operator: ! bash <acest fișier>. Precheck (ping manager prin VPN), apoi management permanent pe f014 cu dead-man, apoi verificare.
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad
export SSH_ASKPASS=$S/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0
O="-o PubkeyAuthentication=no -o ConnectTimeout=15"; IP=10.1.14.1
PRE=$(ssh $O socadmin@$IP 'echo "$(hostname) ping_manager=$(ping -c2 -W2 10.0.0.100 >/dev/null 2>&1 && echo OK || echo FAIL) wg1=$(systemctl is-enabled wg-quick@wg1)"' 2>/dev/null)
echo "PRECHECK: $PRE"
echo "$PRE" | grep -q '^f014 ping_manager=OK' || { echo "STOP: precheck eșuat — nimic modificat"; exit 1; }
scp -q $O $S/f014_mgmt_persist.sh socadmin@$IP:/tmp/mp.sh && ssh $O socadmin@$IP "sudo -S -p '' bash /tmp/mp.sh" < $S/.fleetpw 2>/dev/null
echo "aștept 90 s aplicarea..."; sleep 90
for i in 1 2 3 4 5 6; do
  R=$(ssh $O socadmin@$IP "sudo -S -p '' bash -c 'tail -5 \$(ls -t /root/mgmt-persist-*.log | head -1); ip -br -4 a | grep -v ^lo; ip -o link show eno1 | grep -o \"master [a-z0-9]*\" || echo eno1: fără punte'" < $S/.fleetpw 2>/dev/null) && { echo "$R"; break; }
  echo "încă nu răspunde ($i/6)..."; sleep 20
done
[ -n "${R:-}" ] || echo "NU răspunde după 3 min — la consolă: ip -br a ; sudo cat /root/mgmt-persist-*.log"
