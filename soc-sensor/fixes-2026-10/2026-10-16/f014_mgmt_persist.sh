#!/bin/bash
# f014 @ Clinica Sarafoleanu (mod NE-inline, copie de trafic). enp2s0 = NO-CARRIER (placă suspectă).
# Management permanent pe enp0s25 (DHCP, prin br0 cu un singur membru), eno1 scos din punte = viitor port de captură (fără IP).
# Dead-man: dacă în 120 s după aplicare 10.0.0.100 nu răspunde prin VPN, revine la netplan-ul vechi + dhclient br0.
set -u
H=$(hostname); [ "$H" = f014 ] || { echo "[$H] ABORT hostname"; exit 3; }
N=/etc/netplan/50-cyber3.yaml; TS=$(date -u +%Y%m%d-%H%M%S); LOG=/root/mgmt-persist-$TS.log
cp -a $N /root/50-cyber3.yaml.bak-mgmt-$TS
cat > /root/revert-mgmt.sh <<EOF
#!/bin/bash
cp -a /root/50-cyber3.yaml.bak-mgmt-$TS $N; netplan apply; sleep 5; (dhclient br0 || dhcpcd br0) 2>/dev/null; systemctl restart wg-quick@wg1
echo "\$(date -u +%T) REVERT executat" >> $LOG
EOF
chmod 700 /root/revert-mgmt.sh
cat > $N <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    enp2s0:
      dhcp4: true
      optional: true
    eno1:
      dhcp4: false
      optional: true
    enp0s25:
      dhcp4: false
  bridges:
    br0:
      interfaces: [enp0s25]
      dhcp4: true
      parameters:
        stp: false
        forward-delay: 0
EOF
chmod 600 $N
netplan generate 2>>$LOG || { cp -a /root/50-cyber3.yaml.bak-mgmt-$TS $N; echo "[$H] ABORT: netplan invalid — restaurat"; exit 2; }
echo "[$H] netplan valid; aplic în fundal cu dead-man 120 s. Jurnal: $LOG"
nohup bash -c "
  sleep 3; echo \"\$(date -u +%T) apply\" >> $LOG
  ip link set eno1 nomaster 2>>$LOG; netplan apply 2>>$LOG; sleep 10
  OK=0; for i in \$(seq 1 22); do ping -c1 -W2 10.0.0.100 >/dev/null 2>&1 && { OK=1; break; }; sleep 5; done
  if [ \$OK = 1 ]; then echo \"\$(date -u +%T) OK: 10.0.0.100 accesibil; br0=\$(ip -br -4 a show br0 | awk '{print \$3}') eno1_master=\$(ip -o link show eno1 | grep -o 'master [a-z0-9]*' || echo niciunul)\" >> $LOG
  else echo \"\$(date -u +%T) FĂRĂ VPN după 120 s -> revert\" >> $LOG; /root/revert-mgmt.sh; fi
" >/dev/null 2>&1 &
echo "[$H] pornit; reconectați-vă peste ~1 min și citiți $LOG"
