#!/bin/bash
# f014 (Clinica Sarafoleanu) — PAS 0 la staging: sursă apt, rețea de management permanentă, disc, pachete de bază.
# Rulează ca root pe senzor. Nimic inline încă; br0 se configurează la pașii următori.
set -u
TS=$(date -u +%Y%m%d-%H%M%S)
say(){ echo "[f014 $(date -u +%T)] $*"; }

# 1) Sursa de pachete (Ubuntu instalat fără mirror: liniile „deb  jammy...” n-au URL)
cp -a /etc/apt/sources.list /etc/apt/sources.list.bak-$TS
sed -i 's|^deb  |deb http://archive.ubuntu.com/ubuntu |g' /etc/apt/sources.list
say "sources.list: $(grep -c '^deb http://archive.ubuntu.com/ubuntu' /etc/apt/sources.list) linii reparate"

# 2) Disc: LVM folosește doar 100G din 223G
lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv >/dev/null 2>&1 && resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv >/dev/null 2>&1
say "disc /: $(df -h / | awk 'END{print $2" total, "$4" liber"}')"

# 3) Pachete de bază (fără întrebări debconf în sesiune non-tty)
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
apt-get update -qq >/dev/null 2>&1 && say "apt update OK" || say "EROARE apt update"
apt-get install -y -qq wireguard-tools tcpdump curl gnupg unzip ethtool >/dev/null 2>&1 && say "pachete de bază instalate" || say "EROARE la instalarea pachetelor"

# 4) Rețeaua de management permanentă pe enp2s0 (DHCP la staging); eno1 + enp0s25 rămân fără IP (viitorul br0)
mkdir -p /root/netplan-bak-$TS; cp -a /etc/netplan/* /root/netplan-bak-$TS/ 2>/dev/null
echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
cat > /etc/netplan/50-cyber3.yaml <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    enp2s0:
      dhcp4: true
    eno1:
      optional: true
    enp0s25:
      optional: true
EOF
chmod 600 /etc/netplan/50-cyber3.yaml
rm -f /etc/netplan/50-cloud-init.yaml
if netplan generate 2>/tmp/netplan.err; then
  say "netplan valid; aplic peste 3 s (sesiunea SSH poate cădea câteva secunde)"
  nohup sh -c 'sleep 3; netplan apply; pkill -f "dhclient enp2s0" 2>/dev/null' >/dev/null 2>&1 &
else
  say "EROARE netplan: $(cat /tmp/netplan.err) — restaurez"; rm -f /etc/netplan/50-cyber3.yaml; cp -a /root/netplan-bak-$TS/* /etc/netplan/
fi
say "PAS 0 gata"
