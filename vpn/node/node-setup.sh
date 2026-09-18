#!/usr/bin/env bash
# CYBER3.AI VPN — setup nod exit (Hetzner Cloud, Ubuntu 24.04). Idempotent.
# Rulează ca root pe FIECARE nod. Face: WireGuard server + ip_forward + nft NAT
# masquerade + resolver unbound (no-logs) + hook IOC (cron orar).
set -euo pipefail

WG_NET="10.3.0"; WG_PORT=51820
WAN=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
echo ">> WAN iface detectat: ${WAN}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y wireguard nftables unbound curl

# 1) forwarding
cat >/etc/sysctl.d/99-vpn.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl --system >/dev/null

# 2) chei server (doar dacă nu există)
cd /etc/wireguard
if [ ! -f server.key ]; then
  umask 077
  wg genkey | tee server.key | wg pubkey > server.pub
fi
SRV_PRIV=$(cat server.key)

# 3) wg0.conf — peers se adaugă manual (Pas 1) sau via agent (Pas 2)
if [ ! -f /etc/wireguard/wg0.conf ]; then
cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${WG_NET}.1/24
ListenPort = ${WG_PORT}
PrivateKey = ${SRV_PRIV}
PostUp   = nft add table inet vpn; nft add chain inet vpn post '{ type nat hook postrouting priority 100 ; }'; nft add rule inet vpn post oifname "${WAN}" masquerade
PostDown = nft delete table inet vpn
EOF
fi

# 4) resolver unbound (no-logs) + zona blocare IOC
mkdir -p /etc/unbound/unbound.conf.d
cat >/etc/unbound/unbound.conf.d/cyber3.conf <<EOF
server:
  interface: ${WG_NET}.1
  access-control: ${WG_NET}.0/24 allow
  do-ip6: no
  hide-identity: yes
  hide-version: yes
  qname-minimisation: yes
  verbosity: 0
  log-queries: no
  log-replies: no
  log-servfail: no
  include: "/etc/unbound/ioc.blocklist"
EOF
touch /etc/unbound/ioc.blocklist

# 5) hook IOC: trage domeniile (cron orar). Endpoint de confirmat/adăugat în worker.
cat >/usr/local/bin/cyber3-ioc-sync.sh <<'EOS'
#!/usr/bin/env bash
set -e
SRC="https://cyber3-edge.cyber3.workers.dev/v1/domains"
OUT=/etc/unbound/ioc.blocklist
curl -fsS --max-time 60 "$SRC" 2>/dev/null \
 | grep -E '^[a-z0-9.-]+$' \
 | awk '{print "local-zone: \""$1"\" always_nxdomain"}' > "$OUT.tmp" \
 && mv "$OUT.tmp" "$OUT" && systemctl reload unbound || true
EOS
chmod +x /usr/local/bin/cyber3-ioc-sync.sh
echo "0 * * * * root /usr/local/bin/cyber3-ioc-sync.sh" >/etc/cron.d/cyber3-ioc

# 6) pornire
systemctl enable --now unbound
systemctl enable --now wg-quick@wg0
systemctl restart wg-quick@wg0

# 7) postura RAM-only: logurile de sistem in RAM (volatile), sterse la reboot; fara persistenta pe disc.
#    (peers WireGuard sunt efemeri prin agent.py = fara wg-quick save; server.key ramane, e identitatea nodului)
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/cyber3-volatile.conf <<EOF
[Journal]
Storage=volatile
RuntimeMaxUse=50M
EOF
rm -rf /var/log/journal
systemctl restart systemd-journald || true

echo "============================================"
echo "SERVER PUBKEY: $(cat /etc/wireguard/server.pub)"
echo "WAN iface:     ${WAN}"
echo "WG net:        ${WG_NET}.1/24  port ${WG_PORT}/udp"
echo "Resolver:      ${WG_NET}.1 (unbound, no-logs)"
echo "============================================"
