#!/bin/bash
# f014 — PAS 1 canonic: Suricata 8.0.7 (OISF) + wazuh-agent 4.9.2-1 + iptables-persistent (preseed) + HOLD.
# Versiunile = cele de pe golden f012 (suricata 1:8.0.7-0ubuntu2, wazuh-agent 4.9.2-1).
set -u
say(){ echo "[f014 $(date -u +%T)] $*"; }
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
SV='1:8.0.7-0ubuntu2'; WV='4.9.2-1'

# capcana debconf iptables-persistent (agață în sesiune non-tty)
echo 'iptables-persistent iptables-persistent/autosave_v4 boolean false' | debconf-set-selections
echo 'iptables-persistent iptables-persistent/autosave_v6 boolean false' | debconf-set-selections

add-apt-repository -y ppa:oisf/suricata-stable >/dev/null 2>&1 && say "PPA OISF adăugat"
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null
echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq >/dev/null 2>&1 && say "apt update OK"

if apt-cache madison suricata | grep -qF "$SV"; then
  apt-get install -y -qq "suricata=$SV" iptables-persistent >/dev/null 2>&1 && say "suricata $SV + iptables-persistent instalate" || say "EROARE suricata"
else
  say "ATENȚIE: suricata $SV nu mai e în PPA; disponibile: $(apt-cache madison suricata | awk '{print $3}' | tr '\n' ' ') — NU instalez altă versiune fără decizie"
fi
WAZUH_MANAGER='10.0.0.100' apt-get install -y -qq "wazuh-agent=$WV" >/dev/null 2>&1 && say "wazuh-agent $WV instalat" || say "EROARE wazuh-agent"

apt-mark hold suricata wazuh-agent >/dev/null
say "hold: $(apt-mark showhold | tr '\n' ' ')"
# serviciile NU pornesc încă: configurarea vine la PAS 2-3 (golden + identitate)
systemctl disable --now suricata >/dev/null 2>&1; systemctl disable --now wazuh-agent >/dev/null 2>&1
# ca pe f012: fără actualizări automate (pot rupe senzorul)
systemctl disable --now unattended-upgrades >/dev/null 2>&1
say "unattended-upgrades: $(systemctl is-enabled unattended-upgrades 2>/dev/null)"
dpkg-query -W -f='${Package}=${Version}\n' suricata wazuh-agent iptables-persistent
say "PAS 1 gata"
