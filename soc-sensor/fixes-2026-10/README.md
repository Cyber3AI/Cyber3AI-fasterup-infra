# Intervenții pe senzori, 8–12.10.2026

Toate au backup și auto-revert. Lansatorul rulează pe laptop, iar scriptul `*_sensor.sh` rulează ca root pe senzor.

| Script | Senzor | Ce face |
|---|---|---|
| `usb-mgmt-watchdog-v2.sh` / `deploy-usb-wd-v2-icisoc104.sh` | icisoc104 | Watchdog pentru adaptorul USB de management (r8152 Tx timeout): ping/wg capăt-la-capăt + reset USB. |
| `cn_blocare_permanenta*.sh` | icisoc109 | 91.92.33.76 (OnionDrop C2) intră permanent în permaban + sid 9100910–9100914. |
| `ppi_protectie_webmc*.sh` | icisoc108 | Protecția centralei KX-NS1000 192.168.1.159: sid 9100920/9100921. |
| `eb_exceptie_ingusta*.sh` | icisoc103 | Pass-ul 9100902 scos; 2061633 dezactivat și înlocuit cu 9100903 (alert pe 192.168.2.9) + 9100904 (drop pentru rest). |
| `i107_verificare_span*.sh` | icisoc107 | Read-only: SPAN-ul lipsește la client. |
| `rep_drop_*.sh` | icisoc102, icisoc108 | 12.10: drop pe reputație (Spamhaus/DShield/CINS), 367 de reguli trecute pe drop. |
