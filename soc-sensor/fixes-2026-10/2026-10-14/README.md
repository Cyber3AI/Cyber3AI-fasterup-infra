# Intervenții 14.10.2026

**Convenții:**
- Lansatoarele rulează pe Acer, cu `! bash <script>`.
- Scripturile `*_sensor.sh` și `*_manager.sh` rulează ca root pe țintă.
- Parola flotei e citită dintr-un fișier local de sesiune și nu e inclusă aici.
- Toate scripturile fac backup înainte de modificare și revin automat la eroare.
- Pe senzorii inline vii nu se folosesc niciodată `suricata -T` sau `reload-rules`.

## Senzor nou f014 (Clinica Sarafoleanu): build canonic NEXTGEN la staging, din golden f012

| Script | Ce face |
|---|---|
| `f014_pas0.sh` | Sursa apt, extinderea LVM, pachete de bază, netplan de management (`enp2s0` DHCP) |
| `f014_pas1.sh` | Suricata `1:8.0.7-0ubuntu2` + wazuh-agent `4.9.2-1` + preseed iptables-persistent + hold |
| `golden_check.sh` | Read-only: senzorul e la standardul canonic? (candidat golden) |
| `golden_pack.sh` | Pe golden: 3 arhive de configurare canonică; exclude starea și identitatea sursei |
| `f014_pas23.sh` | Despachetare golden, identitate f014, L2 dezarmat, curățarea valorilor f012/f010, br0, iptables, systemd |
| `f014_pas45.sh` | wg1 `10.1.14.1` + înrolare Wazuh cu parolă (agent 026) + ops-agent + token NOC |
| `f014_pas6.sh` | Pornirea serviciilor + executor MLEO (installer canonic `soc-sensor/mleo/`) |
| `f014_acceptanta.sh` | Testul de acceptanță §10 (read-only) |
| `f014_portal.sh` | Slot portal F014 + `SENSORS` + harta MLEO |

## Reguli CYBER3 + MISP neîncărcate pe f007, f008, f009, f011, f012

| Script | Ce face |
|---|---|
| `lr_check.sh` | Read-only: `rule-files` + linia „N rule files processed” din `suricata.log` |
| `activare_reguli.sh` + `activare_reguli_sensor.sh` | `rule-files` = suricata + cyber3-misp + cyber3-local, un restart, verificare 3 fișiere / 0 failed / 4 cozi, auto-revert |
| `relay2_suppress_sensor.sh` | relay-2 46.62.221.30 = infra SOC: supresie + `pass` 9100930/9100931 |

## Lista MISP de domenii (înghețată din 16.09)

| Script | Ce face |
|---|---|
| `domains_fix.sh` + `domains_fix_sensor.sh` | Wrapper `cyber3-apply-domains` fără `reload-rules`; f011/f012/f014 adăugați în distribuitorul de pe portal |
| `misp_gen_fix.sh` + `misp_gen_fix_manager.sh` | Generator: plafon 60 → 400 pagini (`C3-FIX-20261014-PAGINI`), rulare + distribuire. Rezultat: 597.184 domenii |

## CyberBot: excepții la blocarea IOC

| Script | Ce face |
|---|---|
| `cyberbot_ioccdn.sh` + `cyberbot_ioccdn_manager.sh` | 45 de rețele CDN/cloud → `IOC_CDN` doar jurnal (`C3-FIX-20261014-IOC-CDN`); test simulat pe copie |
| `cyberbot_iocaws.sh` + `cyberbot_iocaws_manager.sh` | + AWS (1.741 rețele din `ip-ranges.json`) (`C3-FIX-20261014-IOC-AWS`) |
| `cyber3-refresh-aws.py` + `cyberbot_aws_refresh.sh` + `cyberbot_aws_refresh_manager.sh` | Reîmprospătare lunară a listei AWS (cron root `30 4 1 * *`) |

Detalii complete: `Desktop/00_NOTE TRANSFER/NOTA_TRANSFER_2026-10-14.md`, manifestele din `FasterUp NEXTGEN SOC/` și dosarul `Suricata IPS NEXT GEN/` (04_CAPCANE §I).
