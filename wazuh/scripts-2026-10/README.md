# Modificări pe managerul Wazuh (10.0.0.100), 10–11.10.2026

`local_rules.xml` din repo NU e sincronizat: fișierul live e citibil doar ca root. Pentru o copie: `sudo cat /var/ossec/etc/rules/local_rules.xml`.

## Reguli adăugate
- **`r213_fix_manager.sh` (10.10):** reguli-copil peste 100213/100214:
  - 100250, nivel 7: acces la distanță;
  - 100251, nivel 12: honeytoken;
  - 100252, nivel 8: C2 / ClickFix.
- **`hunt_cb_manager.sh` + `cb_hunt_patch.py` (10.10):**
  - regula 100260, nivel 8: CYBER3 Threat Hunt;
  - CyberBot `handle_threat_hunt`: doar notificare.
- **`r250_flood_manager.sh` (11.10):** copilul 100254, nivel 2 (neindexat), pentru „in DNS Lookup|in TLS SNI” ale uneltelor de acces la distanță.
  - A oprit floodul de ~25.000 de alerte/zi venit din 100250.

Fiecare script face backup `.bak-*` în `/var/ossec/etc/rules/` și are auto-revert.
