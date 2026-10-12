# CYBER3 Threat Hunt (buton ▸ HUNT în portal) — 10.10.2026

Vânătoare automată pe indexul Wazuh (`wazuh-alerts-*`), la fiecare 6 ore, pe o fereastră de 7 zile.

## Vânători
- **H1:** răspuns reușit la atac.
- **H2:** upload acceptat (HTTP 200).
- **H3:** stager PowerShell urmat de C2.
- **H4:** C2 permis, inițiat din interior.
- **H5:** peste 100 MB ieșiți într-o sesiune.
- **H6:** honeytoken.
- **H7:** acces la distanță pe o stație nouă.
- **H8:** senzor fără alerte de rețea.

## Live (sursa adevărului = serverele)
- **Motor:** `socadmin@10.0.0.22:/opt/cyber3/hunt/threat_hunt.py`.
  - Timer `cyber3-threat-hunt.timer`, la 00/6:15 UTC.
  - Ieșire: `/opt/fasterup-portal/data/threat_hunt/latest.json`.
- **API:** `portal/app/routes/api_hunt.py`.
  - `/api/hunt/findings` și `/api/hunt/summary`, filtrate prin RBAC (`g.visible_agent_ids`).
  - `/api/hunt/containment`: card MLEO; aprobare/eliberare DOAR cu rolul supervisor.
- **Notificări prin CyberBot:**
  - motorul trimite cu `--notify` (PUT /events), regula 100260 nivel 8 face alerta, iar `handle_threat_hunt` din `cyberbot.py` notifică;
  - patch: `cb_hunt_patch.py` + `../../wazuh/scripts-2026-10/hunt_cb_manager.sh`.
- **Instalare:** `deploy_hunt.sh` instalează portalul; `deploy_hunt_pas1_si_motor.sh` instalează managerul și motorul.
  - Lansatoarele citesc parola flotei din scratchpad-ul sesiunii (`.fleetpw`). La o reinstalare, ajustați calea.
