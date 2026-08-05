# fasterup-infra — config-uri infra internă SOC (FasterUp / CYBER3)

Versionare a **config-urilor** (fără secrete) pentru portal, Wazuh, MISP și relay-hub Hetzner.

> **Secretele NU sunt aici** (redactate `<REDACTED>` / excluse). Backup-ul complet de restaurare rapidă (cu secrete, arhive tar) este în **Cloudflare R2**: bucket `cyber3-code`, prefix `infra-dr/` — vezi `infra-dr/RESTORE.md`.

## Structură
- `portal/` — cod Flask (`app/`), frontend (`frontend/index.html`), nginx, supervisor, `env.example`.
- `wazuh/` — `ossec.conf`, reguli/decoders locale, config indexer/dashboard + opensearch-security (DLS/RBAC), filebeat.
- `misp/` — `config.php` (redactat) + `misp_schema.sql` (structura DB, 103 tabele).
- `relay-hub/` — WireGuard `wg1.conf` (chei redactate), sshd, fail2ban, sysctl.

## Restaurare
Pentru restaurare completă folosește arhivele din R2 (au secretele reale) + parola de flotă (o știe operatorul). Config-urile de aici sunt pentru referință/versionare și diff.
