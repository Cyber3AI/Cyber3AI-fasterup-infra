# MLEO — carantina stațiilor interne compromise (10–12.10.2026)

## Etapa 1: observare
- **Identitatea IP → MAC se caută STRICT pe senzorul clientului.** Înainte exista un fallback global, iar 326 de IP-uri private apar la mai mulți clienți.
- **Semnale:**
  - Threat Hunt H3/H4/H6, cu severitate CRITIC sau ÎNALT, pe gazdă privată;
  - CyberBot `BLOCARE_IMEDIATA` cu `rule=100216`, pe IP intern, în ultimele 72 de ore.
- **Tabela `contain`** din `mleo.db`, cu stările: proposed, notify, active, released, rejected, expired, stale.
- **`mleo-critical.conf`:** dispozitive care primesc DOAR notificare (DNS CNI, centrala PPI, server Elbi).

## Etapa 2: aprobare supervisor
- **Butoane în ▸ HUNT:** Aprobă / Respinge / Eliberează, doar pentru rolul supervisor (`require_supervisor` pe server).
- **Execuția pe senzor:** `mleo.py approve|release <txid> <user>` → ssh → `sudo -n /usr/local/sbin/cyber3-mleo-contain`.
- **Executorul:** `../../soc-sensor/mleo/cyber3-mleo-contain`.
  - Lanțul iptables `CYBER3_MLEO_C` este primul în FORWARD.
  - Permite RFC1918 și multicast; restul traficului primește DROP, pe IP și pe MAC.
  - TTL 24 h, cu timer de expirare la 5 minute; maximum 5 carantine pe senzor.
  - Refuză gateway-uri, IP-uri publice, `ar-allowlist` și adresele/MAC-urile senzorului.
- **Privilegiul `socadmin`** de a rula executorul ca root (`/etc/sudoers.d/cyber3-mleo`) a fost aprobat explicit de operator pe 10.10.2026.
- **Instalare:**
  - executorul e pe 17/18 senzori (lipsește f010, offline din 01.10; icisoc110 e exclus);
  - portalul: `deploy_mleo_etapa2.sh` + `fin_mleo_etapa2.sh`.
  - Lecție: în scripturile trimise prin `bash -s`, ssh/subprocess primesc `</dev/null`, altfel consumă scriptul.
