# CYBER3 Scan — Notă de transfer (actualizat 24 iunie 2026)

Scanner propriu **descoperire rețea + vulnerabilități**, rulat PE SENZORI (inline), înlocuiește Nuclei. Parte din oferta **VAS**. Diferențiator: **descoperă rețeaua clientului FĂRĂ a primi IP-uri** (inline pe trunk).

**Cod:** `CYBER3.APP/c3scan/` → `c3scan.py` (descoperire), `c3vuln.py` (vulnerabilități), `oui.txt` (39k producători). **Pe senzor:** `/opt/cyber3/c3scan/`. **Output:** `/var/log/cyber3/discovery.json` + `findings.json`.

## ✅ CONSTRUIT + TESTAT pe f003 (rețea reală client)
- **Descoperire PASIVĂ** — sniffer AF_PACKET br0, VLAN din PACKET_AUXDATA, hosturi/MAC/producător/rol/hostname/servicii. Zero input.
- **Descoperire ACTIVĂ** — `smart_sweep` ARP tag-uit (probe→full pe VLAN-acasă) → MAC real + hosturi tăcute.
- **#2 PORTSCAN** — `connect-scan` (interfață VLAN temporară pe br0 + IP liber + `connect()` kernel). **OBLIGATORIU** fiindcă gateway-ul UniFi face **SYN-proxy** (SYN-scan brut → toate porturile false). Curățare subif în finally.
- **#3a VULN** (`c3vuln.py`) — servicii periculoase expuse, **SMBv1** (EternalBlue CVE-2017-0144), TLS expirat/self-signed, panouri admin web. Output findings.json. `purge()` subif la start+sfârșit.

**Rezultate f003:** 411 hosturi → 283 cu servicii → **199 findings: 11 SMBv1 CRITIC, 4 Telnet, 3 MSSQL+1 MySQL+4 FTP, 23 panouri web, 105 RDP, 48 TLS self/untrusted.**

## ⚠️ Limitări / capcane
- Subrețele rutate off-trunk (ex. 10.242.30.x) = doar IP+pasiv (ne-ARP-abile, inerent inline).
- SYN-scan inutil prin SYN-proxy → connect() obligatoriu.
- Subif VLAN squatting IP → purge obligatoriu (rezolvat).
- Garduri: doar RFC1918, exclude senzor/gateway/fragile (medical/OT), non-distructiv, un scan odată, self-scan suppress Suricata.

## 📋 DE FĂCUT — sesiunea următoare

### #3b — Adâncire vulnerabilități
- **CISA KEV + CVE pe versiuni**: fetch catalog KEV (ca oui.txt), match banner produs/versiune → „exploatat-în-lume". Enrich baza CYBER3 cu NVD+KEV.
- **SNMP community „public"** (UDP GET sysDescr) → default-cred/info leak.
- **Default creds** (opt-in, doar non-fragile) pe panourile web găsite.

### #4 — Integrare PORTAL (spec de la operator, 24 iun)
- **Bloc „CYBER3 Scan" ÎNAINTE de blocul Nuclei** în portal.
- **SIMPLU:** un **dropdown de selecție senzor** + buton **„▸ ENGAGE"** (operatorul a propus „CYBER3 Scan Engage"; recomandat: blocul e deja titrat „CYBER3 Scan", deci pe buton doar „ENGAGE" ca să nu fie redundant). Nivel implicit **„mediu (sigur)"**.
- Mecanism ca Nuclei: portal → SSH senzor → rulează `c3scan.py --active --ports` apoi `c3vuln.py` → rezultate JSON înapoi la portal → afișare (hosturi descoperite + findings pe severitate). Model: `api_nuclei.py` / endpoint-urile `/api/nuclei/*` din portal (socadmin@10.0.0.22).

### #5 — Rapoarte (FOARTE IMPORTANT, cerut explicit)
- **Integrează partea de raportare către client ÎN rapoartele existente din portal** (generatorul lunar NIS2 — vezi [[portal-rapoarte-nis2]]). NU raport separat.
- **Raport MATCH alerte–scanare**: join pe IP → vulnerabilități (c3vuln) + alerte (Suricata/Wazuh) + exploatat-în-lume (KEV/MISP) → scor risc combinat + acțiune. Capitol nou în raportul lunar, bilingv RO/EN.

## Cum reiei
1. Citește memoria `cyber3-scan-product` + [[portal-rapoarte-nis2]] (structura raportului).
2. Cod în `CYBER3.APP/c3scan/`; pe f003 în `/opt/cyber3/c3scan/`.
3. Ordine: **#3b → #4 (portal: bloc înainte de Nuclei, dropdown senzor + ENGAGE) → #5 (raport MATCH în raportul lunar din portal).**
