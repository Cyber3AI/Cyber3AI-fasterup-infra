"""CYBER3 Scan — bibliotecă de remediere pas-cu-pas (RO + EN).

Sursa de adevăr pentru categoriile de vulnerabilități este scannerul on-sensor
`/opt/cyber3/c3scan/c3vuln.py`. Fiecare finding are câmpurile:
    {ip, vlan, severity(int 0-10), category, title, remediation(text scurt inline)}

Categoriile REALE emise de c3vuln.py (verificate pe senzor, 03 aug 2026):
    servicii expuse (sufix "-EXPUS"):
        TELNET-EXPUS, FTP-EXPUS, VNC-EXPUS, REDIS-EXPUS, MSSQL-EXPUS,
        MYSQL-EXPUS, POSTGRES-EXPUS, MODBUS-EXPUS, S7-EXPUS, BACNET-EXPUS, RDP-EXPUS
    alte:
        SMBv1, SNMP-PUBLIC, PANOU-WEB, DEFAULT-CRED,
        TLS-EXPIRAT, TLS-SELF, TLS-NEÎNCREZUT, CVE, CVE-KEV

Câmpul `remediation` livrat de scanner e un one-liner. Cerința operatorului /
ICISOC este un „step-by-step": pași NUMEROTAȚI, concreți, de remediere per tip de
vulnerabilitate. Acest modul furnizează acei pași + funcția de potrivire
`category -> pași`, cu fallback onest pe remedierea inline a scannerului pentru
orice categorie viitoare necunoscută aici.

API public:
    get_remediation(finding, lang) -> dict {key, label, why, steps[list[str]], refs}
    remediation_key(finding)       -> cheia canonică folosită la grupare
    REMEDIATION, CVE_STEPS          -> dicționarele brute (pt. teste / extindere)
"""
import re

# ---------------------------------------------------------------------------
# Normalizare categorie: serviciile expuse vin ca "<SVC>-EXPUS"; le mapăm la
# cheia de bază "<SVC>". Restul categoriilor rămân neschimbate.
# ---------------------------------------------------------------------------
_EXPOSED_ALIAS = {
    'TELNET-EXPUS': 'TELNET', 'FTP-EXPUS': 'FTP', 'VNC-EXPUS': 'VNC',
    'REDIS-EXPUS': 'REDIS', 'MSSQL-EXPUS': 'MSSQL', 'MYSQL-EXPUS': 'MYSQL',
    'POSTGRES-EXPUS': 'POSTGRES', 'MODBUS-EXPUS': 'MODBUS', 'S7-EXPUS': 'S7',
    'BACNET-EXPUS': 'BACNET', 'RDP-EXPUS': 'RDP',
}

_CVE_RE = re.compile(r'CVE-\d{4}-\d{3,7}', re.I)


def _canon_category(cat):
    """Normalizează sufixul -EXPUS și uniformizează câteva sinonime OT."""
    if not cat:
        return ''
    c = str(cat).strip()
    if c in _EXPOSED_ALIAS:
        return _EXPOSED_ALIAS[c]
    # OT: S7 și MODBUS/BACNET partajează recomandarea de segmentare
    return c


# ---------------------------------------------------------------------------
# Pași specifici per CVE cunoscut (au prioritate față de blocul generic CVE).
# Cheia = CVE id extras din titlu. Fiecare: {label, ro:[...], en:[...]}
# ---------------------------------------------------------------------------
CVE_STEPS = {
    'CVE-2021-41773': {
        'label': {'ro': 'Apache httpd 2.4.49 — path traversal → RCE',
                  'en': 'Apache httpd 2.4.49 — path traversal → RCE'},
        'ro': [
            'Actualizează Apache httpd la ≥ 2.4.51 (2.4.50 NU e suficient — vezi CVE-2021-42013).',
            'Până la upgrade, blochează traversarea: adaugă „Require all denied” pe secțiunea „<Directory />” și dezactivează mod_cgi/mod_cgid dacă nu sunt necesare.',
            'Verifică logurile de acces pentru cereri cu „..%2e” / „/cgi-bin/” suspecte — semn de exploatare.',
            'Dacă serverul a fost expus în internet, tratează gazda ca potențial compromisă și rotește secretele.',
            'Rescanează cu CYBER3 Scan pentru a confirma versiunea corectată.',
        ],
        'en': [
            'Upgrade Apache httpd to ≥ 2.4.51 (2.4.50 is NOT enough — see CVE-2021-42013).',
            'Until patched, block traversal: set "Require all denied" on "<Directory />" and disable mod_cgi/mod_cgid if not needed.',
            'Review access logs for requests containing "..%2e" / suspicious "/cgi-bin/" — sign of exploitation.',
            'If the server was internet-facing, treat the host as potentially compromised and rotate secrets.',
            'Rescan with CYBER3 Scan to confirm the fixed version.',
        ],
    },
    'CVE-2021-42013': {
        'label': {'ro': 'Apache httpd 2.4.50 — path traversal → RCE',
                  'en': 'Apache httpd 2.4.50 — path traversal → RCE'},
        'ro': [
            'Actualizează Apache httpd la ≥ 2.4.51 (corecția completă pentru bypass-ul din 2.4.50).',
            'Dezactivează mod_cgi/mod_cgid dacă nu sunt strict necesare; aplică „Require all denied” pe „<Directory />”.',
            'Caută în loguri cereri encodate dublu („%%32%65”) către /cgi-bin/ — indiciu de exploatare.',
            'Dacă a fost expus public, tratează gazda ca potențial compromisă.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Upgrade Apache httpd to ≥ 2.4.51 (complete fix for the 2.4.50 bypass).',
            'Disable mod_cgi/mod_cgid if not strictly needed; apply "Require all denied" on "<Directory />".',
            'Search logs for double-encoded ("%%32%65") requests to /cgi-bin/ — exploitation hint.',
            'If it was internet-facing, treat the host as potentially compromised.',
            'Rescan to confirm.',
        ],
    },
    'CVE-2011-2523': {
        'label': {'ro': 'vsftpd 2.3.4 — backdoor (port 6200)',
                  'en': 'vsftpd 2.3.4 — backdoor (port 6200)'},
        'ro': [
            'Tratează gazda ca DEJA COMPROMISĂ — acest build conține un backdoor care deschide un shell pe 6200/tcp.',
            'Izolează imediat gazda de rețea (regulă firewall / port switch) până la curățare.',
            'Reinstalează vsftpd dintr-o sursă oficială curată sau reconstruiește gazda de la zero.',
            'Rotește toate credențialele și cheile care au existat pe gazdă.',
            'Verifică porturile 6200/tcp și procesele/cron-urile adăugate; caută persistență.',
            'Rescanează după reconstrucție.',
        ],
        'en': [
            'Treat the host as ALREADY COMPROMISED — this build contains a backdoor opening a shell on 6200/tcp.',
            'Isolate the host from the network immediately (firewall rule / switch port) until cleaned.',
            'Reinstall vsftpd from a clean official source, or rebuild the host from scratch.',
            'Rotate every credential and key that ever lived on the host.',
            'Check for 6200/tcp and added processes/cron jobs; hunt for persistence.',
            'Rescan after rebuild.',
        ],
    },
    'CVE-2015-3306': {
        'label': {'ro': 'ProFTPD 1.3.5 — mod_copy RCE',
                  'en': 'ProFTPD 1.3.5 — mod_copy RCE'},
        'ro': [
            'Actualizează ProFTPD la ≥ 1.3.5a.',
            'Dezactivează mod_copy (comenzile SITE CPFR/CPTO) dacă upgrade-ul nu e imediat posibil.',
            'Restricționează accesul FTP la sursele autorizate pe firewall.',
            'Verifică webroot-ul pentru fișiere încărcate neautorizat (webshell).',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Upgrade ProFTPD to ≥ 1.3.5a.',
            'Disable mod_copy (SITE CPFR/CPTO commands) if upgrade is not immediately possible.',
            'Restrict FTP access to authorized sources on the firewall.',
            'Check the webroot for unauthorized uploaded files (webshell).',
            'Rescan to confirm.',
        ],
    },
    'CVE-2018-15473': {
        'label': {'ro': 'OpenSSH <7.7 — enumerare utilizatori',
                  'en': 'OpenSSH <7.7 — username enumeration'},
        'ro': [
            'Actualizează OpenSSH la ≥ 7.7 (elimină diferența de timp care permite enumerarea).',
            'Impune autentificare pe cheie și dezactivează autentificarea pe parolă unde e posibil.',
            'Restricționează 22/tcp pe firewall și adaugă rate-limiting / fail2ban.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Upgrade OpenSSH to ≥ 7.7 (removes the timing difference enabling enumeration).',
            'Enforce key-based auth and disable password auth where possible.',
            'Restrict 22/tcp on the firewall and add rate-limiting / fail2ban.',
            'Rescan to confirm.',
        ],
    },
    'CVE-2019-10149': {
        'label': {'ro': 'Exim <4.92 — RCE (Return of the WIZard)',
                  'en': 'Exim <4.92 — RCE (Return of the WIZard)'},
        'ro': [
            'Actualizează Exim la ≥ 4.92 URGENT — vulnerabilitatea e exploatată de viermi/ransomware.',
            'Tratează gazda ca potențial compromisă dacă a fost expusă în internet: caută cron-uri/chei SSH adăugate.',
            'Restricționează 25/tcp la relee autorizate; nu accepta mail direct din internet decât unde e necesar.',
            'Rotește credențialele și cheile de pe gazdă dacă găsești indicii de compromitere.',
            'Rescanează după corecție.',
        ],
        'en': [
            'Upgrade Exim to ≥ 4.92 URGENTLY — actively exploited by worms/ransomware.',
            'Treat the host as potentially compromised if internet-facing: hunt for added cron jobs / SSH keys.',
            'Restrict 25/tcp to authorized relays; do not accept mail directly from the internet unless required.',
            'Rotate host credentials and keys if you find compromise indicators.',
            'Rescan after fixing.',
        ],
    },
}


# ---------------------------------------------------------------------------
# Pași per categorie. Fiecare intrare: {label{ro,en}, why{ro,en}, ro:[...], en:[...]}
# `why` = de ce contează (o frază). `ro`/`en` = pași NUMEROTAȚI (fără numere în text;
# renderer-ul le numerotează).
# ---------------------------------------------------------------------------
REMEDIATION = {
    'SMBv1': {
        'label': {'ro': 'SMBv1 activ (EternalBlue / WannaCry — CVE-2017-0144)',
                  'en': 'SMBv1 enabled (EternalBlue / WannaCry — CVE-2017-0144)'},
        'why': {'ro': 'Protocol vechi cu RCE remote fără autentificare; vector de ransomware și mișcare laterală.',
                'en': 'Legacy protocol with unauthenticated remote RCE; ransomware and lateral-movement vector.'},
        'refs': ['CVE-2017-0144', 'MS17-010'],
        'ro': [
            'Inventariază gazdele cu SMBv1 activ (lista din acest raport) și rolul fiecăreia (fișiere, imprimare, aplicație legacy).',
            'Dezactivează SMBv1 pe Windows: „Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol” (sau prin GPO pe tot domeniul); repornește.',
            'Aplică patch-ul MS17-010 pe toate gazdele Windows; pentru sisteme EOL (XP/2003/7) planifică migrarea — nu mai primesc corecții.',
            'Blochează 445/tcp și 139/tcp la perimetru și între VLAN-uri care nu au nevoie de partajare de fișiere.',
            'Izolează într-un VLAN dedicat gazdele legacy care nu pot renunța la SMBv1, cu acces strict controlat.',
            'Impune SMBv2/SMBv3 ca minim și activează SMB signing pe controlerele de domeniu și serverele de fișiere.',
            'Rescanează cu CYBER3 Scan și confirmă că nicio gazdă nu mai negociază dialectul SMBv1.',
        ],
        'en': [
            'Inventory hosts with SMBv1 enabled (list in this report) and each one’s role (file, print, legacy app).',
            'Disable SMBv1 on Windows: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" (or domain-wide via GPO); reboot.',
            'Apply MS17-010 on all Windows hosts; for EOL systems (XP/2003/7) plan migration — they no longer receive patches.',
            'Block 445/tcp and 139/tcp at the perimeter and between VLANs that do not need file sharing.',
            'Isolate legacy hosts that cannot drop SMBv1 into a dedicated VLAN with tightly controlled access.',
            'Enforce SMBv2/SMBv3 as minimum and enable SMB signing on domain controllers and file servers.',
            'Rescan with CYBER3 Scan and confirm no host still negotiates the SMBv1 dialect.',
        ],
    },
    'TELNET': {
        'label': {'ro': 'Telnet expus — autentificare în CLAR', 'en': 'Telnet exposed — cleartext authentication'},
        'why': {'ro': 'Parolele circulă necriptat; oricine pe cale poate captura credențialele.',
                'en': 'Passwords travel in cleartext; anyone on-path can capture credentials.'},
        'refs': [],
        'ro': [
            'Identifică serviciul care ascultă pe 23/tcp și de ce (echipament de rețea, cameră, gazdă legacy).',
            'Activează SSH (v2) pe echipament ca alternativă criptată; generează chei noi.',
            'Dezactivează complet serviciul Telnet în configurația echipamentului.',
            'Blochează 23/tcp la firewall/perimetru și între VLAN-uri.',
            'Rotește toate credențialele folosite anterior pe Telnet — au putut fi capturate în clar.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Identify what listens on 23/tcp and why (network gear, camera, legacy host).',
            'Enable SSH (v2) on the device as an encrypted alternative; generate fresh keys.',
            'Fully disable the Telnet service in the device configuration.',
            'Block 23/tcp at the firewall/perimeter and between VLANs.',
            'Rotate every credential previously used over Telnet — they may have been captured in cleartext.',
            'Rescan to confirm.',
        ],
    },
    'FTP': {
        'label': {'ro': 'FTP expus — posibil în clar', 'en': 'FTP exposed — possibly cleartext'},
        'why': {'ro': 'FTP clasic trimite date și parole necriptat; accesul anonim expune fișiere.',
                'en': 'Plain FTP sends data and passwords unencrypted; anonymous access exposes files.'},
        'refs': [],
        'ro': [
            'Determină dacă FTP este necesar; dacă nu, dezactivează serviciul.',
            'Pentru transfer de fișiere, migrează la SFTP (peste SSH) sau FTPS (peste TLS).',
            'Dezactivează accesul anonim („anonymous”).',
            'Restricționează 21/tcp (și intervalul de porturi pasive) pe firewall la sursele autorizate.',
            'Rotește credențialele expuse.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Determine whether FTP is needed; if not, disable the service.',
            'For file transfer, migrate to SFTP (over SSH) or FTPS (over TLS).',
            'Disable anonymous access.',
            'Restrict 21/tcp (and the passive port range) on the firewall to authorized sources.',
            'Rotate exposed credentials.',
            'Rescan to confirm.',
        ],
    },
    'VNC': {
        'label': {'ro': 'VNC expus', 'en': 'VNC exposed'},
        'why': {'ro': 'Acces grafic de la distanță, frecvent cu parole slabe; nu ar trebui expus direct.',
                'en': 'Remote graphical access, often weakly protected; should not be exposed directly.'},
        'refs': [],
        'ro': [
            'Identifică gazda și motivul pentru care rulează VNC.',
            'Impune parolă tare; unde VNC limitează lungimea parolei, adaugă un al doilea strat (VPN) la nivel de rețea.',
            'Nu expune VNC direct — tunelează prin VPN sau SSH.',
            'Restricționează 5900-5906/tcp pe firewall la stațiile administrative.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Identify the host and why VNC is running.',
            'Enforce a strong password; where VNC caps password length, add a network-level second layer (VPN).',
            'Do not expose VNC directly — tunnel it through VPN or SSH.',
            'Restrict 5900-5906/tcp on the firewall to administrative workstations.',
            'Rescan to confirm.',
        ],
    },
    'REDIS': {
        'label': {'ro': 'Redis expus (frecvent FĂRĂ autentificare)', 'en': 'Redis exposed (often with NO auth)'},
        'why': {'ro': 'Redis fără parolă permite citire/scriere totală și, adesea, RCE prin injecție de chei.',
                'en': 'Passwordless Redis allows full read/write and often RCE via key injection.'},
        'refs': [],
        'ro': [
            'Verifică dacă Redis are autentificare activă („requirepass”); frecvent e deschis fără parolă.',
            'Setează „requirepass” cu o parolă tare și, unde e posibil, folosește ACL (Redis 6+).',
            'Leagă Redis de loopback („bind 127.0.0.1”) sau de interfața internă strict necesară; „protected-mode yes”.',
            'Blochează 6379/tcp pe firewall; nu-l expune între segmente.',
            'Verifică dacă instanța a fost deja compromisă (chei „backup”/„crackit”, cron injectat, chei SSH adăugate).',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Check whether Redis has authentication ("requirepass"); it is often open with no password.',
            'Set "requirepass" with a strong password and, where possible, use ACLs (Redis 6+).',
            'Bind Redis to loopback ("bind 127.0.0.1") or the strictly-needed internal interface; "protected-mode yes".',
            'Block 6379/tcp on the firewall; do not expose it between segments.',
            'Check whether the instance is already compromised ("backup"/"crackit" keys, injected cron, added SSH keys).',
            'Rescan to confirm.',
        ],
    },
    'MSSQL': {
        'label': {'ro': 'MS SQL Server expus', 'en': 'MS SQL Server exposed'},
        'why': {'ro': 'Bază de date expusă în rețea largă = țintă de brute-force și exfiltrare.',
                'en': 'A database exposed on the broad network is a brute-force and exfiltration target.'},
        'refs': [],
        'ro': [
            'Nu expune baza de date în rețea largă; leag-o de interfața/segmentul serverelor de aplicație.',
            'Restricționează 1433/tcp (și 1434/udp browser) pe firewall la serverele de aplicație autorizate.',
            'Impune autentificare tare; dezactivează sau parolează complex contul „sa”.',
            'Activează criptarea conexiunii (TLS) și auditarea autentificărilor eșuate.',
            'Aplică ultimele patch-uri de securitate ale motorului SQL Server.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Do not expose the database on the broad network; bind it to the app-server segment/interface.',
            'Restrict 1433/tcp (and 1434/udp browser) on the firewall to authorized app servers.',
            'Enforce strong authentication; disable or set a complex password on the "sa" account.',
            'Enable connection encryption (TLS) and audit failed logins.',
            'Apply the latest SQL Server security patches.',
            'Rescan to confirm.',
        ],
    },
    'MYSQL': {
        'label': {'ro': 'MySQL expus', 'en': 'MySQL exposed'},
        'why': {'ro': 'Bază de date expusă = țintă de brute-force și exfiltrare de date.',
                'en': 'Exposed database = brute-force and data-exfiltration target.'},
        'refs': [],
        'ro': [
            'Nu expune baza de date în rețea largă; leag-o de segmentul serverelor de aplicație.',
            'Restricționează 3306/tcp pe firewall la serverele autorizate; „bind-address” pe interfața internă.',
            'Elimină conturile anonime și „root” accesibil de la distanță; impune parole tari.',
            'Activează TLS pentru conexiuni și logarea autentificărilor eșuate.',
            'Aplică ultimele patch-uri de securitate.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Do not expose the database broadly; bind it to the app-server segment.',
            'Restrict 3306/tcp on the firewall to authorized servers; set "bind-address" to the internal interface.',
            'Remove anonymous accounts and remotely-reachable "root"; enforce strong passwords.',
            'Enable TLS for connections and log failed logins.',
            'Apply the latest security patches.',
            'Rescan to confirm.',
        ],
    },
    'POSTGRES': {
        'label': {'ro': 'PostgreSQL expus', 'en': 'PostgreSQL exposed'},
        'why': {'ro': 'Bază de date expusă = țintă de brute-force și exfiltrare.',
                'en': 'Exposed database = brute-force and exfiltration target.'},
        'refs': [],
        'ro': [
            'Nu expune baza de date în rețea largă; „listen_addresses” pe interfața internă necesară.',
            'Restricționează 5432/tcp pe firewall la serverele autorizate.',
            'Configurează „pg_hba.conf” cu „scram-sha-256” și surse restrânse; elimină „trust”.',
            'Activează TLS pentru conexiuni și auditarea autentificărilor.',
            'Aplică ultimele patch-uri de securitate.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Do not expose the database broadly; set "listen_addresses" to the needed internal interface.',
            'Restrict 5432/tcp on the firewall to authorized servers.',
            'Configure "pg_hba.conf" with "scram-sha-256" and narrow sources; remove "trust".',
            'Enable TLS for connections and audit logins.',
            'Apply the latest security patches.',
            'Rescan to confirm.',
        ],
    },
    'MODBUS': {
        'label': {'ro': 'Modbus / OT expus', 'en': 'Modbus / OT exposed'},
        'why': {'ro': 'Protocol industrial fără autentificare nativă; comenzi de la orice sursă cu rută.',
                'en': 'Industrial protocol with no native auth; commands from any routable source.'},
        'refs': [],
        'ro': [
            'Tratează echipamentul ca activ OT critic — protocolul (502/tcp) nu are autentificare nativă.',
            'Plasează-l într-un VLAN OT segmentat, fără rută directă din rețeaua IT/office.',
            'Permite accesul doar de la stațiile SCADA/HMI autorizate, printr-un firewall industrial (conduit).',
            'Blochează 502/tcp dinspre IT și internet.',
            'Monitorizează traficul OT (senzorul CYBER3 inline îl observă deja) pentru comenzi neautorizate.',
            'Planifică mentenanță cu furnizorul pentru firmware la zi.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Treat the device as a critical OT asset — the protocol (502/tcp) has no native authentication.',
            'Place it in a segmented OT VLAN with no direct route from the IT/office network.',
            'Allow access only from authorized SCADA/HMI stations, through an industrial firewall (conduit).',
            'Block 502/tcp from IT and the internet.',
            'Monitor OT traffic (the inline CYBER3 sensor already sees it) for unauthorized commands.',
            'Schedule vendor maintenance for up-to-date firmware.',
            'Rescan to confirm.',
        ],
    },
    'S7': {
        'label': {'ro': 'Siemens S7 / OT expus', 'en': 'Siemens S7 / OT exposed'},
        'why': {'ro': 'PLC industrial expus; comenzi/oprire posibile fără autentificare puternică.',
                'en': 'Exposed industrial PLC; commands/stop possible without strong authentication.'},
        'refs': [],
        'ro': [
            'Tratează PLC-ul ca activ OT critic (102/tcp — S7comm).',
            'Segmentează-l într-un VLAN OT, fără rută directă din IT/office.',
            'Permite accesul doar de la stațiile de inginerie autorizate, prin firewall industrial.',
            'Activează protecția de acces / parola PLC din TIA Portal unde e suportată.',
            'Blochează 102/tcp dinspre IT și internet.',
            'Monitorizează traficul OT pentru comenzi neautorizate; planifică firmware la zi.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Treat the PLC as a critical OT asset (102/tcp — S7comm).',
            'Segment it into an OT VLAN with no direct route from IT/office.',
            'Allow access only from authorized engineering stations, through an industrial firewall.',
            'Enable PLC access protection / password in TIA Portal where supported.',
            'Block 102/tcp from IT and the internet.',
            'Monitor OT traffic for unauthorized commands; schedule up-to-date firmware.',
            'Rescan to confirm.',
        ],
    },
    'BACNET': {
        'label': {'ro': 'BACnet / OT expus', 'en': 'BACnet / OT exposed'},
        'why': {'ro': 'Protocol de automatizare a clădirii fără autentificare; expunere = control neautorizat.',
                'en': 'Building-automation protocol without auth; exposure = unauthorized control.'},
        'refs': [],
        'ro': [
            'Tratează echipamentul BMS/BACnet (47808/udp) ca activ OT.',
            'Segmentează-l într-un VLAN de automatizare a clădirii, fără rută din IT/office.',
            'Permite accesul doar de la stațiile de management BMS autorizate.',
            'Blochează 47808/udp dinspre IT și internet.',
            'Monitorizează traficul pentru comenzi neautorizate.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Treat the BMS/BACnet device (47808/udp) as an OT asset.',
            'Segment it into a building-automation VLAN with no route from IT/office.',
            'Allow access only from authorized BMS management stations.',
            'Block 47808/udp from IT and the internet.',
            'Monitor traffic for unauthorized commands.',
            'Rescan to confirm.',
        ],
    },
    'RDP': {
        'label': {'ro': 'RDP expus (brute-force / BlueKeep)', 'en': 'RDP exposed (brute-force / BlueKeep)'},
        'why': {'ro': 'RDP expus e țintă majoră de brute-force și ransomware; vulnerabil la BlueKeep pe sisteme vechi.',
                'en': 'Exposed RDP is a major brute-force/ransomware target; BlueKeep-vulnerable on old systems.'},
        'refs': ['CVE-2019-0708'],
        'ro': [
            'Nu expune RDP direct — acces doar prin VPN sau gateway RD cu MFA.',
            'Activează Network Level Authentication (NLA).',
            'Impune parole tari + MFA; limitează strict conturile cu drept de RDP.',
            'Restricționează 3389/tcp pe firewall; aplică lockout/rate-limiting la brute-force.',
            'Aplică patch-urile (ex. BlueKeep CVE-2019-0708 pe sisteme vechi).',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Do not expose RDP directly — access only via VPN or an RD gateway with MFA.',
            'Enable Network Level Authentication (NLA).',
            'Enforce strong passwords + MFA; strictly limit accounts with RDP rights.',
            'Restrict 3389/tcp on the firewall; apply lockout/rate-limiting against brute-force.',
            'Apply patches (e.g. BlueKeep CVE-2019-0708 on old systems).',
            'Rescan to confirm.',
        ],
    },
    'SNMP-PUBLIC': {
        'label': {'ro': 'SNMP community „public” activă (info-leak)', 'en': 'SNMP "public" community active (info-leak)'},
        'why': {'ro': 'Comunitatea implicită „public” expune configurația și topologia echipamentului.',
                'en': 'The default "public" community leaks device configuration and topology.'},
        'refs': [],
        'ro': [
            'Schimbă community-ul „public” cu unul greu de ghicit (și „private” dacă e setat pentru scriere).',
            'Migrează la SNMPv3 cu autentificare + criptare (authPriv).',
            'Restricționează 161/udp pe firewall la stațiile de management NMS autorizate.',
            'Dezactivează SNMP acolo unde nu e folosit.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Change the "public" community to a hard-to-guess value (and "private" if set for write).',
            'Migrate to SNMPv3 with authentication + encryption (authPriv).',
            'Restrict 161/udp on the firewall to authorized NMS management stations.',
            'Disable SNMP where it is not used.',
            'Rescan to confirm.',
        ],
    },
    'PANOU-WEB': {
        'label': {'ro': 'Panou de administrare/login web expus', 'en': 'Web admin/login panel exposed'},
        'why': {'ro': 'Interfețe de management (router/cameră/NAS) expuse invită brute-force și credențiale default.',
                'en': 'Exposed management UIs (router/camera/NAS) invite brute-force and default credentials.'},
        'refs': [],
        'ro': [
            'Restricționează accesul la panou (VPN/allowlist de IP); nu-l expune în rețea largă/internet.',
            'Schimbă orice credențial default; impune parolă tare + MFA unde e suportat.',
            'Actualizează firmware-ul/aplicația panoului la ultima versiune.',
            'Dezactivează conturile neutilizate și interfețele de management nefolosite (ex. WAN admin).',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Restrict access to the panel (VPN/IP allowlist); do not expose it broadly / on the internet.',
            'Change any default credential; enforce strong password + MFA where supported.',
            'Update the panel firmware/application to the latest version.',
            'Disable unused accounts and unused management interfaces (e.g. WAN admin).',
            'Rescan to confirm.',
        ],
    },
    'DEFAULT-CRED': {
        'label': {'ro': 'Credențiale DEFAULT acceptate', 'en': 'DEFAULT credentials accepted'},
        'why': {'ro': 'Un cont default valid = acces complet imediat pentru orice atacator.',
                'en': 'A valid default account = immediate full access for any attacker.'},
        'refs': [],
        'ro': [
            'Schimbă IMEDIAT parola contului cu credențiale default acceptate (contul e indicat în constatare).',
            'Verifică în loguri dacă acest cont a fost deja folosit neautorizat.',
            'Dezactivează sau redenumește conturile default acolo unde e posibil.',
            'Impune o politică de parole tari + MFA; interzice reutilizarea parolelor.',
            'Restricționează accesul la interfață (VPN/allowlist).',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'IMMEDIATELY change the password of the account with accepted default credentials (named in the finding).',
            'Check logs whether this account was already used without authorization.',
            'Disable or rename default accounts where possible.',
            'Enforce a strong-password + MFA policy; forbid password reuse.',
            'Restrict access to the interface (VPN/allowlist).',
            'Rescan to confirm.',
        ],
    },
    'TLS-EXPIRAT': {
        'label': {'ro': 'Certificat TLS EXPIRAT', 'en': 'TLS certificate EXPIRED'},
        'why': {'ro': 'Certificatul expirat rupe încrederea și antrenează utilizatorii să ignore avertismentele.',
                'en': 'An expired certificate breaks trust and trains users to ignore warnings.'},
        'refs': [],
        'ro': [
            'Reînnoiește certificatul de la o CA (sau CA internă pentru servicii interne).',
            'Automatizează reînnoirea (ex. ACME/Let’s Encrypt intern) ca să nu reexpire.',
            'Verifică lanțul complet și data de expirare pe toate serviciile care folosesc același certificat.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Renew the certificate from a CA (or an internal CA for internal services).',
            'Automate renewal (e.g. internal ACME/Let’s Encrypt) so it does not expire again.',
            'Verify the full chain and expiry on every service using the same certificate.',
            'Rescan to confirm.',
        ],
    },
    'TLS-SELF': {
        'label': {'ro': 'Certificat TLS self-signed', 'en': 'Self-signed TLS certificate'},
        'why': {'ro': 'Certificatul self-signed nu poate fi verificat; deschide calea atacurilor man-in-the-middle.',
                'en': 'A self-signed certificate cannot be validated; it opens the door to man-in-the-middle.'},
        'refs': [],
        'ro': [
            'Înlocuiește certificatul self-signed cu unul emis de o CA recunoscută (sau CA internă distribuită gazdelor).',
            'Distribuie certificatul rădăcină al CA interne pe stații dacă serviciul e intern.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Replace the self-signed certificate with one issued by a recognized CA (or an internal CA distributed to hosts).',
            'Distribute the internal CA root certificate to workstations if the service is internal.',
            'Rescan to confirm.',
        ],
    },
    'TLS-NEÎNCREZUT': {
        'label': {'ro': 'Certificat TLS neîncrezut', 'en': 'Untrusted TLS certificate'},
        'why': {'ro': 'Lanț de certificate incomplet sau nume nepotrivit; clienții nu pot valida serverul.',
                'en': 'Incomplete chain or name mismatch; clients cannot validate the server.'},
        'refs': [],
        'ro': [
            'Verifică lanțul de certificate (intermediari lipsă) și corectează-l pe server.',
            'Asigură-te că numele din certificat (CN/SAN) corespunde gazdei folosite.',
            'Rescanează pentru confirmare.',
        ],
        'en': [
            'Verify the certificate chain (missing intermediates) and fix it on the server.',
            'Ensure the certificate name (CN/SAN) matches the host in use.',
            'Rescan to confirm.',
        ],
    },
    'CVE': {
        'label': {'ro': 'Versiune software vulnerabilă (CVE)', 'en': 'Vulnerable software version (CVE)'},
        'why': {'ro': 'Versiunea din banner corespunde unei vulnerabilități publice cunoscute.',
                'en': 'The banner version matches a known public vulnerability.'},
        'refs': [],
        'ro': [
            'Identifică versiunea exactă a componentei vulnerabile (indicată în constatare, din banner).',
            'Aplică patch-ul/upgrade-ul recomandat de furnizor la o versiune neafectată.',
            'Dacă patch-ul nu e imediat posibil, aplică mitigarea temporară (dezactivare modul/funcție, WAF, restricționare acces).',
            'Verifică gazda pentru semne de exploatare a acestei vulnerabilități.',
            'Rescanează cu CYBER3 Scan pentru confirmare.',
        ],
        'en': [
            'Identify the exact version of the vulnerable component (named in the finding, from the banner).',
            'Apply the vendor-recommended patch/upgrade to an unaffected version.',
            'If patching is not immediately possible, apply a temporary mitigation (disable module/feature, WAF, restrict access).',
            'Check the host for signs of exploitation of this vulnerability.',
            'Rescan with CYBER3 Scan to confirm.',
        ],
    },
    'CVE-KEV': {
        'label': {'ro': 'Vulnerabilitate EXPLOATATĂ-ÎN-LUME (CISA KEV)', 'en': 'Actively EXPLOITED vulnerability (CISA KEV)'},
        'why': {'ro': 'Vulnerabilitate din catalogul CISA KEV — exploatată activ în atacuri reale; prioritate maximă.',
                'en': 'In the CISA KEV catalog — actively exploited in real attacks; top priority.'},
        'refs': [],
        'ro': [
            'Prioritizează această gazdă ÎNAINTEA celorlalte — vulnerabilitatea e exploatată activ în lume.',
            'Aplică URGENT patch-ul/upgrade-ul furnizorului la o versiune neafectată.',
            'Dacă patch-ul întârzie, izolează gazda (segmentare/firewall) până la corecție.',
            'Vânează indicii de compromitere pe gazdă (procese, cron, conturi, chei adăugate).',
            'Corelează cu alertele SOC pe același IP (vezi capitolul MATCH) — dacă apare, tratează ca incident.',
            'Rescanează după corecție pentru confirmare.',
        ],
        'en': [
            'Prioritize this host ABOVE the others — the vulnerability is actively exploited in the wild.',
            'URGENTLY apply the vendor patch/upgrade to an unaffected version.',
            'If the patch is delayed, isolate the host (segmentation/firewall) until fixed.',
            'Hunt for compromise indicators on the host (processes, cron, accounts, added keys).',
            'Correlate with SOC alerts on the same IP (see the MATCH chapter) — if present, treat as an incident.',
            'Rescan after fixing to confirm.',
        ],
    },
    # future-proofing: servicii/soft la EOL (nedetectate încă drept categorie separată,
    # dar prinse via CVE/bannere vechi). Mapare manuală dacă apare.
    'EOL': {
        'label': {'ro': 'Software / sistem la EOL (fără suport)', 'en': 'End-of-life software / system (unsupported)'},
        'why': {'ro': 'Nu mai primește patch-uri de securitate; orice vulnerabilitate nouă rămâne permanent deschisă.',
                'en': 'No longer receives security patches; any new vulnerability stays permanently open.'},
        'refs': [],
        'ro': [
            'Inventariază componentele/sistemele ajunse la EOL (versiunea din banner).',
            'Planifică migrarea/upgrade-ul la o versiune suportată — este singura corecție reală.',
            'Până la migrare, izolează gazda într-un segment restrâns și limitează-i accesul la strictul necesar.',
            'Monitorizează intens gazda (senzorul CYBER3 inline) și blochează accesul din/spre exterior.',
            'Rescanează după migrare.',
        ],
        'en': [
            'Inventory the EOL components/systems (banner version).',
            'Plan migration/upgrade to a supported version — that is the only real fix.',
            'Until migration, isolate the host in a tight segment and limit its access to the strict minimum.',
            'Monitor the host intensively (inline CYBER3 sensor) and block external in/out access.',
            'Rescan after migration.',
        ],
    },
}


def remediation_key(finding):
    """Cheia canonică de grupare pentru un finding.

    Pentru CVE/CVE-KEV cu CVE cunoscut întoarce id-ul CVE (pași dedicați); altfel
    întoarce categoria normalizată (fără sufix -EXPUS). Necunoscut → categoria brută.
    """
    cat = _canon_category(finding.get('category'))
    if cat in ('CVE', 'CVE-KEV'):
        m = _CVE_RE.search(str(finding.get('title', '')))
        if m and m.group(0).upper() in CVE_STEPS:
            return m.group(0).upper()
        return cat  # CVE generic sau CVE-KEV generic
    return cat


def get_remediation(finding, lang='ro'):
    """Întoarce blocul de remediere afișabil pentru un finding.

    Rezultat: {key, label, why, steps(list[str]), refs(list[str]), is_kev(bool)}.
    Fallback onest: dacă nu există intrare în bibliotecă, folosește remedierea inline
    a scannerului (`finding['remediation']`) ca pas unic, ca să nu pierdem informația.
    """
    l = 'en' if str(lang).lower().startswith('en') else 'ro'
    key = remediation_key(finding)
    cat = _canon_category(finding.get('category'))
    is_kev = (cat == 'CVE-KEV')

    if key in CVE_STEPS:
        entry = CVE_STEPS[key]
        base = REMEDIATION['CVE-KEV'] if is_kev else REMEDIATION['CVE']
        return {
            'key': key,
            'label': entry['label'][l],
            'why': base['why'][l],
            'steps': list(entry[l]),
            'refs': [key],
            'is_kev': is_kev,
        }

    if key in REMEDIATION:
        e = REMEDIATION[key]
        return {
            'key': key,
            'label': e['label'][l],
            'why': e['why'][l],
            'steps': list(e[l]),
            'refs': list(e.get('refs', [])),
            'is_kev': is_kev,
        }

    # necunoscut: fallback pe remedierea inline din scanner (onest, nu inventăm)
    inline = str(finding.get('remediation', '') or '').strip()
    label = str(finding.get('category', '-'))
    steps = [inline] if inline else (
        ['Consultați analistul SOC pentru pași de remediere.'] if l == 'ro'
        else ['Consult your SOC analyst for remediation steps.'])
    return {'key': key or label, 'label': label, 'why': '', 'steps': steps, 'refs': [], 'is_kev': is_kev}
