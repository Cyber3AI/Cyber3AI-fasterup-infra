#!/usr/bin/env python3
"""fasterup.ai — concept NOU (oct 2026): FasterUp NEXTGEN SOC, pachetul END-TO-END: o tehnologie, un furnizor.

Pagina principală pentru 8 limbi: EN = website/index.html, restul website/<cod>/index.html.
EN + RO = dicționarele de mai jos; celelalte limbi = i18n-nextgen/<cod>.json (aceleași chei ca EN).
Rulare (din FasterUp.AI/):  python3 build_nextgen.py
ÎNLOCUIEȘTE paginile principale generate de build_site.py (vechiul generator rămâne pentru istoric).
Paginile secundare (contact, privacy, terms, alerta-ransomware) NU sunt atinse.

Reguli de conținut (MANIFEST_FasterUp_NEXTGEN_SOC.md):
 - pe public NU apar numele motoarelor terțe (Suricata/Wazuh) — „Inline IPS", „SIEM";
 - FĂRĂ contoare de blocări pe public (doar Capabilities Status: Active + beculeț + timp de răspuns);
 - FĂRĂ patent/brevet; „tehnologie proprietară, deținută integral end-to-end";
 - FĂRĂ superlative absolute („unbreakable" ca garanție) — adevăr + dovadă.
Imagini: assets/phones/*.webp (capturile fișei Google Play CYBER3), assets/desk/desktop-*-{en,ro}.webp (aplicația desktop reală).
"""
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "website")
LANGS = [("en", "EN"), ("ro", "RO"), ("es", "ES"), ("it", "IT"), ("de", "DE"), ("fr", "FR"), ("ru", "RU"), ("zh", "中文")]
SHOT_LANGS = {"en", "ro"}
STATUS_LANGS = {"en", "ro", "es", "it", "de", "fr", "ru", "zh"}
MAIL = "mailto:contact@rol.ro?subject=FasterUp%20-%20Assessment"
PLAY = "https://play.google.com/store/apps/details?id=ai.cyber3.app"
APPSTORE = "https://apps.apple.com/app/id6814547519"
WINDOWS = "https://cyber3-edge.cyber3.workers.dev/desktop"


def lpath(c): return "/" if c == "en" else f"/{c}/"


# ───────────────────────────── TEXTE EN ─────────────────────────────
EN = dict(
    title="FasterUp.AI — One technology. One vendor. Autonomous cyber defense, end to end.",
    desc="FasterUp NEXTGEN SOC: seven complementary defense layers from the Ethernet wire to the workstation and the phone, orchestrated by MLEO, decided by CyberBot Fusion and explained by CYBER3.AI, our sovereign security LLM. Managed SOC, Vulnerability Assessment and endpoint protection from a single vendor.",
    nav=["Platform", "7 Layers", "MLEO", "CYBER3.AI", "VAS", "Agentic Ops", "Endpoint", "Packages"],
    nav_cta="Request assessment", lang_label="Language",
    hero_k="FASTERUP NEXTGEN SOC · AUTONOMOUS · END TO END",
    hero_h1='One technology. One vendor. <span class="grad">Every layer.</span>',
    hero_p="FasterUp detects, decides and blocks cyber threats across seven complementary layers — from the Ethernet wire to the workstation and the phone. MLEO orchestrates every layer, CyberBot Fusion decides in seconds, and CYBER3.AI, our sovereign security LLM, explains, investigates and reports. Managed SOC, Vulnerability Assessment and endpoint protection — engineered, owned and operated by one team.",
    hero_cta2="Explore the platform",
    st1="threat to autonomous decision", st2="complementary defense layers", st3="monitoring & autonomous response", st4="live threat indicators",
    ring_center="Your organization",
    rings=["Inline IPS", "Active Response", "L2 Shield", "CyberBot Fusion", "CYBER3 Edge", "Desktop XDR", "Mobile"],
    tr=["ISO/IEC 27001:2022 certified company", "NIS2 Art. 21/23 reporting", "GDPR — your data stays on your premises", "Proprietary technology, owned end to end"],
    pf_k="THE PLATFORM", pf_h="The whole defense chain. One owner.",
    pf_p="Most organizations stitch together a firewall vendor, a SIEM vendor, an MSSP, an antivirus and a scanner — and the attacker lives in the gaps between them. FasterUp is one chain, engineered as one organism: no integration seams, no tickets bouncing between providers, one report.",
    chain=[("Sensors", "Inline at every site — IPS at the wire, firewall response and L2 Shield at Ethernet level."),
           ("CyberBot Fusion", "Four sources fused on every alert — an autonomous decision in 2–11 seconds."),
           ("MLEO", "Chooses the layer that enforces — and isolates the attacker, not the victim."),
           ("CYBER3.AI", "Our sovereign security LLM explains, investigates, prioritizes and reports."),
           ("CYBER3 apps", "Windows, Android and iPhone — the SOC on every workstation and phone."),
           ("Agentic Ops", "NOC, Health Check, CCC and Ops Agents keep everything running, 24/7.")],
    pf_note="One contract. One accountable team. From the cable to the phone in your pocket.",
    ly_k="CASCADE DEFENSE", ly_h="Seven complementary layers. Every threat stopped — even if one layer is bypassed.",
    ly_p="The layers are not copies of each other. Each one sees what the others cannot: three work on IP, domains and hashes, one is the only defense at Ethernet level, one stops threats in the cloud before they reach your network, and two live on your devices.",
    ly_cols=["Layer", "Level", "How it stops the threat", "Response", "Status"],
    layers=[("Network — Inline IPS", "L3/L4 + app", "Drops hostile packets at the wire: signatures, anomalies, deep packet inspection.", "~ms"),
            ("Host — Active Response", "L3", "Native drop in the firewall of the protected host.", "seconds"),
            ("Ethernet — L2 Shield", "L2", "The only layer at Ethernet level: stops ARP spoofing, man-in-the-middle and rogue DHCP — the blind spot of IP defenses.", "~ms"),
            ("Decision — CyberBot Fusion", "L3 · IP / domain / hash", "Fuses four sources into one autonomous decision — including command-and-control traffic.", "2–11 s"),
            ("Cloud — CYBER3 Edge", "cloud", "DNS shield, cloud threat indicators and a browser extension stop threats before they reach the network.", "edge"),
            ("Device — CYBER3 Desktop XDR", "endpoint", "On-access scanning, quarantine, DNS shield and automatic isolation of an infected workstation.", "on device"),
            ("Mobile — CYBER3 Mobile", "endpoint", "Real-time anti-scam, DNS filtering, link and SMS analysis on every staff phone.", "on device")],
    active="Active",
    ly_note="Capabilities Status — no attack counters are published: what we stop for you stays between us.",
    fl_k="SENSOR FLEET", fl_h="Sensors that live inside your network — and never stand in its way.",
    fl_p="Dedicated FasterUp sensors run the first defense layers on the spot, at every site. They are built to protect without ever becoming the reason your network stops.",
    fl_cards=[("Inline or passive", "Installed in about 15 minutes per site, with no agents on your endpoints — VLAN-aware, up to 10 Gbps links."),
              ("Fail-open by design", "Multi-queue packet inspection that steps aside if it ever stalls: traffic keeps flowing, protection resumes automatically."),
              ("Self-updating", "Detection rules refreshed autonomously, with self-guard and automatic rollback if anything looks wrong."),
              ("Private by default", "Your data stays on your premises; only security metadata travels to the SOC, over an encrypted private VPN.")],
    fb_k="FALLBACK EVERYWHERE", fb_h="No single point of failure. Anywhere.",
    fb_p="Every critical part of the platform has a second path that takes over on its own. If one component fails, the defense doesn't.",
    fb_items=[("Sensors", "Fail-open inspection — your traffic never stops because of us."),
              ("SOC core", "Clustered event platform plus a disaster-recovery site in the cloud."),
              ("Monitoring", "The agentic NOC runs on independent cloud infrastructure — visible even if a site goes dark."),
              ("AI", "Multi-engine CYBER3.AI with automatic failover — no single AI vendor can switch it off."),
              ("Threat database", "Served from 300+ edge locations; the apps keep protecting on-device, even offline."),
              ("Data", "Encrypted off-site backups with tested restore procedures.")],
    fu_k="LAYER 4 · CYBERBOT FUSION", fu_h="Four sources. One autonomous decision. In seconds.",
    fu_p="Every alert is checked against four independent sources at once. CyberBot fuses them into a single verdict and acts — without waiting for a human at 3 a.m.",
    fu_src=[("Network telemetry", "inline IDS/IPS at every site"), ("SIEM correlation", "events correlated across the whole estate"),
            ("Threat intelligence", "live global feeds"), ("CYBER3 Database", "our own indicators, growing every day")],
    fu_ladder_h="Severity-driven action",
    fu_ladder=["Silent log", "Automatic IP block", "Urgent alert", "Human escalation"],
    fu_b=["Blocks outbound command-and-control, not just inbound attacks", "Anti-false-positive guard: your own infrastructure is never blocked", "Plain-language alert to your team by Telegram and email"],
    ml_k="MLEO · MULTI LAYER ENFORCEMENT ORCHESTRATOR", ml_h="It doesn't just detect on seven layers. It decides which layer strikes.",
    ml_p="MLEO is the core that links the seven layers into one organism. It correlates what each layer sees, gives every device a single identity across layers, and enforces on the layer that stops the threat best — with no redundant blocks and no conflicts.",
    ml_cards=[("Unified identity", "The same device seen as an IP at Layer 3 and as a MAC, VLAN and switch port at Layer 2."),
              ("Evasion-proof", "Changing IP address no longer helps the attacker — the block follows the device."),
              ("Isolate the attacker, not the victim", "During ARP spoofing, traffic looks like it comes from the victim. Directional correlation isolates the real source."),
              ("Safe by construction", "Quarantine VLAN instead of port shutdown, allowlist and transaction-ID rollback as preconditions, fail-safe on every layer.")],
    ml_note="Deployed in stages: the first stages give full visibility without touching the client network.",
    ai_k="CYBER3.AI · SOVEREIGN SECURITY LLM", ai_h="An AI analyst built into the SOC and VAS — not bolted on.",
    ai_p="CYBER3.AI is our security language model, built for one job: defense. It sits across the whole chain — reading the same CYBER3 Database as the sensors, the apps and the scanner.",
    ai_roles=[("Explains", "Alerts and findings in plain language, in your team's language: what happened, why it matters, what was already done."),
              ("Investigates", "A security copilot that correlates indicators across the CYBER3 Database and live threat intelligence."),
              ("Prioritizes", "Turns vulnerability findings into a remediation order: what to fix first, and how."),
              ("Reports", "Drafts incident and NIS2 Art. 21/23 reporting from real SOC data.")],
    ai_sov_h="Sovereign by design",
    ai_sov=["A self-hosted security model in the EU", "Multi-engine architecture with automatic failover — no single AI vendor can switch your SOC off", "Grounded on our own threat database, not on the open internet"],
    db_k="CYBER3 DATABASE", db_h="Our own threat intelligence. Growing every day.",
    db_p="The CYBER3 Database fuses global threat feeds with indicators our own sensors observe in real networks. It is published daily to a global edge network and powers every layer: the sensors, the AI, the desktop and the mobile apps — one live truth everywhere.",
    db_l1="threat indicators — live", db_l2="first-party indicators from our sensors", db_l3="edge locations serving lookups",
    db_vec_h="Proprietary vector database", db_vec_t="Operational, for embedding-based pattern matching.",
    db_vec_p="It stores semantic vectors of historical attacks and recognizes new variants of known campaigns — even when explicit IOCs are missing.",
    db_b=["Daily publication pipeline, verified end to end", "Privacy-preserving lookups: only a hashed prefix leaves a device", "The same database protects networks, workstations and phones"],
    vas_k="VAS · CYBER3 SCAN & GLOBAL SCAN", vas_h="Agile scanning that finds the whole network — and never trips the alarm.",
    vas_p="Vulnerability Assessment built by the team that defends the networks. Our scanner runs from the sensor already inside your network, so it discovers everything — even what nobody remembered to give it.",
    vas_cards=[("Discovers without being told", "Passive listening plus tagged probes on every VLAN map hosts, MAC addresses, vendors and roles — including silent devices."),
               ("Unstoppable Adaptive Scan", "Studies the target and moves in measured steps; it backs off at the first sign of a firewall and doesn't set off alarms."),
               ("Agile Global Scan", "On-demand external exposure scan from the cloud — no installation, results in minutes. Whole-network scan built into the Windows app."),
               ("Prioritized, actionable", "Known vulnerabilities (CVE), insecure configurations and exposed services — ranked so you fix what matters first.")],
    ag_k="AGENTIC OPERATIONS", ag_h="An army of agents that runs the platform — around the clock.",
    ag_p="Our people handle the exceptions. Agents handle everything else: they watch, repair, command and respond, and they prove every day that the chain still works.",
    agents=[("NOC Agentic", "Watches the entire infrastructure from an independent cloud vantage point — every sensor, service and tunnel — with live diagrams, AI summaries and alerts."),
            ("Health Check Agentic", "Administers and self-repairs the sensor fleet 24/7: stalled capture, stuck services, dropped tunnels — fixed before anyone notices. Synthetic tests validate the pipeline end to end."),
            ("CCC Agentic", "The Command & Control Centre: one cockpit over the whole ecosystem, where operators command the agents and see threat intelligence flow into autonomous response."),
            ("Ops Agents", "CYBER3.AI agents that triage alerts, correlate indicators, investigate and respond — with autonomy levels from human-approved actions to pre-approved playbooks with a circuit breaker.")],
    ag_note="Autonomous rule updates with self-guard and automatic rollback. Fail-open by design: your traffic never stops because of us.",
    ep_k="ENDPOINT · CYBER3", ep_h="The SOC, extended to every workstation — and every phone.",
    ep_p="The same platform, native on Windows, Android and iPhone. Organizations enroll devices with an activation code or silently at deployment; only security metadata ever leaves a device.",
    ep_desk_h="CYBER3 for Windows — EDR/XDR",
    ep_desk_b=["Automatic isolation of a workstation on confirmed malware — reversible, supervised by the SOC", "Client console: inventory, remote scan, isolation and reconnection in under 30 seconds", "Global Scan of the whole internal network, browser protection, encrypted VPN", "Digitally signed with Microsoft Trusted Signing, updated automatically"],
    ep_desk_tabs=[("home", "Dashboard"), ("globalscan", "Global Scan"), ("isolation", "Threat isolation"), ("vpn", "VPN")],
    ep_mob_h="CYBER3 for Android & iPhone",
    ep_mob_b=["Scam call and message protection, message check with AI explanation", "Web protection: ads, trackers and phishing blocked in every app", "Phone security score, identity and breach monitoring, encrypted VPN", "The same threat database as the sensors and workstations"],
    wy_k="WHY ONE VENDOR", wy_h="FasterUp vs. the usual multi-vendor setup",
    wy_c=["", "FasterUp", "Typical multi-vendor setup"],
    wy_rows=[("From detection to block", "Seconds, autonomous", "Hours — tickets between providers"),
             ("Protection at Ethernet level (L2)", "y", "n"),
             ("Network + workstation + phone in one chain", "y", "p"),
             ("AI analyst explaining every finding", "y", "p"),
             ("Own threat database, fed by own sensors", "y", "n"),
             ("Self-repairing sensor fleet", "y", "n"),
             ("One unified NIS2 report", "y", "n"),
             ("Data stays on your premises (metadata only)", "y", "p"),
             ("One contract, one accountable team", "y", "n")],
    wy_y="Included", wy_n="Not included", wy_p="Partial",
    pk_k="PACKAGES", pk_h="Sized to your institution",
    pk_p="Each package includes everything in the previous one and adds layers and capabilities. The exact configuration — sites, sensors, workstations, phones — is set after an initial assessment.",
    pk_best="Best for", pk_rec="RECOMMENDED",
    packages=[("Standard", "Includes", ["Managed 24/7 SOC · autonomous response in 2–11 s", "Inline sensor at the main site", "Layers 1–4: Inline IPS · Active Response · L2 Shield · CyberBot Fusion", "MLEO: L3 ↔ L2 correlation and enforcement on the right layer", "Monthly scheduled VAS", "Plain-language alerts + client portal with NIS2 reports", "Health Check Agentic 24/7"], "A central office with concentrated IT — autonomous 24/7 monitoring and a regular vulnerability picture, without building a SOC of your own."),
              ("Extended", "Everything in Standard, plus", ["Inline sensors at every site", "Layer 5 · CYBER3 Edge for the whole organization", "Layer 6 · CYBER3 Desktop XDR on critical workstations", "Client console: isolation, remote scans, fleet status", "Global Scan of the internal network", "MLEO across all sites", "Bi-weekly VAS"], "Multi-site institutions with elevated exposure — network coverage everywhere plus XDR where it matters most."),
              ("Complete", "Everything in Extended, plus", ["CYBER3 Desktop XDR on every workstation", "Layer 7 · CYBER3 Mobile on staff phones", "MLEO across all 7 layers", "Continuous VAS", "Breach and identity monitoring for the organization", "Unified network + endpoint + mobile reporting (NIS2 Art. 21/23)"], "Sensitive citizen data and strict compliance — full multi-layer defense under one vendor and one report.")],
    pk_note="A detailed financial offer is prepared on request, based on the initial assessment and the procurement method applicable to your institution.",
    sp_k="GET STARTED", sp_h="From assessment to autonomous defense",
    steps=[("Assessment", "We map your assets and exposure with a vulnerability assessment — a clear picture of where you stand."),
           ("Sensor deployment", "Inline or passive, about 15 minutes per site, no agents on your endpoints."),
           ("Autonomous SOC", "24/7 detection and response, plain-language alerts, client portal and NIS2 reports from day one.")],
    end_h="See your network the way an attacker does — before they do.", end_p="Start with an assessment. No commitment, scoped to your environment.",
    ft_tag="Autonomous cybersecurity for business and public administration — one technology, one vendor, end to end.",
    ft_h=["Platform", "Ecosystem", "Company"],
    ft_status="Service status", ft_contact="Contact", ft_privacy="Privacy", ft_terms="Terms",
    ft_copy="FasterUp.AI is a brand of ROL PORTAL SERVICES SRL · © 2026",
)

# ───────────────────────────── TEXTE RO ─────────────────────────────
RO = dict(
    title="FasterUp.AI — O tehnologie. Un furnizor. Apărare cibernetică autonomă, cap-coadă.",
    desc="FasterUp NEXTGEN SOC: șapte straturi complementare de apărare, de la cablul Ethernet la stația de lucru și telefon, orchestrate de MLEO, decise de CyberBot Fusion și explicate de CYBER3.AI, LLM-ul nostru suveran de securitate. SOC gestionat, Evaluarea Vulnerabilităților și protecția endpoint — de la un singur furnizor.",
    nav=["Platformă", "7 straturi", "MLEO", "CYBER3.AI", "VAS", "Agenți", "Endpoint", "Pachete"],
    nav_cta="Solicită evaluare", lang_label="Limba",
    hero_k="FASTERUP NEXTGEN SOC · AUTONOM · CAP-COADĂ",
    hero_h1='O tehnologie. Un furnizor. <span class="grad">Toate straturile.</span>',
    hero_p="FasterUp detectează, decide și blochează amenințările cibernetice pe șapte straturi complementare — de la cablul Ethernet la stația de lucru și telefon. MLEO orchestrează fiecare strat, CyberBot Fusion decide în câteva secunde, iar CYBER3.AI, LLM-ul nostru suveran de securitate, explică, investighează și raportează. SOC gestionat, Evaluarea Vulnerabilităților și protecția endpoint — proiectate, deținute și operate de o singură echipă.",
    hero_cta2="Descoperă platforma",
    st1="de la amenințare la decizia autonomă", st2="straturi complementare de apărare", st3="monitorizare și răspuns autonom", st4="indicatori de amenințare live",
    ring_center="Organizația ta",
    rings=["IPS inline", "Active Response", "L2 Shield", "CyberBot Fusion", "CYBER3 Edge", "Desktop XDR", "Mobil"],
    tr=["Companie certificată ISO/IEC 27001:2022", "Raportare NIS2 art. 21/23", "GDPR — datele rămân la tine", "Tehnologie proprietară, deținută integral"],
    pf_k="PLATFORMA", pf_h="Tot lanțul de apărare. Un singur proprietar.",
    pf_p="Majoritatea organizațiilor lipesc între ele un furnizor de firewall, unul de SIEM, un MSSP, un antivirus și un scaner — iar atacatorul trăiește în golurile dintre ele. FasterUp e un singur lanț, gândit ca un singur organism: fără cusături de integrare, fără tichete plimbate între furnizori, un singur raport.",
    chain=[("Senzori", "Inline în fiecare locație — IPS la fir, răspuns în firewall și L2 Shield la nivel Ethernet."),
           ("CyberBot Fusion", "Patru surse fuzionate la fiecare alertă — decizie autonomă în 2–11 secunde."),
           ("MLEO", "Alege stratul care execută — și izolează atacatorul, nu victima."),
           ("CYBER3.AI", "LLM-ul nostru suveran de securitate explică, investighează, prioritizează și raportează."),
           ("Aplicațiile CYBER3", "Windows, Android și iPhone — SOC-ul pe fiecare stație și telefon."),
           ("Operațiuni agentice", "NOC, Health Check, CCC și Ops Agents țin totul în funcțiune, 24/7.")],
    pf_note="Un contract. O echipă responsabilă. De la cablu la telefonul din buzunar.",
    ly_k="APĂRARE ÎN CASCADĂ", ly_h="Șapte straturi complementare. Orice amenințare oprită — chiar dacă un strat e ocolit.",
    ly_p="Straturile nu sunt copii unul al altuia. Fiecare vede ce celelalte nu văd: trei lucrează pe IP, domenii și hash-uri, unul e singura apărare la nivel Ethernet, unul oprește amenințările în cloud înainte să ajungă în rețea, iar două trăiesc pe dispozitivele tale.",
    ly_cols=["Strat", "Nivel", "Cum oprește amenințarea", "Răspuns", "Stare"],
    layers=[("Rețea — IPS inline", "L3/L4 + aplicație", "Pică pachetele ostile la fir: semnături, anomalii, inspecție profundă a pachetelor.", "~ms"),
            ("Gazdă — Active Response", "L3", "Blocare nativă în firewall-ul gazdei protejate.", "secunde"),
            ("Ethernet — L2 Shield", "L2", "Singurul strat la nivel Ethernet: oprește ARP spoofing, man-in-the-middle și DHCP fals — unghiul mort al apărărilor IP.", "~ms"),
            ("Decizie — CyberBot Fusion", "L3 · IP / domeniu / hash", "Fuzionează patru surse într-o decizie autonomă — inclusiv traficul de comandă-și-control.", "2–11 s"),
            ("Cloud — CYBER3 Edge", "cloud", "DNS shield, indicatori de amenințare în cloud și o extensie de browser opresc amenințările înainte să ajungă în rețea.", "edge"),
            ("Dispozitiv — CYBER3 Desktop XDR", "endpoint", "Scanare la acces, carantină, DNS shield și izolarea automată a unei stații infectate.", "pe stație"),
            ("Mobil — CYBER3 Mobile", "endpoint", "Anti-scam în timp real, filtrare DNS, analiză de linkuri și SMS pe fiecare telefon al angajaților.", "pe telefon")],
    active="Activ",
    ly_note="Capabilities Status — nu publicăm contoare de atacuri: ce oprim pentru tine rămâne între noi.",
    fl_k="FLOTA DE SENZORI", fl_h="Senzori care trăiesc în rețeaua ta — și nu-i stau niciodată în cale.",
    fl_p="Senzorii dedicați FasterUp rulează primele straturi de apărare chiar la fața locului, în fiecare locație. Sunt construiți să protejeze fără să devină vreodată motivul pentru care rețeaua se oprește.",
    fl_cards=[("Inline sau pasiv", "Instalați în circa 15 minute pe locație, fără agenți pe stațiile tale — compatibili VLAN, legături de până la 10 Gbps."),
              ("Fail-open prin design", "Inspecție pe mai multe cozi care se dă la o parte dacă se blochează: traficul curge în continuare, protecția revine automat."),
              ("Se actualizează singuri", "Regulile de detecție se reîmprospătează autonom, cu auto-protecție și revenire automată dacă ceva nu e în regulă."),
              ("Privat implicit", "Datele rămân la tine; spre SOC pleacă doar metadate de securitate, printr-un VPN privat criptat.")],
    fb_k="REZERVĂ PESTE TOT", fb_h="Niciun punct unic de cădere. Nicăieri.",
    fb_p="Fiecare componentă critică a platformei are o a doua cale care preia singură controlul. Dacă o componentă cade, apărarea nu cade.",
    fb_items=[("Senzori", "Inspecție fail-open — traficul tău nu se oprește niciodată din cauza noastră."),
              ("Nucleul SOC", "Platformă de evenimente în cluster plus o locație de recuperare în cloud."),
              ("Monitorizare", "NOC-ul agentic rulează pe infrastructură cloud independentă — vizibil chiar dacă o locație cade."),
              ("AI", "CYBER3.AI multi-motor cu comutare automată — niciun furnizor AI nu-l poate opri."),
              ("Baza de amenințări", "Servită din peste 300 de locații edge; aplicațiile protejează pe dispozitiv, chiar și offline."),
              ("Date", "Copii de siguranță criptate, în afara locației, cu proceduri de restaurare testate.")],
    fu_k="STRATUL 4 · CYBERBOT FUSION", fu_h="Patru surse. O decizie autonomă. În câteva secunde.",
    fu_p="Fiecare alertă e verificată simultan față de patru surse independente. CyberBot le fuzionează într-un singur verdict și acționează — fără să aștepte un om la 3 dimineața.",
    fu_src=[("Telemetrie de rețea", "IDS/IPS inline în fiecare locație"), ("Corelare SIEM", "evenimente corelate în toată organizația"),
            ("Threat intelligence", "fluxuri globale live"), ("CYBER3 Database", "indicatorii noștri, în creștere zilnică")],
    fu_ladder_h="Acțiune după severitate",
    fu_ladder=["Jurnalizare discretă", "Blocare automată a IP-ului", "Alertă urgentă", "Escaladare la om"],
    fu_b=["Blochează comanda-și-controlul spre exterior, nu doar atacurile din afară", "Gardă anti-fals-pozitiv: infrastructura ta nu e blocată niciodată", "Alertă pe înțeles trimisă echipei pe Telegram și email"],
    ml_k="MLEO · MULTI LAYER ENFORCEMENT ORCHESTRATOR", ml_h="Nu doar detectează pe șapte straturi. Decide ce strat lovește.",
    ml_p="MLEO e nucleul care leagă cele șapte straturi într-un singur organism. Corelează ce vede fiecare strat, dă fiecărui dispozitiv o identitate unică între straturi și execută pe stratul care oprește cel mai bine amenințarea — fără blocări redundante și fără conflicte.",
    ml_cards=[("Identitate unificată", "Același dispozitiv văzut ca IP la nivelul 3 și ca MAC, VLAN și port de switch la nivelul 2."),
              ("Imun la evaziune", "Schimbarea adresei IP nu mai ajută atacatorul — blocarea urmează dispozitivul."),
              ("Izolează atacatorul, nu victima", "La ARP spoofing traficul pare să vină de la victimă. Corelarea direcțională izolează sursa reală."),
              ("Sigur prin construcție", "VLAN de carantină în loc de oprirea portului, allowlist și rollback cu ID de tranzacție ca precondiții, fail-safe pe fiecare strat.")],
    ml_note="Implementat pe etape: primele etape dau vizibilitate completă fără să atingă rețeaua clientului.",
    ai_k="CYBER3.AI · LLM SUVERAN DE SECURITATE", ai_h="Un analist AI integrat în SOC și VAS — nu lipit pe deasupra.",
    ai_p="CYBER3.AI e modelul nostru de limbaj pentru securitate, construit pentru un singur lucru: apărarea. Stă de-a lungul întregului lanț — citind aceeași CYBER3 Database ca senzorii, aplicațiile și scanerul.",
    ai_roles=[("Explică", "Alerte și constatări pe înțeles, în limba echipei tale: ce s-a întâmplat, de ce contează, ce s-a făcut deja."),
              ("Investighează", "Un copilot de securitate care corelează indicatorii din CYBER3 Database și threat intelligence live."),
              ("Prioritizează", "Transformă vulnerabilitățile găsite într-o ordine de remediere: ce repari întâi și cum."),
              ("Raportează", "Redactează rapoarte de incident și raportarea NIS2 art. 21/23 din datele reale ale SOC-ului.")],
    ai_sov_h="Suveran prin design",
    ai_sov=["Model de securitate găzduit de noi, în UE", "Arhitectură multi-motor cu comutare automată — niciun furnizor AI nu-ți poate opri SOC-ul", "Ancorat în propria bază de amenințări, nu în internetul deschis"],
    db_k="CYBER3 DATABASE", db_h="Propria noastră bază de amenințări. În creștere în fiecare zi.",
    db_p="CYBER3 Database fuzionează fluxurile globale de amenințări cu indicatorii pe care propriii noștri senzori îi observă în rețele reale. E publicată zilnic într-o rețea globală edge și alimentează fiecare strat: senzorii, AI-ul, aplicațiile desktop și mobile — un singur adevăr live peste tot.",
    db_l1="indicatori de amenințare — live", db_l2="indicatori proprii, de la senzorii noștri", db_l3="locații edge care servesc verificările",
    db_vec_h="Bază de date vectorială proprietară", db_vec_t="Operațională, pentru pattern matching prin embedding.",
    db_vec_p="Stochează vectori semantici ai atacurilor istorice și recunoaște variante noi ale campaniilor cunoscute — chiar când IOC-urile explicite lipsesc.",
    db_b=["Publicare zilnică, verificată cap-coadă", "Verificări care protejează intimitatea: de pe dispozitiv pleacă doar un prefix de hash", "Aceeași bază protejează rețele, stații și telefoane"],
    vas_k="VAS · CYBER3 SCAN ȘI GLOBAL SCAN", vas_h="Scanare agilă care găsește toată rețeaua — și nu declanșează alarma.",
    vas_p="Evaluarea Vulnerabilităților construită de echipa care apără rețelele. Scanerul rulează din senzorul aflat deja în rețeaua ta, deci descoperă tot — chiar și ce n-a știut nimeni să-i dea.",
    vas_cards=[("Descoperă fără să i se spună", "Ascultare pasivă plus sonde etichetate pe fiecare VLAN cartografiază gazde, adrese MAC, producători și roluri — inclusiv dispozitivele tăcute."),
               ("Unstoppable Adaptive Scan", "Studiază ținta și avansează în pași măsurați; se retrage la primul semn de firewall și nu declanșează alarme."),
               ("Global Scan agil", "Scanare la cerere a expunerii externe, din cloud — fără instalare, rezultate în câteva minute. Scanarea întregii rețele e inclusă în aplicația Windows."),
               ("Prioritizat, acționabil", "Vulnerabilități cunoscute (CVE), configurări nesigure și servicii expuse — ordonate ca să repari întâi ce contează.")],
    ag_k="OPERAȚIUNI AGENTICE", ag_h="O armată de agenți care rulează platforma — non-stop.",
    ag_p="Oamenii noștri tratează excepțiile. Agenții se ocupă de rest: supraveghează, repară, comandă și răspund — și dovedesc în fiecare zi că lanțul funcționează.",
    agents=[("NOC Agentic", "Supraveghează toată infrastructura dintr-un punct independent, în cloud — fiecare senzor, serviciu și tunel — cu scheme live, rezumate AI și alerte."),
            ("Health Check Agentic", "Administrează și repară singur flota de senzori 24/7: captură blocată, servicii înțepenite, tuneluri căzute — reparate înainte să observe cineva. Testele sintetice validează lanțul cap-coadă."),
            ("CCC Agentic", "Command & Control Centre: un singur cockpit peste tot ecosistemul, de unde operatorii comandă agenții și văd cum threat intelligence-ul devine răspuns autonom."),
            ("Ops Agents", "Agenți CYBER3.AI care triază alerte, corelează indicatori, investighează și răspund — cu niveluri de autonomie de la acțiuni aprobate de om la playbook-uri pre-aprobate cu întrerupător de siguranță.")],
    ag_note="Actualizare autonomă a regulilor, cu auto-protecție și revenire automată. Fail-open prin design: traficul tău nu se oprește niciodată din cauza noastră.",
    ep_k="ENDPOINT · CYBER3", ep_h="SOC-ul, extins pe fiecare stație de lucru — și pe fiecare telefon.",
    ep_p="Aceeași platformă, nativ pe Windows, Android și iPhone. Organizațiile înrolează dispozitivele cu un cod de activare sau silențios la instalare; de pe dispozitiv pleacă doar metadate de securitate.",
    ep_desk_h="CYBER3 pentru Windows — EDR/XDR",
    ep_desk_b=["Izolarea automată a stației la malware confirmat — reversibilă, supravegheată de SOC", "Consola clientului: inventar, scanare de la distanță, izolare și reconectare în sub 30 de secunde", "Global Scan al întregii rețele interne, protecție browser, VPN criptat", "Semnată digital prin Microsoft Trusted Signing, actualizată automat"],
    ep_desk_tabs=[("home", "Panou principal"), ("globalscan", "Global Scan"), ("isolation", "Izolare amenințări"), ("vpn", "VPN")],
    ep_mob_h="CYBER3 pentru Android și iPhone",
    ep_mob_b=["Protecție la apeluri și mesaje frauduloase, verificare mesaje cu explicație AI", "Protecție web: reclame, trackere și phishing blocate în toate aplicațiile", "Scor de securitate al telefonului, monitorizare identitate și breșe, VPN criptat", "Aceeași bază de amenințări ca senzorii și stațiile"],
    wy_k="DE CE UN SINGUR FURNIZOR", wy_h="FasterUp vs. soluția obișnuită cu mai mulți furnizori",
    wy_c=["", "FasterUp", "Soluție obișnuită multi-furnizor"],
    wy_rows=[("De la detecție la blocare", "Secunde, autonom", "Ore — tichete între furnizori"),
             ("Protecție la nivel Ethernet (L2)", "y", "n"),
             ("Rețea + stație + telefon într-un singur lanț", "y", "p"),
             ("Analist AI care explică fiecare constatare", "y", "p"),
             ("Bază proprie de amenințări, alimentată de senzori proprii", "y", "n"),
             ("Flotă de senzori care se repară singură", "y", "n"),
             ("Un singur raport NIS2 unificat", "y", "n"),
             ("Datele rămân la tine (doar metadate)", "y", "p"),
             ("Un contract, o echipă responsabilă", "y", "n")],
    wy_y="Inclus", wy_n="Nu", wy_p="Parțial",
    pk_k="PACHETE", pk_h="Dimensionat pentru instituția ta",
    pk_p="Fiecare pachet include tot ce are cel anterior și adaugă straturi și capabilități. Configurația exactă — locații, senzori, stații, telefoane — se stabilește după o evaluare inițială.",
    pk_best="Potrivit pentru", pk_rec="RECOMANDAT",
    packages=[("Standard", "Include", ["SOC gestionat 24/7 · răspuns autonom în 2–11 s", "Senzor inline la sediul principal", "Straturile 1–4: IPS inline · Active Response · L2 Shield · CyberBot Fusion", "MLEO: corelare L3 ↔ L2 și execuție pe stratul potrivit", "VAS lunar programat", "Alerte pe înțeles + portal client cu rapoarte NIS2", "Health Check Agentic 24/7"], "Sediu central cu IT concentrat — monitorizare autonomă 24/7 și o imagine regulată a vulnerabilităților, fără să-ți construiești propriul SOC."),
              ("Extins", "Tot ce are Standard, plus", ["Senzori inline în fiecare locație", "Stratul 5 · CYBER3 Edge pentru toată organizația", "Stratul 6 · CYBER3 Desktop XDR pe stațiile critice", "Consola clientului: izolare, scanări de la distanță, starea flotei", "Global Scan al rețelei interne", "MLEO în toate locațiile", "VAS la două săptămâni"], "Instituții cu mai multe locații și expunere ridicată — acoperire de rețea peste tot plus XDR unde contează cel mai mult."),
              ("Complet", "Tot ce are Extins, plus", ["CYBER3 Desktop XDR pe fiecare stație", "Stratul 7 · CYBER3 Mobile pe telefoanele angajaților", "MLEO pe toate cele 7 straturi", "VAS continuu", "Monitorizarea breșelor și a identității pentru organizație", "Raportare unificată rețea + endpoint + mobil (NIS2 art. 21/23)"], "Date sensibile ale cetățenilor și conformitate strictă — apărare completă pe mai multe straturi, de la un furnizor și într-un singur raport.")],
    pk_note="Oferta financiară detaliată se întocmește la cerere, pe baza evaluării inițiale și a procedurii de achiziție aplicabile instituției tale.",
    sp_k="ÎNCEPE", sp_h="De la evaluare la apărare autonomă",
    steps=[("Evaluare", "Îți cartografiem activele și expunerea printr-o evaluare a vulnerabilităților — o imagine clară a situației."),
           ("Instalarea senzorilor", "Inline sau pasiv, circa 15 minute pe locație, fără agenți pe stațiile tale."),
           ("SOC autonom", "Detecție și răspuns 24/7, alerte pe înțeles, portal client și rapoarte NIS2 din prima zi.")],
    end_h="Vezi-ți rețeaua cum o vede un atacator — înaintea lui.", end_p="Începe cu o evaluare. Fără obligații, adaptată mediului tău.",
    ft_tag="Securitate cibernetică autonomă pentru companii și administrație publică — o tehnologie, un furnizor, cap-coadă.",
    ft_h=["Platformă", "Ecosistem", "Companie"],
    ft_status="Starea serviciilor", ft_contact="Contact", ft_privacy="Confidențialitate", ft_terms="Termeni",
    ft_copy="FasterUp.AI este o marcă a ROL PORTAL SERVICES SRL · © 2026",
)

ZONE = ["#ff3b4b", "#ff7a45", "#e8c35a", "#4f8cff", "#22c7e8", "#34d399", "#9b7bff"]   # culoarea fiecărui strat (fir → telefon)

XMARK_SVG = """url("data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><g fill='%23F00'><rect x='44' y='15' width='12' height='70'/><rect x='15' y='44' width='70' height='12'/><rect x='36' y='13' width='28' height='6'/><rect x='36' y='81' width='28' height='6'/><rect x='13' y='36' width='6' height='28'/><rect x='81' y='36' width='6' height='28'/><rect x='27' y='22' width='6' height='16'/><rect x='22' y='27' width='16' height='6'/><rect x='67' y='22' width='6' height='16'/><rect x='62' y='27' width='16' height='6'/><rect x='27' y='62' width='6' height='16'/><rect x='22' y='67' width='16' height='6'/><rect x='67' y='62' width='6' height='16'/><rect x='62' y='67' width='16' height='6'/></g><circle cx='50' cy='50' r='47' fill='none' stroke='%23F00' stroke-width='3'/></svg>")"""

CSS = r"""
:root{--bg:#030a18;--bg2:#061430;--panel:rgba(17,42,82,.5);--line:rgba(120,165,255,.15);--line2:rgba(120,165,255,.26);--text:#eef3ff;--mute:#a3b6d6;--dim:#6f86ad;
--red:#FF0000;--red2:#ff3b4b;--gold:#D4AF37;--gold2:#f2d778;--blue:#33A1FF;--green:#22d38a;--r:22px;--max:1220px;--sh:0 30px 80px -20px rgba(0,0,0,.65)}
*{box-sizing:border-box;margin:0;padding:0}html{scroll-behavior:smooth;-webkit-text-size-adjust:100%}
body{background:var(--bg);color:var(--text);font:16px/1.6 Inter,'Segoe UI',system-ui,-apple-system,Arial,sans-serif;-webkit-font-smoothing:antialiased;overflow-x:hidden}
img{max-width:100%;display:block}a{color:inherit;text-decoration:none}
h1,h2,h3{font-family:Sora,Inter,'Segoe UI',system-ui,sans-serif;letter-spacing:-.02em;line-height:1.1}
:lang(zh) h1,:lang(zh) h2,:lang(zh) h3,:lang(ru) h1,:lang(ru) h2{letter-spacing:0}
.wrap{max-width:var(--max);margin:0 auto;padding:0 24px}
.grad{background:linear-gradient(92deg,#ff4d5a,#ff1a1a 35%,#D4AF37);-webkit-background-clip:text;background-clip:text;color:transparent}
.kicker{display:inline-flex;align-items:center;gap:8px;font:700 12px/1.3 Inter,sans-serif;letter-spacing:2px;text-transform:uppercase;color:var(--gold);padding:8px 14px;border:1px solid rgba(212,175,55,.35);border-radius:999px;background:rgba(212,175,55,.07)}
:lang(zh) .kicker,:lang(ru) .kicker{letter-spacing:.5px}
.kicker::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--red);box-shadow:0 0 10px var(--red);flex:0 0 auto}
.sec{padding:110px 0;position:relative}
.head{text-align:center;max-width:860px;margin:0 auto 60px}
.head h2{font-size:clamp(30px,4.4vw,52px);margin:18px 0 16px}.head p{color:var(--mute);font-size:clamp(16px,1.6vw,19px)}
.reveal{opacity:0;transform:translateY(26px);transition:opacity .8s cubic-bezier(.2,.7,.2,1),transform .8s cubic-bezier(.2,.7,.2,1)}.reveal.in{opacity:1;transform:none}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:10px;font:700 15px/1 Inter,sans-serif;padding:16px 26px;border-radius:14px;transition:transform .2s,box-shadow .2s,background .2s;border:0;cursor:pointer}
.btn-red{background:linear-gradient(180deg,#ff2b2b,#d60000);color:#fff;box-shadow:0 12px 32px -8px rgba(255,0,0,.65),inset 0 1px 0 rgba(255,255,255,.25)}
.btn-red:hover{transform:translateY(-2px);box-shadow:0 18px 44px -8px rgba(255,0,0,.85)}
.btn-ghost{background:rgba(255,255,255,.06);border:1px solid var(--line2);color:var(--text)}.btn-ghost:hover{background:rgba(255,255,255,.11)}
.btn-sm{padding:11px 18px;font-size:14px;border-radius:12px}
/* NAV */
.nav{position:fixed;inset:0 0 auto 0;z-index:50;border-bottom:1px solid transparent;transition:background .3s,border-color .3s}
.nav.solid{background:rgba(3,10,24,.8);backdrop-filter:blur(18px) saturate(1.4);-webkit-backdrop-filter:blur(18px) saturate(1.4);border-bottom-color:var(--line)}
.nav .wrap{display:flex;align-items:center;gap:24px;height:72px}
.brand{display:inline-flex;align-items:center;font:900 21px/1 'Segoe UI',system-ui,-apple-system,Arial,sans-serif;letter-spacing:.3px;white-space:nowrap;color:#fff}
.brand .fu{color:#FF0000;text-shadow:0 0 8px rgba(255,0,0,.35)}
.xmark{display:inline-block;vertical-align:middle;width:1em;height:1em;margin-right:.4em;position:relative;top:-.04em;background:__XMARK__ center/contain no-repeat;filter:drop-shadow(0 0 6px rgba(255,0,0,.6));animation:c3pulse 1.8s ease-in-out infinite}
@keyframes c3pulse{0%,100%{filter:drop-shadow(0 0 3px rgba(255,0,0,.5));transform:scale(1)}50%{filter:drop-shadow(0 0 9px rgba(255,0,0,.95));transform:scale(1.13)}}
.links{display:flex;gap:20px;margin-left:8px}.links a{font-size:14px;font-weight:500;color:var(--mute);transition:color .2s;white-space:nowrap}.links a:hover{color:var(--text)}
.nav-r{margin-left:auto;display:flex;align-items:center;gap:12px}
.lang{background:rgba(255,255,255,.05);color:var(--text);border:1px solid var(--line2);border-radius:999px;padding:8px 12px;font:700 13px/1 Inter,sans-serif;cursor:pointer}
.lang option{background:#0b1a38;color:#fff}
.burger{display:none;background:none;border:0;color:var(--text);width:40px;height:40px;cursor:pointer}
/* HERO */
.hero{position:relative;min-height:100vh;padding:140px 0 70px;overflow:hidden;isolation:isolate}
.aurora{position:absolute;inset:-20%;z-index:-2;background:radial-gradient(40% 35% at 18% 28%,rgba(51,161,255,.24),transparent 70%),radial-gradient(35% 32% at 82% 30%,rgba(255,0,0,.2),transparent 70%),radial-gradient(45% 40% at 60% 90%,rgba(212,175,55,.12),transparent 70%);filter:blur(8px);animation:drift 20s ease-in-out infinite alternate}
@keyframes drift{to{transform:translate3d(3%,-2%,0) rotate(4deg) scale(1.06)}}
.gridbg{position:absolute;inset:0;z-index:-1;background-image:linear-gradient(var(--line) 1px,transparent 1px),linear-gradient(90deg,var(--line) 1px,transparent 1px);background-size:64px 64px;mask-image:radial-gradient(ellipse 70% 60% at 50% 40%,#000 30%,transparent 80%);-webkit-mask-image:radial-gradient(ellipse 70% 60% at 50% 40%,#000 30%,transparent 80%);opacity:.5}
.hero .wrap{display:grid;grid-template-columns:1.05fr .95fr;gap:30px;align-items:center}
.hero h1{font-size:clamp(38px,4.9vw,66px);font-weight:800;margin:22px 0}
.hero .lead{font-size:clamp(16px,1.55vw,19px);color:var(--mute);max-width:640px}
.cta{display:flex;flex-wrap:wrap;gap:12px;margin:32px 0 40px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;max-width:680px}
.stat{padding:16px;border-radius:16px;background:var(--panel);border:1px solid var(--line)}
.stat b{display:block;font:800 clamp(20px,2.2vw,28px)/1.1 Sora,sans-serif;white-space:nowrap;font-variant-numeric:tabular-nums}
.stat span{display:block;color:var(--mute);font-size:12.5px;line-height:1.35;margin-top:6px}
.ringbox{position:relative;width:100%;max-width:600px;aspect-ratio:1;justify-self:center}
.ringbox svg{width:100%;height:100%;overflow:hidden}
.ring{fill:none;stroke-width:2;opacity:.85;transform-origin:300px 300px}
.ring.dash{stroke-dasharray:4 10;animation:spin 60s linear infinite}.ring.dash.rev{animation-direction:reverse}
@keyframes spin{to{transform:rotate(360deg)}}
.ring.hit{animation:hit .6s ease-out}
.rlabel{font:700 13px Inter,sans-serif;letter-spacing:.2px}
.core{font:800 15px Sora,sans-serif;fill:#fff}
/* TRUST */
.trust{border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:rgba(6,20,48,.55)}
.trust .wrap{display:flex;flex-wrap:wrap;justify-content:space-between;gap:16px 28px;padding:24px}
.trust div{display:flex;align-items:center;gap:10px;color:var(--mute);font-size:14.5px;font-weight:500}.trust svg{color:var(--gold);flex:0 0 auto}
/* CHAIN */
.chain{display:grid;grid-template-columns:repeat(6,1fr);gap:16px;position:relative}
.chain::before{content:"";position:absolute;left:4%;right:4%;top:46px;height:2px;background:linear-gradient(90deg,var(--red),var(--gold),var(--blue),var(--green));opacity:.6}
.chain::after{content:"";position:absolute;top:43px;left:4%;width:60px;height:8px;border-radius:8px;background:#fff;filter:blur(4px);opacity:.8;animation:run 4s linear infinite}
@keyframes run{to{left:92%}}
.cnode{position:relative;text-align:center;padding:0 4px}
.cnode .n{width:92px;height:92px;margin:0 auto 18px;border-radius:50%;display:grid;place-items:center;background:radial-gradient(circle at 35% 30%,#16336a,#081833);border:1px solid var(--line2);box-shadow:0 0 0 6px rgba(3,10,24,1),0 0 40px -6px var(--c);font:800 26px Sora,sans-serif;color:var(--c);position:relative;z-index:1}
.cnode h3{font-size:17px;margin-bottom:8px}.cnode p{color:var(--mute);font-size:14px}
.pfnote{text-align:center;margin-top:46px;color:var(--gold);font-weight:600;font-size:17px}
/* LAYERS */
.ltable{border:1px solid var(--line);border-radius:26px;overflow:hidden;background:rgba(6,18,42,.6)}
.lrow{display:grid;grid-template-columns:56px 1.3fr .8fr 2.4fr .7fr .7fr;gap:16px;align-items:center;padding:18px 26px;border-top:1px solid var(--line);transition:background .25s}
.lrow:hover{background:rgba(255,255,255,.03)}
.lrow.h{border-top:0;color:var(--dim);font:700 12px/1 Inter,sans-serif;letter-spacing:1.4px;text-transform:uppercase;padding-top:20px;padding-bottom:14px}
.lnum{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;font:800 16px Sora,sans-serif;color:#fff;background:var(--c);box-shadow:0 0 22px -4px var(--c)}
.lname{font-weight:700;font-size:16px}.llev{color:var(--mute);font-size:13.5px}.lhow{color:var(--mute);font-size:14.5px}
.lt{font:700 14px Sora,sans-serif;color:var(--gold2);white-space:nowrap}
.lst{display:flex;align-items:center;gap:8px;font-weight:600;font-size:14px;color:var(--green)}
.lst i{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green);animation:pulse 1.8s infinite}
@keyframes pulse{50%{opacity:.35}}
.lnote{padding:16px 26px 22px;color:var(--dim);font-size:13.5px;border-top:1px solid var(--line)}
/* FUSION */
.two{display:grid;grid-template-columns:1fr 1fr;gap:54px;align-items:center}
.two h2{font-size:clamp(30px,3.8vw,46px);margin:18px 0 16px}.two .lead{color:var(--mute);font-size:17.5px}
.ul{list-style:none;display:grid;gap:12px;margin-top:26px}.ul li{display:flex;gap:12px;align-items:flex-start;font-weight:500}
.ck{width:22px;height:22px;flex:0 0 auto;color:var(--green);background:rgba(34,211,138,.12);border-radius:50%;padding:3px;margin-top:1px}
.fusion{position:relative;aspect-ratio:1;max-width:520px;width:100%;justify-self:center}
.fusion svg{position:absolute;inset:0;width:100%;height:100%}
.fsrc{position:absolute;width:44%;padding:16px;border-radius:16px;background:var(--panel);border:1px solid var(--line2);backdrop-filter:blur(8px)}
.fsrc b{display:block;font-size:15px}.fsrc span{color:var(--mute);font-size:13px}
.fsrc.s0{left:0;top:0}.fsrc.s1{right:0;top:0}.fsrc.s2{left:0;bottom:0}.fsrc.s3{right:0;bottom:0}
.fcore{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:150px;height:150px;border-radius:50%;display:grid;place-items:center;text-align:center;font:800 15px/1.2 Sora,sans-serif;background:radial-gradient(circle,#2a0b12,#0a1530 70%);border:1px solid rgba(255,0,0,.5);box-shadow:0 0 60px -6px rgba(255,0,0,.6),inset 0 0 30px rgba(255,0,0,.25);animation:corep 2.6s ease-in-out infinite}
@keyframes corep{50%{box-shadow:0 0 90px 0 rgba(255,0,0,.75),inset 0 0 40px rgba(255,0,0,.35)}}
.fcore small{display:block;color:var(--gold2);font:700 12px Inter,sans-serif;margin-top:4px}
.flow{stroke:url(#fg);stroke-width:2;fill:none;stroke-dasharray:6 8;animation:dash 1.2s linear infinite}
@keyframes dash{to{stroke-dashoffset:-28}}
.ladder{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:28px}
.ladder div{padding:12px 10px;border-radius:12px;text-align:center;font-size:13px;font-weight:600;background:rgba(255,255,255,.04);border:1px solid var(--line)}
.ladder div:nth-child(1){border-color:rgba(160,180,210,.35)}.ladder div:nth-child(2){border-color:rgba(255,59,75,.55);color:#ff8a94}.ladder div:nth-child(3){border-color:rgba(232,195,90,.55);color:var(--gold2)}.ladder div:nth-child(4){border-color:rgba(51,161,255,.55);color:#8cc8ff}
.lh{margin-top:26px;color:var(--dim);font:700 12px Inter,sans-serif;letter-spacing:1.4px;text-transform:uppercase}
/* CARDS */
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}
.card{position:relative;padding:28px;border-radius:var(--r);background:linear-gradient(180deg,rgba(17,42,82,.6),rgba(6,18,42,.35));border:1px solid var(--line);overflow:hidden;transition:transform .3s,border-color .3s}
.card:hover{transform:translateY(-6px);border-color:rgba(255,0,0,.45)}
.card::after{content:"";position:absolute;right:-60px;bottom:-80px;width:220px;height:220px;background:radial-gradient(circle,rgba(255,0,0,.14),transparent 70%)}
.card .i{font:800 13px Sora,sans-serif;color:var(--red2);letter-spacing:1px}
.card h3{font-size:19px;margin:12px 0 10px}.card p{color:var(--mute);font-size:14.5px}
.note{text-align:center;color:var(--dim);font-size:14px;margin-top:30px}
/* AI */
.ai{background:radial-gradient(60% 60% at 50% 40%,rgba(255,0,0,.08),transparent 70%)}
.aigrid{display:grid;grid-template-columns:1.2fr 1fr;gap:30px;align-items:stretch}
.roles{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.role{padding:24px;border-radius:20px;background:var(--panel);border:1px solid var(--line)}
.role b{display:flex;align-items:center;gap:10px;font:700 18px Sora,sans-serif;margin-bottom:8px}.role b i{width:10px;height:10px;border-radius:50%;background:var(--red);box-shadow:0 0 12px var(--red)}
.role p{color:var(--mute);font-size:14.5px}
.sov{padding:32px;border-radius:24px;border:1px solid transparent;background:linear-gradient(180deg,#0f2450,#091835) padding-box,linear-gradient(160deg,var(--red),var(--gold)) border-box;box-shadow:0 30px 80px -30px rgba(255,0,0,.45)}
.sov h3{font-size:24px;margin-bottom:6px}.sov .tag{font:800 13px Sora,sans-serif;color:#FF0000;letter-spacing:.5px}
/* DATABASE */
.dbnums{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:30px 0}
.dbn{padding:22px;border-radius:18px;background:var(--panel);border:1px solid var(--line)}
.dbn b{display:block;font:800 clamp(26px,3vw,38px)/1 Sora,sans-serif;font-variant-numeric:tabular-nums;background:linear-gradient(180deg,#fff,#b9c8e6);-webkit-background-clip:text;background-clip:text;color:transparent;white-space:nowrap}
.dbn span{color:var(--mute);font-size:13.5px}
.dbviz{position:relative;aspect-ratio:1;max-width:480px;width:100%;justify-self:center;border-radius:50%;background:radial-gradient(circle at 50% 50%,rgba(212,175,55,.18),rgba(6,18,42,.2) 55%,transparent 70%)}
.dbviz canvas{position:absolute;inset:0;width:100%;height:100%}
.dbviz .c{position:absolute;inset:34%;border-radius:50%;display:grid;place-items:center;text-align:center;font:800 16px/1.2 Sora,sans-serif;background:radial-gradient(circle,#1c2c55,#0a1530);border:1px solid rgba(212,175,55,.5);box-shadow:0 0 50px -8px rgba(212,175,55,.6)}
.dbviz .c small{display:block;color:var(--gold2);font:600 11px Inter,sans-serif;margin-top:4px}
.vec{display:flex;gap:18px;align-items:flex-start;padding:24px;border-radius:20px;margin:0 0 22px;border:1px solid transparent;background:linear-gradient(180deg,#0f2449,#081733) padding-box,var(--gl) border-box;box-shadow:0 0 0 1px rgba(212,175,55,.1),0 18px 50px -22px rgba(212,175,55,.45)}
.vec b{display:block;font:800 19px Sora,sans-serif;color:#fff}.vec em{display:block;font-style:normal;color:var(--gold2);font-weight:600;font-size:14.5px;margin:4px 0 8px}.vec p{color:var(--mute);font-size:15px}
.vi{flex:0 0 auto;width:54px;height:54px;border-radius:14px;position:relative;background:radial-gradient(circle,#1c2c55,#0a1530);border:1px solid rgba(212,175,55,.5)}
.vi i{position:absolute;width:6px;height:6px;border-radius:50%;background:#f2d778;box-shadow:0 0 8px #f2d778;animation:pulse 2s infinite}
.vi i:nth-child(1){left:10px;top:12px}.vi i:nth-child(2){left:30px;top:9px;animation-delay:.3s}.vi i:nth-child(3){left:20px;top:25px;animation-delay:.6s;background:#ff3b4b;box-shadow:0 0 8px #ff3b4b}.vi i:nth-child(4){left:38px;top:30px;animation-delay:.9s}.vi i:nth-child(5){left:12px;top:38px;animation-delay:1.2s}.vi i:nth-child(6){left:30px;top:42px;animation-delay:1.5s;background:#33A1FF;box-shadow:0 0 8px #33A1FF}
/* AGENTS */
.agents{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}
.agent{padding:28px;border-radius:22px;background:linear-gradient(180deg,rgba(17,42,82,.65),rgba(6,18,42,.35));border:1px solid var(--line);position:relative;overflow:hidden}
.agent .dot{display:inline-flex;align-items:center;gap:8px;font:700 11px Inter,sans-serif;letter-spacing:1px;color:var(--green);text-transform:uppercase;margin-bottom:14px}
.agent .dot i{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green);animation:pulse 1.6s infinite}
.agent h3{font-size:20px;margin-bottom:10px}.agent p{color:var(--mute);font-size:14.5px}
.agent .scan{position:absolute;left:0;right:0;top:-40%;height:40%;background:linear-gradient(180deg,transparent,rgba(51,161,255,.08),transparent);animation:scanv 5s linear infinite}
@keyframes scanv{to{top:110%}}
/* FALLBACK */
.fb{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.fbi{display:flex;gap:16px;align-items:flex-start;padding:24px;border-radius:20px;background:var(--panel);border:1px solid var(--line)}
.fbi b{display:block;font:700 17px Sora,sans-serif;margin-bottom:6px}.fbi p{color:var(--mute);font-size:14.5px}
.fbx{position:relative;flex:0 0 auto;width:38px;height:38px}
.fbx i{position:absolute;width:24px;height:24px;border-radius:8px;border:2px solid var(--green)}
.fbx i:first-child{left:0;top:0;background:rgba(34,211,138,.15)}.fbx i:last-child{right:0;bottom:0;border-color:var(--gold);border-style:dashed;animation:pulse 2.4s infinite}
/* ENDPOINT */
.ep{display:grid;grid-template-columns:1.45fr 1fr;gap:30px;align-items:start}
.epb{padding:30px;border-radius:26px;background:linear-gradient(180deg,rgba(17,42,82,.55),rgba(6,18,42,.3));border:1px solid var(--line)}
.epb h3{font-size:22px;margin-bottom:16px}
.screen{border-radius:14px;padding:9px;background:linear-gradient(160deg,#2b3449,#0c111b);box-shadow:var(--sh);margin-bottom:16px}
.screen .dots{display:flex;gap:6px;padding:2px 4px 8px}.screen .dots i{width:10px;height:10px;border-radius:50%;background:#ff5f57}.screen .dots i:nth-child(2){background:#febc2e}.screen .dots i:nth-child(3){background:#28c840}
.view{position:relative;aspect-ratio:3/2;border-radius:8px;overflow:hidden;background:#071430}.view img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;opacity:0;transition:opacity .6s}.view img.on{opacity:1}
.dtabs{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:18px}
.dtab{padding:8px 14px;border-radius:999px;border:1px solid var(--line2);background:rgba(255,255,255,.03);color:var(--mute);font:600 13px/1 Inter,sans-serif;cursor:pointer}.dtab.on,.dtab:hover{background:var(--text);color:#06122b}
.phones{display:flex;justify-content:center;gap:14px;margin-bottom:22px;height:430px;position:relative}
.phone{width:200px;aspect-ratio:660/1467;border-radius:34px;padding:7px;background:linear-gradient(145deg,#2a3348,#0b0f18 40%,#1b2232);box-shadow:var(--sh),0 0 0 1px rgba(255,255,255,.08)}
.phone img{width:100%;height:100%;object-fit:cover;border-radius:28px}
.phones .phone:nth-child(1){transform:rotate(-5deg) translateY(16px)}.phones .phone:nth-child(2){transform:rotate(5deg)}
.stores{display:flex;flex-wrap:wrap;gap:10px;margin-top:18px;align-items:center}
.store{display:inline-flex;align-items:center;height:46px}.store img{height:46px;width:auto}.store.gp img{height:68px;margin:-11px -8px}
.store.win{background:#000;border:1px solid #a6a6a6;color:#fff;padding:0 14px;border-radius:10px;gap:8px;font:600 15px Inter,sans-serif}
/* WHY */
.cmp{max-width:980px;margin:0 auto;border:1px solid var(--line);border-radius:26px;overflow:hidden;background:rgba(6,18,42,.6)}
.cmp table{width:100%;border-collapse:collapse}
.cmp th,.cmp td{padding:17px 22px;text-align:center;border-top:1px solid var(--line);font-size:15px}
.cmp th:first-child,.cmp td:first-child{text-align:left;font-weight:500;padding-left:30px}
.cmp thead th{border-top:0;color:var(--mute);font-weight:600;font-size:14px;padding-top:24px}
.cmp thead th.us{font:900 19px 'Segoe UI',system-ui,sans-serif;color:#FF0000}
.cmp td.us{background:rgba(255,0,0,.07);color:var(--text);font-weight:700}
.cmp .mk{display:inline-grid;place-items:center;width:28px;height:28px;border-radius:50%}
.cmp .y{color:var(--green)}.cmp .y .mk{background:rgba(34,211,138,.14)}.cmp .n{color:#5d6f92}.cmp .n .mk{background:rgba(255,255,255,.04)}.cmp .p{color:var(--gold)}.cmp .p .mk{background:rgba(212,175,55,.12)}
.cmp .t{color:var(--mute);font-size:14px}
/* PACKAGES */
.pk{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;align-items:stretch}
.pkc{position:relative;display:flex;flex-direction:column;padding:32px 28px;border-radius:26px;background:linear-gradient(180deg,rgba(17,42,82,.6),rgba(6,18,42,.4));border:1px solid var(--line)}
.pkc.best{border:1px solid transparent;background:linear-gradient(180deg,#0f2550,#0a1a3a) padding-box,linear-gradient(160deg,var(--red),var(--gold)) border-box;box-shadow:0 30px 80px -30px rgba(255,0,0,.5)}
.pkc .pop{position:absolute;top:-13px;left:50%;transform:translateX(-50%);font:800 11px/1 Inter,sans-serif;letter-spacing:1.5px;padding:8px 14px;border-radius:999px;background:linear-gradient(90deg,#ff1a1a,#ff6a3d);color:#fff;white-space:nowrap}
.pkc h3{font-size:26px}.pkc .inc{color:var(--gold);font:700 12px Inter,sans-serif;letter-spacing:1.2px;text-transform:uppercase;margin:16px 0 12px}
.pkc ul{list-style:none;display:grid;gap:11px;margin-bottom:22px}.pkc li{display:flex;gap:10px;font-size:14.5px}
.pkc .bf{margin-top:auto;padding-top:18px;border-top:1px solid var(--line);color:var(--mute);font-size:14px}.pkc .bf b{display:block;color:var(--text);font-size:12px;letter-spacing:1.2px;text-transform:uppercase;margin-bottom:6px}
/* STEPS */
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;counter-reset:s}
.step{padding:30px;border-radius:22px;border:1px solid var(--line);background:rgba(255,255,255,.02)}
.step .sn{width:46px;height:46px;border-radius:14px;display:grid;place-items:center;font:800 18px Sora,sans-serif;background:linear-gradient(180deg,#ff2b2b,#b80000);margin-bottom:16px}
.step h3{font-size:20px;margin-bottom:8px}.step p{color:var(--mute);font-size:15px}
/* END + FOOTER */
.endbox{position:relative;overflow:hidden;text-align:center;padding:80px 30px;border-radius:36px;background:radial-gradient(60% 90% at 50% 0%,rgba(255,0,0,.3),transparent 70%),linear-gradient(180deg,#0e2250,#081633);border:1px solid var(--line2)}
.endbox h2{font-size:clamp(28px,4vw,50px);margin-bottom:12px}.endbox p{color:var(--mute);font-size:18px;margin-bottom:30px}
footer{border-top:1px solid var(--line);padding:60px 0 32px;background:#02070f;margin-top:100px}
.fgrid{display:grid;grid-template-columns:1.6fr 1fr 1fr 1fr;gap:36px}.fgrid p{color:var(--dim);font-size:14px;margin-top:14px;max-width:360px}
.fgrid h4{font:700 12.5px/1 Inter,sans-serif;letter-spacing:1.5px;text-transform:uppercase;color:var(--mute);margin-bottom:16px}
.fgrid a{display:block;color:var(--dim);font-size:14.5px;margin:9px 0;transition:color .2s}.fgrid a:hover{color:var(--text)}
.certs{display:inline-block;margin-top:16px;color:var(--gold);border:1px solid rgba(212,175,55,.35);border-radius:10px;padding:6px 12px;font-size:12px}
.fbot{display:flex;flex-wrap:wrap;justify-content:space-between;gap:12px;margin-top:44px;padding-top:22px;border-top:1px solid var(--line);color:var(--dim);font-size:13px}
.sw{display:inline-flex;align-items:center;gap:8px}.sw i{width:8px;height:8px;border-radius:50%;background:var(--dim)}.sw i.ok{background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse 2s infinite}.sw i.deg{background:#e8b53a}
/* CONTUR AURIU PREMIUM (cerut de operator): gradient auriu pe margine + strălucire discretă */
:root{--gl:linear-gradient(135deg,#f6e7a8 0%,#D4AF37 28%,#8a6d1f 55%,#D4AF37 78%,#f6e7a8 100%)}
.card,.agent,.role,.fbi,.dbn,.stat,.epb,.pkc,.step,.fsrc,.ltable,.cmp,.sov,.endbox{border:1px solid transparent!important;
 background:linear-gradient(180deg,#0f2449,#081733) padding-box,var(--gl) border-box!important;
 box-shadow:0 0 0 1px rgba(212,175,55,.08),0 18px 50px -22px rgba(212,175,55,.35),inset 0 1px 0 rgba(255,236,170,.12)}
.pkc.best,.sov{box-shadow:0 0 0 1px rgba(212,175,55,.2),0 30px 80px -26px rgba(212,175,55,.55),inset 0 1px 0 rgba(255,236,170,.18)!important}
.card,.agent,.fbi,.role,.pkc,.step,.dbn,.epb{transition:transform .3s,box-shadow .3s}
.card:hover,.agent:hover,.fbi:hover,.role:hover,.pkc:hover,.step:hover,.dbn:hover{transform:translateY(-5px);box-shadow:0 0 0 1px rgba(212,175,55,.35),0 24px 60px -18px rgba(212,175,55,.55),inset 0 1px 0 rgba(255,236,170,.2)}
.lrow{border-top-color:rgba(212,175,55,.16)}.cmp th,.cmp td{border-top-color:rgba(212,175,55,.16)}.lnote{border-top-color:rgba(212,175,55,.16)}
.pkc .bf{border-top-color:rgba(212,175,55,.22)}
/* cercurile: noduri, nuclee */
.cnode .n{border:2px solid transparent;background:radial-gradient(circle at 35% 30%,#16336a,#081833) padding-box,var(--gl) border-box;box-shadow:0 0 0 6px #030a18,0 0 34px -4px rgba(212,175,55,.6),0 0 46px -8px var(--c)}
.fcore{border:2px solid transparent;background:radial-gradient(circle,#2a0b12,#0a1530 70%) padding-box,var(--gl) border-box}
.dbviz .c{border:2px solid transparent;background:radial-gradient(circle,#1c2c55,#0a1530) padding-box,var(--gl) border-box}
.fbx i:first-child{border-color:#D4AF37;background:rgba(212,175,55,.14)}
/* grilele nu au voie să lărgească pagina */
.fb>*,.hero .wrap>*,.two>*,.aigrid>*,.ep>*,.chain>*,.cards>*,.agents>*,.pk>*,.steps>*{min-width:0}
@media(max-width:1180px){.links{display:none}}
@media(max-width:1080px){.hero .wrap,.two,.aigrid,.ep{grid-template-columns:minmax(0,1fr)}.hero{padding-top:120px}.ringbox{max-width:520px}
.chain{grid-template-columns:repeat(3,minmax(0,1fr));row-gap:36px}.chain::before,.chain::after{display:none}
.cards,.agents,.fb{grid-template-columns:repeat(2,minmax(0,1fr))}.pk{grid-template-columns:minmax(0,1fr);max-width:560px;margin:0 auto}.pkc.best{order:-1}
.lrow{grid-template-columns:44px 1fr auto;row-gap:6px}.lrow .llev,.lrow .lhow{grid-column:2/4}.lrow .lt{grid-column:2}.lrow .lst{grid-column:3;grid-row:1}.lrow.h{display:none}.fgrid{grid-template-columns:1fr 1fr}}
@media(max-width:760px){.burger{display:block}.nav-r .btn{display:none}.nav.open .links{display:flex;position:absolute;top:72px;left:0;right:0;flex-direction:column;gap:0;background:rgba(3,10,24,.97);border-bottom:1px solid var(--line);padding:6px 24px 16px}.nav.open .links a{padding:13px 0;border-bottom:1px solid var(--line);font-size:16px}}
@media(max-width:640px){.wrap{padding:0 16px}.sec{padding:76px 0}.head{margin-bottom:40px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}
.chain,.cards,.agents,.roles,.steps,.dbnums,.fb{grid-template-columns:minmax(0,1fr)}.ladder{grid-template-columns:repeat(2,minmax(0,1fr))}
.fusion{aspect-ratio:auto;display:grid;gap:10px}.fusion svg{display:none}.fsrc,.fcore{position:static;width:auto;transform:none}.fcore{width:140px;height:140px;margin:6px auto}
.phones{height:330px}.phone{width:150px;border-radius:26px;padding:5px}.phone img{border-radius:22px}
.cmp table{table-layout:fixed}.cmp th:first-child{width:46%}.cmp th,.cmp td{padding:12px 8px;font-size:13px;overflow-wrap:anywhere;hyphens:auto;-webkit-hyphens:auto}.cmp thead th.us{font-size:15px}.cmp th:first-child,.cmp td:first-child{padding-left:16px}.cmp .t{font-size:12px}
.lrow{padding:16px}.endbox{padding:54px 20px;border-radius:26px}.fgrid{grid-template-columns:1fr}.brand{font-size:19px}.epb{padding:20px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}.reveal{opacity:1;transform:none}}
""".replace("__XMARK__", XMARK_SVG)

CK = '<svg viewBox="0 0 24 24" class="ck" aria-hidden="true"><path d="M5 12.5l4.2 4.2L19 7" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>'
I_OK = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.2 4.2L19 7"/></svg>'
I_X = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>'
I_HALF = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M6 12h12"/></svg>'
TRUST_IC = [
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M12 2l8 3v6c0 5-3.5 9.5-8 11-4.5-1.5-8-6-8-11V5z"/><path d="M9 12l2 2 4-4"/></svg>',
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h6"/></svg>',
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/></svg>',
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M12 2l3 6 6 .9-4.5 4.3 1 6.3L12 16.8 6.5 19.5l1-6.3L3 8.9 9 8z"/></svg>']


def ring_svg(T):
    """7 inele concentrice (stratul 1 = exterior … 7 = interior), etichete pe inel, centrul = organizația."""
    out = ['<svg viewBox="-20 -20 640 640" role="img" aria-label="7 layers"><defs><linearGradient id="gold" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#f6e7a8"/><stop offset=".3" stop-color="#D4AF37"/><stop offset=".55" stop-color="#8a6d1f"/><stop offset=".8" stop-color="#D4AF37"/><stop offset="1" stop-color="#f6e7a8"/></linearGradient><radialGradient id="cg"><stop offset="0" stop-color="#2a0b12"/><stop offset="1" stop-color="#081833"/></radialGradient></defs>']
    for i in range(7):
        r = 288 - i * 32
        c = ZONE[i]
        out.append(f'<circle class="ring" id="r{i}" cx="300" cy="300" r="{r}" stroke="url(#gold)" stroke-opacity=".55"/>')
        out.append(f'<circle class="ring dash{" rev" if i % 2 else ""}" cx="300" cy="300" r="{r}" stroke="{c}" style="animation-duration:{40 + i * 9}s"/>')
    for i, name in enumerate(T["rings"]):
        r = 288 - i * 32
        import math
        a = math.radians(-150 + i * 42)          # etichete răspândite în jurul inelelor, fără suprapuneri
        x, y = 300 + r * math.cos(a), 300 + r * math.sin(a)
        w = len(name) * 7.6 + 38
        out.append(f'<g transform="translate({x:.1f},{y:.1f})"><rect x="{-w / 2:.0f}" y="-13" rx="11" height="26" width="{w:.0f}" fill="#06122b" stroke="{ZONE[i]}" stroke-opacity=".8"/>'
                   f'<text class="rlabel" x="0" y="4.5" text-anchor="middle" fill="#fff"><tspan fill="{ZONE[i]}">{i + 1}</tspan>  {name}</text></g>')
    out.append('<circle cx="300" cy="300" r="74" fill="url(#cg)" stroke="url(#gold)" stroke-width="2.5"/>'
               f'<text class="core" x="300" y="305" text-anchor="middle">{T["ring_center"]}</text><g id="pz"></g></svg>')
    return "".join(out)


def cmp_cell(v, T, us=False):
    u = " us" if us else ""
    if v == "y": return f'<td class="y{u}"><span class="mk" title="{T["wy_y"]}">{I_OK}</span></td>'
    if v == "n": return f'<td class="n{u}"><span class="mk" title="{T["wy_n"]}">{I_X}</span></td>'
    if v == "p": return f'<td class="p{u}"><span class="mk" title="{T["wy_p"]}">{I_HALF}</span></td>'
    return f'<td class="t{u}">{v}</td>'


def lis(items): return "".join(f"<li>{CK}<span>{x}</span></li>" for x in items)


def render(T, L):
    pop = f'<span class="pop">{T["pk_rec"]}</span>'
    home = lpath(L); sfx = L if L in SHOT_LANGS else "en"; st = L if L in STATUS_LANGS else "en"
    ids = ["platform", "layers", "mleo", "ai", "vas", "agents", "endpoint", "packages"]
    navl = "".join(f'<a href="#{i}">{n}</a>' for i, n in zip(ids, T["nav"]))
    opts = "".join(f'<option value="{lpath(c)}"{" selected" if c == L else ""}>{n}</option>' for c, n in LANGS)
    alts = "".join(f'<link rel="alternate" hreflang="{c}" href="https://fasterup.ai{lpath(c)}">' for c, _ in LANGS)
    o = [f'''<!DOCTYPE html>
<html lang="{L}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{T["title"]}</title>
<meta name="description" content="{T["desc"]}">
<link rel="canonical" href="https://fasterup.ai{home}">{alts}<link rel="alternate" hreflang="x-default" href="https://fasterup.ai/">
<meta name="theme-color" content="#030a18">
<meta property="og:type" content="website"><meta property="og:url" content="https://fasterup.ai{home}"><meta property="og:title" content="{T["title"]}"><meta property="og:description" content="{T["desc"]}">
<link rel="icon" href="/assets/icon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Sora:wght@600;700;800&display=swap" rel="stylesheet">
<style>{CSS}</style>
</head>
<body>
<header class="nav" id="nav"><div class="wrap">
  <a class="brand" href="{home}" aria-label="FasterUp.AI"><i class="xmark" aria-hidden="true"></i><span class="fu">FasterUp</span>.AI</a>
  <nav class="links" id="links">{navl}</nav>
  <div class="nav-r">
    <select class="lang" aria-label="{T["lang_label"]}" onchange="try{{localStorage.setItem('fulang',this.value)}}catch(e){{}};document.cookie='fulang='+encodeURIComponent(this.value)+';path=/;max-age=31536000;samesite=lax';location.href=this.value">{opts}</select>
    <a class="btn btn-red btn-sm" href="{MAIL}">{T["nav_cta"]}</a>
    <button class="burger" aria-label="Menu" onclick="document.getElementById('nav').classList.toggle('open')"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg></button>
  </div>
</div></header>
''']
    if L == "en":
        # rădăcina: limba salvată > România (fus orar sau limba browserului) > limba browserului (comportamentul de până acum)
        o.append("""<script>(function(){var p=location.pathname;if(p!=='/'&&p!=='/index.html')return;var s=null;try{s=localStorage.getItem('fulang')}catch(e){}
if(s&&s!=='/'){location.replace(s);return}if(s==='/')return;var tz='';try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone||''}catch(e){}
var l=(navigator.language||'en').slice(0,2).toLowerCase();if(tz==='Europe/Bucharest'||l==='ro'){location.replace('/ro/');return}
var m={es:'/es/',it:'/it/',de:'/de/',fr:'/fr/',ru:'/ru/',zh:'/zh/'};if(m[l])location.replace(m[l])})();</script>""")
    o.append(f'''
<section class="hero"><div class="aurora"></div><div class="gridbg"></div><div class="wrap">
  <div>
    <span class="kicker">{T["hero_k"]}</span>
    <h1>{T["hero_h1"]}</h1>
    <p class="lead">{T["hero_p"]}</p>
    <div class="cta"><a class="btn btn-red" href="{MAIL}">{T["nav_cta"]}</a><a class="btn btn-ghost" href="#platform">{T["hero_cta2"]}</a></div>
    <div class="stats">
      <div class="stat"><b>10ms–11s</b><span>{T["st1"]}</span></div>
      <div class="stat"><b>7</b><span>{T["st2"]}</span></div>
      <div class="stat"><b>24/7</b><span>{T["st3"]}</span></div>
      <div class="stat"><b class="ioc" data-n="2895988">2.9M+</b><span>{T["st4"]}</span></div>
    </div>
  </div>
  <div class="ringbox" aria-hidden="true">{ring_svg(T)}</div>
</div></section>
<div class="trust"><div class="wrap">{"".join(f"<div>{TRUST_IC[i]}{t}</div>" for i, t in enumerate(T["tr"]))}</div></div>

<section class="sec" id="platform"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["pf_k"]}</span><h2>{T["pf_h"]}</h2><p>{T["pf_p"]}</p></div>
  <div class="chain reveal">{"".join(f'<div class="cnode" style="--c:{ZONE[[0, 3, 2, 0, 5, 4][i]]}"><div class="n">{i + 1}</div><h3>{h}</h3><p>{p}</p></div>' for i, (h, p) in enumerate(T["chain"]))}</div>
  <p class="pfnote reveal">{T["pf_note"]}</p>
</div></section>

<section class="sec" id="layers" style="padding-top:40px"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["ly_k"]}</span><h2>{T["ly_h"]}</h2><p>{T["ly_p"]}</p></div>
  <div class="ltable reveal">
    <div class="lrow h"><span></span><span>{T["ly_cols"][0]}</span><span>{T["ly_cols"][1]}</span><span>{T["ly_cols"][2]}</span><span>{T["ly_cols"][3]}</span><span>{T["ly_cols"][4]}</span></div>
    {"".join(f'<div class="lrow"><span class="lnum" style="--c:{ZONE[i]}">{i + 1}</span><span class="lname">{n}</span><span class="llev">{lv}</span><span class="lhow">{hw}</span><span class="lt">{t}</span><span class="lst"><i></i>{T["active"]}</span></div>' for i, (n, lv, hw, t) in enumerate(T["layers"]))}
    <div class="lnote">{T["ly_note"]}</div>
  </div>
</div></section>

<section class="sec" id="sensors" style="padding-top:40px"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["fl_k"]}</span><h2>{T["fl_h"]}</h2><p>{T["fl_p"]}</p></div>
  <div class="cards">{"".join(f'<article class="card reveal"><span class="i">0{i + 1}</span><h3>{h}</h3><p>{p}</p></article>' for i, (h, p) in enumerate(T["fl_cards"]))}</div>
</div></section>

<section class="sec" id="fusion"><div class="wrap two">
  <div class="reveal">
    <span class="kicker">{T["fu_k"]}</span><h2>{T["fu_h"]}</h2><p class="lead">{T["fu_p"]}</p>
    <div class="lh">{T["fu_ladder_h"]}</div>
    <div class="ladder">{"".join(f"<div>{x}</div>" for x in T["fu_ladder"])}</div>
    <ul class="ul">{lis(T["fu_b"])}</ul>
  </div>
  <div class="fusion reveal">
    <svg viewBox="0 0 520 520" aria-hidden="true"><defs><linearGradient id="fg" x1="0" x2="1"><stop offset="0" stop-color="#33A1FF"/><stop offset="1" stop-color="#ff1a1a"/></linearGradient></defs>
      <path class="flow" d="M120 90 C 200 150, 220 200, 260 260"/><path class="flow" d="M400 90 C 320 150, 300 200, 260 260"/>
      <path class="flow" d="M120 430 C 200 370, 220 320, 260 260"/><path class="flow" d="M400 430 C 320 370, 300 320, 260 260"/></svg>
    {"".join(f'<div class="fsrc s{i}"><b>{h}</b><span>{p}</span></div>' for i, (h, p) in enumerate(T["fu_src"]))}
    <div class="fcore">CyberBot<br>Fusion<small>2–11 s</small></div>
  </div>
</div></section>

<section class="sec" id="mleo" style="background:linear-gradient(180deg,transparent,rgba(51,161,255,.05) 50%,transparent)"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["ml_k"]}</span><h2>{T["ml_h"]}</h2><p>{T["ml_p"]}</p></div>
  <div class="cards">{"".join(f'<article class="card reveal"><span class="i">0{i + 1}</span><h3>{h}</h3><p>{p}</p></article>' for i, (h, p) in enumerate(T["ml_cards"]))}</div>
  <p class="note reveal">{T["ml_note"]}</p>
</div></section>

<section class="sec ai" id="ai"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["ai_k"]}</span><h2>{T["ai_h"]}</h2><p>{T["ai_p"]}</p></div>
  <div class="aigrid">
    <div class="roles">{"".join(f'<div class="role reveal"><b><i></i>{h}</b><p>{p}</p></div>' for h, p in T["ai_roles"])}</div>
    <div class="sov reveal"><span class="tag">CYBER3.AI</span><h3>{T["ai_sov_h"]}</h3><ul class="ul">{lis(T["ai_sov"])}</ul></div>
  </div>
</div></section>

<section class="sec" id="database"><div class="wrap two">
  <div class="reveal">
    <span class="kicker">{T["db_k"]}</span><h2>{T["db_h"]}</h2><p class="lead">{T["db_p"]}</p>
    <div class="dbnums">
      <div class="dbn"><b class="ioc" data-n="2895988">2,895,988</b><span>{T["db_l1"]}</span></div>
      <div class="dbn"><b id="fp">42,213</b><span>{T["db_l2"]}</span></div>
      <div class="dbn"><b>300+</b><span>{T["db_l3"]}</span></div>
    </div>
    <div class="vec"><span class="vi" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i></span><div><b>{T["db_vec_h"]}</b><em>{T["db_vec_t"]}</em><p>{T["db_vec_p"]}</p></div></div>
    <ul class="ul">{lis(T["db_b"])}</ul>
  </div>
  <div class="dbviz reveal" aria-hidden="true"><canvas id="dbc" width="600" height="600"></canvas><div class="c">CYBER3<br>Database<small>live</small></div></div>
</div></section>

<section class="sec" id="vas"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["vas_k"]}</span><h2>{T["vas_h"]}</h2><p>{T["vas_p"]}</p></div>
  <div class="cards">{"".join(f'<article class="card reveal"><span class="i">0{i + 1}</span><h3>{h}</h3><p>{p}</p></article>' for i, (h, p) in enumerate(T["vas_cards"]))}</div>
</div></section>

<section class="sec" id="agents" style="background:radial-gradient(60% 50% at 50% 50%,rgba(34,211,138,.05),transparent 70%)"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["ag_k"]}</span><h2>{T["ag_h"]}</h2><p>{T["ag_p"]}</p></div>
  <div class="agents">{"".join(f'<article class="agent reveal"><div class="scan"></div><span class="dot"><i></i>{T["active"]}</span><h3>{h}</h3><p>{p}</p></article>' for h, p in T["agents"])}</div>
  <p class="note reveal">{T["ag_note"]}</p>
</div></section>

<section class="sec" id="fallback"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["fb_k"]}</span><h2>{T["fb_h"]}</h2><p>{T["fb_p"]}</p></div>
  <div class="fb">{"".join(f'<div class="fbi reveal"><span class="fbx"><i></i><i></i></span><div><b>{h}</b><p>{p}</p></div></div>' for h, p in T["fb_items"])}</div>
</div></section>

<section class="sec" id="endpoint"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["ep_k"]}</span><h2>{T["ep_h"]}</h2><p>{T["ep_p"]}</p></div>
  <div class="ep">
    <div class="epb reveal"><h3>{T["ep_desk_h"]}</h3>
      <div class="dtabs">{"".join(f'<button class="dtab{" on" if i == 0 else ""}" data-i="{i}">{lb}</button>' for i, (k, lb) in enumerate(T["ep_desk_tabs"]))}</div>
      <div class="screen"><div class="dots"><i></i><i></i><i></i></div><div class="view" id="dview">{"".join(f'<img class="{"on" if i == 0 else ""}" src="/assets/desk/desktop-{k}-{sfx}.webp" alt="CYBER3 for Windows — {lb}" width="1600" height="1067" loading="lazy" decoding="async">' for i, (k, lb) in enumerate(T["ep_desk_tabs"]))}</div></div>
      <ul class="ul">{lis(T["ep_desk_b"])}</ul>
      <div class="stores"><a class="store win" href="{WINDOWS}"><svg width="18" height="18" viewBox="0 0 24 24"><path fill="currentColor" d="M3 5.1 10.4 4v7.1H3zM11.4 3.9 21 2.5v8.6h-9.6zM3 12.1h7.4v7.1L3 18.1zM11.4 12.1H21v8.6l-9.6-1.4z"/></svg>Windows</a></div>
    </div>
    <div class="epb reveal"><h3>{T["ep_mob_h"]}</h3>
      <div class="phones"><div class="phone"><img src="/assets/phones/message-check.webp" alt="" width="660" height="1467" loading="lazy"></div><div class="phone"><img src="/assets/phones/calls.webp" alt="" width="660" height="1467" loading="lazy"></div></div>
      <ul class="ul">{lis(T["ep_mob_b"])}</ul>
      <div class="stores"><a class="store gp" href="{PLAY}"><img src="/assets/google-play-badge.png" alt="Google Play" width="227" height="88" loading="lazy"></a><a class="store" href="{APPSTORE}"><img src="/assets/app-store-badge.svg" alt="App Store" width="138" height="46" loading="lazy"></a></div>
    </div>
  </div>
</div></section>

<section class="sec" id="why"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["wy_k"]}</span><h2>{T["wy_h"]}</h2></div>
  <div class="cmp reveal"><table><thead><tr><th>{T["wy_c"][0]}</th><th class="us">{T["wy_c"][1]}</th><th>{T["wy_c"][2]}</th></tr></thead>
    <tbody>{"".join(f"<tr><td>{r[0]}</td>{cmp_cell(r[1], T, True)}{cmp_cell(r[2], T)}</tr>" for r in T["wy_rows"])}</tbody></table></div>
</div></section>

<section class="sec" id="packages"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["pk_k"]}</span><h2>{T["pk_h"]}</h2><p>{T["pk_p"]}</p></div>
  <div class="pk">{"".join(f'<article class="pkc{" best" if i == 2 else ""} reveal">{pop if i == 2 else ""}<h3>{n}</h3><div class="inc">{inc}</div><ul>{lis(items)}</ul><div class="bf"><b>{T["pk_best"]}</b>{bf}</div></article>' for i, (n, inc, items, bf) in enumerate(T["packages"]))}</div>
  <p class="note reveal">{T["pk_note"]}</p>
</div></section>

<section class="sec" id="start" style="padding-top:40px"><div class="wrap">
  <div class="head reveal"><span class="kicker">{T["sp_k"]}</span><h2>{T["sp_h"]}</h2></div>
  <div class="steps">{"".join(f'<div class="step reveal"><div class="sn">{i + 1}</div><h3>{h}</h3><p>{p}</p></div>' for i, (h, p) in enumerate(T["steps"]))}</div>
</div></section>

<section><div class="wrap"><div class="endbox reveal"><h2>{T["end_h"]}</h2><p>{T["end_p"]}</p><a class="btn btn-red" href="{MAIL}">{T["nav_cta"]}</a></div></div></section>

<footer><div class="wrap">
  <div class="fgrid">
    <div><a class="brand" href="{home}"><i class="xmark" aria-hidden="true"></i><span class="fu">FasterUp</span>.AI</a><p>{T["ft_tag"]}</p><span class="certs">ISO/IEC 27001:2022 · GDPR · NIS2</span></div>
    <div><h4>{T["ft_h"][0]}</h4>{"".join(f'<a href="#{i}">{n}</a>' for i, n in list(zip(ids, T["nav"]))[:5])}</div>
    <div><h4>{T["ft_h"][1]}</h4><a href="https://cyber3.app/">CYBER3 — app</a><a href="https://cyber3.ai/">CYBER3.AI — LLM</a><a href="https://cyber3.ai/status/{st}/" target="_blank" rel="noopener">{T["ft_status"]}</a></div>
    <div><h4>{T["ft_h"][2]}</h4><a href="/contact">{T["ft_contact"]}</a><a href="/privacy">{T["ft_privacy"]}</a><a href="/terms">{T["ft_terms"]}</a></div>
  </div>
  <div class="fbot"><span>{T["ft_copy"]} · ROL PORTAL SERVICES SRL · CUI RO 36837313 · J2016016379403</span><a class="sw" href="https://cyber3.ai/status/{st}/" target="_blank" rel="noopener"><i id="swd"></i><span id="swt">…</span></a></div>
</div></footer>
''')
    o.append(JS)
    o.append("</body></html>\n")
    return "".join(o)


JS = r"""<script>
(function(){
var nav=document.getElementById('nav');function sc(){nav.classList.toggle('solid',scrollY>20)}sc();addEventListener('scroll',sc,{passive:true});
document.querySelectorAll('#links a').forEach(function(a){a.addEventListener('click',function(){nav.classList.remove('open')})});
var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target)}})},{threshold:.1,rootMargin:'0px 0px -40px 0px'});
document.querySelectorAll('.reveal').forEach(function(el){io.observe(el)});
// capturi desktop
var dt=[].slice.call(document.querySelectorAll('.dtab')),di=[].slice.call(document.querySelectorAll('#dview img'));
dt.forEach(function(b,k){b.addEventListener('click',function(){dt.forEach(function(x,j){x.classList.toggle('on',j===k)});di.forEach(function(x,j){x.classList.toggle('on',j===k)})})});
// inelele: amenințări care vin din exterior și sunt oprite pe un strat (vizualizare, nu date)
var pz=document.getElementById('pz'),NS='http://www.w3.org/2000/svg',Z=['#ff3b4b','#ff7a45','#e8c35a','#4f8cff','#22c7e8','#34d399','#9b7bff'];
var reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
function shot(){if(!pz||document.hidden)return;var a=Math.random()*Math.PI*2,k=Math.floor(Math.random()*7),R0=316,R1=288-k*32+4,c=document.createElementNS(NS,'circle');
 c.setAttribute('r','4.5');c.setAttribute('fill','#ff2020');c.setAttribute('filter','drop-shadow(0 0 6px #f00)');pz.appendChild(c);var t0=performance.now(),D=900+k*120;
 (function step(t){var p=Math.min(1,(t-t0)/D),r=R0+(R1-R0)*p;c.setAttribute('cx',300+r*Math.cos(a));c.setAttribute('cy',300+r*Math.sin(a));
  if(p<1){requestAnimationFrame(step);return}c.remove();var b=document.createElementNS(NS,'circle');b.setAttribute('cx',300+R1*Math.cos(a));b.setAttribute('cy',300+R1*Math.sin(a));
  b.setAttribute('fill','none');b.setAttribute('stroke',Z[k]);b.setAttribute('stroke-width','2');pz.appendChild(b);var t1=performance.now();
  (function burst(t){var q=Math.min(1,(t-t1)/600);b.setAttribute('r',4+22*q);b.setAttribute('opacity',1-q);if(q<1)requestAnimationFrame(burst);else b.remove()})(t1);
  var ring=document.getElementById('r'+k);if(ring){ring.setAttribute('stroke-opacity','1');ring.setAttribute('stroke-width','4');setTimeout(function(){ring.setAttribute('stroke-opacity','.55');ring.setAttribute('stroke-width','2')},380)}
 })(t0)}
if(!reduce){setInterval(shot,700);shot()}
// CYBER3 Database: cifrele REALE din manifest (+ ritmul contorului de pe blog, +0,1/s)
var L=document.documentElement.lang,els=[].slice.call(document.querySelectorAll('.ioc')),base=+(els[0]&&els[0].dataset.n)||2500000,t0=Date.now();
function fmt(n,compact){try{return compact?(n/1e6).toLocaleString(L,{maximumFractionDigits:1})+'M+':n.toLocaleString(L)}catch(e){return n}}
function draw(){var n=Math.floor(base+(Date.now()-t0)/10000);els.forEach(function(e){e.textContent=fmt(n,!!e.closest('.stat'))})}
fetch('https://cyber3-edge.cyber3.workers.dev/v1/manifest',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){if(d&&d.count){base=Math.max(+d.count,2500000);t0=Date.now();draw()}
 var fp=document.getElementById('fp');if(fp&&d&&d.count_firstparty)fp.textContent=(+d.count_firstparty).toLocaleString(L)}).catch(function(){});draw();setInterval(draw,1000);
// vizualizarea bazei: particule (surse) care curg spre nucleu
var cv=document.getElementById('dbc');if(cv&&!reduce){var x=cv.getContext('2d'),P=[];for(var i=0;i<120;i++)P.push({a:Math.random()*6.283,r:120+Math.random()*170,s:.4+Math.random()*1.2,c:Math.random()<.2?'#ff3b4b':(Math.random()<.5?'#e8c35a':'#33A1FF')});
 (function loop(){x.clearRect(0,0,600,600);P.forEach(function(p){p.r-=p.s;p.a+=.004;if(p.r<95){p.r=290;p.a=Math.random()*6.283}var X=300+p.r*Math.cos(p.a),Y=300+p.r*Math.sin(p.a);
  x.globalAlpha=Math.min(1,(p.r-95)/60);x.fillStyle=p.c;x.beginPath();x.arc(X,Y,2,0,6.283);x.fill()});x.globalAlpha=1;requestAnimationFrame(loop)})()}
// stare servicii
var U=["https://cyber3-edge.cyber3.workers.dev/v1/health","https://cyber3-vpn-cp.cyber3.workers.dev/health"];
function chk(){Promise.all(U.map(function(u){return fetch(u,{cache:"no-store"}).then(function(r){return r.ok?0:1}).catch(function(){return 1})})).then(function(r){var bad=r.reduce(function(a,b){return a+b},0),d=document.getElementById('swd'),t=document.getElementById('swt');if(!d)return;d.className=bad?'deg':'ok';t.textContent=bad?'Degraded':'All systems operational'})}chk();setInterval(chk,60000);
})();
</script>
"""


def load(c):
    if c == "en": return EN
    if c == "ro": return RO
    f = os.path.join(HERE, "i18n-nextgen", f"{c}.json")
    if not os.path.exists(f): return None
    T = dict(EN); T.update(json.load(open(f, encoding="utf-8"))); return T


if __name__ == "__main__":
    for c, _ in LANGS:
        T = load(c)
        if T is None: print(c, "LIPSĂ traducere — sărit"); continue
        out = os.path.join(OUT, "index.html" if c == "en" else f"{c}/index.html")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        open(out, "w", encoding="utf-8").write(render(T, c)); print(c, os.path.getsize(out), "bytes")
