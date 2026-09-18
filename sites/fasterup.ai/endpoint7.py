# -*- coding: utf-8 -*-
# fasterup.ai — capitolul „SOC-ul, extins la fiecare stație de lucru” (#xdr), refăcut 18 sep 2026:
#   stratul 6 = CYBER3 EDR/XDR for Desktop (capturi REALE din aplicație) · stratul 7 = CYBER3 Mobile Protection
#   + ecosistemul celor 7 straturi, cu un singur proprietar al tehnologiei, end-to-end.
# Textele: X[lang] (en/ro aici; celelalte limbi în i18n7/<lang>.py, cu aceeași structură).
import html, importlib, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Capturi desktop (assets/shots/<nume>-<ro|en>.webp) în ordinea galeriei.
DESK_SHOTS = ["home", "globalscan", "isolation", "pcscan", "vpn"]
# Capturi mobile (assets/shots/<fișier>) — completate în MOB_SHOTS după inventarul capturilor reale.
MOB_SHOTS = ["home", "guard"]

X = {}
X["en"] = dict(
  kicker="ENDPOINT XDR · CYBER3",
  h2="The SOC, extended to every workstation — and every phone",
  p="Layers 6 and 7 of the cascade run on people's devices: CYBER3 EDR/XDR for Desktop on every Windows workstation and CYBER3 Mobile Protection on every phone. Both report to the same SOC, draw on the same threat database and are orchestrated by the same MLEO — one owner of the technology, from the network sensor to the app on the phone.",
  d_tag="Layer 6 · Windows", d_h="CYBER3 EDR/XDR for Desktop",
  d_p="A native Windows app that turns every workstation into a detection and response point connected to the SOC. Digitally signed, updated automatically, managed per organization from the client console.",
  d_caps=["Dashboard", "Global Scan", "Workstation isolation", "Computer scan", "CYBER3 VPN"],
  d_blocks=[
   ("🛡️", "Real-time protection", "DNS-Shield on the whole workstation: dangerous domains are blocked at resolution, and DNS keeps working if the shield ever stops (fail-open). A local threat engine with 2.5M+ known indicators and a browser protection extension with 29,131 rules."),
   ("🔍", "Computer scan", "Checks the workstation's security posture — antivirus, firewall, UAC, updates — and scans Downloads, Temp and startup items for known malware. Score 0–100, one-click quarantine, automatic re-scan every 3 hours."),
   ("🛰️", "CYBER3 Global Scan, built in", "Discovers every device on the local network, checks 38 exposed ports and matches software versions against known CVEs — non-destructive, it only “looks at the doors”. Optional AI report saved to the organization's account."),
   ("🛑", "Workstation isolation", "At confirmed malware, or on a SOC command, the CYBER3 guardian cuts the workstation off the network while keeping the link to the SOC, so it can be reconnected remotely. It reconnects by itself after 30 minutes unless the SOC holds it; a kill-switch disarms it instantly."),
   ("🖥️", "Client console + SOC", "Organization mode starts with an activation code or silently at deployment. The desktopapp.cyber3.ai console shows the workstation inventory, status and events, and runs remote scan, isolation and reconnection — picked up by the workstation within 30 seconds. Each client sees only its own fleet."),
   ("📡", "Security telemetry", "Only security metadata leaves the workstation — heartbeat, scans, threats, isolation — through the local sensor or, off-site, through the CYBER3 cloud edge. In personal mode, nothing is sent."),
   ("🔒", "CYBER3 VPN", "Encrypted, no-logs WireGuard VPN: 400 MB free every day, unlimited by subscription, servers in 4 countries, choice of server on paid plans."),
   ("⚡", "Instant checks + backup", "Messages (AI verdict), links, phone numbers, email breaches and passwords (k-anonymity: only a hash prefix leaves the device). Backup of important files to the on-site server, with retention."),
  ],
  m_tag="Layer 7 · Android", m_h="CYBER3 Mobile Protection",
  m_p="The Android app that stops scams, phishing and dangerous sites on every employee's phone — in real time, with on-device processing. The same threat database as the sensors and workstations, refreshed every 12 hours. Available on Google Play.",
  m_caps=["Home", "Call & message protection"],
  m_blocks=[
   ("📞", "Call protection", "CYBER3 becomes the phone's Caller ID: every incoming number is checked against the threat database. Optional auto-reject for known scam numbers and a visual warning over the call screen."),
   ("💬", "Message protection", "Reads incoming notifications — SMS, WhatsApp and other apps — without SMS permissions, and warns only when a message is dangerous."),
   ("🤖", "Message check", "Paste or share a message from any app and get Safe, Suspect or Danger, with the reasons: imitated brand, risky domain, urgency or payment wording, URL tricks — explained by AI."),
   ("🌐", "Web protection", "A DNS filter on the phone, with no server in between: dangerous domains from the threat database, ads and trackers are blocked in every app."),
   ("📱", "Phone scan", "A 0–100 score: screen lock, USB debugging, developer options, security patch age; apps with admin or accessibility rights, sideloaded apps with risky permissions — and every installed app's hash checked against the threat database."),
   ("🪪", "Identity & breaches", "Email breach check with continuous monitoring every 12 hours and a notification on each new breach; password check with k-anonymity."),
   ("🔒", "CYBER3 VPN", "Encrypted, no-logs WireGuard VPN: 400 MB free every day, unlimited by subscription, 6 servers in 4 countries, split tunneling and a built-in speed test."),
   ("🔗", "Number & link check + reporting", "Check any number or link; unknown threats can be reported and, once validated by an analyst, join the shared threat database."),
  ],
  e_h="One ecosystem. One owner of the technology, end-to-end.",
  e_p="The seven layers are not products from different vendors glued together. They are one system, built, operated and supported by the same company — so there are no blind spots between products and one accountable owner for the whole chain.",
  e_where=[("1–4", "On the sensor, at your site", "Inline IPS · Active Response · L2 Shield · CYBER3 Context Fusion Engine"),
           ("5", "In the cloud, anywhere", "CYBER3 Edge — DNS-shield and the threat database at the edge"),
           ("6", "On every workstation", "CYBER3 EDR/XDR for Desktop"),
           ("7", "On every phone", "CYBER3 Mobile Protection")],
  e_shared_h="Shared by all seven layers",
  e_shared=["the same CYBER3 threat database (2.5M+ indicators, refreshed daily)", "the same SOC, 24/7", "the same MLEO orchestrator: a threat seen on one layer is enforced on the right one", "a closed loop: our own sensors contribute their indicators to the database that protects workstations and phones"],
  e_own_h="What we build and operate ourselves",
  e_own=["network sensors and their rule sets", "L2 Shield", "CYBER3 Context Fusion Engine and MLEO", "CYBER3 Edge and the threat database", "the sovereign security LLM", "the Desktop and Mobile apps", "the VPN network", "the client console and the SOC portal"],
  why_h="Why it matters for an institution",
  why=["It covers the dominant attack vector: the employee and the workstation — phishing, scams, malicious links and attachments, leaked passwords.",
       "It protects staff working in the field or remotely, not only inside the physical perimeter.",
       "Privacy by design: on-device processing and k-anonymity; no accounts required, no ads, no advertising SDKs.",
       "Endpoint telemetry feeds the same SOC and MLEO, closing the loop between network detection and endpoint detection."],
)
X["ro"] = dict(
  kicker="ENDPOINT XDR · CYBER3",
  h2="SOC-ul, extins la fiecare stație de lucru — și pe fiecare telefon",
  p="Straturile 6 și 7 ale cascadei rulează pe dispozitivele oamenilor: CYBER3 EDR/XDR for Desktop pe fiecare stație Windows și CYBER3 Mobile Protection pe fiecare telefon. Ambele raportează la același SOC, folosesc aceeași bază de amenințări și sunt orchestrate de același MLEO — un singur proprietar al tehnologiei, de la senzorul din rețea până la aplicația de pe telefon.",
  d_tag="Stratul 6 · Windows", d_h="CYBER3 EDR/XDR for Desktop",
  d_p="Aplicație nativă Windows care transformă fiecare stație într-un punct de detecție și răspuns conectat la SOC. Semnată digital, actualizată automat, administrată per organizație din consola client.",
  d_caps=["Panou principal", "Global Scan", "Izolarea stației", "Scanare calculator", "CYBER3 VPN"],
  d_blocks=[
   ("🛡️", "Protecție în timp real", "DNS-Shield pe toată stația: domeniile periculoase sunt blocate la rezolvare, iar DNS-ul continuă să meargă dacă scutul se oprește vreodată (fail-open). Motor local de amenințări cu peste 2,5 milioane de indicatori cunoscuți și extensie de protecție pentru browser cu 29.131 de reguli."),
   ("🔍", "Scanare calculator", "Verifică postura de securitate a stației — antivirus, firewall, UAC, actualizări — și scanează Downloads, Temp și elementele de pornire după malware cunoscut. Scor 0–100, carantină dintr-un clic, rescanare automată la fiecare 3 ore."),
   ("🛰️", "CYBER3 Global Scan, integrat", "Descoperă toate dispozitivele din rețeaua locală, verifică 38 de porturi expuse și compară versiunile de software cu vulnerabilitățile CVE cunoscute — nedistructiv, doar „se uită la uși”. Raport AI opțional, salvat în contul organizației."),
   ("🛑", "Izolarea stației", "La malware confirmat sau la comanda SOC, gardianul CYBER3 taie stația de la rețea, dar păstrează legătura cu SOC-ul, ca să poată fi reconectată de la distanță. Se reconectează singură după 30 de minute dacă SOC-ul nu o menține izolată; un kill-switch o dezarmează instantaneu."),
   ("🖥️", "Consola client + SOC", "Modul organizație pornește cu un cod de activare sau silențios, la desfășurare. Consola desktopapp.cyber3.ai arată inventarul stațiilor, starea și evenimentele și rulează de la distanță scanarea, izolarea și reconectarea — preluate de stație în maximum 30 de secunde. Fiecare client își vede doar flota proprie."),
   ("📡", "Telemetrie de securitate", "De pe stație pleacă doar metadate de securitate — heartbeat, scanări, amenințări, izolare — prin senzorul local sau, în afara sediului, prin edge-ul cloud CYBER3. În modul personal nu se trimite nimic."),
   ("🔒", "CYBER3 VPN", "VPN WireGuard criptat, fără loguri: 400 MB gratuit în fiecare zi, nelimitat cu abonament, servere în 4 țări, alegerea serverului pe planurile plătite."),
   ("⚡", "Verificări instant + backup", "Mesaje (verdict AI), linkuri, numere de telefon, breșe de email și parole (k-anonimitate: doar un prefix de hash părăsește dispozitivul). Backup al fișierelor importante pe serverul din sediu, cu retenție."),
  ],
  m_tag="Stratul 7 · Android", m_h="CYBER3 Mobile Protection",
  m_p="Aplicația Android care oprește scam-ul, phishing-ul și site-urile periculoase pe telefonul fiecărui angajat — în timp real, cu procesare pe dispozitiv. Aceeași bază de amenințări ca senzorii și stațiile, actualizată la 12 ore. Disponibilă pe Google Play.",
  m_caps=["Ecran principal", "Protecție apeluri și mesaje"],
  m_blocks=[
   ("📞", "Protecție apeluri", "CYBER3 devine Caller ID-ul telefonului: fiecare număr care sună e verificat în baza de amenințări. Respingere automată opțională a numerelor de scam cunoscute și avertizare vizuală peste ecranul de apel."),
   ("💬", "Protecție mesaje", "Citește notificările primite — SMS, WhatsApp și alte aplicații — fără permisiuni SMS și avertizează doar când un mesaj e periculos."),
   ("🤖", "Verificare mesaje", "Lipești sau partajezi un mesaj din orice aplicație și primești Sigur, Suspect sau Pericol, cu motivele: brand imitat, domeniu riscant, urgență sau plată, trucuri în URL — explicate de AI."),
   ("🌐", "Protecție web", "Filtru DNS pe telefon, fără niciun server la mijloc: domeniile periculoase din baza de amenințări, reclamele și trackerele sunt blocate în toate aplicațiile."),
   ("📱", "Scanare telefon", "Scor 0–100: blocarea ecranului, depanarea USB, opțiunile pentru dezvoltatori, vechimea patch-ului de securitate; aplicații cu drepturi de administrator sau accesibilitate, aplicații instalate din afara magazinului cu permisiuni riscante — iar hash-ul fiecărei aplicații e verificat în baza de amenințări."),
   ("🪪", "Identitate & breșe", "Verificarea emailului în breșe, cu monitorizare continuă la 12 ore și notificare la fiecare breșă nouă; verificarea parolei cu k-anonimitate."),
   ("🔒", "CYBER3 VPN", "VPN WireGuard criptat, fără loguri: 400 MB gratuit în fiecare zi, nelimitat cu abonament, 6 servere în 4 țări, split tunneling și test de viteză integrat."),
   ("🔗", "Verificare număr & link + raportare", "Verifici orice număr sau link; amenințările necunoscute pot fi raportate și, după validarea unui analist, intră în baza comună de amenințări."),
  ],
  e_h="Un singur ecosistem. Un singur proprietar al tehnologiei, end-to-end.",
  e_p="Cele șapte straturi nu sunt produse de la furnizori diferiți, lipite între ele. Sunt un singur sistem, construit, operat și susținut de aceeași companie — deci fără puncte oarbe între produse și cu un singur responsabil pentru tot lanțul.",
  e_where=[("1–4", "Pe senzor, la sediul tău", "Inline IPS · Active Response · L2 Shield · CYBER3 Context Fusion Engine"),
           ("5", "În cloud, oriunde", "CYBER3 Edge — DNS-shield și baza de amenințări la edge"),
           ("6", "Pe fiecare stație", "CYBER3 EDR/XDR for Desktop"),
           ("7", "Pe fiecare telefon", "CYBER3 Mobile Protection")],
  e_shared_h="Comun tuturor celor șapte straturi",
  e_shared=["aceeași bază de amenințări CYBER3 (peste 2,5 milioane de indicatori, actualizată zilnic)", "același SOC, 24/7", "același orchestrator MLEO: o amenințare văzută pe un strat e executată pe stratul potrivit", "o buclă închisă: senzorii noștri contribuie cu propriii indicatori la baza care protejează stațiile și telefoanele"],
  e_own_h="Ce construim și operăm noi înșine",
  e_own=["senzorii de rețea și seturile lor de reguli", "L2 Shield", "CYBER3 Context Fusion Engine și MLEO", "CYBER3 Edge și baza de amenințări", "LLM-ul de securitate suveran", "aplicațiile Desktop și Mobile", "rețeaua VPN", "consola client și portalul SOC"],
  why_h="De ce contează pentru o instituție",
  why=["Acoperă vectorul de atac dominant: angajatul și stația de lucru — phishing, scam, linkuri și atașamente malițioase, parole scurse.",
       "Protejează personalul aflat în teren sau în telemuncă, nu doar în perimetrul fizic.",
       "Confidențialitate prin design: procesare pe dispozitiv și k-anonimitate; fără conturi obligatorii, fără reclame, fără SDK-uri de publicitate.",
       "Telemetria de pe endpoint alimentează același SOC și MLEO, închizând bucla dintre detecția din rețea și cea de pe stație."],
)

# Celelalte limbi: i18n7/<lang>.py definește X_LANG cu aceeași structură.
for _l in ("es", "it", "de", "fr", "ru", "zh"):
    try:
        X[_l] = importlib.import_module("i18n7." + _l).X_LANG
    except Exception:
        pass


def _e(s):
    return html.escape(s, quote=False)


def _gallery(gid, shots, caps, alt_prefix):
    if not shots:
        return ""
    main = ('<figure class="x7-main"><img id="%s-main" src="%s" alt="%s" loading="lazy" width="1600" height="%d"></figure>'
            % (gid, shots[0][0], _e(alt_prefix + " — " + caps[0]), shots[0][1]))
    thumbs = "".join(
        '<button type="button" class="x7-th%s" data-g="%s" data-src="%s" data-alt="%s"><img src="%s" alt="" loading="lazy"><span>%s</span></button>'
        % (" on" if i == 0 else "", gid, s[0], _e(alt_prefix + " — " + caps[i]), s[0], _e(caps[i]))
        for i, s in enumerate(shots))
    return '<div class="x7-gal">%s<div class="x7-thumbs">%s</div></div>' % (main, thumbs)


def _blocks(blocks):
    return "".join('<div class="x7-b"><div class="x7-bi">%s</div><h4>%s</h4><p>%s</p></div>' % (i, _e(h), _e(p))
                   for i, h, p in blocks)


def endpoint_section(lang):
    d = X.get(lang, X["en"])
    sl = "ro" if lang == "ro" else "en"
    dshots = [("/assets/shots/desktop-%s-%s.webp" % (n, sl), 1067) for n in DESK_SHOTS]
    desk = ('<div class="x7-prod">'
            '<div class="x7-ph"><span class="x7-tag">%s</span><h3>%s</h3><p>%s</p></div>'
            '%s<div class="x7-blocks">%s</div></div>') % (
        _e(d["d_tag"]), _e(d["d_h"]), _e(d["d_p"]),
        _gallery("x7d", dshots, d["d_caps"], d["d_h"]), _blocks(d["d_blocks"]))
    mob = ""
    if d.get("m_blocks"):
        d = dict(d, _sl=sl)
        mob = ('<div class="x7-prod x7-mob">'
               '<div class="x7-ph"><span class="x7-tag x7-tag7">%s</span><h3>%s</h3><p>%s</p></div>'
               '%s<div class="x7-blocks">%s</div></div>') % (
            _e(d["m_tag"]), _e(d["m_h"]), _e(d["m_p"]),
            _mob_gallery(d), _blocks(d["m_blocks"]))
    where = "".join('<div class="x7-w"><b>%s</b><span class="x7-wl">%s</span><span class="x7-wn">%s</span></div>' % (_e(n), _e(l), _e(t))
                    for n, l, t in d["e_where"])
    shared = "".join("<li>%s</li>" % _e(x) for x in d["e_shared"])
    own = "".join("<span>%s</span>" % _e(x) for x in d["e_own"])
    why = "".join("<li>%s</li>" % _e(x) for x in d["why"])
    eco = ('<div class="x7-eco"><h3>%s</h3><p class="x7-ep">%s</p>'
           '<div class="x7-where">%s</div>'
           '<div class="x7-ecols"><div><h4>%s</h4><ul class="x7-shared">%s</ul></div>'
           '<div><h4>%s</h4><div class="x7-own">%s</div></div></div>'
           '<div class="x7-why"><h4>%s</h4><ul>%s</ul></div></div>') % (
        _e(d["e_h"]), _e(d["e_p"]), where, _e(d["e_shared_h"]), shared, _e(d["e_own_h"]), own, _e(d["why_h"]), why)
    return ('\n<section id="xdr" class="section x7">\n  <div class="head">\n    <div class="kicker">%s</div>\n'
            '    <h2>%s</h2>\n    <p>%s</p>\n  </div>\n  %s\n  %s\n  %s\n'
            '  <script src="/endpoint7.js" defer></script>\n</section>\n') % (
        _e(d["kicker"]), _e(d["h2"]), _e(d["p"]), desk, mob, eco)


def _mob_gallery(d):
    if not MOB_SHOTS:
        return ""
    caps = d.get("m_caps") or []
    sl = d.get("_sl", "en")
    items = "".join('<figure class="x7-phone"><img src="/assets/shots/mobile-%s-%s.webp" alt="%s" loading="lazy" width="540" height="1202"><figcaption>%s</figcaption></figure>'
                    % (n, sl, _e(d["m_h"] + " — " + (caps[i] if i < len(caps) else "")), _e(caps[i] if i < len(caps) else ""))
                    for i, n in enumerate(MOB_SHOTS))
    return '<div class="x7-phones">%s</div>' % items
