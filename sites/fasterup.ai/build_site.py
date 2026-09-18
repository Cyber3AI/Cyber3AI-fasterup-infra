# -*- coding: utf-8 -*-
# Generator i18n pentru fasterup.ai — un template, 7 limbi. Reuse exact CSS-ul cyber3.
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from defense7 import defense_section, defense_head
from site7 import OVR, packages_section
from endpoint7 import endpoint_section
BASE = os.path.join(os.path.dirname(__file__), "website")

LANGS = ["ro", "en", "es", "it", "de", "fr", "ru", "zh"]
PATH  = {"en":"/", "ro":"/ro/", "es":"/es/", "it":"/it/", "de":"/de/", "fr":"/fr/", "ru":"/ru/", "zh":"/zh/"}
HTMLLANG = {"en":"en","ro":"ro","es":"es","it":"it","de":"de","fr":"fr","ru":"ru","zh":"zh"}
CONTACT_LABEL = {"en":"Contact","ro":"Contact","es":"Contacto","it":"Contatto","de":"Kontakt","fr":"Contact","ru":"Контакты","zh":"联系"}

# Selector de limbă (identic peste tot) — ordine: RO · EN · ES · IT · DE · FR · RU · ZH
SELECT = """    <select class="lang" aria-label="%(lang_label)s" onchange="localStorage.setItem('fulang',this.value);document.cookie='fulang='+encodeURIComponent(this.value)+';path=/;max-age=31536000;samesite=lax';location.href=this.value">
      <option value="/ro/">RO</option>
      <option value="/">EN</option>
      <option value="/es/">ES</option>
      <option value="/it/">IT</option>
      <option value="/de/">DE</option>
      <option value="/fr/">FR</option>
      <option value="/ru/">RU</option>
      <option value="/zh/">中文</option>
    </select>"""

# Pe pagina rădăcină (EN): încarcă automat limba browserului. Altfel doar marchează selectorul.
AUTODETECT = """<script>
  (function(){
    var p=location.pathname;
    if(p!=='/'&&p!=='/index.html')return;
    var saved=localStorage.getItem('fulang');
    if(saved&&saved!=='/'){location.replace(saved);return;}
    if(saved==='/')return;
    // România: geo (fus orar) SAU limba browserului -> română. Altfel, limba browserului.
    var tz='';try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'';}catch(e){}
    var l=(navigator.language||'en').slice(0,2).toLowerCase();
    if(tz==='Europe/Bucharest'||l==='ro'){location.replace('/ro/');return;}
    var map={es:'/es/',it:'/it/',de:'/de/',fr:'/fr/',ru:'/ru/',zh:'/zh/'};
    if(map[l])location.replace(map[l]);
  })();
  (function(){var p=location.pathname,m=p.match(/^\\/(ro|es|it|de|fr|ru|zh)\\//),v=m?'/'+m[1]+'/':'/',s=document.querySelector('.lang');if(s)s.value=v;})();
</script>"""

MARKONLY = """<script>
  (function(){var p=location.pathname,m=p.match(/^\\/(ro|es|it|de|fr|ru|zh)\\//),v=m?'/'+m[1]+'/':'/',s=document.querySelector('.lang');if(s)s.value=v;})();
</script>"""

def detail(summary, body):
    """Acordeon „conținut în spate" — randat doar dacă există traducere (summary+body)."""
    if not summary or not body:
        return ""
    return ('\n      <details class="more"><summary>%s</summary>'
            '\n        <div class="body">%s</div>\n      </details>') % (summary, body)

def card(ico, h3, p, tags, note, feature=False, badge=None, det=""):
    cls = "card feature" if feature else "card"
    b = ('<div class="badge">%s</div>' % badge) if badge else ""
    techs = "".join("<span>%s</span>" % t for t in tags)
    return """    <article class="%s">
      %s<div class="ico">%s</div>
      <h3>%s</h3>
      <p>%s</p>
      <div class="tech">%s</div>
      <p class="note">%s</p>%s
    </article>""" % (cls, b, ico, h3, p, techs, note, det)

def xcard(ico, h3, p, summary, body):
    """Card compact pentru secțiunea Endpoint XDR (cu acordeon)."""
    return ('    <article class="card"><div class="ico">%s</div><h3>%s</h3><p>%s</p>'
            '<details class="more"><summary>%s</summary><div class="body">%s</div></details></article>'
            ) % (ico, h3, p, summary, body)

def plat(pico, h3, p, btn_label, btn_href, btn_ghost, hint, det=""):
    gc = " ghost" if btn_ghost else ""
    return """    <article class="plat">
      <div class="pico">%s</div>
      <h3>%s</h3>
      <p>%s</p>
      <a class="btn%s" href="%s">%s</a>
      <span class="hint">%s</span>%s
    </article>""" % (pico, h3, p, gc, btn_href, btn_label, hint, det)

def node(cls, b, s, body=None):
    if body:
        return ('<details class="node %s"><summary><b>%s</b><span>%s</span></summary>'
                '\n        <div class="nbody">%s</div>\n      </details>') % (cls, b, s, body)
    return '<div class="node %s"><b>%s</b><span>%s</span></div>' % (cls, b, s)

def principle(b, s):
    # Întotdeauna interactiv (acordeon) — b și s există în toate limbile.
    return '<details class="p"><summary><b>%s</b></summary><span>%s</span></details>' % (b, s)

def kanon_block(tag, summary, body):
    """Bloc kanon: dacă există un rezumat tradus → acordeon interactiv; altfel bloc simplu."""
    if summary:
        return ('<details class="kanon" open>\n      <summary><span class="tag">%s</span> %s</summary>'
                '\n      <div class="kbody">%s</div>\n    </details>') % (tag, summary, body)
    return '<div class="kanon">\n      <span class="tag">%s</span>\n      %s\n    </div>' % (tag, body)

# ---------- Pilonii CYBER3 (integrați din cyber3.ai în secțiunea Endpoint XDR) ----------
def pillar_card(p):
    items = "".join('<li>%s</li>' % i for i in p["items"])
    return ('    <article class="pillar">\n'
            '      <div class="pl-ico">%s</div>\n'
            '      <h3>%s</h3>\n'
            '      <p class="pl-lead">%s</p>\n'
            '      <div class="pl-tech"><span class="pl-tk">%s</span> %s</div>\n'
            '      <ul class="pl-list">%s</ul></article>') % (
        p["ico"], p["name"], p["lead"], p.get("tklabel", "How it works"), p["tech"], items)

DAPP = {
 "en": dict(h="XDR for desktop &amp; laptop — now with VPN, Global Scan &amp; auto-isolation",
   p="The same CYBER3.AI app runs natively on Windows — turning every workstation into an XDR endpoint connected to FasterUp Security Operations Center. New in the latest release: encrypted no-logs CYBER3 VPN (free 400 MB/day, Unlimited with a plan), CYBER3 Global Scan of the whole network, and automatic network isolation on confirmed malware — reversible remotely from the SOC. Plus device scan, anti-scam, web protection, backup to your on-prem server and breach monitoring. Officially signed for Windows; the fleet is managed per client in the operational portal.",
   home="Dashboard", prot="Protected",
   nav=["Home","CYBER3 VPN","Global Scan","Leak monitor","PC scan","Isolation","Messages","Links","Web","Backup"],
   tiles=[("🔒","CYBER3 VPN"),("🛰️","Global Scan"),("🔴","Leak monitor"),("🛡️","PC scan"),("🛑","Isolation"),("🤖","Messages"),("🔗","Links"),("🌐","Web"),("💾","Backup")]),
 "ro": dict(h="XDR pentru desktop și laptop — acum cu VPN, Global Scan și izolare automată",
   p="Aceeași aplicație CYBER3.AI rulează nativ pe Windows — transformând fiecare stație într-un endpoint XDR conectat la FasterUp Security Operations Center. Nou în ultima versiune: CYBER3 VPN criptat, fără loguri (gratuit 400 MB/zi, Nelimitat cu abonament), CYBER3 Global Scan pe toată rețeaua și izolare automată de rețea la malware confirmat — reversibilă de la distanță, din SOC. Plus scanare dispozitiv, anti-scam, protecție web, backup pe serverul din sediu și monitorizare breșe. Semnată oficial pentru Windows; flota se administrează per client în portalul operațional.",
   home="Tablou de bord", prot="Protejat",
   nav=["Acasă","CYBER3 VPN","Global Scan","Monitorizare","Scanare PC","Izolare","Mesaje","Linkuri","Web","Backup"],
   tiles=[("🔒","CYBER3 VPN"),("🛰️","Global Scan"),("🔴","Monitorizare"),("🛡️","Scanare PC"),("🛑","Izolare"),("🤖","Mesaje"),("🔗","Linkuri"),("🌐","Web"),("💾","Backup")]),
}

def desktop_app_mock(lang):
    # CAPTURI REALE din aplicația desktop (nu mock CSS) — randate headless din app (ImageComposeScene),
    # regenerate la fiecare versiune cu CYBER3_SHOT_DIR (vezi preview/App.kt shotMode). RO pe pagina RO, EN în rest.
    d = DAPP.get(lang, DAPP["en"])
    sl = "ro" if lang == "ro" else "en"
    st = "width:100%;height:auto;border-radius:12px;border:1px solid rgba(30,76,149,.55);box-shadow:0 10px 34px rgba(0,0,0,.4)"
    return ('  <div class="dapp-wrap">\n'
        '    <div class="dapp-shots" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px">\n'
        '      <img src="/assets/shots/desktop-home-%s.png" alt="CYBER3.AI Windows — dashboard" loading="lazy" style="%s">\n'
        '      <img src="/assets/shots/desktop-vpn-%s.png" alt="CYBER3 VPN — Windows" loading="lazy" style="%s">\n'
        '    </div>\n'
        '    <div class="dapp-note"><h3>%s</h3><p>%s</p></div>\n'
        '  </div>\n') % (sl, st, sl, st, d["h"], d["p"])

XPILLARS = {
 "en": dict(
   sub="Six pillars on every endpoint — each connected to FasterUp Security Operations Center. Per-capability detail below.",
   pillars=[
     dict(ico="🔒", name="VPN Total Protection", tklabel="The three tiers", lead="From a free VPN every day to unlimited protection — on mobile and Windows.", tech="Standard is free: a device-wide DNS filter plus a real encrypted no-logs VPN — 400 MB free every day through our own exit servers. Unlimited VPN adds unlimited traffic and unlimited devices on high-speed servers in 4 countries (3 continents), with kill switch, split tunneling and server choice. Maximum Protection adds ultimate-speed servers plus Scam Shield Pro, Data Removal (GDPR) and breach monitoring.", items=["Free — DNS filter + VPN 400 MB/day","Unlimited VPN — unlimited traffic &amp; devices, kill switch, split tunneling","Maximum Protection — ultimate servers + identity"]),
     dict(ico="🛡️", name="Phone Protection", tklabel="How it works",
       lead="Stops fraudulent calls and messages before they reach the user.",
       tech="Incoming numbers and SMS are screened in real time against scam, spam and fraud feeds; classification runs on-device, so no contact data leaves the endpoint.",
       items=["Scam &amp; spam call blocking","Fraudulent SMS detection","Caller reputation lookup"]),
     dict(ico="📱", name="Device Security Scan", tklabel="How it works",
       lead="A 0–100 posture score for every workstation and mobile.",
       tech="Audits screen lock, OS updates, firewall and risky permissions, then scans installed apps and files against a live malware database — with one-tap fixes and quarantine.",
       items=["0–100 security posture score","Malware scan of apps &amp; files","One-tap fixes &amp; quarantine","Auto network isolation on malware (Windows)"]),
     dict(ico="🌐", name="Web &amp; Network Protection", tklabel="How it works",
       lead="Blocks dangerous sites device-wide; encrypts the connection.",
       tech="A device-wide DNS filter blocks malicious and ad domains across every app — on-device, no traffic rerouted. Links are checked against 2.5M+ indicators; an optional encrypted, no-logs VPN routes through our own exit servers.",
       items=["Device-wide DNS filtering","Link check vs 2.5M+ threats","Optional encrypted no-logs VPN","CYBER3 Global Scan — whole-network scan"]),
     dict(ico="🤖", name="Instant Anti-Scam Checks", tklabel="How it works",
       lead="Staff paste a message, link, number or password — instant verdict.",
       tech="An AI engine plus live threat intelligence return a verdict in seconds and explain, in plain words, why something is risky. Passwords use k-anonymity — only a hashed prefix leaves the device.",
       items=["Message &amp; link verdicts","Phone-number reputation","Password leak check (k-anonymity)"]),
     dict(ico="🪪", name="Identity &amp; Monitoring", tklabel="How it works",
       lead="Know the moment staff credentials leak — and where they are exposed.",
       tech="Continuous breach monitoring alerts when an email appears in a new leak; a 0–100 exposure score shows which breaches and what data were exposed. Email is never stored.",
       items=["Continuous breach monitoring","0–100 identity exposure score","Digital footprint report"]),
   ]),
 "ro": dict(
   sub="Șase piloni pe fiecare endpoint — fiecare conectat la FasterUp Security Operations Center. Detaliile pe fiecare capabilitate mai jos.",
   pillars=[
     dict(ico="🔒", name="VPN Total Protection", tklabel="Cele trei niveluri", lead="De la VPN gratuit în fiecare zi la protecție nelimitată — pe mobil și Windows.", tech="Standard e gratuit: filtru DNS pe tot dispozitivul plus un VPN real criptat, fără loguri — 400 MB gratuit în fiecare zi, prin serverele noastre de ieșire. VPN Nelimitat adaugă trafic și dispozitive nelimitate pe servere de mare viteză din 4 țări (3 continente), cu kill switch, split tunneling și alegerea serverului. Protecție maximă adaugă servere de viteză supremă plus Scam Shield Pro, Ștergere date (GDPR) și monitorizare breșe.", items=["Gratuit — filtru DNS + VPN 400 MB/zi","VPN Nelimitat — trafic și dispozitive nelimitate, kill switch, split tunneling","Protecție maximă — servere supreme + identitate"]),
     dict(ico="🛡️", name="Protecție telefon", tklabel="Cum funcționează",
       lead="Oprește apelurile și mesajele frauduloase înainte să ajungă la utilizator.",
       tech="Numerele și SMS-urile primite sunt verificate în timp real față de fluxuri de scam, spam și fraudă; clasificarea rulează on-device, deci datele de contact nu părăsesc endpoint-ul.",
       items=["Blocare apeluri scam &amp; spam","Detecție SMS fraudulos","Reputația apelantului"]),
     dict(ico="📱", name="Scanare dispozitiv", tklabel="Cum funcționează",
       lead="Un scor 0–100 de postură pentru fiecare stație și mobil.",
       tech="Verifică blocarea ecranului, actualizările OS, firewall-ul și permisiunile riscante, apoi scanează aplicațiile și fișierele față de o bază de malware live — cu remedieri și carantină rapidă.",
       items=["Scor de securitate 0–100","Scanare malware aplicații &amp; fișiere","Remedieri &amp; carantină rapidă","Izolare automată de rețea la malware (Windows)"]),
     dict(ico="🌐", name="Protecție Web &amp; rețea", tklabel="Cum funcționează",
       lead="Blochează site-urile periculoase pe tot dispozitivul; criptează conexiunea.",
       tech="Un filtru DNS pe tot dispozitivul blochează domeniile malițioase și de reclame în toate aplicațiile — on-device, fără a reruta traficul. Linkurile se verifică față de 2,5M+ indicatori; un VPN opțional criptat, fără loguri, trece prin serverele noastre de ieșire.",
       items=["Filtru DNS pe tot dispozitivul","Verificare linkuri vs 2,5M+ amenințări","VPN opțional criptat, fără loguri","CYBER3 Global Scan — scanează toată rețeaua"]),
     dict(ico="🤖", name="Verificări instant Anti-Scam", tklabel="Cum funcționează",
       lead="Angajații lipesc un mesaj, link, număr sau parolă — verdict instant.",
       tech="Un motor AI plus inteligență de amenințare live întorc un verdict în secunde și explică, pe înțeles, de ce ceva e riscant. Parolele folosesc k-anonymity — doar un prefix de hash părăsește dispozitivul.",
       items=["Verdict mesaje &amp; linkuri","Reputația numărului de telefon","Verificare parolă scursă (k-anonymity)"]),
     dict(ico="🪪", name="Identitate &amp; Monitorizare", tklabel="Cum funcționează",
       lead="Află în clipa în care credențialele se scurg — și unde sunt expuse.",
       tech="Monitorizarea continuă a breșelor alertează când un email apare într-o scurgere nouă; un scor de expunere 0–100 arată în ce breșe și ce date au fost expuse. Emailul nu e stocat niciodată.",
       items=["Monitorizare continuă a breșelor","Scor de expunere identitate 0–100","Raport amprentă digitală"]),
   ]),
 "es": dict(kicker="ENDPOINT XDR · CYBER3.AI", h2="El SOC, extendido a cada estación de trabajo", nav="Endpoint XDR",
   p="Lo que distingue esta oferta: la app CYBER3.AI se instala en equipos de escritorio, portátiles y móviles — convirtiendo cada endpoint en un punto de detección y respuesta conectado al mismo SOC. XDR real, alimentado por la misma inteligencia de amenazas en vivo. La mayoría de las comprobaciones se ejecutan en el dispositivo, así que la protección funciona sin conexión y los datos permanecen privados.",
   sub="Seis pilares en cada endpoint — conectados a FasterUp Security Operations Center.",
   pillars=[
     dict(ico="🔒", name="VPN Protección Total", tklabel="Los tres niveles", lead="De una VPN gratis cada día a protección ilimitada — en móvil y Windows.", tech="Standard es gratis: filtro DNS en todo el dispositivo más una VPN real cifrada sin registros — 400 MB gratis cada día a través de nuestros propios servidores de salida. VPN Ilimitada añade tráfico y dispositivos ilimitados en servidores de alta velocidad en 4 países (3 continentes), con kill switch, split tunneling y elección de servidor. Protección máxima añade servidores de máxima velocidad más Scam Shield Pro, Eliminación de datos (RGPD) y monitorización de brechas.", items=["Gratis — filtro DNS + VPN 400 MB/día","VPN Ilimitada — tráfico y dispositivos ilimitados, kill switch","Protección máxima — servidores máximos + identidad"]),
     dict(ico="🛡️", name="Protección telefónica", tklabel="Cómo funciona", lead="Detiene llamadas y mensajes fraudulentos antes de que lleguen al usuario.", tech="Los números y SMS entrantes se filtran en tiempo real frente a fuentes de estafa, spam y fraude; la clasificación se ejecuta en el dispositivo, así que ningún dato de contacto sale del endpoint.", items=["Bloqueo de llamadas estafa y spam","Detección de SMS fraudulentos","Reputación del llamante"]),
     dict(ico="📱", name="Escaneo de seguridad del dispositivo", tklabel="Cómo funciona", lead="Una puntuación de postura 0–100 para cada estación y móvil.", tech="Audita el bloqueo de pantalla, las actualizaciones del SO, el firewall y los permisos arriesgados, luego escanea apps y archivos frente a una base de malware en vivo — con correcciones y cuarentena en un toque.", items=["Puntuación de seguridad 0–100","Escaneo de malware de apps y archivos","Correcciones y cuarentena en un toque","Aislamiento de red automático ante malware (Windows)"]),
     dict(ico="🌐", name="Protección web y de red", tklabel="Cómo funciona", lead="Bloquea sitios peligrosos en todo el dispositivo; cifra la conexión.", tech="Un filtro DNS en todo el dispositivo bloquea dominios maliciosos y de anuncios en todas las apps — en el dispositivo, sin redirigir el tráfico. Los enlaces se comprueban frente a más de 2,5M de indicadores; una VPN cifrada opcional sin registros pasa por nuestros propios servidores de salida.", items=["Filtrado DNS en todo el dispositivo","Comprobación de enlaces vs 2,5M+ amenazas","VPN cifrada opcional sin registros","CYBER3 Global Scan — escaneo de toda la red"]),
     dict(ico="🤖", name="Comprobaciones antifraude instantáneas", tklabel="Cómo funciona", lead="El personal pega un mensaje, enlace, número o contraseña — veredicto instantáneo.", tech="Un motor de IA y la inteligencia de amenazas en vivo devuelven un veredicto en segundos y explican, en lenguaje claro, por qué algo es arriesgado. Las contraseñas usan k-anonymity — solo un prefijo hash sale del dispositivo.", items=["Veredictos de mensajes y enlaces","Reputación de número de teléfono","Comprobación de contraseña filtrada (k-anonymity)"]),
     dict(ico="🪪", name="Identidad y monitorización", tklabel="Cómo funciona", lead="Sepa en el momento en que se filtran las credenciales — y dónde están expuestas.", tech="La monitorización continua de brechas avisa cuando un correo aparece en una filtración nueva; una puntuación de exposición 0–100 muestra en qué brechas y qué datos quedaron expuestos. El correo nunca se almacena.", items=["Monitorización continua de brechas","Puntuación de exposición de identidad 0–100","Informe de huella digital"]),
   ]),
 "it": dict(kicker="ENDPOINT XDR · CYBER3.AI", h2="Il SOC, esteso a ogni postazione di lavoro", nav="Endpoint XDR",
   p="Ciò che distingue questa offerta: l'app CYBER3.AI si installa su desktop, laptop e dispositivi mobili — trasformando ogni endpoint in un punto di rilevamento e risposta connesso allo stesso SOC. XDR reale, alimentato dalla stessa intelligence sulle minacce in tempo reale. La maggior parte dei controlli viene eseguita sul dispositivo, così la protezione funziona offline e i dati restano privati.",
   sub="Sei pilastri su ogni endpoint — connessi a FasterUp Security Operations Center.",
   pillars=[
     dict(ico="🔒", name="VPN Protezione Totale", tklabel="I tre livelli", lead="Da una VPN gratuita ogni giorno alla protezione illimitata — su mobile e Windows.", tech="Standard è gratis: filtro DNS su tutto il dispositivo più una vera VPN cifrata senza log — 400 MB gratis ogni giorno attraverso i nostri server di uscita. VPN Illimitata aggiunge traffico e dispositivi illimitati su server ad alta velocità in 4 paesi (3 continenti), con kill switch, split tunneling e scelta del server. Protezione massima aggiunge server di velocità massima più Scam Shield Pro, Rimozione dati (GDPR) e monitoraggio violazioni.", items=["Gratis — filtro DNS + VPN 400 MB/giorno","VPN Illimitata — traffico e dispositivi illimitati, kill switch","Protezione massima — server massimi + identità"]),
     dict(ico="🛡️", name="Protezione telefono", tklabel="Come funziona", lead="Blocca chiamate e messaggi fraudolenti prima che raggiungano l'utente.", tech="Numeri e SMS in arrivo vengono filtrati in tempo reale rispetto a feed di truffa, spam e frode; la classificazione viene eseguita sul dispositivo, quindi nessun dato di contatto lascia l'endpoint.", items=["Blocco chiamate truffa e spam","Rilevamento SMS fraudolenti","Reputazione del chiamante"]),
     dict(ico="📱", name="Scansione di sicurezza del dispositivo", tklabel="Come funziona", lead="Un punteggio di postura 0–100 per ogni postazione e dispositivo mobile.", tech="Verifica blocco schermo, aggiornamenti del SO, firewall e permessi rischiosi, poi scansiona app e file rispetto a un database malware live — con correzioni e quarantena con un tocco.", items=["Punteggio di sicurezza 0–100","Scansione malware di app e file","Correzioni e quarantena rapide","Isolamento di rete automatico al malware (Windows)"]),
     dict(ico="🌐", name="Protezione Web e rete", tklabel="Come funziona", lead="Blocca i siti pericolosi su tutto il dispositivo; cifra la connessione.", tech="Un filtro DNS su tutto il dispositivo blocca domini dannosi e pubblicitari in tutte le app — sul dispositivo, senza reindirizzare il traffico. I link vengono controllati rispetto a oltre 2,5M di indicatori; una VPN cifrata opzionale senza log passa dai nostri server di uscita.", items=["Filtro DNS su tutto il dispositivo","Controllo link vs 2,5M+ minacce","VPN cifrata opzionale senza log","CYBER3 Global Scan — scansione di tutta la rete"]),
     dict(ico="🤖", name="Controlli anti-truffa istantanei", tklabel="Come funziona", lead="Il personale incolla un messaggio, link, numero o password — verdetto istantaneo.", tech="Un motore IA e l'intelligence sulle minacce in tempo reale restituiscono un verdetto in pochi secondi e spiegano, in parole semplici, perché qualcosa è rischioso. Le password usano k-anonymity — solo un prefisso hash lascia il dispositivo.", items=["Verdetti su messaggi e link","Reputazione del numero di telefono","Controllo password compromessa (k-anonymity)"]),
     dict(ico="🪪", name="Identità e monitoraggio", tklabel="Come funziona", lead="Scopri nel momento in cui le credenziali trapelano — e dove sono esposte.", tech="Il monitoraggio continuo delle violazioni avvisa quando un'email compare in una nuova fuga; un punteggio di esposizione 0–100 mostra in quali violazioni e quali dati sono stati esposti. L'email non viene mai memorizzata.", items=["Monitoraggio continuo delle violazioni","Punteggio di esposizione identità 0–100","Report impronta digitale"]),
   ]),
 "de": dict(kicker="ENDPOINT XDR · CYBER3.AI", h2="Das SOC, erweitert auf jeden Arbeitsplatz", nav="Endpoint XDR",
   p="Was dieses Angebot auszeichnet: Die CYBER3.AI-App wird auf Desktops, Laptops und Mobilgeräten installiert — und macht jeden Endpunkt zu einem Erkennungs- und Reaktionspunkt, der mit demselben SOC verbunden ist. Echtes XDR, gespeist von derselben Live-Bedrohungsintelligenz. Die meisten Prüfungen laufen auf dem Gerät, sodass der Schutz offline funktioniert und Daten privat bleiben.",
   sub="Sechs Säulen auf jedem Endpunkt — verbunden mit FasterUp Security Operations Center.",
   pillars=[
     dict(ico="🔒", name="VPN Total Protection", tklabel="Die drei Stufen", lead="Vom kostenlosen VPN jeden Tag bis zu unbegrenztem Schutz — auf Mobilgerät und Windows.", tech="Standard ist kostenlos: ein geräteweiter DNS-Filter plus ein echtes verschlüsseltes No-Logs-VPN — 400 MB gratis pro Tag über unsere eigenen Exit-Server. Unbegrenztes VPN fügt unbegrenzten Traffic und unbegrenzte Geräte auf Hochgeschwindigkeitsservern in 4 Ländern (3 Kontinente) hinzu — mit Kill Switch, Split Tunneling und Serverwahl. Maximaler Schutz fügt Server mit Höchstgeschwindigkeit plus Scam Shield Pro, Datenentfernung (DSGVO) und Breach-Monitoring hinzu.", items=["Kostenlos — DNS-Filter + VPN 400 MB/Tag","Unbegrenztes VPN — unbegrenzter Traffic und Geräte, Kill Switch","Maximaler Schutz — Top-Server + Identität"]),
     dict(ico="🛡️", name="Telefonschutz", tklabel="So funktioniert es", lead="Stoppt betrügerische Anrufe und Nachrichten, bevor sie den Nutzer erreichen.", tech="Eingehende Nummern und SMS werden in Echtzeit gegen Betrugs-, Spam- und Fraud-Feeds geprüft; die Klassifizierung läuft auf dem Gerät, sodass keine Kontaktdaten den Endpunkt verlassen.", items=["Blockieren von Betrugs- und Spam-Anrufen","Erkennung betrügerischer SMS","Anrufer-Reputation"]),
     dict(ico="📱", name="Geräte-Sicherheitsscan", tklabel="So funktioniert es", lead="Ein 0–100 Posture-Score für jede Workstation und jedes Mobilgerät.", tech="Prüft Bildschirmsperre, OS-Updates, Firewall und riskante Berechtigungen, scannt dann Apps und Dateien gegen eine Live-Malware-Datenbank — mit Fixes und Quarantäne per Tippen.", items=["Sicherheits-Score 0–100","Malware-Scan von Apps und Dateien","Fixes und Quarantäne per Tipp","Automatische Netzwerk-Isolierung bei Malware (Windows)"]),
     dict(ico="🌐", name="Web- und Netzwerkschutz", tklabel="So funktioniert es", lead="Blockiert gefährliche Seiten geräteweit; verschlüsselt die Verbindung.", tech="Ein geräteweiter DNS-Filter blockiert bösartige und Werbe-Domains in allen Apps — auf dem Gerät, ohne Umleitung des Datenverkehrs. Links werden gegen 2,5 Mio.+ Indikatoren geprüft; ein optionales verschlüsseltes No-Logs-VPN läuft über unsere eigenen Exit-Server.", items=["Geräteweites DNS-Filtern","Link-Prüfung vs 2,5 Mio.+ Bedrohungen","Optionales verschlüsseltes No-Logs-VPN","CYBER3 Global Scan — Scan des gesamten Netzwerks"]),
     dict(ico="🤖", name="Sofortige Anti-Betrugs-Prüfungen", tklabel="So funktioniert es", lead="Mitarbeiter fügen Nachricht, Link, Nummer oder Passwort ein — sofortiges Urteil.", tech="Eine KI-Engine plus Live-Bedrohungsintelligenz liefern in Sekunden ein Urteil und erklären in einfachen Worten, warum etwas riskant ist. Passwörter nutzen k-anonymity — nur ein Hash-Präfix verlässt das Gerät.", items=["Urteile zu Nachrichten und Links","Rufnummern-Reputation","Passwort-Leak-Prüfung (k-anonymity)"]),
     dict(ico="🪪", name="Identität und Monitoring", tklabel="So funktioniert es", lead="Erfahren Sie im Moment, in dem Zugangsdaten geleakt werden — und wo sie exponiert sind.", tech="Kontinuierliches Breach-Monitoring warnt, wenn eine E-Mail in einem neuen Leak auftaucht; ein 0–100 Expositions-Score zeigt, in welchen Breaches und welche Daten exponiert wurden. Die E-Mail wird nie gespeichert.", items=["Kontinuierliches Breach-Monitoring","Identitäts-Expositions-Score 0–100","Digital-Footprint-Bericht"]),
   ]),
 "fr": dict(kicker="ENDPOINT XDR · CYBER3.AI", h2="Le SOC, étendu à chaque poste de travail", nav="Endpoint XDR",
   p="Ce qui distingue cette offre : l'app CYBER3.AI s'installe sur ordinateurs de bureau, portables et mobiles — transformant chaque endpoint en point de détection et de réponse connecté au même SOC. Un vrai XDR, alimenté par la même intelligence des menaces en direct. La plupart des vérifications s'exécutent sur l'appareil, la protection fonctionne donc hors ligne et les données restent privées.",
   sub="Six piliers sur chaque endpoint — connectés à FasterUp Security Operations Center.",
   pillars=[
     dict(ico="🔒", name="VPN Protection Totale", tklabel="Les trois niveaux", lead="D'un VPN gratuit chaque jour à une protection illimitée — sur mobile et Windows.", tech="Standard est gratuit : un filtre DNS sur tout l'appareil plus un vrai VPN chiffré sans journaux — 400 Mo gratuits chaque jour via nos propres serveurs de sortie. VPN Illimité ajoute trafic et appareils illimités sur des serveurs haute vitesse dans 4 pays (3 continents), avec kill switch, split tunneling et choix du serveur. Protection maximale ajoute des serveurs ultra-rapides plus Scam Shield Pro, Suppression de données (RGPD) et surveillance des violations.", items=["Gratuit — filtre DNS + VPN 400 Mo/jour","VPN Illimité — trafic et appareils illimités, kill switch","Protection maximale — serveurs ultimes + identité"]),
     dict(ico="🛡️", name="Protection téléphone", tklabel="Comment ça marche", lead="Stoppe les appels et messages frauduleux avant qu'ils n'atteignent l'utilisateur.", tech="Les numéros et SMS entrants sont filtrés en temps réel face à des flux d'arnaque, spam et fraude ; la classification s'exécute sur l'appareil, donc aucune donnée de contact ne quitte l'endpoint.", items=["Blocage des appels arnaque et spam","Détection des SMS frauduleux","Réputation de l'appelant"]),
     dict(ico="📱", name="Analyse de sécurité de l'appareil", tklabel="Comment ça marche", lead="Un score de posture 0–100 pour chaque poste et mobile.", tech="Vérifie le verrouillage d'écran, les mises à jour de l'OS, le pare-feu et les permissions à risque, puis analyse apps et fichiers face à une base de malwares en direct — avec corrections et quarantaine en un geste.", items=["Score de sécurité 0–100","Analyse malware des apps et fichiers","Corrections et quarantaine rapides","Isolement réseau automatique en cas de malware (Windows)"]),
     dict(ico="🌐", name="Protection Web et réseau", tklabel="Comment ça marche", lead="Bloque les sites dangereux sur tout l'appareil ; chiffre la connexion.", tech="Un filtre DNS sur tout l'appareil bloque les domaines malveillants et publicitaires dans toutes les apps — sur l'appareil, sans réacheminer le trafic. Les liens sont vérifiés face à plus de 2,5 M d'indicateurs ; un VPN chiffré optionnel sans journaux passe par nos propres serveurs de sortie.", items=["Filtrage DNS sur tout l'appareil","Vérification de liens vs 2,5 M+ menaces","VPN chiffré optionnel sans journaux","CYBER3 Global Scan — analyse de tout le réseau"]),
     dict(ico="🤖", name="Vérifications anti-arnaque instantanées", tklabel="Comment ça marche", lead="Le personnel colle un message, lien, numéro ou mot de passe — verdict instantané.", tech="Un moteur IA et l'intelligence des menaces en direct renvoient un verdict en quelques secondes et expliquent, en mots simples, pourquoi quelque chose est risqué. Les mots de passe utilisent la k-anonymity — seul un préfixe de hachage quitte l'appareil.", items=["Verdicts sur messages et liens","Réputation du numéro de téléphone","Vérification de mot de passe fuité (k-anonymity)"]),
     dict(ico="🪪", name="Identité et surveillance", tklabel="Comment ça marche", lead="Sachez à l'instant où les identifiants fuitent — et où ils sont exposés.", tech="La surveillance continue des violations alerte quand un e-mail apparaît dans une nouvelle fuite ; un score d'exposition 0–100 montre dans quelles violations et quelles données ont été exposées. L'e-mail n'est jamais stocké.", items=["Surveillance continue des violations","Score d'exposition d'identité 0–100","Rapport d'empreinte numérique"]),
   ]),
 "ru": dict(kicker="ENDPOINT XDR · CYBER3.AI", h2="SOC, расширенный на каждое рабочее место", nav="Endpoint XDR",
   p="Что отличает это предложение: приложение CYBER3.AI устанавливается на настольные ПК, ноутбуки и мобильные устройства — превращая каждую конечную точку в точку обнаружения и реагирования, подключённую к тому же SOC. Настоящий XDR, питаемый той же актуальной разведкой угроз. Большинство проверок выполняется на устройстве, поэтому защита работает офлайн, а данные остаются приватными.",
   sub="Шесть столпов на каждой конечной точке — подключены к FasterUp Security Operations Center.",
   pillars=[
     dict(ico="🔒", name="VPN Полная защита", tklabel="Три уровня", lead="От бесплатного VPN каждый день до безлимитной защиты — на мобильном и Windows.", tech="Standard бесплатный: DNS-фильтр на всём устройстве плюс настоящий шифрованный VPN без логов — 400 МБ бесплатно каждый день через наши собственные exit-серверы. Безлимитный VPN добавляет безлимитный трафик и устройства на высокоскоростных серверах в 4 странах (3 континента), с kill switch, split tunneling и выбором сервера. Максимальная защита добавляет серверы максимальной скорости плюс Scam Shield Pro, Удаление данных (GDPR) и мониторинг утечек.", items=["Бесплатно — DNS-фильтр + VPN 400 МБ/день","Безлимитный VPN — безлимитный трафик и устройства, kill switch","Максимальная защита — топ-серверы + идентичность"]),
     dict(ico="🛡️", name="Защита телефона", tklabel="Как это работает", lead="Останавливает мошеннические звонки и сообщения до того, как они дойдут до пользователя.", tech="Входящие номера и SMS проверяются в реальном времени по фидам мошенничества, спама и фрода; классификация выполняется на устройстве, поэтому данные контактов не покидают конечную точку.", items=["Блокировка мошеннических и спам-звонков","Обнаружение мошеннических SMS","Репутация звонящего"]),
     dict(ico="📱", name="Сканирование безопасности устройства", tklabel="Как это работает", lead="Оценка состояния 0–100 для каждой рабочей станции и мобильного.", tech="Проверяет блокировку экрана, обновления ОС, брандмауэр и опасные разрешения, затем сканирует приложения и файлы по живой базе вредоносного ПО — с исправлениями и карантином в одно касание.", items=["Оценка безопасности 0–100","Сканирование приложений и файлов на вредонос","Исправления и карантин в касание","Автоматическая изоляция от сети при вредоносе (Windows)"]),
     dict(ico="🌐", name="Защита веб и сети", tklabel="Как это работает", lead="Блокирует опасные сайты на всём устройстве; шифрует соединение.", tech="DNS-фильтр на всём устройстве блокирует вредоносные и рекламные домены во всех приложениях — на устройстве, без перенаправления трафика. Ссылки проверяются по 2,5 млн+ индикаторов; опциональный шифрованный VPN без логов идёт через наши собственные exit-серверы.", items=["DNS-фильтрация на всём устройстве","Проверка ссылок по 2,5 млн+ угроз","Опциональный шифрованный VPN без логов","CYBER3 Global Scan — сканирование всей сети"]),
     dict(ico="🤖", name="Мгновенные антимошеннические проверки", tklabel="Как это работает", lead="Сотрудник вставляет сообщение, ссылку, номер или пароль — мгновенный вердикт.", tech="ИИ-движок и актуальная разведка угроз выдают вердикт за секунды и объясняют простыми словами, почему что-то опасно. Пароли используют k-anonymity — устройство покидает только префикс хеша.", items=["Вердикты по сообщениям и ссылкам","Репутация номера телефона","Проверка утёкшего пароля (k-anonymity)"]),
     dict(ico="🪪", name="Идентичность и мониторинг", tklabel="Как это работает", lead="Узнайте в момент утечки учётных данных — и где они раскрыты.", tech="Непрерывный мониторинг утечек оповещает, когда email появляется в новой утечке; оценка экспозиции 0–100 показывает, в каких утечках и какие данные раскрыты. Email никогда не хранится.", items=["Непрерывный мониторинг утечек","Оценка экспозиции идентичности 0–100","Отчёт о цифровом следе"]),
   ]),
 "zh": dict(kicker="ENDPOINT XDR · CYBER3.AI", h2="将 SOC 延伸到每一台工作站", nav="Endpoint XDR",
   p="本方案的独特之处：CYBER3.AI 应用可安装在台式机、笔记本和移动设备上——让每个终端都成为连接到同一 SOC 的检测与响应点。真正的 XDR，由同一套实时威胁情报驱动。大多数检测在设备本地运行，因此离线也能防护，数据保持私密。",
   sub="每个终端上的六大支柱——连接到 FasterUp Security Operations Center。",
   pillars=[
     dict(ico="🔒", name="VPN 全面保护", tklabel="三个等级", lead="从每天免费的 VPN 到无限保护——手机与 Windows 通用。", tech="Standard 免费：全设备 DNS 过滤，外加真正的加密无日志 VPN——每天免费 400 MB，经由我们自有出口服务器。无限流量 VPN 增加高速服务器上的无限流量和无限设备（4 个国家、3 大洲），支持 kill switch、分应用隧道和服务器选择。至尊防护增加极速服务器，外加 Scam Shield Pro、数据删除（GDPR）和泄露监控。", items=["免费 — DNS 过滤 + 每天 400 MB VPN","无限流量 VPN — 无限流量与设备，kill switch","至尊防护 — 顶级服务器 + 身份保护"]),
     dict(ico="🛡️", name="电话防护", tklabel="工作原理", lead="在诈骗来电和短信到达用户之前将其拦截。", tech="来电号码和短信会实时对照诈骗、垃圾和欺诈情报源进行筛查；分类在设备本地运行，联系人数据不会离开终端。", items=["拦截诈骗与垃圾来电","识别欺诈短信","来电者信誉查询"]),
     dict(ico="📱", name="设备安全扫描", tklabel="工作原理", lead="为每台工作站和移动设备提供 0–100 安全评分。", tech="检查屏幕锁、系统更新、防火墙和高风险权限，再对照实时恶意软件库扫描应用与文件——一键修复与隔离。", items=["0–100 安全评分","应用与文件恶意软件扫描","一键修复与隔离","检测到恶意软件时自动网络隔离（Windows）"]),
     dict(ico="🌐", name="Web 与网络防护", tklabel="工作原理", lead="在整台设备上拦截危险网站；加密连接。", tech="全设备 DNS 过滤在所有应用中拦截恶意与广告域名——本地运行，不转发流量。链接对照 250万+ 指标核查；可选的加密无日志 VPN 通过我们自有出口服务器。", items=["全设备 DNS 过滤","链接核查 vs 250万+ 威胁","可选加密无日志 VPN","CYBER3 Global Scan — 全网扫描"]),
     dict(ico="🤖", name="即时反诈骗检测", tklabel="工作原理", lead="员工粘贴消息、链接、号码或密码——即时给出判定。", tech="AI 引擎结合实时威胁情报在数秒内给出判定，并用通俗语言解释风险原因。密码采用 k-anonymity——只有哈希前缀离开设备。", items=["消息与链接判定","电话号码信誉","密码泄露检测（k-anonymity）"]),
     dict(ico="🪪", name="身份与监测", tklabel="工作原理", lead="在凭据泄露的那一刻就知道——以及暴露在何处。", tech="持续的数据泄露监测会在邮箱出现在新泄露中时提醒你；0–100 暴露评分显示涉及哪些泄露、哪些数据被暴露。邮箱从不存储。", items=["持续数据泄露监测","0–100 身份暴露评分","数字足迹报告"]),
   ]),
}

# ============ NEXTGEN SOC — 5 straturi + FasterUp Orchestrator (public, fără nume de furnizori) ============
NEXTGEN = {
 "en": dict(kicker="DEFENSE IN DEPTH", h2="Five complementary layers of autonomous defense",
   p="From the network to the host to the AI decision, extended to the workstation and mobile where the app is installed — every threat stopped even if one layer is bypassed. No two layers are redundant; each catches what the others cannot.",
   layers=[("CYBER3 Desktop EDR/XDR","Endpoint","On the workstation: malicious domains blocked at DNS, scanning, quarantine."),
           ("CYBER3 Mobile Protection","Mobile","On the phone: real-time anti-scam and DNS filtering, anywhere."),
           ("Inline IPS engine","Network","At the wire: the malicious packet dropped on the spot, in milliseconds."),
           ("Host detection &amp; response","Host","A DROP rule written straight into the host firewall — native fallback."),
           ("CyberBot Fusion","AI","Fuses 4 sources, decides autonomously, blocks even Command &amp; Control (C2).")],
   otag="PROPRIETARY CORE · OWNED END-TO-END", oh="FasterUp Orchestrator",
   op="The innovation isn't the components — it's their orchestration. FasterUp Orchestrator fuses the four sources, decides in under 11 seconds and coordinates the five layers as one organism. Proprietary technology, owned end-to-end.",
   spec_cap="from the reflex at the wire to the context decision",
   roots="Deep roots, unlimited AI resources: a sovereign security LLM (no external dependency, no token cap), the CYBER3 threat-intelligence database that grows continuously, plus network and cloud scanning."),
 "ro": dict(kicker="APĂRARE ÎN ADÂNCIME", h2="Cinci straturi complementare de apărare autonomă",
   p="De la rețea la gazdă la decizia AI, extinsă pe stație și mobil unde e instalată aplicația — fiecare amenințare oprită chiar dacă un strat e ocolit. Straturile nu sunt redundante; fiecare prinde ce ceilalți nu văd.",
   layers=[("CYBER3 Desktop EDR/XDR","Dispozitiv","Pe stație: domenii periculoase blocate la DNS, scanare, carantină."),
           ("CYBER3 Mobile Protection","Mobil","Pe telefon: anti-scam în timp real și filtrare DNS, oriunde."),
           ("Motor IPS inline","Rețea","La fir: pachetul rău e picat pe loc, în milisecunde."),
           ("Detecție &amp; răspuns pe gazdă","Gazdă","Regulă DROP scrisă direct în firewall-ul gazdei — fallback nativ."),
           ("CyberBot Fusion","AI","Fuzionează 4 surse, decide autonom, blochează inclusiv Comandă și Control (C2).")],
   otag="NUCLEU PROPRIETAR · TEHNOLOGIE END-TO-END", oh="FasterUp Orchestrator",
   op="Inovația nu sunt componentele — ci orchestrarea lor. FasterUp Orchestrator fuzionează cele patru surse, decide în sub 11 secunde și coordonează cele cinci straturi ca un singur organism. Tehnologie proprietară, deținută integral (end-to-end).",
   spec_cap="de la reflexul la fir la decizia de context",
   roots="Rădăcini adânci, resurse AI nelimitate: un LLM de securitate suveran (fără dependență externă, fără plafon de tokeni), baza de date CYBER3 de intel care crește permanent, plus scanare de rețea și cloud."),
 "es": dict(kicker="DEFENSA EN PROFUNDIDAD", h2="Cinco capas complementarias de defensa autónoma",
   p="De la red al host a la decisión de IA, extendida a la estación y al móvil donde la app está instalada — cada amenaza detenida aunque se eluda una capa. Ninguna capa es redundante; cada una detecta lo que las demás no ven.",
   layers=[("CYBER3 Desktop EDR/XDR","Dispositivo","En el equipo: dominios maliciosos bloqueados por DNS, escaneo, cuarentena."),
           ("CYBER3 Mobile Protection","Móvil","En el teléfono: anti-fraude en tiempo real y filtrado DNS, en cualquier lugar."),
           ("Motor IPS en línea","Red","En el cable: el paquete malicioso se descarta al instante, en milisegundos."),
           ("Detección y respuesta en el host","Host","Una regla DROP escrita directamente en el firewall del host — respaldo nativo."),
           ("CyberBot Fusion","IA","Fusiona 4 fuentes, decide de forma autónoma, bloquea incluso Comando y Control (C2).")],
   otag="NÚCLEO PROPIO · TECNOLOGÍA END-TO-END", oh="FasterUp Orchestrator",
   op="La innovación no son los componentes — es su orquestación. FasterUp Orchestrator fusiona las cuatro fuentes, decide en menos de 11 segundos y coordina las cinco capas como un solo organismo. Tecnología propia, controlada de extremo a extremo (end-to-end).",
   spec_cap="del reflejo en el cable a la decisión de contexto",
   roots="Raíces profundas, recursos de IA ilimitados: un LLM de seguridad soberano (sin dependencia externa, sin límite de tokens), la base de datos CYBER3 de inteligencia que crece continuamente, más escaneo de red y nube."),
 "de": dict(kicker="TIEFGESTAFFELTE VERTEIDIGUNG", h2="Fünf komplementäre Schichten autonomer Verteidigung",
   p="Vom Netzwerk über den Host bis zur KI-Entscheidung, erweitert auf Arbeitsplatz und Mobilgerät, wo die App installiert ist — jede Bedrohung gestoppt, selbst wenn eine Schicht umgangen wird. Keine Schicht ist redundant; jede fängt ab, was die anderen nicht sehen.",
   layers=[("CYBER3 Desktop EDR/XDR","Gerät","Auf dem Arbeitsplatz: bösartige Domains per DNS blockiert, Scan, Quarantäne."),
           ("CYBER3 Mobile Protection","Mobil","Auf dem Telefon: Echtzeit-Anti-Scam und DNS-Filterung, überall."),
           ("Inline-IPS-Engine","Netzwerk","Auf der Leitung: das bösartige Paket wird sofort verworfen, in Millisekunden."),
           ("Host-Erkennung &amp; -Reaktion","Host","Eine DROP-Regel direkt in der Host-Firewall — nativer Rückfall."),
           ("CyberBot Fusion","KI","Fusioniert 4 Quellen, entscheidet autonom, blockiert selbst Command &amp; Control (C2).")],
   otag="EIGENER KERN · END-TO-END-TECHNOLOGIE", oh="FasterUp Orchestrator",
   op="Die Innovation sind nicht die Komponenten — sondern ihre Orchestrierung. FasterUp Orchestrator fusioniert die vier Quellen, entscheidet in unter 11 Sekunden und koordiniert die fünf Schichten als einen Organismus. Eigene Technologie, durchgängig in eigener Hand (end-to-end).",
   spec_cap="vom Reflex auf der Leitung zur Kontextentscheidung",
   roots="Tiefe Wurzeln, unbegrenzte KI-Ressourcen: ein souveränes Sicherheits-LLM (keine externe Abhängigkeit, kein Token-Limit), die CYBER3-Threat-Intelligence-Datenbank, die stetig wächst, plus Netzwerk- und Cloud-Scan."),
 "fr": dict(kicker="DÉFENSE EN PROFONDEUR", h2="Cinq couches complémentaires de défense autonome",
   p="Du réseau à l'hôte à la décision de l'IA, étendue au poste et au mobile là où l'application est installée — chaque menace arrêtée même si une couche est contournée. Aucune couche n'est redondante ; chacune capte ce que les autres ne voient pas.",
   layers=[("CYBER3 Desktop EDR/XDR","Appareil","Sur le poste : domaines malveillants bloqués au DNS, analyse, quarantaine."),
           ("CYBER3 Mobile Protection","Mobile","Sur le téléphone : anti-arnaque en temps réel et filtrage DNS, partout."),
           ("Moteur IPS en ligne","Réseau","Sur le fil : le paquet malveillant est rejeté sur-le-champ, en millisecondes."),
           ("Détection &amp; réponse sur l'hôte","Hôte","Une règle DROP écrite directement dans le pare-feu de l'hôte — repli natif."),
           ("CyberBot Fusion","IA","Fusionne 4 sources, décide de façon autonome, bloque même le Command &amp; Control (C2).")],
   otag="NOYAU PROPRIÉTAIRE · TECHNOLOGIE END-TO-END", oh="FasterUp Orchestrator",
   op="L'innovation, ce ne sont pas les composants — c'est leur orchestration. FasterUp Orchestrator fusionne les quatre sources, décide en moins de 11 secondes et coordonne les cinq couches comme un seul organisme. Technologie propriétaire, maîtrisée de bout en bout (end-to-end).",
   spec_cap="du réflexe sur le fil à la décision de contexte",
   roots="Racines profondes, ressources IA illimitées : un LLM de sécurité souverain (sans dépendance externe, sans plafond de jetons), la base CYBER3 de renseignement qui grandit en permanence, plus l'analyse réseau et cloud."),
 "ru": dict(kicker="ЭШЕЛОНИРОВАННАЯ ЗАЩИТА", h2="Пять взаимодополняющих слоёв автономной защиты",
   p="От сети к хосту и к решению ИИ, с расширением на рабочую станцию и мобильный, где установлено приложение — каждая угроза остановлена, даже если один слой обойдён. Слои не дублируют друг друга; каждый ловит то, что не видят другие.",
   layers=[("CYBER3 Desktop EDR/XDR","Устройство","На рабочей станции: вредоносные домены блокируются на DNS, сканирование, карантин."),
           ("CYBER3 Mobile Protection","Мобильный","На телефоне: анти-скам в реальном времени и DNS-фильтрация, где угодно."),
           ("Встроенный IPS-движок","Сеть","На проводе: вредоносный пакет отбрасывается сразу, за миллисекунды."),
           ("Обнаружение и реагирование на хосте","Хост","Правило DROP прямо в брандмауэре хоста — встроенный резерв."),
           ("CyberBot Fusion","ИИ","Сливает 4 источника, решает автономно, блокирует даже Command &amp; Control (C2).")],
   otag="СОБСТВЕННОЕ ЯДРО · ТЕХНОЛОГИЯ END-TO-END", oh="FasterUp Orchestrator",
   op="Инновация — не компоненты, а их оркестрация. FasterUp Orchestrator сливает четыре источника, решает менее чем за 11 секунд и координирует пять слоёв как единый организм. Собственная технология, полностью под собственным контролем (end-to-end).",
   spec_cap="от рефлекса на проводе до контекстного решения",
   roots="Глубокие корни, неограниченные ресурсы ИИ: суверенная LLM для безопасности (без внешней зависимости, без лимита токенов), база данных CYBER3, которая постоянно растёт, плюс сетевое и облачное сканирование."),
 "zh": dict(kicker="纵深防御", h2="五层互补的自主防御",
   p="从网络到主机再到 AI 决策,并延伸到已安装应用的工作站与手机——即使一层被绕过，每个威胁仍被拦截。各层互补而非冗余,每一层都能捕获其他层看不到的威胁。",
   layers=[("CYBER3 Desktop EDR/XDR","终端","在工作站上:在 DNS 层拦截恶意域名、扫描、隔离。"),
           ("CYBER3 Mobile Protection","移动","在手机上:实时反诈骗与 DNS 过滤,随时随地。"),
           ("内联 IPS 引擎","网络","在链路上:恶意数据包即刻丢弃,毫秒级。"),
           ("主机检测与响应","主机","直接在主机防火墙写入 DROP 规则——原生兜底。"),
           ("CyberBot Fusion","AI","融合 4 个来源,自主决策,甚至拦截命令与控制 (C2)。")],
   otag="自有核心 · 端到端自有技术", oh="FasterUp Orchestrator",
   op="创新不在组件,而在其编排。FasterUp Orchestrator 融合四个来源,在 11 秒内决策,并将五层协调为一个有机整体。自有技术,端到端完全自主掌控。",
   spec_cap="从链路上的反射到上下文决策",
   roots="根基深厚,AI 资源无限:自主安全大模型(无外部依赖、无 token 上限),持续增长的 CYBER3 威胁情报数据库,以及网络与云端扫描。"),
 "it": dict(kicker="DIFESA IN PROFONDITÀ", h2="Cinque livelli complementari di difesa autonoma",
   p="Dalla rete all'host alla decisione dell'IA, estesa alla postazione e al mobile dove l'app è installata — ogni minaccia fermata anche se un livello viene aggirato. Nessun livello è ridondante; ciascuno intercetta ciò che gli altri non vedono.",
   layers=[("CYBER3 Desktop EDR/XDR","Dispositivo","Sulla postazione: domini dannosi bloccati al DNS, scansione, quarantena."),
           ("CYBER3 Mobile Protection","Mobile","Sul telefono: anti-truffa in tempo reale e filtro DNS, ovunque."),
           ("Motore IPS inline","Rete","Sul filo: il pacchetto dannoso scartato all'istante, in millisecondi."),
           ("Rilevamento e risposta sull'host","Host","Una regola DROP scritta direttamente nel firewall dell'host — fallback nativo."),
           ("CyberBot Fusion","IA","Fonde 4 fonti, decide in autonomia, blocca perfino Comando e Controllo (C2).")],
   otag="NUCLEO PROPRIETARIO · TECNOLOGIA END-TO-END", oh="FasterUp Orchestrator",
   op="L'innovazione non sono i componenti — è la loro orchestrazione. FasterUp Orchestrator fonde le quattro fonti, decide in meno di 11 secondi e coordina i cinque livelli come un unico organismo. Tecnologia proprietaria, controllata end-to-end.",
   spec_cap="dal riflesso sul filo alla decisione di contesto",
   roots="Radici profonde, risorse IA illimitate: un LLM di sicurezza sovrano (nessuna dipendenza esterna, nessun limite di token), il database di intelligence CYBER3 che cresce di continuo, più scansione di rete e cloud."),
}
# Culorile urmează ORDINEA AFIȘATĂ (poziția), nu identitatea stratului.
NX_ZONECOLOR = ["#3b82f6", "#f59e0b", "#10b981", "#a78bfa", "#22d3ee"]
# Ordinea afișată: întâi NUCLEUL pe care îl are orice client (rețea → gazdă → decizie AI),
# apoi cele 2 straturi pe bază de aplicație (desktop, mobil) — majoritatea clienților NU le au.
# Indexează în d["layers"] (ordine originală: 0=Desktop, 1=Mobil, 2=IPS, 3=Gazdă, 4=AI).
NX_ORDER = [2, 3, 4, 0, 1]
NX_TECH = {
 "en": [["Inline packet drop","Signature + anomaly","Deep packet inspection"],["Firewall DROP rule","Automatic enforcement","Host-level"],["4-source fusion","Autonomous 2–11 s","Blocks C2"],["DNS-layer blocking","On-access scan","Quarantine + rollback"],["Real-time anti-scam","DNS filtering","Link & SMS analysis"]],
 "ro": [["Drop inline de pachete","Semnătură + anomalie","Inspecție profundă (DPI)"],["Regulă DROP firewall","Aplicare automată","La nivel de gazdă"],["Fuziune 4 surse","Autonom 2–11 s","Blochează C2"],["Blocare la nivel DNS","Scanare la acces","Carantină + rollback"],["Anti-scam în timp real","Filtrare DNS","Analiză link & SMS"]],
 "es": [["Descarte de paquetes inline","Firma + anomalía","Inspección profunda (DPI)"],["Regla DROP de firewall","Aplicación automática","A nivel de host"],["Fusión de 4 fuentes","Autónomo 2–11 s","Bloquea C2"],["Bloqueo a nivel DNS","Análisis en acceso","Cuarentena + reversión"],["Anti-fraude en tiempo real","Filtrado DNS","Análisis de enlaces y SMS"]],
 "de": [["Inline-Paket-Drop","Signatur + Anomalie","Deep Packet Inspection"],["Firewall-DROP-Regel","Automatische Durchsetzung","Auf Host-Ebene"],["4-Quellen-Fusion","Autonom 2–11 s","Blockiert C2"],["Blockieren auf DNS-Ebene","Zugriffs-Scan","Quarantäne + Rollback"],["Echtzeit-Anti-Scam","DNS-Filterung","Link- & SMS-Analyse"]],
 "fr": [["Rejet de paquets en ligne","Signature + anomalie","Inspection approfondie (DPI)"],["Règle DROP pare-feu","Application automatique","Au niveau de l'hôte"],["Fusion de 4 sources","Autonome 2–11 s","Bloque le C2"],["Blocage au niveau DNS","Analyse à l'accès","Quarantaine + restauration"],["Anti-arnaque en temps réel","Filtrage DNS","Analyse liens & SMS"]],
 "ru": [["Инлайн-сброс пакетов","Сигнатура + аномалия","Глубокий анализ (DPI)"],["Правило DROP в брандмауэре","Автоматическое применение","На уровне хоста"],["Слияние 4 источников","Автономно 2–11 с","Блокирует C2"],["Блокировка на уровне DNS","Проверка при доступе","Карантин + откат"],["Анти-скам в реальном времени","DNS-фильтрация","Анализ ссылок и SMS"]],
 "zh": [["内联丢包","特征 + 异常","深度包检测 (DPI)"],["防火墙 DROP 规则","自动执行","主机级"],["四源融合","自主 2–11 秒","拦截 C2"],["DNS 层拦截","访问时扫描","隔离 + 回滚"],["实时反诈骗","DNS 过滤","链接与短信分析"]],
 "it": [["Drop di pacchetti inline","Firma + anomalia","Ispezione approfondita (DPI)"],["Regola DROP del firewall","Applicazione automatica","A livello di host"],["Fusione di 4 fonti","Autonomo 2–11 s","Blocca il C2"],["Blocco a livello DNS","Scansione all'accesso","Quarantena + ripristino"],["Anti-truffa in tempo reale","Filtro DNS","Analisi link e SMS"]],
}

# ---- 7 STRATURI: L2 Shield (strat 3) + CYBER3 Edge (strat 5) adaugate la cele 5 de baza ----
NX_COLORS7 = ["#3b82f6", "#f59e0b", "#22d3ee", "#34d399", "#a78bfa", "#2dd4bf", "#fb7185"]
NUMFIX = {"en": ("Five", "Seven"), "ro": ("Cinci", "Șapte"), "es": ("Cinco", "Siete"), "de": ("Fünf", "Sieben"),
          "fr": ("Cinq", "Sept"), "ru": ("Пять", "Семь"), "zh": ("五", "七"), "it": ("Cinque", "Sette")}
NX_ADD = {
 "en": {"l2shield": ("L2 Shield", "Ethernet", "The only Ethernet-level layer: stops ARP spoofing, rogue DHCP and MITM — attacks the IP layers cannot see."),
        "edge": ("CYBER3 Edge", "Cloud", "Web &amp; DNS protection anywhere, even off-network: malicious domains and URLs blocked at the DNS/HTTP layer before connection.")},
 "ro": {"l2shield": ("L2 Shield", "Ethernet", "Singurul strat la nivel Ethernet: oprește ARP spoofing, DHCP fals și MITM — atacuri pe care straturile IP nu le văd."),
        "edge": ("CYBER3 Edge", "Cloud", "Protecție web &amp; DNS oriunde, chiar și în afara rețelei: domenii și URL-uri periculoase blocate la nivel DNS/HTTP înainte de conectare.")},
 "es": {"l2shield": ("Escudo L2", "Ethernet", "La única capa a nivel Ethernet: detiene ARP spoofing, DHCP falso y MITM — ataques que las capas IP no ven."),
        "edge": ("CYBER3 Edge", "Nube", "Protección web y DNS en cualquier lugar, incluso fuera de la red: dominios y URLs maliciosos bloqueados a nivel DNS/HTTP antes de conectar.")},
 "de": {"l2shield": ("L2 Shield", "Ethernet", "Die einzige Schicht auf Ethernet-Ebene: stoppt ARP-Spoofing, Rogue-DHCP und MITM — Angriffe, die die IP-Schichten nicht sehen."),
        "edge": ("CYBER3 Edge", "Cloud", "Web- &amp; DNS-Schutz überall, auch außerhalb des Netzwerks: bösartige Domains und URLs auf DNS/HTTP-Ebene vor der Verbindung blockiert.")},
 "fr": {"l2shield": ("Bouclier L2", "Ethernet", "La seule couche au niveau Ethernet : arrête l'ARP spoofing, le DHCP pirate et le MITM — des attaques invisibles pour les couches IP."),
        "edge": ("CYBER3 Edge", "Cloud", "Protection web &amp; DNS partout, même hors réseau : domaines et URL malveillants bloqués au niveau DNS/HTTP avant la connexion.")},
 "ru": {"l2shield": ("L2 Shield", "Ethernet", "Единственный слой на уровне Ethernet: останавливает ARP-спуфинг, поддельный DHCP и MITM — атаки, невидимые для IP-слоёв."),
        "edge": ("CYBER3 Edge", "Облако", "Веб- и DNS-защита где угодно, даже вне сети: вредоносные домены и URL блокируются на уровне DNS/HTTP до соединения.")},
 "zh": {"l2shield": ("L2 二层防护", "以太网", "唯一的以太网层防护:阻止 ARP 欺骗、伪造 DHCP 和中间人攻击——IP 层看不到的攻击。"),
        "edge": ("CYBER3 Edge", "云端", "随处可用的 Web 与 DNS 防护,即使在网络之外:在连接前于 DNS/HTTP 层拦截恶意域名与网址。")},
 "it": {"l2shield": ("Scudo L2", "Ethernet", "L'unico livello a livello Ethernet: ferma ARP spoofing, DHCP fasullo e MITM — attacchi che i livelli IP non vedono."),
        "edge": ("CYBER3 Edge", "Cloud", "Protezione web e DNS ovunque, anche fuori rete: domini e URL dannosi bloccati a livello DNS/HTTP prima della connessione.")},
}
NX_ADD_TECH = {
 "en": {"l2shield": ["Anti-ARP-spoof (gateway pin)", "Anti-rogue-DHCP", "MAC control · L2 native"], "edge": ["DNS-shield", "Cloud IOC (2M+ indicators)", "Browser extension"]},
 "ro": {"l2shield": ["Anti-ARP-spoof (pin gateway)", "Anti-DHCP-fals", "Control MAC · nativ L2"], "edge": ["DNS-shield", "IOC cloud (2M+ indicatori)", "Extensie de browser"]},
 "es": {"l2shield": ["Anti-ARP-spoof (pin gateway)", "Anti-DHCP-falso", "Control MAC · L2 nativo"], "edge": ["DNS-shield", "IOC en nube (2M+ indicadores)", "Extensión de navegador"]},
 "de": {"l2shield": ["Anti-ARP-Spoof (Gateway-Pin)", "Anti-Rogue-DHCP", "MAC-Kontrolle · L2 nativ"], "edge": ["DNS-Shield", "Cloud-IOC (2 Mio.+ Indikatoren)", "Browser-Erweiterung"]},
 "fr": {"l2shield": ["Anti-ARP-spoof (pin passerelle)", "Anti-DHCP-pirate", "Contrôle MAC · L2 natif"], "edge": ["DNS-shield", "IOC cloud (2M+ indicateurs)", "Extension de navigateur"]},
 "ru": {"l2shield": ["Анти-ARP-спуфинг (пин шлюза)", "Анти-DHCP-подделка", "Контроль MAC · L2"], "edge": ["DNS-щит", "Облачные IOC (2M+ индикаторов)", "Расширение браузера"]},
 "zh": {"l2shield": ["反 ARP 欺骗(网关绑定)", "反伪造 DHCP", "MAC 管控 · 二层原生"], "edge": ["DNS 防护盾", "云端 IOC(200万+ 指标)", "浏览器扩展"]},
 "it": {"l2shield": ["Anti-ARP-spoof (pin gateway)", "Anti-DHCP-fasullo", "Controllo MAC · L2 nativo"], "edge": ["DNS-shield", "IOC cloud (2M+ indicatori)", "Estensione browser"]},
}
def _numfix(txt, nf):
    return txt.replace(nf[0], nf[1]).replace(nf[0].lower(), nf[1].lower())

def nextgen_section(lang):
    d = NEXTGEN.get(lang, NEXTGEN["en"])
    tech = NX_TECH.get(lang, NX_TECH["en"])          # [IPS, Host, AI, Desktop, Mobile]
    add = NX_ADD.get(lang, NX_ADD["en"])
    addt = NX_ADD_TECH.get(lang, NX_ADD_TECH["en"])
    L = d["layers"]                                   # [Desktop, Mobile, IPS, Host, AI]
    # Ordine afisata (7): IPS, AR/Gazda, L2 Shield, CyberBot, CYBER3 Edge, Desktop, Mobil
    disp = [(L[2], tech[0]), (L[3], tech[1]), (add["l2shield"], addt["l2shield"]),
            (L[4], tech[2]), (add["edge"], addt["edge"]), (L[0], tech[3]), (L[1], tech[4])]
    rows = ""
    for i, (layer, chips_) in enumerate(disp):
        name, zone, desc = layer
        c = NX_COLORS7[i]
        chips = "".join("<span>%s</span>" % t for t in chips_)
        rows += ('    <div class="nx-layer" style="--nxc:%s">\n'
                 '      <div class="nx-idx">%d<span>%s</span></div>\n'
                 '      <div class="nx-body">\n'
                 '        <div class="nx-main"><h3>%s</h3><p>%s</p></div>\n'
                 '        <div class="nx-tech">%s</div>\n'
                 '      </div>\n'
                 '    </div>\n') % (c, i + 1, zone, name, desc, chips)
    nf = NUMFIX.get(lang, NUMFIX["en"])
    h2 = _numfix(d["h2"], nf); op = _numfix(d["op"], nf)
    return ('\n<section id="defense" class="section">\n'
            '  <div class="head"><div class="kicker">%s</div><h2>%s</h2><p>%s</p></div>\n'
            '  <div class="nx-stack">\n%s  </div>\n'
            '  <div class="nx-orch">\n'
            '    <div class="nx-otag">%s</div>\n'
            '    <h3>%s</h3><p>%s</p>\n'
            '    <div class="nx-flow"><span>4</span><span class="nx-ar">→</span><span class="nx-core">FasterUp Orchestrator</span><span class="nx-ar">→</span><span>7</span></div>\n'
            '    <div class="nx-spec"><b>10&nbsp;ms → 11&nbsp;s</b><span>%s</span></div>\n'
            '    <p class="nx-roots">%s</p>\n'
            '  </div>\n</section>\n') % (d["kicker"], h2, d["p"], rows,
            d["otag"], d["oh"], op, d["spec_cap"], d["roots"])


def page(lang, T):
    home = PATH[lang]
    script = AUTODETECT if lang == "en" else MARKONLY   # redirect client-side pe rădăcină (browser + geo RO via fus orar)
    ml = T.get("more_label")
    cards = "\n\n".join([
        card("🛡️", T["s1_h"], T["s1_p"], T["s1_t"], T["s1_n"], feature=True, badge=T["s1_b"], det=detail(ml, T.get("s1_d"))),
        card("🎯", T["s2_h"], T["s2_p"], T["s2_t"], T["s2_n"], feature=True, badge=T["s2_b"], det=detail(ml, T.get("s2_d"))),
        card("🤖", T["s3_h"], T["s3_p"], T["s3_t"], T["s3_n"], det=detail(ml, T.get("s3_d"))),
        card("🧠", T["s4_h"], T["s4_p"], T["s4_t"], T["s4_n"], det=detail(ml, T.get("s4_d"))),
        card("🖥️", T["s5_h"], T["s5_p"], T["s5_t"], T["s5_n"], det=detail(ml, T.get("s5_d"))),
        card("🔔", T["s6_h"], T["s6_p"], T["s6_t"], T["s6_n"], det=detail(ml, T.get("s6_d"))),
    ])
    nodes = "\n      <div class=\"arrow\">→</div>\n      ".join([
        node("device", T["n1_b"], T["n1_s"], T.get("n1_d")),
        node("edge", T["n2_b"], T["n2_s"], T.get("n2_d")),
        node("soc", T["n3_b"], T["n3_s"], T.get("n3_d")),
        node("device", T["n4_b"], T["n4_s"], T.get("n4_d")),
    ])
    principles = "\n    ".join([
        principle(T["p1_b"], T["p1_s"]), principle(T["p2_b"], T["p2_s"]),
        principle(T["p3_b"], T["p3_s"]), principle(T["p4_b"], T["p4_s"]),
        principle(T["p5_b"], T["p5_s"]), principle(T["p6_b"], T["p6_s"]),
    ])
    kanon_html = kanon_block(T["kanon_tag"], T.get("kanon_sum"), T.get("kanon_body", T["kanon"]))
    hc_html = kanon_block(T["hc_tag"], T.get("hc_sum"), T.get("hc_body", T["hc"]))
    plats = "\n\n".join([
        plat("🎯", T["g1_h"], T["g1_p"], T["g1_btn"], "mailto:contact@rol.ro?subject=FasterUp%20-%20Contact", False, T["g1_hint"], det=detail(ml, T.get("g1_d"))),
        plat("🖥️", T["g2_h"], T["g2_p"], T["g2_btn"], "#technology", True, T["g2_hint"], det=detail(ml, T.get("g2_d"))),
        plat("🛡️", T["g3_h"], T["g3_p"], T["g3_btn"], "mailto:contact@rol.ro?subject=FasterUp%20-%20Contact", False, T["g3_hint"], det=detail(ml, T.get("g3_d"))),
    ])
    # Secțiuni Endpoint XDR + Packages + linkuri nav/footer — DOAR dacă limba are conținutul tradus.
    xdr_section = pkg_section = extra_nav = ""
    if T.get("xdr_h2"):
        xs = "\n".join([
            xcard("🛡️", T["x1_h"], T["x1_p"], ml, T["x1_d"]), xcard("🤖", T["x2_h"], T["x2_p"], ml, T["x2_d"]),
            xcard("🔗", T["x3_h"], T["x3_p"], ml, T["x3_d"]),
            xcard("📡", T["x5_h"], T["x5_p"], ml, T["x5_d"]), xcard("🔑", T["x6_h"], T["x6_p"], ml, T["x6_d"]),
            xcard("📞", T["x7_h"], T["x7_p"], ml, T["x7_d"]), xcard("🧩", T["x8_h"], T["x8_p"], ml, T["x8_d"]),
            xcard("🪪", T["x9_h"], T["x9_p"], ml, T["x9_d"]),
        ])
        _xp = XPILLARS.get(lang, XPILLARS["en"])
        pcards = "\n".join(pillar_card(x) for x in _xp["pillars"])
        xdr_section = ('\n<section id="xdr" class="section">\n  <div class="head">\n    <div class="kicker">%s</div>\n'
            '    <h2>%s</h2>\n    <p>%s</p>\n  </div>\n'
            '  <p class="pillars-sub">%s</p>\n  <div class="pillars">\n%s\n  </div>\n'
            '%s'
            '  <details class="kanon" open>\n    <summary><span class="tag">%s</span> %s</summary>\n'
            '    <div class="kbody">%s</div>\n  </details>\n</section>\n') % (
            T["xdr_kicker"], T["xdr_h2"], T["xdr_p"], _xp["sub"], pcards, desktop_app_mock(lang),
            T["xdr_why_tag"], T["xdr_why_sum"], T["xdr_why_body"])
        pk = "\n".join([
            '    <article class="card"><div class="badge" style="background:#1E4C95">%s</div><h3>%s</h3>\n      <p>%s</p>\n      <details class="more"><summary>%s</summary><div class="body">%s</div></details></article>' % (T["pk1_b"], T["pk1_h"], T["pk1_p"], T["pkg_dsum"], T["pk1_d"]),
            '    <article class="card"><div class="badge" style="background:#1E4C95">%s</div><h3>%s</h3>\n      <p>%s</p>\n      <details class="more"><summary>%s</summary><div class="body">%s</div></details></article>' % (T["pk2_b"], T["pk2_h"], T["pk2_p"], T["pkg_dsum"], T["pk2_d"]),
            '    <article class="card feature"><div class="badge">%s</div><h3>%s</h3>\n      <p>%s</p>\n      <details class="more"><summary>%s</summary><div class="body">%s</div></details></article>' % (T["pk3_b"], T["pk3_h"], T["pk3_p"], T["pkg_dsum"], T["pk3_d"]),
        ])
        pkg_section = ('\n<section id="packages" class="section alt">\n  <div class="head">\n    <div class="kicker">%s</div>\n'
            '    <h2>%s</h2>\n    <p>%s</p>\n  </div>\n  <div class="cards">\n%s\n  </div>\n'
            '  <p class="pricenote">%s</p>\n</section>\n') % (T["pkg_kicker"], T["pkg_h2"], T["pkg_p"], pk, T["pricenote"])
        extra_nav = '    <a href="#xdr">%s</a>\n    <a href="#packages">%s</a>\n' % (T["nav_xdr"], T["nav_packages"])
    elif lang in XPILLARS:
        # Limbile fără conținut XDR complet (ES/IT/DE/FR/RU/ZH): doar pilonii + header (traduse), fără xcards/why.
        _xp = XPILLARS[lang]
        pcards = "\n".join(pillar_card(x) for x in _xp["pillars"])
        xdr_section = ('\n<section id="xdr" class="section">\n  <div class="head">\n    <div class="kicker">%s</div>\n'
            '    <h2>%s</h2>\n    <p>%s</p>\n  </div>\n'
            '  <p class="pillars-sub">%s</p>\n  <div class="pillars">\n%s\n  </div>\n%s</section>\n') % (
            _xp["kicker"], _xp["h2"], _xp["p"], _xp["sub"], pcards, desktop_app_mock(lang))
        extra_nav = '    <a href="#xdr">%s</a>\n' % _xp.get("nav", "Endpoint XDR")
    # 18 sep 2026: capitolul Endpoint (Desktop + Mobile + ecosistem) și pachetele cu capabilități crescătoare
    xdr_section = endpoint_section(lang)
    if T.get("pk2_h"):
        pkg_section = packages_section(lang, T)
    return """<!DOCTYPE html>
<html lang="%(hl)s">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(title)s</title>
<meta name="description" content="%(desc)s">
<meta property="og:title" content="%(title)s">
<meta property="og:description" content="%(ogd)s">
<meta property="og:image" content="/assets/icon.svg">
<link rel="icon" href="/assets/icon.svg">
<link rel="stylesheet" href="/styles.css">
<script async src="https://www.googletagmanager.com/gtag/js?id=G-KH8RKEF517"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-KH8RKEF517');</script>
</head>
<body>

<header class="nav">
  <a class="brand" href="%(home)s"><i class="xmark"></i><span>FasterUp</span>.AI</a>
  <nav class="links">
    <a href="#services">%(nav_services)s</a>
    <a href="#technology">%(nav_tech)s</a>
%(extra_nav)s    <a href="#start">%(nav_start)s</a>
    <a href="/contact">%(nav_contact)s</a>
%(select)s
    <a class="btn-sm" href="#start">%(cta_assess)s</a>
  </nav>
</header>
%(script)s

<section class="hero">
  <div class="grid-bg"></div>
  <div class="hero-inner">
    <div class="eyebrow">▸ FASTERUP AI AUTONOMOUS PLATFORM</div>
    <h1><span class="r">%(h1a)s</span><br>%(h1b)s</h1>
    <p class="sub">%(sub)s</p>
    <div class="cta">
      <a class="btn" href="#start">▸ %(cta_assess)s</a>
      <a class="btn ghost" href="#technology">%(cta_how)s</a>
    </div>
    <div class="stats">
      <div><b>10ms–11s</b><span>%(stat1)s</span></div>
      <div><b>24/7</b><span>%(stat2)s</span></div>
      <div><b>%(stat3b)s</b><span>%(stat3)s</span></div>
      <div><b data-count="914944" data-suffix="+">0</b><span>%(stat4)s</span></div>
    </div>
  </div>
</section>

<section id="services" class="section">
  <div class="head">
    <div class="kicker">%(svc_kicker)s</div>
    <h2>%(svc_h2)s</h2>
    <p>%(svc_p)s</p>
  </div>
  <div class="cards">
%(cards)s
  </div>
</section>

<section id="technology" class="section alt d7">
  <div class="head">
    <div class="kicker">%(tech_kicker)s</div>
    <h2>%(d7_h2)s</h2>
    <p>%(d7_p)s</p>
  </div>
%(defense_block)s
  <div class="head d7-pipehead">
    <h3>%(tech_h2)s</h3>
    <p>%(tech_p)s</p>
  </div>
  <div class="arch">
    <div class="flow">
      %(nodes)s
    </div>
    %(kanon_html)s
    %(hc_html)s
  </div>
  <div class="principles">
    %(principles)s
  </div>
</section>
%(nextgen_section)s%(xdr_section)s%(pkg_section)s
<section id="start" class="section">
  <div class="head">
    <div class="kicker">%(start_kicker)s</div>
    <h2>%(start_h2)s</h2>
    <p>%(start_p)s</p>
  </div>
  <div class="dl">
%(plats)s
  </div>
</section>

<style>
.c3foot{width:100%%;box-sizing:border-box;border-top:1px solid #1E4C95;background:#040f24;color:#9FB3D1;padding:12px 22px;display:flex;flex-direction:column;gap:6px;font-size:12px}
.c3foot .c3r{display:flex;flex-wrap:wrap;align-items:center;gap:4px 16px;width:100%%}
.c3foot .c3b{font-weight:800;font-size:15px;color:#FF0000}.c3foot .c3b .cr{color:#fff}
.c3foot .c3tag{color:#9FB3D1}
.c3foot .c3badges{margin-left:auto;color:#D4AF37;border:1px solid rgba(212,175,55,.4);border-radius:8px;padding:3px 10px;font-size:10.5px;letter-spacing:.3px}
.c3foot a{color:#9FB3D1;text-decoration:none}.c3foot a:hover{color:#D4AF37}
.c3foot .c3sep{color:#1E4C95}
.c3foot .c3r3{border-top:1px solid rgba(30,76,149,.3);padding-top:6px;color:#6f86ad;font-size:10.5px}
.c3foot .c3grow{flex:1;min-width:10px}
@media(max-width:760px){.c3foot .c3badges{margin-left:0}.c3foot .c3grow{display:none}}
</style>
<footer class="c3foot">
  <div class="c3r">
    <span class="c3b">FasterUp<span class="cr">.AI</span></span>
    <span class="c3tag">%(foot_tag)s</span>
    <span class="c3badges">ISO/IEC 27001:2022 · GDPR · NIS2 · AI Act</span>
    <a class="c3sw" href="https://cyber3.ai/status/%(status_lang)s/" target="_blank" rel="noopener"><i id="c3swd"></i><span id="c3swt">…</span></a>
  </div>
  <div class="c3r">
    <a href="#services">%(nav_services)s</a><a href="#technology">%(nav_tech)s</a>%(extra_nav)s<a href="#start">%(nav_start)s</a><a href="https://cyber3.ai/status/%(status_lang)s/" target="_blank" rel="noopener">%(status_label)s</a>
    <span class="c3sep">·</span>
    <a href="/contact">%(nav_contact)s</a><a href="/terms">%(nav_terms)s</a><a href="/privacy">%(nav_privacy)s</a>
  </div>
  <div class="c3r c3r3">
    <span>ROL PORTAL SERVICES SRL · CUI RO 36837313 · J2016016379403 · ISO/IEC 27001:2022 · <a href="mailto:contact@rol.ro">contact@rol.ro</a></span>
    <span class="c3grow"></span>
    <span>© 2026 FasterUp.AI — ROL PORTAL SERVICES SRL · %(rights)s</span>
  </div>
</footer>

<script src="/app.js"></script>
<style>.c3sw{display:inline-flex;align-items:center;gap:7px;font-size:11.5px;color:#9FB3D1;text-decoration:none}.c3sw:hover span{color:#D4AF37}
.c3sw i{width:8px;height:8px;border-radius:50%%;background:#9FB3D1;flex:0 0 auto}
.c3sw i.ok{background:#37d39b;box-shadow:0 0 6px #37d39b;animation:c3swp 2s ease-in-out infinite}
.c3sw i.deg{background:#e8b53a;box-shadow:0 0 6px #e8b53a}
@keyframes c3swp{0%%,100%%{opacity:1}50%%{opacity:.45}}</style>
<script>(function(){var U=["https://cyber3-edge.cyber3.workers.dev/v1/health","https://cyber3-llm.cyber3.workers.dev/v1/health","https://cyber3-vpn-cp.cyber3.workers.dev/health"];
function chk(){Promise.all(U.map(function(u){return fetch(u,{cache:"no-store"}).then(function(r){return r.ok?0:1}).catch(function(){return 1})})).then(function(res){
var bad=res.reduce(function(a,b){return a+b},0),d=document.getElementById("c3swd"),t=document.getElementById("c3swt");if(!d)return;
d.className=bad?"deg":"ok";t.textContent=bad?"%(status_deg)s":"%(status_ok)s";});}chk();setInterval(chk,60000);})();</script>
</body>
</html>
""" % dict(T, hl=HTMLLANG[lang], home=home, select=SELECT % T, script=script,
               status_lang=lang, status_label={"ro":"Stare servicii","en":"Service status","es":"Estado del servicio","it":"Stato del servizio","de":"Dienststatus","fr":"État du service","ru":"Состояние сервиса","zh":"服务状态"}[lang],
               status_ok={"ro":"Toate sistemele funcționează","en":"All systems operational","es":"Todos los sistemas operativos","it":"Tutti i sistemi operativi","de":"Alle Systeme betriebsbereit","fr":"Tous les systèmes opérationnels","ru":"Все системы работают","zh":"所有系统运行正常"}[lang],
               status_deg={"ro":"Unele servicii sunt afectate","en":"Some services affected","es":"Algunos servicios afectados","it":"Alcuni servizi interessati","de":"Einige Dienste beeinträchtigt","fr":"Certains services affectés","ru":"Некоторые сервисы затронуты","zh":"部分服务受影响"}[lang],
           cards=cards, nodes=nodes, principles=principles, plats=plats,
           kanon_html=kanon_html, hc_html=hc_html, xdr_section=xdr_section,
           pkg_section=pkg_section, extra_nav=extra_nav, nextgen_section="",
           defense_block=defense_section(lang, ""), d7_h2=defense_head(lang)[0], d7_p=defense_head(lang)[1],
           nav_contact=CONTACT_LABEL[lang])

# ------------------------------------------------------------------ TRANSLATIONS
TR = {}

TR["en"] = dict(
 lang_label="Language", title="FasterUp.AI — AI Autonomous Cybersecurity Platform",
 desc="FasterUp AI Autonomous Platform — managed SOC and Vulnerability Assessment for business and public administration. Detects, decides and responds autonomously.",
 ogd="Managed SOC & Vulnerability Assessment for business and public administration. Autonomous detection and response in seconds.",
 nav_services="Services", nav_tech="Technology", nav_start="Get started", nav_terms="Terms", nav_privacy="Privacy",
 cta_assess="Request assessment", cta_how="How it works",
 h1a="Autonomous Cybersecurity", h1b="for Business &amp; Public Administration",
 sub="FasterUp detects, decides and responds to cyber threats in real time — fusing network sensors, SIEM correlation and AI context analysis into a single autonomous decision. Managed Security Operations Center and Vulnerability Assessment, deployed at your premises.",
 stat1="threat to autonomous decision", stat2="monitoring &amp; response", stat3b="4-source", stat3="AI context fusion per alert", stat4="live threat indicators",
 svc_kicker="SERVICES", svc_h2="Two services. One autonomous platform.",
 svc_p="Managed detection &amp; response and continuous vulnerability assessment — powered by the same AI engine and the same live threat intelligence.",
 s1_b="MANAGED · 24/7", s1_h="SOC — Security Operations Center",
 s1_p="Fully managed, autonomous monitoring of your network. FasterUp detects intrusions, network anomalies, command-and-control, data exfiltration and policy violations — then the AI engine decides and acts: block, notify or escalate, in seconds.",
 s1_t=["Suricata IDS","Cluster 1 SIEM","CYBER3 AI Context Fusion Engine","MISP threat intel"], s1_n="Autonomous response in seconds — not hours. Alerts and reports reach your team by Telegram &amp; email.",
 s2_b="CONTINUOUS", s2_h="VAS — Vulnerability Assessment",
 s2_p="Continuous, automated assessment of your assets for known vulnerabilities, misconfigurations and exposed services. You receive prioritized, actionable reports — so you fix what matters first, before attackers find it.",
 s2_t=["asset discovery","CVE detection","scheduled scans","prioritized reporting"], s2_n="Know your exposure before attackers do. Scans run safely, on a schedule you control.",
 s3_h="Autonomous Response", s3_p="Every alert is scored by AI across all sources. By severity, FasterUp logs, blocks the source IP automatically, raises an urgent alert, or escalates to a human — no analyst required to act.",
 s3_t=["block","notify","escalate"], s3_n="Severity-driven actions, 24/7 — even at 3 a.m.",
 s4_h="AI Context Fusion Engine", s4_p="The CYBER3 AI Context Fusion Engine unifies four independent sources — threat intelligence, network telemetry, SIEM correlation and the CYBER3 Database — into one contextual risk decision.",
 s4_t=["multi-source","contextual risk","2–11s"], s4_n="Fusion of four signals into a structured decision — proprietary FasterUp technology.",
 s5_h="Network Sensors", s5_p="Dedicated sensors deployed at your sites — inline or passive — watch your traffic for ARP spoofing, rogue DHCP, scanning, exploits and anomalous behaviour, without touching your endpoints.",
 s5_t=["inline / passive","private VPN","no endpoint agents"], s5_n="Connected back to the SOC over an encrypted private VPN.",
 s6_h="Clear, Human Alerts", s6_p="When something matters, your team gets a concise, human-readable explanation — what happened, why it's a threat, and what FasterUp already did about it — by Telegram and email.",
 s6_t=["Telegram","email","AI explanation"], s6_n="No noise. Only what needs your attention, explained plainly.",
 tech_kicker="TECHNOLOGY", tech_h2="Sense. Correlate. Decide. Act — autonomously.",
 tech_p="The FasterUp AI Autonomous Platform turns raw network signal into a structured response in seconds, fusing four independent intelligence sources for every decision.",
 n1_b="Network Sensors", n1_s="Suricata IDS · inline or passive", n2_b="SIEM Correlation", n2_s="Cluster 1 SIEM · events normalized &amp; correlated",
 n3_b="CYBER3 AI Context Fusion Engine", n3_s="autonomous decision in 2–11s", n4_b="Response", n4_s="block · notify · escalate",
 kanon_tag="AUTONOMOUS", kanon="Each alert is scored by AI across four sources. <b>Suspicious</b> events are logged silently; a <b>confirmed attack</b> triggers an automatic IP block; <b>severe</b> events raise an urgent alert; a <b>critical compromise</b> escalates to a human analyst. End-to-end: 2–11 seconds.",
 p1_b="Autonomous by default", p1_s="Decides and acts without waiting for an analyst — the platform handles the routine, humans handle the exceptions.",
 p2_b="Multi-source context fusion", p2_s="MISP threat intel + Suricata telemetry + Cluster 1 SIEM correlation + CYBER3 Database — on every single decision.",
 p3_b="Deployed at your premises", p3_s="Sensors live on your network; only metadata flows to the SOC over an encrypted private VPN.",
 p4_b="Built for accountability", p4_s="Full audit trail, structured reporting and GDPR-aligned data handling — designed for public administration.",
 start_kicker="GET STARTED", start_h2="From assessment to autonomous defense",
 start_p="A simple onboarding for organizations of any size — from a single office to a distributed public institution.",
 g1_h="1 · Assessment", g1_p="We map your assets and exposure with a Vulnerability Assessment — a clear picture of where you stand.", g1_btn="▸ Request assessment", g1_hint="No commitment · scoped to your environment",
 g2_h="2 · Sensor deployment", g2_p="We install network sensors at your sites — inline or passive — connected to the SOC over a private encrypted VPN.", g2_btn="▸ See the architecture", g2_hint="~15 min per site · no endpoint agents",
 g3_h="3 · Autonomous SOC", g3_p="24/7 AI monitoring and response goes live. You receive alerts and reports — the platform handles the rest.", g3_btn="▸ Talk to us", g3_hint="Managed · autonomous · always on",
 foot_tag="AI Autonomous Cybersecurity Platform for business and public administration. Managed SOC &amp; Vulnerability Assessment.",
 foot_platform="Platform", foot_legal="Legal", foot_company="Company", romania="Romania", rights="All rights reserved.",
)

TR["ro"] = dict(
 lang_label="Limbă", title="FasterUp.AI — Platformă Autonomă de Securitate Cibernetică cu AI",
 desc="FasterUp AI Autonomous Platform — SOC administrat și Evaluare de Vulnerabilități pentru business și administrație publică. Detectează, decide și răspunde autonom.",
 ogd="SOC administrat și Evaluare de Vulnerabilități pentru business și administrație publică. Detecție și răspuns autonom în secunde.",
 nav_services="Servicii", nav_tech="Tehnologie", nav_start="Începe", nav_terms="Termeni", nav_privacy="Confidențialitate",
 cta_assess="Solicită evaluare", cta_how="Cum funcționează",
 h1a="Securitate cibernetică autonomă", h1b="pentru business și administrație publică",
 sub="FasterUp detectează, decide și răspunde la amenințările cibernetice în timp real — fuzionând senzori de rețea, corelare SIEM și analiză de context cu AI într-o singură decizie autonomă. Centru de Operațiuni de Securitate administrat și Evaluare de Vulnerabilități, instalate la sediul tău.",
 stat1="de la amenințare la decizie autonomă", stat2="monitorizare și răspuns", stat3b="4 surse", stat3="fuziune de context AI per alertă", stat4="indicatori de amenințare live",
 svc_kicker="SERVICII", svc_h2="Două servicii. O singură platformă autonomă.",
 svc_p="Detecție și răspuns administrate și evaluare continuă de vulnerabilități — alimentate de același motor AI și aceeași inteligență de amenințare live.",
 s1_b="ADMINISTRAT · 24/7", s1_h="SOC — Centru de Operațiuni de Securitate",
 s1_p="Monitorizare autonomă, complet administrată, a rețelei tale. FasterUp detectează intruziuni, anomalii de rețea, comandă-și-control, exfiltrare de date și încălcări de politici — apoi motorul AI decide și acționează: blochează, notifică sau escaladează, în secunde.",
 s1_t=["Suricata IDS","Cluster 1 SIEM","CYBER3 AI Context Fusion Engine","MISP threat intel"], s1_n="Răspuns autonom în secunde — nu ore. Alertele și rapoartele ajung la echipa ta pe Telegram și email.",
 s2_b="CONTINUU", s2_h="VAS — Evaluare de Vulnerabilități",
 s2_p="Evaluare automată și continuă a activelor tale pentru vulnerabilități cunoscute, configurări greșite și servicii expuse. Primești rapoarte prioritizate și acționabile — ca să repari întâi ce contează, înainte să găsească atacatorii.",
 s2_t=["descoperire active","detecție CVE","scanări programate","raportare prioritizată"], s2_n="Cunoaște-ți expunerea înaintea atacatorilor. Scanările rulează în siguranță, după un program pe care îl controlezi.",
 s3_h="Răspuns autonom", s3_p="Fiecare alertă e evaluată de AI pe toate sursele. În funcție de severitate, FasterUp înregistrează, blochează automat IP-ul sursă, ridică o alertă urgentă sau escaladează către un analist — fără să fie nevoie de om ca să acționeze.",
 s3_t=["blochează","notifică","escaladează"], s3_n="Acțiuni în funcție de severitate, 24/7 — chiar și la 3 dimineața.",
 s4_h="Motor AI de Fuziune a Contextului", s4_p="Motorul CYBER3 AI Context Fusion Engine unifică patru surse independente — inteligență de amenințare, telemetrie de rețea, corelare SIEM și CYBER3 Database — într-o singură decizie contextuală de risc.",
 s4_t=["multi-sursă","risc contextual","2–11s"], s4_n="Fuziunea a patru semnale într-o decizie structurată — tehnologie proprietară FasterUp.",
 s5_h="Senzori de rețea", s5_p="Senzori dedicați instalați la sediile tale — inline sau pasivi — urmăresc traficul pentru ARP spoofing, DHCP fals, scanări, exploit-uri și comportament anormal, fără să atingă stațiile de lucru.",
 s5_t=["inline / pasiv","VPN privat","fără agenți pe stații"], s5_n="Conectați la SOC printr-un VPN privat criptat.",
 s6_h="Alerte clare, pe înțelesul omului", s6_p="Când ceva contează, echipa ta primește o explicație concisă și clară — ce s-a întâmplat, de ce e o amenințare și ce a făcut deja FasterUp în privința asta — pe Telegram și email.",
 s6_t=["Telegram","email","explicație AI"], s6_n="Fără zgomot. Doar ce are nevoie de atenția ta, explicat simplu.",
 tech_kicker="TEHNOLOGIE", tech_h2="Detectează. Corelează. Decide. Acționează — autonom.",
 tech_p="Platforma FasterUp AI Autonomous transformă semnalul brut de rețea într-un răspuns structurat în secunde, fuzionând patru surse independente de inteligență pentru fiecare decizie.",
 n1_b="Senzori de rețea", n1_s="Suricata IDS · inline sau pasiv", n2_b="Corelare SIEM", n2_s="Cluster 1 SIEM · evenimente normalizate și corelate",
 n3_b="CYBER3 AI Context Fusion Engine", n3_s="decizie autonomă în 2–11s", n4_b="Răspuns", n4_s="blochează · notifică · escaladează",
 kanon_tag="AUTONOM", kanon="Fiecare alertă e evaluată de AI pe patru surse. Evenimentele <b>suspecte</b> sunt înregistrate silențios; un <b>atac confirmat</b> declanșează blocarea automată a IP-ului; evenimentele <b>severe</b> ridică o alertă urgentă; un <b>compromis critic</b> escaladează către un analist uman. Cap-la-cap: 2–11 secunde.",
 p1_b="Autonom în mod implicit", p1_s="Decide și acționează fără să aștepte un analist — platforma se ocupă de rutină, oamenii de excepții.",
 p2_b="Fuziune de context multi-sursă", p2_s="MISP threat intel + telemetrie Suricata + corelare Cluster 1 SIEM + CYBER3 Database — la fiecare decizie.",
 p3_b="Instalat la sediul tău", p3_s="Senzorii stau în rețeaua ta; doar metadate ajung la SOC printr-un VPN privat criptat.",
 p4_b="Construit pentru răspundere", p4_s="Pistă de audit completă, raportare structurată și prelucrare de date conformă GDPR — gândit pentru administrația publică.",
 start_kicker="ÎNCEPE", start_h2="De la evaluare la apărare autonomă",
 start_p="Un onboarding simplu pentru organizații de orice mărime — de la un singur birou la o instituție publică distribuită.",
 g1_h="1 · Evaluare", g1_p="Cartografiem activele și expunerea ta printr-o Evaluare de Vulnerabilități — o imagine clară a punctului în care te afli.", g1_btn="▸ Solicită evaluare", g1_hint="Fără angajament · adaptat mediului tău",
 g2_h="2 · Instalare senzori", g2_p="Instalăm senzori de rețea la sediile tale — inline sau pasivi — conectați la SOC printr-un VPN privat criptat.", g2_btn="▸ Vezi arhitectura", g2_hint="~15 min per locație · fără agenți pe stații",
 g3_h="3 · SOC autonom", g3_p="Monitorizarea și răspunsul AI 24/7 intră în funcțiune. Primești alerte și rapoarte — platforma se ocupă de rest.", g3_btn="▸ Hai să vorbim", g3_hint="Administrat · autonom · mereu activ",
 foot_tag="Platformă Autonomă de Securitate Cibernetică cu AI pentru business și administrație publică. SOC administrat și Evaluare de Vulnerabilități.",
 foot_platform="Platformă", foot_legal="Legal", foot_company="Companie", romania="România", rights="Toate drepturile rezervate.",
)

TR["es"] = dict(
 lang_label="Idioma", title="FasterUp.AI — Plataforma Autónoma de Ciberseguridad con IA",
 desc="FasterUp AI Autonomous Platform — SOC gestionado y Evaluación de Vulnerabilidades para empresas y administración pública. Detecta, decide y responde de forma autónoma.",
 ogd="SOC gestionado y Evaluación de Vulnerabilidades para empresas y administración pública. Detección y respuesta autónoma en segundos.",
 nav_services="Servicios", nav_tech="Tecnología", nav_start="Empezar", nav_terms="Términos", nav_privacy="Privacidad",
 cta_assess="Solicitar evaluación", cta_how="Cómo funciona",
 h1a="Ciberseguridad autónoma", h1b="para empresas y administración pública",
 sub="FasterUp detecta, decide y responde a las amenazas cibernéticas en tiempo real — fusionando sensores de red, correlación SIEM y análisis de contexto con IA en una única decisión autónoma. Centro de Operaciones de Seguridad gestionado y Evaluación de Vulnerabilidades, instalados en sus instalaciones.",
 stat1="de la amenaza a la decisión autónoma", stat2="monitorización y respuesta", stat3b="4 fuentes", stat3="fusión de contexto IA por alerta", stat4="indicadores de amenaza en vivo",
 svc_kicker="SERVICIOS", svc_h2="Dos servicios. Una plataforma autónoma.",
 svc_p="Detección y respuesta gestionadas y evaluación continua de vulnerabilidades — impulsadas por el mismo motor de IA y la misma inteligencia de amenazas en vivo.",
 s1_b="GESTIONADO · 24/7", s1_h="SOC — Centro de Operaciones de Seguridad",
 s1_p="Monitorización autónoma y totalmente gestionada de su red. FasterUp detecta intrusiones, anomalías de red, mando y control, exfiltración de datos y violaciones de políticas — y luego el motor de IA decide y actúa: bloquea, notifica o escala, en segundos.",
 s1_t=["Suricata IDS","Cluster 1 SIEM","CYBER3 AI Context Fusion Engine","MISP threat intel"], s1_n="Respuesta autónoma en segundos — no horas. Las alertas e informes llegan a su equipo por Telegram y email.",
 s2_b="CONTINUO", s2_h="VAS — Evaluación de Vulnerabilidades",
 s2_p="Evaluación automática y continua de sus activos en busca de vulnerabilidades conocidas, configuraciones incorrectas y servicios expuestos. Recibe informes priorizados y accionables — para corregir primero lo que importa, antes de que lo encuentren los atacantes.",
 s2_t=["descubrimiento de activos","detección de CVE","escaneos programados","informes priorizados"], s2_n="Conozca su exposición antes que los atacantes. Los escaneos se ejecutan de forma segura, según un calendario que usted controla.",
 s3_h="Respuesta autónoma", s3_p="Cada alerta es evaluada por la IA en todas las fuentes. Según la gravedad, FasterUp registra, bloquea automáticamente la IP de origen, genera una alerta urgente o escala a un humano — sin necesidad de un analista para actuar.",
 s3_t=["bloquea","notifica","escala"], s3_n="Acciones según la gravedad, 24/7 — incluso a las 3 de la madrugada.",
 s4_h="Motor de Fusión de Contexto IA", s4_p="El motor CYBER3 AI Context Fusion Engine unifica cuatro fuentes independientes — inteligencia de amenazas, telemetría de red, correlación SIEM y CYBER3 Database — en una única decisión contextual de riesgo.",
 s4_t=["multi-fuente","riesgo contextual","2–11s"], s4_n="Fusión de cuatro señales en una decisión estructurada — tecnología propia de FasterUp.",
 s5_h="Sensores de red", s5_p="Sensores dedicados instalados en sus sedes — inline o pasivos — vigilan su tráfico en busca de ARP spoofing, DHCP fraudulento, escaneos, exploits y comportamiento anómalo, sin tocar sus equipos.",
 s5_t=["inline / pasivo","VPN privada","sin agentes en equipos"], s5_n="Conectados al SOC mediante una VPN privada cifrada.",
 s6_h="Alertas claras y humanas", s6_p="Cuando algo importa, su equipo recibe una explicación concisa y comprensible — qué pasó, por qué es una amenaza y qué hizo ya FasterUp al respecto — por Telegram y email.",
 s6_t=["Telegram","email","explicación IA"], s6_n="Sin ruido. Solo lo que necesita su atención, explicado con claridad.",
 tech_kicker="TECNOLOGÍA", tech_h2="Detectar. Correlacionar. Decidir. Actuar — de forma autónoma.",
 tech_p="La plataforma FasterUp AI Autonomous convierte la señal de red en bruto en una respuesta estructurada en segundos, fusionando cuatro fuentes de inteligencia independientes para cada decisión.",
 n1_b="Sensores de red", n1_s="Suricata IDS · inline o pasivo", n2_b="Correlación SIEM", n2_s="Cluster 1 SIEM · eventos normalizados y correlacionados",
 n3_b="CYBER3 AI Context Fusion Engine", n3_s="decisión autónoma en 2–11s", n4_b="Respuesta", n4_s="bloquea · notifica · escala",
 kanon_tag="AUTÓNOMO", kanon="Cada alerta es evaluada por la IA en cuatro fuentes. Los eventos <b>sospechosos</b> se registran en silencio; un <b>ataque confirmado</b> desencadena un bloqueo automático de IP; los eventos <b>graves</b> generan una alerta urgente; un <b>compromiso crítico</b> escala a un analista humano. De extremo a extremo: 2–11 segundos.",
 p1_b="Autónomo por defecto", p1_s="Decide y actúa sin esperar a un analista — la plataforma gestiona la rutina, los humanos las excepciones.",
 p2_b="Fusión de contexto multi-fuente", p2_s="MISP threat intel + telemetría Suricata + correlación Cluster 1 SIEM + CYBER3 Database — en cada decisión.",
 p3_b="Instalado en sus instalaciones", p3_s="Los sensores residen en su red; solo los metadatos fluyen al SOC mediante una VPN privada cifrada.",
 p4_b="Diseñado para la rendición de cuentas", p4_s="Registro de auditoría completo, informes estructurados y tratamiento de datos conforme al RGPD — pensado para la administración pública.",
 start_kicker="EMPEZAR", start_h2="De la evaluación a la defensa autónoma",
 start_p="Una incorporación sencilla para organizaciones de cualquier tamaño — desde una sola oficina hasta una institución pública distribuida.",
 g1_h="1 · Evaluación", g1_p="Cartografiamos sus activos y exposición con una Evaluación de Vulnerabilidades — una imagen clara de su situación.", g1_btn="▸ Solicitar evaluación", g1_hint="Sin compromiso · adaptado a su entorno",
 g2_h="2 · Despliegue de sensores", g2_p="Instalamos sensores de red en sus sedes — inline o pasivos — conectados al SOC mediante una VPN privada cifrada.", g2_btn="▸ Ver la arquitectura", g2_hint="~15 min por sede · sin agentes en equipos",
 g3_h="3 · SOC autónomo", g3_p="La monitorización y respuesta con IA 24/7 entra en funcionamiento. Recibe alertas e informes — la plataforma hace el resto.", g3_btn="▸ Hablemos", g3_hint="Gestionado · autónomo · siempre activo",
 foot_tag="Plataforma Autónoma de Ciberseguridad con IA para empresas y administración pública. SOC gestionado y Evaluación de Vulnerabilidades.",
 foot_platform="Plataforma", foot_legal="Legal", foot_company="Empresa", romania="Rumanía", rights="Todos los derechos reservados.",
)

TR["de"] = dict(
 lang_label="Sprache", title="FasterUp.AI — Autonome KI-Cybersicherheitsplattform",
 desc="FasterUp AI Autonomous Platform — verwaltetes SOC und Schwachstellenbewertung für Unternehmen und öffentliche Verwaltung. Erkennt, entscheidet und reagiert autonom.",
 ogd="Verwaltetes SOC & Schwachstellenbewertung für Unternehmen und öffentliche Verwaltung. Autonome Erkennung und Reaktion in Sekunden.",
 nav_services="Leistungen", nav_tech="Technologie", nav_start="Loslegen", nav_terms="AGB", nav_privacy="Datenschutz",
 cta_assess="Bewertung anfragen", cta_how="So funktioniert's",
 h1a="Autonome Cybersicherheit", h1b="für Unternehmen und öffentliche Verwaltung",
 sub="FasterUp erkennt, entscheidet und reagiert in Echtzeit auf Cyberbedrohungen — durch die Fusion von Netzwerksensoren, SIEM-Korrelation und KI-Kontextanalyse zu einer einzigen autonomen Entscheidung. Verwaltetes Security Operations Center und Schwachstellenbewertung, bei Ihnen vor Ort installiert.",
 stat1="von der Bedrohung zur autonomen Entscheidung", stat2="Überwachung &amp; Reaktion", stat3b="4 Quellen", stat3="KI-Kontextfusion pro Alarm", stat4="Live-Bedrohungsindikatoren",
 svc_kicker="LEISTUNGEN", svc_h2="Zwei Leistungen. Eine autonome Plattform.",
 svc_p="Verwaltete Erkennung &amp; Reaktion und kontinuierliche Schwachstellenbewertung — angetrieben von derselben KI-Engine und derselben Live-Bedrohungsintelligenz.",
 s1_b="VERWALTET · 24/7", s1_h="SOC — Security Operations Center",
 s1_p="Vollständig verwaltete, autonome Überwachung Ihres Netzwerks. FasterUp erkennt Eindringversuche, Netzwerkanomalien, Command-and-Control, Datenexfiltration und Richtlinienverstöße — dann entscheidet und handelt die KI-Engine: blockieren, benachrichtigen oder eskalieren, in Sekunden.",
 s1_t=["Suricata IDS","Cluster 1 SIEM","CYBER3 AI Context Fusion Engine","MISP threat intel"], s1_n="Autonome Reaktion in Sekunden — nicht Stunden. Alarme und Berichte erreichen Ihr Team per Telegram &amp; E-Mail.",
 s2_b="KONTINUIERLICH", s2_h="VAS — Schwachstellenbewertung",
 s2_p="Kontinuierliche, automatisierte Bewertung Ihrer Assets auf bekannte Schwachstellen, Fehlkonfigurationen und exponierte Dienste. Sie erhalten priorisierte, umsetzbare Berichte — um zuerst das Wichtige zu beheben, bevor Angreifer es finden.",
 s2_t=["Asset-Erkennung","CVE-Erkennung","geplante Scans","priorisierte Berichte"], s2_n="Kennen Sie Ihre Exposition vor den Angreifern. Scans laufen sicher, nach einem von Ihnen gesteuerten Zeitplan.",
 s3_h="Autonome Reaktion", s3_p="Jeder Alarm wird von der KI über alle Quellen bewertet. Je nach Schweregrad protokolliert FasterUp, blockiert automatisch die Quell-IP, löst einen dringenden Alarm aus oder eskaliert an einen Menschen — kein Analyst muss handeln.",
 s3_t=["blockieren","benachrichtigen","eskalieren"], s3_n="Vom Schweregrad gesteuerte Aktionen, 24/7 — auch um 3 Uhr morgens.",
 s4_h="KI-Kontextfusions-Engine", s4_p="Die CYBER3 AI Context Fusion Engine vereint vier unabhängige Quellen — Bedrohungsintelligenz, Netzwerktelemetrie, SIEM-Korrelation und die CYBER3 Database — zu einer einzigen kontextbezogenen Risikoentscheidung.",
 s4_t=["Multi-Quelle","kontextbezogenes Risiko","2–11s"], s4_n="Fusion von vier Signalen zu einer strukturierten Entscheidung — proprietäre FasterUp-Technologie.",
 s5_h="Netzwerksensoren", s5_p="Dedizierte Sensoren an Ihren Standorten — inline oder passiv — überwachen Ihren Datenverkehr auf ARP-Spoofing, Rogue-DHCP, Scans, Exploits und anomales Verhalten, ohne Ihre Endgeräte zu berühren.",
 s5_t=["inline / passiv","privates VPN","keine Endpunkt-Agenten"], s5_n="Über ein verschlüsseltes privates VPN mit dem SOC verbunden.",
 s6_h="Klare, verständliche Alarme", s6_p="Wenn etwas zählt, erhält Ihr Team eine prägnante, verständliche Erklärung — was passiert ist, warum es eine Bedrohung ist und was FasterUp bereits dagegen getan hat — per Telegram und E-Mail.",
 s6_t=["Telegram","E-Mail","KI-Erklärung"], s6_n="Kein Rauschen. Nur das, was Ihre Aufmerksamkeit braucht, klar erklärt.",
 tech_kicker="TECHNOLOGIE", tech_h2="Erfassen. Korrelieren. Entscheiden. Handeln — autonom.",
 tech_p="Die FasterUp AI Autonomous Platform verwandelt rohe Netzwerksignale in Sekunden in eine strukturierte Reaktion und fusioniert für jede Entscheidung vier unabhängige Informationsquellen.",
 n1_b="Netzwerksensoren", n1_s="Suricata IDS · inline oder passiv", n2_b="SIEM-Korrelation", n2_s="Cluster 1 SIEM · Ereignisse normalisiert &amp; korreliert",
 n3_b="CYBER3 AI Context Fusion Engine", n3_s="autonome Entscheidung in 2–11s", n4_b="Reaktion", n4_s="blockieren · benachrichtigen · eskalieren",
 kanon_tag="AUTONOM", kanon="Jeder Alarm wird von der KI über vier Quellen bewertet. <b>Verdächtige</b> Ereignisse werden still protokolliert; ein <b>bestätigter Angriff</b> löst eine automatische IP-Sperre aus; <b>schwere</b> Ereignisse lösen einen dringenden Alarm aus; eine <b>kritische Kompromittierung</b> eskaliert an einen menschlichen Analysten. Ende-zu-Ende: 2–11 Sekunden.",
 p1_b="Standardmäßig autonom", p1_s="Entscheidet und handelt, ohne auf einen Analysten zu warten — die Plattform übernimmt die Routine, Menschen die Ausnahmen.",
 p2_b="Multi-Quellen-Kontextfusion", p2_s="MISP threat intel + Suricata-Telemetrie + Cluster 1 SIEM-Korrelation + CYBER3 Database — bei jeder Entscheidung.",
 p3_b="Bei Ihnen vor Ort installiert", p3_s="Die Sensoren befinden sich in Ihrem Netzwerk; nur Metadaten fließen über ein verschlüsseltes privates VPN zum SOC.",
 p4_b="Auf Rechenschaft ausgelegt", p4_s="Vollständiger Audit-Trail, strukturierte Berichte und DSGVO-konforme Datenverarbeitung — für die öffentliche Verwaltung konzipiert.",
 start_kicker="LOSLEGEN", start_h2="Von der Bewertung zur autonomen Verteidigung",
 start_p="Ein einfaches Onboarding für Organisationen jeder Größe — vom einzelnen Büro bis zur verteilten öffentlichen Einrichtung.",
 g1_h="1 · Bewertung", g1_p="Wir erfassen Ihre Assets und Exposition mit einer Schwachstellenbewertung — ein klares Bild Ihrer Lage.", g1_btn="▸ Bewertung anfragen", g1_hint="Unverbindlich · auf Ihre Umgebung zugeschnitten",
 g2_h="2 · Sensor-Installation", g2_p="Wir installieren Netzwerksensoren an Ihren Standorten — inline oder passiv — über ein privates verschlüsseltes VPN mit dem SOC verbunden.", g2_btn="▸ Architektur ansehen", g2_hint="~15 Min. pro Standort · keine Endpunkt-Agenten",
 g3_h="3 · Autonomes SOC", g3_p="Die KI-Überwachung und -Reaktion rund um die Uhr geht live. Sie erhalten Alarme und Berichte — die Plattform erledigt den Rest.", g3_btn="▸ Sprechen wir", g3_hint="Verwaltet · autonom · immer aktiv",
 foot_tag="Autonome KI-Cybersicherheitsplattform für Unternehmen und öffentliche Verwaltung. Verwaltetes SOC &amp; Schwachstellenbewertung.",
 foot_platform="Plattform", foot_legal="Rechtliches", foot_company="Unternehmen", romania="Rumänien", rights="Alle Rechte vorbehalten.",
)

TR["fr"] = dict(
 lang_label="Langue", title="FasterUp.AI — Plateforme Autonome de Cybersécurité par IA",
 desc="FasterUp AI Autonomous Platform — SOC géré et Évaluation de Vulnérabilités pour les entreprises et l'administration publique. Détecte, décide et répond de façon autonome.",
 ogd="SOC géré & Évaluation de Vulnérabilités pour entreprises et administration publique. Détection et réponse autonomes en secondes.",
 nav_services="Services", nav_tech="Technologie", nav_start="Démarrer", nav_terms="Conditions", nav_privacy="Confidentialité",
 cta_assess="Demander une évaluation", cta_how="Comment ça marche",
 h1a="Cybersécurité autonome", h1b="pour les entreprises et l'administration publique",
 sub="FasterUp détecte, décide et répond aux cybermenaces en temps réel — en fusionnant capteurs réseau, corrélation SIEM et analyse de contexte par IA en une seule décision autonome. Centre d'Opérations de Sécurité géré et Évaluation de Vulnérabilités, déployés dans vos locaux.",
 stat1="de la menace à la décision autonome", stat2="surveillance &amp; réponse", stat3b="4 sources", stat3="fusion de contexte IA par alerte", stat4="indicateurs de menace en direct",
 svc_kicker="SERVICES", svc_h2="Deux services. Une plateforme autonome.",
 svc_p="Détection et réponse gérées et évaluation continue des vulnérabilités — propulsées par le même moteur IA et la même intelligence des menaces en direct.",
 s1_b="GÉRÉ · 24/7", s1_h="SOC — Centre d'Opérations de Sécurité",
 s1_p="Surveillance autonome et entièrement gérée de votre réseau. FasterUp détecte les intrusions, anomalies réseau, command-and-control, exfiltration de données et violations de politiques — puis le moteur IA décide et agit : bloque, notifie ou escalade, en secondes.",
 s1_t=["Suricata IDS","Cluster 1 SIEM","CYBER3 AI Context Fusion Engine","MISP threat intel"], s1_n="Réponse autonome en secondes — pas en heures. Les alertes et rapports parviennent à votre équipe par Telegram &amp; e-mail.",
 s2_b="CONTINU", s2_h="VAS — Évaluation de Vulnérabilités",
 s2_p="Évaluation automatique et continue de vos actifs pour les vulnérabilités connues, mauvaises configurations et services exposés. Vous recevez des rapports priorisés et exploitables — pour corriger d'abord l'essentiel, avant que les attaquants ne le trouvent.",
 s2_t=["découverte d'actifs","détection de CVE","scans planifiés","rapports priorisés"], s2_n="Connaissez votre exposition avant les attaquants. Les scans s'exécutent en toute sécurité, selon un calendrier que vous contrôlez.",
 s3_h="Réponse autonome", s3_p="Chaque alerte est évaluée par l'IA sur toutes les sources. Selon la gravité, FasterUp journalise, bloque automatiquement l'IP source, déclenche une alerte urgente ou escalade vers un humain — aucun analyste requis pour agir.",
 s3_t=["bloque","notifie","escalade"], s3_n="Actions selon la gravité, 24/7 — même à 3 h du matin.",
 s4_h="Moteur de Fusion de Contexte IA", s4_p="Le moteur CYBER3 AI Context Fusion Engine unifie quatre sources indépendantes — renseignement sur les menaces, télémétrie réseau, corrélation SIEM et CYBER3 Database — en une seule décision contextuelle de risque.",
 s4_t=["multi-source","risque contextuel","2–11s"], s4_n="Fusion de quatre signaux en une décision structurée — technologie propriétaire FasterUp.",
 s5_h="Capteurs réseau", s5_p="Des capteurs dédiés déployés sur vos sites — inline ou passifs — surveillent votre trafic pour l'ARP spoofing, le DHCP pirate, les scans, les exploits et les comportements anormaux, sans toucher à vos postes.",
 s5_t=["inline / passif","VPN privé","sans agents sur postes"], s5_n="Reliés au SOC via un VPN privé chiffré.",
 s6_h="Des alertes claires et humaines", s6_p="Quand quelque chose compte, votre équipe reçoit une explication concise et compréhensible — ce qui s'est passé, pourquoi c'est une menace et ce que FasterUp a déjà fait — par Telegram et e-mail.",
 s6_t=["Telegram","e-mail","explication IA"], s6_n="Pas de bruit. Seulement ce qui requiert votre attention, expliqué simplement.",
 tech_kicker="TECHNOLOGIE", tech_h2="Détecter. Corréler. Décider. Agir — de façon autonome.",
 tech_p="La plateforme FasterUp AI Autonomous transforme le signal réseau brut en une réponse structurée en secondes, en fusionnant quatre sources de renseignement indépendantes pour chaque décision.",
 n1_b="Capteurs réseau", n1_s="Suricata IDS · inline ou passif", n2_b="Corrélation SIEM", n2_s="Cluster 1 SIEM · événements normalisés &amp; corrélés",
 n3_b="CYBER3 AI Context Fusion Engine", n3_s="décision autonome en 2–11s", n4_b="Réponse", n4_s="bloque · notifie · escalade",
 kanon_tag="AUTONOME", kanon="Chaque alerte est évaluée par l'IA sur quatre sources. Les événements <b>suspects</b> sont journalisés en silence ; une <b>attaque confirmée</b> déclenche un blocage IP automatique ; les événements <b>graves</b> déclenchent une alerte urgente ; une <b>compromission critique</b> escalade vers un analyste humain. De bout en bout : 2–11 secondes.",
 p1_b="Autonome par défaut", p1_s="Décide et agit sans attendre un analyste — la plateforme gère la routine, les humains les exceptions.",
 p2_b="Fusion de contexte multi-source", p2_s="MISP threat intel + télémétrie Suricata + corrélation Cluster 1 SIEM + CYBER3 Database — à chaque décision.",
 p3_b="Déployé dans vos locaux", p3_s="Les capteurs résident sur votre réseau ; seules les métadonnées circulent vers le SOC via un VPN privé chiffré.",
 p4_b="Conçu pour la responsabilité", p4_s="Piste d'audit complète, rapports structurés et traitement des données conforme au RGPD — pensé pour l'administration publique.",
 start_kicker="DÉMARRER", start_h2="De l'évaluation à la défense autonome",
 start_p="Un déploiement simple pour les organisations de toute taille — d'un seul bureau à une institution publique répartie.",
 g1_h="1 · Évaluation", g1_p="Nous cartographions vos actifs et votre exposition par une Évaluation de Vulnérabilités — une image claire de votre situation.", g1_btn="▸ Demander une évaluation", g1_hint="Sans engagement · adapté à votre environnement",
 g2_h="2 · Déploiement des capteurs", g2_p="Nous installons des capteurs réseau sur vos sites — inline ou passifs — reliés au SOC via un VPN privé chiffré.", g2_btn="▸ Voir l'architecture", g2_hint="~15 min par site · sans agents sur postes",
 g3_h="3 · SOC autonome", g3_p="La surveillance et la réponse par IA 24/7 entrent en service. Vous recevez alertes et rapports — la plateforme fait le reste.", g3_btn="▸ Parlons-en", g3_hint="Géré · autonome · toujours actif",
 foot_tag="Plateforme Autonome de Cybersécurité par IA pour les entreprises et l'administration publique. SOC géré &amp; Évaluation de Vulnérabilités.",
 foot_platform="Plateforme", foot_legal="Mentions légales", foot_company="Société", romania="Roumanie", rights="Tous droits réservés.",
)

TR["ru"] = dict(
 lang_label="Язык", title="FasterUp.AI — Автономная платформа кибербезопасности на ИИ",
 desc="FasterUp AI Autonomous Platform — управляемый SOC и оценка уязвимостей для бизнеса и государственного управления. Обнаруживает, решает и реагирует автономно.",
 ogd="Управляемый SOC и оценка уязвимостей для бизнеса и госуправления. Автономное обнаружение и реагирование за секунды.",
 nav_services="Услуги", nav_tech="Технология", nav_start="Начать", nav_terms="Условия", nav_privacy="Конфиденциальность",
 cta_assess="Запросить оценку", cta_how="Как это работает",
 h1a="Автономная кибербезопасность", h1b="для бизнеса и государственного управления",
 sub="FasterUp обнаруживает, принимает решения и реагирует на киберугрозы в реальном времени — объединяя сетевые датчики, корреляцию SIEM и ИИ-анализ контекста в единое автономное решение. Управляемый центр операций безопасности и оценка уязвимостей, развёрнутые на вашей территории.",
 stat1="от угрозы до автономного решения", stat2="мониторинг и реагирование", stat3b="4 источника", stat3="ИИ-слияние контекста на сигнал", stat4="актуальных индикаторов угроз",
 svc_kicker="УСЛУГИ", svc_h2="Две услуги. Одна автономная платформа.",
 svc_p="Управляемое обнаружение и реагирование и непрерывная оценка уязвимостей — на одном ИИ-движке и одной актуальной разведке угроз.",
 s1_b="УПРАВЛЯЕМЫЙ · 24/7", s1_h="SOC — Центр операций безопасности",
 s1_p="Полностью управляемый автономный мониторинг вашей сети. FasterUp обнаруживает вторжения, сетевые аномалии, command-and-control, утечку данных и нарушения политик — затем ИИ-движок решает и действует: блокирует, уведомляет или эскалирует, за секунды.",
 s1_t=["Suricata IDS","Cluster 1 SIEM","CYBER3 AI Context Fusion Engine","MISP threat intel"], s1_n="Автономная реакция за секунды — не часы. Оповещения и отчёты доходят до вашей команды через Telegram и e-mail.",
 s2_b="НЕПРЕРЫВНО", s2_h="VAS — Оценка уязвимостей",
 s2_p="Непрерывная автоматическая оценка ваших активов на известные уязвимости, ошибки конфигурации и открытые сервисы. Вы получаете приоритизированные отчёты с действиями — чтобы сначала исправить главное, раньше атакующих.",
 s2_t=["обнаружение активов","выявление CVE","плановые сканы","приоритизированные отчёты"], s2_n="Узнайте свою экспозицию раньше атакующих. Сканы выполняются безопасно по контролируемому вами расписанию.",
 s3_h="Автономное реагирование", s3_p="Каждое оповещение оценивается ИИ по всем источникам. По степени серьёзности FasterUp журналирует, автоматически блокирует IP-источник, поднимает срочный сигнал или эскалирует человеку — аналитик не нужен для действия.",
 s3_t=["блокировать","уведомить","эскалировать"], s3_n="Действия по серьёзности, 24/7 — даже в 3 часа ночи.",
 s4_h="ИИ-движок слияния контекста", s4_p="Движок CYBER3 AI Context Fusion Engine объединяет четыре независимых источника — разведку угроз, сетевую телеметрию, корреляцию SIEM и CYBER3 Database — в единое контекстное решение о риске.",
 s4_t=["мульти-источник","контекстный риск","2–11с"], s4_n="Слияние четырёх сигналов в структурированное решение — собственная технология FasterUp.",
 s5_h="Сетевые датчики", s5_p="Выделенные датчики на ваших объектах — inline или пассивные — следят за трафиком на ARP-спуфинг, чужой DHCP, сканирование, эксплойты и аномальное поведение, не затрагивая ваши устройства.",
 s5_t=["inline / пассивный","частный VPN","без агентов на устройствах"], s5_n="Подключены к SOC через зашифрованный частный VPN.",
 s6_h="Понятные оповещения для людей", s6_p="Когда что-то важно, ваша команда получает краткое и понятное объяснение — что произошло, почему это угроза и что FasterUp уже сделал — через Telegram и e-mail.",
 s6_t=["Telegram","e-mail","объяснение ИИ"], s6_n="Без шума. Только то, что требует вашего внимания, объяснено простым языком.",
 tech_kicker="ТЕХНОЛОГИЯ", tech_h2="Воспринимать. Коррелировать. Решать. Действовать — автономно.",
 tech_p="Платформа FasterUp AI Autonomous превращает сырой сетевой сигнал в структурированную реакцию за секунды, объединяя четыре независимых источника разведки для каждого решения.",
 n1_b="Сетевые датчики", n1_s="Suricata IDS · inline или пассивный", n2_b="Корреляция SIEM", n2_s="Cluster 1 SIEM · события нормализованы и скоррелированы",
 n3_b="CYBER3 AI Context Fusion Engine", n3_s="автономное решение за 2–11с", n4_b="Реакция", n4_s="блок · уведомление · эскалация",
 kanon_tag="АВТОНОМНО", kanon="Каждое оповещение оценивается ИИ по четырём источникам. <b>Подозрительные</b> события тихо журналируются; <b>подтверждённая атака</b> запускает автоблокировку IP; <b>серьёзные</b> события поднимают срочный сигнал; <b>критическая компрометация</b> эскалируется аналитику-человеку. От начала до конца: 2–11 секунд.",
 p1_b="Автономно по умолчанию", p1_s="Решает и действует, не дожидаясь аналитика — платформа берёт рутину, люди — исключения.",
 p2_b="Слияние контекста из многих источников", p2_s="MISP threat intel + телеметрия Suricata + корреляция Cluster 1 SIEM + CYBER3 Database — в каждом решении.",
 p3_b="Развёрнуто на вашей территории", p3_s="Датчики находятся в вашей сети; в SOC через зашифрованный частный VPN уходят только метаданные.",
 p4_b="Создано для подотчётности", p4_s="Полный аудит-трейл, структурированная отчётность и обработка данных в соответствии с GDPR — для государственного управления.",
 start_kicker="НАЧАТЬ", start_h2="От оценки к автономной защите",
 start_p="Простое подключение для организаций любого размера — от одного офиса до распределённого госучреждения.",
 g1_h="1 · Оценка", g1_p="Мы составляем карту ваших активов и экспозиции через оценку уязвимостей — ясную картину вашего состояния.", g1_btn="▸ Запросить оценку", g1_hint="Без обязательств · под вашу среду",
 g2_h="2 · Развёртывание датчиков", g2_p="Мы устанавливаем сетевые датчики на ваших объектах — inline или пассивные — подключённые к SOC через частный зашифрованный VPN.", g2_btn="▸ Смотреть архитектуру", g2_hint="~15 мин на объект · без агентов на устройствах",
 g3_h="3 · Автономный SOC", g3_p="ИИ-мониторинг и реагирование 24/7 запускаются. Вы получаете оповещения и отчёты — платформа делает остальное.", g3_btn="▸ Связаться с нами", g3_hint="Управляемый · автономный · всегда онлайн",
 foot_tag="Автономная платформа кибербезопасности на ИИ для бизнеса и государственного управления. Управляемый SOC и оценка уязвимостей.",
 foot_platform="Платформа", foot_legal="Правовое", foot_company="Компания", romania="Румыния", rights="Все права защищены.",
)

TR["zh"] = dict(
 lang_label="语言", title="FasterUp.AI — AI 自主网络安全平台",
 desc="FasterUp AI Autonomous Platform — 面向企业与公共管理的托管 SOC 与漏洞评估。自主检测、决策与响应。",
 ogd="面向企业与公共管理的托管 SOC 与漏洞评估。数秒内自主检测与响应。",
 nav_services="服务", nav_tech="技术", nav_start="开始", nav_terms="条款", nav_privacy="隐私",
 cta_assess="申请评估", cta_how="工作原理",
 h1a="自主网络安全", h1b="面向企业与公共管理",
 sub="FasterUp 实时检测、决策并响应网络威胁——将网络传感器、SIEM 关联和 AI 情境分析融合为单一自主决策。托管安全运营中心与漏洞评估，部署在您的现场。",
 stat1="从威胁到自主决策", stat2="监控与响应", stat3b="4 来源", stat3="每次告警的 AI 情境融合", stat4="实时威胁指标",
 svc_kicker="服务", svc_h2="两项服务。一个自主平台。",
 svc_p="托管检测与响应以及持续漏洞评估——由同一 AI 引擎和同一实时威胁情报驱动。",
 s1_b="托管 · 24/7", s1_h="SOC — 安全运营中心",
 s1_p="对您网络的全托管自主监控。FasterUp 检测入侵、网络异常、命令与控制、数据外泄和策略违规——随后 AI 引擎决策并行动：拦截、通知或升级，在数秒内完成。",
 s1_t=["Suricata IDS","Cluster 1 SIEM","CYBER3 AI Context Fusion Engine","MISP threat intel"], s1_n="数秒内自主响应——而非数小时。告警与报告通过 Telegram 和电子邮件送达您的团队。",
 s2_b="持续", s2_h="VAS — 漏洞评估",
 s2_p="对您资产的持续自动评估，发现已知漏洞、错误配置和暴露服务。您将收到经优先级排序、可执行的报告——在攻击者发现之前先修复最重要的问题。",
 s2_t=["资产发现","CVE 检测","计划扫描","优先级报告"], s2_n="比攻击者更早了解您的暴露面。扫描安全运行，按您控制的计划执行。",
 s3_h="自主响应", s3_p="每条告警都由 AI 跨所有来源评分。按严重程度，FasterUp 记录、自动拦截源 IP、发出紧急告警或升级给人工——无需分析师即可行动。",
 s3_t=["拦截","通知","升级"], s3_n="按严重程度的行动，24/7——即使凌晨 3 点。",
 s4_h="AI 情境融合引擎", s4_p="CYBER3 AI Context Fusion Engine 将四个独立来源——威胁情报、网络遥测、SIEM 关联和 CYBER3 Database——统一为单一情境化风险决策。",
 s4_t=["多来源","情境化风险","2–11秒"], s4_n="将四个信号融合为结构化决策——FasterUp 专有技术。",
 s5_h="网络传感器", s5_p="部署在您站点的专用传感器——inline 或被动——监视您的流量，检测 ARP 欺骗、恶意 DHCP、扫描、漏洞利用和异常行为，而不触及您的终端。",
 s5_t=["inline / 被动","专用 VPN","无终端代理"], s5_n="通过加密专用 VPN 连接回 SOC。",
 s6_h="清晰、易懂的告警", s6_p="当有重要情况时，您的团队会收到简明易懂的解释——发生了什么、为何是威胁，以及 FasterUp 已经采取的措施——通过 Telegram 和电子邮件。",
 s6_t=["Telegram","电子邮件","AI 解释"], s6_n="没有噪音。只呈现需要您关注的内容，清晰说明。",
 tech_kicker="技术", tech_h2="感知。关联。决策。行动——自主完成。",
 tech_p="FasterUp AI Autonomous Platform 在数秒内将原始网络信号转化为结构化响应，为每个决策融合四个独立情报来源。",
 n1_b="网络传感器", n1_s="Suricata IDS · inline 或被动", n2_b="SIEM 关联", n2_s="Cluster 1 SIEM · 事件标准化与关联",
 n3_b="CYBER3 AI Context Fusion Engine", n3_s="2–11秒内自主决策", n4_b="响应", n4_s="拦截 · 通知 · 升级",
 kanon_tag="自主", kanon="每条告警都由 AI 跨四个来源评分。<b>可疑</b>事件被静默记录；<b>确认的攻击</b>触发自动 IP 拦截；<b>严重</b>事件发出紧急告警；<b>关键性入侵</b>升级给人工分析师。端到端：2–11 秒。",
 p1_b="默认自主", p1_s="无需等待分析师即可决策与行动——平台处理常规，人工处理例外。",
 p2_b="多来源情境融合", p2_s="MISP threat intel + Suricata 遥测 + Cluster 1 SIEM 关联 + CYBER3 Database——每个决策皆然。",
 p3_b="部署在您的现场", p3_s="传感器位于您的网络中；仅元数据通过加密专用 VPN 流向 SOC。",
 p4_b="为问责而构建", p4_s="完整审计跟踪、结构化报告以及符合 GDPR 的数据处理——为公共管理而设计。",
 start_kicker="开始", start_h2="从评估到自主防御",
 start_p="为任何规模的组织提供简单的上手流程——从单一办公室到分布式公共机构。",
 g1_h="1 · 评估", g1_p="我们通过漏洞评估梳理您的资产和暴露面——清晰呈现您的现状。", g1_btn="▸ 申请评估", g1_hint="无需承诺 · 按您的环境定制",
 g2_h="2 · 传感器部署", g2_p="我们在您的站点安装网络传感器——inline 或被动——通过专用加密 VPN 连接到 SOC。", g2_btn="▸ 查看架构", g2_hint="每站点约 15 分钟 · 无终端代理",
 g3_h="3 · 自主 SOC", g3_p="7×24 的 AI 监控与响应上线。您收到告警和报告——其余交给平台。", g3_btn="▸ 联系我们", g3_hint="托管 · 自主 · 始终在线",
 foot_tag="面向企业与公共管理的 AI 自主网络安全平台。托管 SOC 与漏洞评估。",
 foot_platform="平台", foot_legal="法律", foot_company="公司", romania="罗马尼亚", rights="保留所有权利。",
)

TR["it"] = dict(
 lang_label="Lingua", title="FasterUp.AI — Piattaforma Autonoma di Cybersicurezza con IA",
 desc="FasterUp AI Autonomous Platform — SOC gestito e Valutazione delle Vulnerabilità per imprese e pubblica amministrazione. Rileva, decide e risponde in modo autonomo.",
 ogd="SOC gestito e Valutazione delle Vulnerabilità per imprese e pubblica amministrazione. Rilevamento e risposta autonomi in secondi.",
 nav_services="Servizi", nav_tech="Tecnologia", nav_start="Inizia", nav_terms="Termini", nav_privacy="Privacy",
 cta_assess="Richiedi una valutazione", cta_how="Come funziona",
 h1a="Cybersicurezza autonoma", h1b="per imprese e pubblica amministrazione",
 sub="FasterUp rileva, decide e risponde alle minacce informatiche in tempo reale — fondendo sensori di rete, correlazione SIEM e analisi del contesto con IA in un'unica decisione autonoma. Centro Operativo di Sicurezza gestito e Valutazione delle Vulnerabilità, installati presso la vostra sede.",
 stat1="dalla minaccia alla decisione autonoma", stat2="monitoraggio e risposta", stat3b="4 fonti", stat3="fusione di contesto IA per allerta", stat4="indicatori di minaccia in tempo reale",
 svc_kicker="SERVIZI", svc_h2="Due servizi. Una piattaforma autonoma.",
 svc_p="Rilevamento e risposta gestiti e valutazione continua delle vulnerabilità — alimentati dallo stesso motore IA e dalla stessa intelligence sulle minacce in tempo reale.",
 s1_b="GESTITO · 24/7", s1_h="SOC — Centro Operativo di Sicurezza",
 s1_p="Monitoraggio autonomo e completamente gestito della vostra rete. FasterUp rileva intrusioni, anomalie di rete, command-and-control, esfiltrazione di dati e violazioni delle policy — poi il motore IA decide e agisce: blocca, notifica o inoltra, in secondi.",
 s1_t=["Suricata IDS","Cluster 1 SIEM","CYBER3 AI Context Fusion Engine","MISP threat intel"], s1_n="Risposta autonoma in secondi — non ore. Allerte e report raggiungono il vostro team via Telegram ed e-mail.",
 s2_b="CONTINUO", s2_h="VAS — Valutazione delle Vulnerabilità",
 s2_p="Valutazione automatica e continua dei vostri asset per vulnerabilità note, configurazioni errate e servizi esposti. Ricevete report prioritizzati e attuabili — così correggete prima ciò che conta, prima che lo trovino gli attaccanti.",
 s2_t=["scoperta degli asset","rilevamento CVE","scansioni pianificate","report prioritizzati"], s2_n="Conoscete la vostra esposizione prima degli attaccanti. Le scansioni vengono eseguite in sicurezza, secondo un calendario che controllate voi.",
 s3_h="Risposta autonoma", s3_p="Ogni allerta è valutata dall'IA su tutte le fonti. In base alla gravità, FasterUp registra, blocca automaticamente l'IP di origine, genera un'allerta urgente o inoltra a un umano — senza bisogno di un analista per agire.",
 s3_t=["blocca","notifica","inoltra"], s3_n="Azioni in base alla gravità, 24/7 — anche alle 3 di notte.",
 s4_h="Motore di Fusione del Contesto IA", s4_p="Il motore CYBER3 AI Context Fusion Engine unifica quattro fonti indipendenti — intelligence sulle minacce, telemetria di rete, correlazione SIEM e CYBER3 Database — in un'unica decisione contestuale di rischio.",
 s4_t=["multi-fonte","rischio contestuale","2–11s"], s4_n="Fusione di quattro segnali in una decisione strutturata — tecnologia proprietaria FasterUp.",
 s5_h="Sensori di rete", s5_p="Sensori dedicati installati nelle vostre sedi — inline o passivi — sorvegliano il traffico per ARP spoofing, DHCP malevolo, scansioni, exploit e comportamenti anomali, senza toccare i vostri dispositivi.",
 s5_t=["inline / passivo","VPN privata","nessun agente sui dispositivi"], s5_n="Collegati al SOC tramite una VPN privata crittografata.",
 s6_h="Allerte chiare e comprensibili", s6_p="Quando qualcosa conta, il vostro team riceve una spiegazione concisa e comprensibile — cosa è successo, perché è una minaccia e cosa ha già fatto FasterUp — via Telegram ed e-mail.",
 s6_t=["Telegram","e-mail","spiegazione IA"], s6_n="Niente rumore. Solo ciò che richiede la vostra attenzione, spiegato in modo semplice.",
 tech_kicker="TECNOLOGIA", tech_h2="Rilevare. Correlare. Decidere. Agire — in modo autonomo.",
 tech_p="La piattaforma FasterUp AI Autonomous trasforma il segnale di rete grezzo in una risposta strutturata in secondi, fondendo quattro fonti di intelligence indipendenti per ogni decisione.",
 n1_b="Sensori di rete", n1_s="Suricata IDS · inline o passivo", n2_b="Correlazione SIEM", n2_s="Cluster 1 SIEM · eventi normalizzati e correlati",
 n3_b="CYBER3 AI Context Fusion Engine", n3_s="decisione autonoma in 2–11s", n4_b="Risposta", n4_s="blocca · notifica · inoltra",
 kanon_tag="AUTONOMO", kanon="Ogni allerta è valutata dall'IA su quattro fonti. Gli eventi <b>sospetti</b> sono registrati in silenzio; un <b>attacco confermato</b> attiva un blocco IP automatico; gli eventi <b>gravi</b> generano un'allerta urgente; una <b>compromissione critica</b> viene inoltrata a un analista umano. End-to-end: 2–11 secondi.",
 p1_b="Autonomo per impostazione predefinita", p1_s="Decide e agisce senza attendere un analista — la piattaforma gestisce la routine, gli umani le eccezioni.",
 p2_b="Fusione di contesto multi-fonte", p2_s="MISP threat intel + telemetria Suricata + correlazione Cluster 1 SIEM + CYBER3 Database — a ogni decisione.",
 p3_b="Installato presso la vostra sede", p3_s="I sensori risiedono nella vostra rete; solo i metadati fluiscono al SOC tramite una VPN privata crittografata.",
 p4_b="Costruito per la responsabilità", p4_s="Audit trail completo, reportistica strutturata e trattamento dei dati conforme al GDPR — pensato per la pubblica amministrazione.",
 start_kicker="INIZIA", start_h2="Dalla valutazione alla difesa autonoma",
 start_p="Un onboarding semplice per organizzazioni di qualsiasi dimensione — da un singolo ufficio a un'istituzione pubblica distribuita.",
 g1_h="1 · Valutazione", g1_p="Mappiamo i vostri asset e la vostra esposizione con una Valutazione delle Vulnerabilità — un quadro chiaro della vostra situazione.", g1_btn="▸ Richiedi una valutazione", g1_hint="Senza impegno · su misura per il vostro ambiente",
 g2_h="2 · Installazione dei sensori", g2_p="Installiamo sensori di rete nelle vostre sedi — inline o passivi — collegati al SOC tramite una VPN privata crittografata.", g2_btn="▸ Vedi l'architettura", g2_hint="~15 min per sede · nessun agente sui dispositivi",
 g3_h="3 · SOC autonomo", g3_p="Il monitoraggio e la risposta IA 24/7 entrano in funzione. Ricevete allerte e report — la piattaforma fa il resto.", g3_btn="▸ Parliamone", g3_hint="Gestito · autonomo · sempre attivo",
 foot_tag="Piattaforma Autonoma di Cybersicurezza con IA per imprese e pubblica amministrazione. SOC gestito e Valutazione delle Vulnerabilità.",
 foot_platform="Piattaforma", foot_legal="Legale", foot_company="Azienda", romania="Romania", rights="Tutti i diritti riservati.",
)

# ---- Conținut tehnic suplimentar (Health Check + principii) per limbă ----
EXTRA = {
 "en": dict(hc_tag="HEALTH CHECK",
   hc="The whole platform runs under an autonomous <b>Health Check</b> that continuously monitors, administers and self-repairs the entire sensor fleet — 24/7, without human intervention. It detects stalled packet capture, restarts stuck services, recovers dropped VPN tunnels, and validates the end-to-end pipeline with synthetic canary alerts. Every sensor heals itself; the fleet stays online.",
   p5_b="Open, proven stack", p5_s="Built on Suricata IDS, SIEM correlation and MISP threat intelligence — hardened, orchestrated and decided by our AI engine.",
   p6_b="Real-time pipeline", p6_s="Raw packet → normalized event → correlated alert → AI decision → response, end-to-end in seconds."),
 "ro": dict(hc_tag="HEALTH CHECK",
   hc="Întreaga platformă rulează sub un <b>Health Check</b> autonom care monitorizează, administrează și se auto-repară continuu pe toată flota de senzori — 24/7, fără intervenție umană. Detectează captura de pachete blocată, repornește serviciile înțepenite, reface tunelurile VPN căzute și validează lanțul cap-la-cap cu alerte canary sintetice. Fiecare senzor se vindecă singur; flota rămâne online.",
   p5_b="Stack deschis, dovedit", p5_s="Construit pe Suricata IDS, corelare SIEM și inteligență de amenințare MISP — întărit, orchestrat și decis de motorul nostru AI.",
   p6_b="Pipeline în timp real", p6_s="Pachet brut → eveniment normalizat → alertă corelată → decizie AI → răspuns, cap-la-cap în secunde."),
 "es": dict(hc_tag="HEALTH CHECK",
   hc="Toda la plataforma funciona bajo un <b>Health Check</b> autónomo que monitoriza, administra y auto-repara continuamente toda la flota de sensores — 24/7, sin intervención humana. Detecta capturas de paquetes detenidas, reinicia servicios atascados, recupera túneles VPN caídos y valida la cadena de extremo a extremo con alertas canary sintéticas. Cada sensor se cura solo; la flota sigue en línea.",
   p5_b="Stack abierto y probado", p5_s="Construido sobre Suricata IDS, correlación SIEM e inteligencia de amenazas MISP — reforzado, orquestado y decidido por nuestro motor de IA.",
   p6_b="Pipeline en tiempo real", p6_s="Paquete bruto → evento normalizado → alerta correlacionada → decisión IA → respuesta, de extremo a extremo en segundos."),
 "de": dict(hc_tag="HEALTH CHECK",
   hc="Die gesamte Plattform läuft unter einem autonomen <b>Health Check</b>, der die gesamte Sensorflotte rund um die Uhr kontinuierlich überwacht, verwaltet und selbst repariert — ohne menschliches Eingreifen. Er erkennt stockende Paketerfassung, startet hängende Dienste neu, stellt abgebrochene VPN-Tunnel wieder her und validiert die Ende-zu-Ende-Pipeline mit synthetischen Canary-Alarmen. Jeder Sensor heilt sich selbst; die Flotte bleibt online.",
   p5_b="Offener, bewährter Stack", p5_s="Aufgebaut auf Suricata IDS, SIEM-Korrelation und MISP-Bedrohungsintelligenz — gehärtet, orchestriert und entschieden von unserer KI-Engine.",
   p6_b="Echtzeit-Pipeline", p6_s="Rohpaket → normalisiertes Ereignis → korrelierter Alarm → KI-Entscheidung → Reaktion, Ende-zu-Ende in Sekunden."),
 "fr": dict(hc_tag="HEALTH CHECK",
   hc="Toute la plateforme fonctionne sous un <b>Health Check</b> autonome qui surveille, administre et auto-répare en continu l'ensemble de la flotte de capteurs — 24/7, sans intervention humaine. Il détecte les captures de paquets bloquées, redémarre les services figés, rétablit les tunnels VPN tombés et valide la chaîne de bout en bout avec des alertes canary synthétiques. Chaque capteur se répare lui-même ; la flotte reste en ligne.",
   p5_b="Stack ouvert et éprouvé", p5_s="Bâti sur Suricata IDS, corrélation SIEM et renseignement sur les menaces MISP — durci, orchestré et décidé par notre moteur IA.",
   p6_b="Pipeline en temps réel", p6_s="Paquet brut → événement normalisé → alerte corrélée → décision IA → réponse, de bout en bout en secondes."),
 "ru": dict(hc_tag="HEALTH CHECK",
   hc="Вся платформа работает под управлением автономного <b>Health Check</b>, который непрерывно мониторит, администрирует и самовосстанавливает весь парк датчиков — 24/7, без участия человека. Он обнаруживает зависший захват пакетов, перезапускает застрявшие службы, восстанавливает оборванные VPN-туннели и проверяет сквозной конвейер синтетическими canary-оповещениями. Каждый датчик чинит себя сам; парк остаётся в строю.",
   p5_b="Открытый, проверенный стек", p5_s="Построен на Suricata IDS, корреляции SIEM и threat intelligence MISP — усилен, оркестрирован, решения принимает наш ИИ-движок.",
   p6_b="Конвейер реального времени", p6_s="Сырой пакет → нормализованное событие → коррелированный сигнал → решение ИИ → реакция, сквозь за секунды."),
 "zh": dict(hc_tag="HEALTH CHECK",
   hc="整个平台由自主的 <b>Health Check</b> 系统统管，全天候持续监控、管理并自我修复整支传感器舰队——无需人工介入。它检测停滞的抓包、重启卡死的服务、恢复断开的 VPN 隧道，并以合成 canary 告警验证端到端管道。每个传感器自我修复，舰队始终在线。",
   p5_b="开放且成熟的技术栈", p5_s="基于 Suricata IDS、SIEM 关联与 MISP 威胁情报——经加固、编排，并由我们的 AI 引擎决策。",
   p6_b="实时管道", p6_s="原始数据包 → 规范化事件 → 关联告警 → AI 决策 → 响应，端到端数秒完成。"),
 "it": dict(hc_tag="HEALTH CHECK",
   hc="L'intera piattaforma funziona sotto un <b>Health Check</b> autonomo che monitora, amministra e auto-ripara continuamente l'intera flotta di sensori — 24/7, senza intervento umano. Rileva la cattura di pacchetti bloccata, riavvia i servizi inceppati, ripristina i tunnel VPN caduti e convalida la pipeline end-to-end con allerte canary sintetiche. Ogni sensore si ripara da solo; la flotta resta online.",
   p5_b="Stack aperto e collaudato", p5_s="Costruito su Suricata IDS, correlazione SIEM e threat intelligence MISP — irrobustito, orchestrato e deciso dal nostro motore IA.",
   p6_b="Pipeline in tempo reale", p6_s="Pacchetto grezzo → evento normalizzato → allerta correlata → decisione IA → risposta, end-to-end in secondi."),
}
# ---- Conținut „în spate" (acordeoane + secțiuni XDR/Packages) — EN + RO (din ofertă) ----
# Limbile fără intrare aici rămân pe conținutul de bază (acordeoanele/XDR/Packages nu apar).
DETAIL = {}
DETAIL["en"] = dict(
 more_label="See details",
 s1_d='<ul><li>24/7 monitoring with <b>no in-house security analysts required</b> — the platform handles the routine, humans handle the exceptions.</li><li>Real-time detection on Suricata IDS, event correlation through Cluster 1 SIEM.</li><li>Four-source context fusion on every alert: MISP + Suricata + SIEM + the CYBER3 Database.</li><li>Severity-driven autonomous action: silent log → automatic IP block → urgent alert → human escalation.</li></ul><div class="adv"><b>Competitive edge:</b> one vendor owns the entire chain — from the network sensor to the decision — so response takes <b>2–11 seconds, not hours</b>, with no SOC to staff, train or keep awake at 3 a.m.</div>',
 s2_d='<ul><li>Automatic <b>asset discovery</b> across your network — you cannot protect what you do not know you have.</li><li>Detection of known vulnerabilities (CVE) and insecure configurations.</li><li>Scheduled scans, run safely, on a calendar <b>you control</b>.</li><li>Prioritized reporting — remediate the highest-impact risks first.</li></ul><div class="adv"><b>Competitive edge:</b> VAS and SOC work together — the SOC stops attacks in progress while VAS <b>proactively shrinks your attack surface</b> before attackers find the gap.</div>',
 s3_d='<ul><li><b>Suspect</b> — ambiguous event, worth tracking → logged silently.</li><li><b>Confirmed</b> — confirmed attack → automatic block of the source IP.</li><li><b>Severe</b> — high-impact event → an urgent alert is raised.</li><li><b>Critical</b> — critical compromise → escalation to a human analyst.</li></ul><div class="adv"><b>Competitive edge:</b> the platform <b>acts without waiting for a human</b>. Your team is involved only when a critical decision genuinely needs it.</div>',
 s4_d='<ul><li>Four independent signals scored together: <b>MISP</b> threat intel, <b>Suricata</b> network telemetry, <b>Cluster 1 SIEM</b> correlation, the <b>CYBER3 Database</b>.</li><li>One contextual risk decision per alert — in 2–11 seconds.</li><li>Proprietary technology, owned end-to-end by ROL PORTAL SERVICES.</li></ul><div class="adv"><b>Competitive edge:</b> the same engine also powers the <b>CYBER3 endpoint app (XDR)</b> — network and workstations share <b>one live threat intelligence</b>, closing the loop between perimeter and endpoint detection.</div>',
 s5_d='<ul><li>Installed inline or passive at each site — <b>~15 minutes per site</b>, no agents on endpoints.</li><li>Watches for ARP spoofing, rogue DHCP, scanning, exploits and anomalous behaviour.</li><li><b>Your data stays on your premises</b> — only metadata flows to the SOC, over an encrypted private VPN.</li></ul><div class="adv"><b>Competitive edge:</b> privacy by design — built for <b>GDPR and public-sector</b> data handling, with full audit trail.</div>',
 s6_d='<ul><li>Plain-language explanation: <b>what happened, why it is a threat, and what the platform already did</b>.</li><li>Delivered to your team by Telegram and email.</li><li>No raw log dumps, no alert storms.</li></ul><div class="adv"><b>Competitive edge:</b> zero alert fatigue — your staff sees <b>only what needs attention</b>, already triaged and acted upon.</div>',
 n1_d='Dedicated sensors at each site capture and inspect traffic for ARP spoofing, rogue DHCP, scans and exploits — no agents on your endpoints. Only metadata leaves your network, over an encrypted private VPN.',
 n2_d='Raw packets become normalized events, then correlated across the whole estate so isolated signals turn into a single, meaningful incident — not thousands of disconnected logs.',
 n3_d='The proprietary engine fuses four independent sources — MISP threat intel, Suricata telemetry, SIEM correlation and the CYBER3 Database — into one contextual risk decision in 2–11 seconds.',
 n4_d='By severity the platform acts on its own: silent log, automatic source-IP block, urgent alert, or escalation to a human analyst — end-to-end in seconds, 24/7.',
 kanon_sum="How the platform decides &amp; acts on every alert",
 hc_sum="The platform that watches — and repairs — itself",
 g1_d='We map the assets and exposure of your institution through a vulnerability assessment — the result is a clear picture of your current state. <b>No commitment, scoped strictly to your environment</b>, and it forms the basis for a correctly sized proposal.',
 g2_d='We install network sensors at each site, inline or passive, connected back to the SOC over an encrypted private VPN. <b>About 15 minutes per site, with no agents on your endpoints.</b> Optionally, we deploy the CYBER3 XDR app on workstations and mobile devices per your policy.',
 g3_d='24/7 AI monitoring and response goes live. You receive clear alerts and reports while the platform handles the rest — running under an autonomous Health Check that monitors, administers and self-repairs the whole fleet, <b>with no human intervention</b>.',
 xdr_kicker="ENDPOINT XDR · CYBER3.AI", xdr_h2="The SOC, extended to every workstation",
 xdr_p='What sets this offer apart: the <b>CYBER3.AI</b> app installs on desktops, laptops and mobile devices — turning every endpoint into a detection &amp; response point connected to the same SOC. Real XDR, fed by the same live threat intelligence. Most checks run on-device, so protection works offline and data stays private (k-anonymity: only the first 4 hex of a SHA-256 hash ever leave the device).',
 x1_h="Device / PC Scan", x1_p="A 0–100 security score in seconds.", x1_d='<ul><li>Lock screen, USB debugging, patch level, firewall, UAC, risky permissions.</li><li>Scans installed apps &amp; files against the live malware database (SHA-256).</li><li>One-click fixes and quarantine.</li></ul>',
 x2_h="AI Scam Shield", x2_p="Instant verdict on suspicious messages.", x2_d='Paste any suspicious SMS or message and get an instant verdict with a plain-language explanation: <b>impersonated brand, typosquatting, risky TLD, urgency &amp; payment tactics.</b>',
 x3_h="Web &amp; Scam Protection", x3_p="Check any link before you open it.", x3_d='Malicious, phishing, ransomware and exploit sites are flagged in real time against the CYBER3 threat database. An on-device Bloom filter resolves <b>99% of checks instantly and offline.</b>',
 x4_h="Browsing Guard", x4_p="Browser extension that blocks threats live.", x4_d='A Chrome / Edge / Firefox extension that blocks scam, phishing and malware sites, plus ads and trackers, while your staff browse.',
 x5_h="Realtime Breach Monitoring", x5_p="Continuous watch on institutional email.", x5_d='Continuous background checks of institutional e-mail addresses, with push alerts the moment one appears in a new data breach.',
 x6_h="Password &amp; Email Breach Check", x6_p="Check exposure with k-anonymity.", x6_d='Checks whether a password or e-mail appeared in known breaches using <b>k-anonymity</b> — the password never leaves the device.',
 x7_h="Scam Number Check", x7_p="Is this number reported as fraud?", x7_d='Checks whether a phone number is reported as scam, spam or fraud in the CYBER3 threat database.',
 x8_h="VPN Lite", x8_p="Device-wide malicious-domain filter.", x8_d='A local DNS filter that blocks malicious and ad domains across the whole device (all apps), <b>on-device</b>, without routing traffic through a server.',
 x9_h="Digital Footprint", x9_p="See how exposed your identity is.", x9_d="""An identity exposure report from known breaches: which breaches you are in, what data leaked, an exposure score (0–100) and clear recommendations. Private — k-anonymity, on-device.""",
 xdr_why_tag="WHY IT MATTERS", xdr_why_sum="Why an endpoint XDR layer matters for a public institution",
 xdr_why_body='<ul><li>Covers the dominant attack vector in the public sector — <b>the employee and the workstation</b>: phishing, scams, malicious links/attachments, compromised passwords.</li><li>Protects staff in the field or working remotely, not just inside the physical perimeter.</li><li><b>Privacy by design</b> (k-anonymity, on-device processing) — essential for public data and GDPR compliance.</li><li>No accounts, no ads, no advertising SDKs — no data leakage to third parties.</li><li>Endpoint telemetry feeds the same SOC, closing the loop: network detection ↔ endpoint detection.</li></ul><div class="adv">Availability: Android (full app), Windows (PC scan, Scam Shield, Web Protection, password checks — standalone, no Java). An iOS app is in development.</div>',
 pkg_kicker="PACKAGES", pkg_h2="Sized to your institution",
 pkg_p="For a county-level or multi-site institution, the solution scales modularly. An indicative structure below — the exact configuration (number of sensors, sites, endpoints) is set after an initial assessment of your environment.",
 pkg_dsum="Best for",
 pk1_b="ESSENTIAL", pk1_h="Essential", pk1_p="Managed 24/7 SOC + 1 sensor at the main site + monthly scheduled VAS.", pk1_d="Central office with concentrated IT infrastructure. Gets you autonomous 24/7 monitoring and a regular vulnerability picture without standing up a SOC of your own.",
 pk2_b="EXTENDED", pk2_h="Extended", pk2_p="SOC + sensors at all sites + bi-weekly VAS + CYBER3 XDR on critical workstations.", pk2_d="Multi-site institutions with elevated exposure. Network coverage everywhere plus endpoint XDR on the workstations that matter most.",
 pk3_b="RECOMMENDED", pk3_h="Complete", pk3_p="SOC + sensors at all sites + continuous VAS + CYBER3 XDR on all endpoints &amp; mobiles + unified reporting.", pk3_d="County level, sensitive citizen data, strict compliance. Full multi-layer defence — perimeter and every workstation — under one vendor and one unified report.",
 pricenote="Pricing: this document presents the services and the technical solution. A detailed financial offer is prepared on request, based on the initial assessment (sites, sensors, endpoints) and the procurement method applicable to your institution.",
 nav_xdr="Endpoint XDR", nav_packages="Packages",
)
DETAIL["ro"] = dict(
 more_label="Vezi detalii",
 s1_d='<ul><li>Monitorizare 24/7 <b>fără analiști de securitate proprii</b> — platforma se ocupă de rutină, oamenii de excepții.</li><li>Detecție în timp real pe Suricata IDS, corelare evenimente prin Cluster 1 SIEM.</li><li>Fuziune de context din patru surse la fiecare alertă: MISP + Suricata + SIEM + baza CYBER3.</li><li>Acțiune autonomă în funcție de severitate: înregistrare silențioasă → blocare automată IP → alertă urgentă → escaladare la om.</li></ul><div class="adv"><b>Avantaj competitiv:</b> un singur furnizor deține tot lanțul — de la senzorul de rețea la decizie — așa că răspunsul durează <b>2–11 secunde, nu ore</b>, fără un SOC de angajat, instruit și ținut treaz la 3 dimineața.</div>',
 s2_d='<ul><li><b>Descoperire automată a activelor</b> din rețea — nu poți proteja ce nu știi că ai.</li><li>Detecție de vulnerabilități cunoscute (CVE) și configurări nesigure.</li><li>Scanări programate, rulate în siguranță, după un calendar <b>pe care îl controlezi tu</b>.</li><li>Raportare prioritizată — remediezi întâi riscurile cu impact maxim.</li></ul><div class="adv"><b>Avantaj competitiv:</b> VAS și SOC lucrează împreună — SOC-ul oprește atacurile în desfășurare, iar VAS <b>reduce proactiv suprafața de atac</b> înainte ca atacatorii să găsească breșa.</div>',
 s3_d='<ul><li><b>Suspect</b> — eveniment ambiguu, de urmărit → înregistrat silențios.</li><li><b>Confirmat</b> — atac confirmat → blocare automată a IP-ului sursă.</li><li><b>Sever</b> — eveniment de impact ridicat → se ridică o alertă urgentă.</li><li><b>Critic</b> — compromitere critică → escaladare către un analist uman.</li></ul><div class="adv"><b>Avantaj competitiv:</b> platforma <b>acționează fără să aștepte un om</b>. Echipa ta intervine doar când o decizie critică chiar o cere.</div>',
 s4_d='<ul><li>Patru semnale independente evaluate împreună: <b>MISP</b> threat intel, telemetrie <b>Suricata</b>, corelare <b>Cluster 1 SIEM</b>, <b>baza CYBER3</b>.</li><li>O singură decizie contextuală de risc per alertă — în 2–11 secunde.</li><li>Tehnologie proprietară, deținută integral de ROL PORTAL SERVICES.</li></ul><div class="adv"><b>Avantaj competitiv:</b> același motor alimentează și aplicația <b>CYBER3 de endpoint (XDR)</b> — rețeaua și stațiile împart <b>aceeași inteligență de amenințare live</b>, închizând bucla dintre perimetru și endpoint.</div>',
 s5_d='<ul><li>Instalați inline sau pasiv la fiecare sediu — <b>~15 minute per locație</b>, fără agenți pe stații.</li><li>Urmăresc ARP spoofing, DHCP fals, scanări, exploit-uri și comportament anormal.</li><li><b>Datele rămân la sediul tău</b> — doar metadate ajung la SOC, printr-un VPN privat criptat.</li></ul><div class="adv"><b>Avantaj competitiv:</b> confidențialitate prin design — gândit pentru <b>GDPR și sectorul public</b>, cu pistă de audit completă.</div>',
 s6_d='<ul><li>Explicație în limbaj uman: <b>ce s-a întâmplat, de ce e o amenințare și ce a făcut deja platforma</b>.</li><li>Livrată echipei tale pe Telegram și email.</li><li>Fără jurnale brute, fără avalanșe de alerte.</li></ul><div class="adv"><b>Avantaj competitiv:</b> zero oboseală de alerte — personalul vede <b>doar ce necesită atenție</b>, deja triat și rezolvat.</div>',
 n1_d='Senzori dedicați la fiecare sediu captează și inspectează traficul pentru ARP spoofing, DHCP fals, scanări și exploit-uri — fără agenți pe stații. Din rețea pleacă doar metadate, printr-un VPN privat criptat.',
 n2_d='Pachetele brute devin evenimente normalizate, apoi corelate pe tot mediul, astfel încât semnale izolate se transformă într-un incident unic și relevant — nu mii de jurnale fără legătură.',
 n3_d='Motorul proprietar fuzionează patru surse independente — MISP threat intel, telemetrie Suricata, corelare SIEM și baza CYBER3 — într-o singură decizie contextuală de risc în 2–11 secunde.',
 n4_d='În funcție de severitate, platforma acționează singură: înregistrare silențioasă, blocare automată a IP-ului sursă, alertă urgentă sau escaladare către un analist uman — cap-la-cap în secunde, 24/7.',
 kanon_sum="Cum decide și acționează platforma la fiecare alertă",
 hc_sum="Platforma care se supraveghează — și se repară — singură",
 g1_d='Cartografiem activele și expunerea instituției printr-o evaluare de vulnerabilități — rezultă o imagine clară a stării actuale. <b>Fără angajament, delimitată strict la mediul tău</b>, și stă la baza unei oferte dimensionate corect.',
 g2_d='Instalăm senzori de rețea la fiecare sediu, inline sau pasiv, conectați la SOC printr-un VPN privat criptat. <b>Aproximativ 15 minute per locație, fără agenți pe stații.</b> Opțional, desfășurăm aplicația CYBER3 XDR pe stații și mobile, conform politicii tale.',
 g3_d='Monitorizarea și răspunsul AI 24/7 intră în funcțiune. Primești alerte și rapoarte clare, iar platforma se ocupă de rest — sub un Health Check autonom care monitorizează, administrează și auto-repară întreaga flotă, <b>fără intervenție umană</b>.',
 xdr_kicker="ENDPOINT XDR · CYBER3.AI", xdr_h2="SOC-ul, extins la fiecare stație de lucru",
 xdr_p='Ce diferențiază această ofertă: aplicația <b>CYBER3.AI</b> se instalează pe desktop-uri, laptopuri și dispozitive mobile — transformând fiecare endpoint într-un punct de detecție și răspuns conectat la același SOC. XDR real, alimentat de aceeași inteligență de amenințare live. Majoritatea verificărilor rulează on-device, deci protecția merge și offline, iar datele rămân private (k-anonimitate: doar primele 4 hex dintr-un hash SHA-256 părăsesc dispozitivul).',
 x1_h="Scanare dispozitiv / PC", x1_p="Scor de securitate 0–100 în câteva secunde.", x1_d='<ul><li>Ecran de blocare, USB debugging, nivel de patch, firewall, UAC, permisiuni riscante.</li><li>Scanează aplicațiile și fișierele instalate față de baza de malware live (SHA-256).</li><li>Remedieri și carantină cu un singur clic.</li></ul>',
 x2_h="AI Scam Shield", x2_p="Verdict instant asupra mesajelor suspecte.", x2_d='Lipești orice SMS sau mesaj suspect și primești instant un verdict, cu explicație în limbaj uman: <b>brand imitat, typosquatting, TLD riscant, tactici de urgență și de plată.</b>',
 x3_h="Web &amp; Scam Protection", x3_p="Verifică orice link înainte să-l deschizi.", x3_d='Site-urile malițioase, de phishing, ransomware și exploit sunt semnalate în timp real față de baza de amenințări CYBER3. Un filtru Bloom on-device rezolvă <b>99% din verificări instant și offline.</b>',
 x4_h="Browsing Guard", x4_p="Extensie de browser care blochează amenințările live.", x4_d='O extensie Chrome / Edge / Firefox care blochează site-uri de scam, phishing și malware, plus reclame și trackere, în timp ce personalul navighează.',
 x5_h="Monitorizare breșe în timp real", x5_p="Supraveghere continuă a emailului instituțional.", x5_d='Verificări continue în fundal ale adreselor de e-mail instituționale, cu alerte push în momentul apariției într-o breșă de date nouă.',
 x6_h="Verificare parolă &amp; email", x6_p="Verifică expunerea prin k-anonimitate.", x6_d='Verifică dacă o parolă sau un e-mail a apărut în breșe cunoscute folosind <b>k-anonimitate</b> — parola nu părăsește niciodată dispozitivul.',
 x7_h="Verificare număr scam", x7_p="E numărul ăsta raportat ca fraudă?", x7_d='Verifică dacă un număr de telefon este raportat ca scam, spam sau fraudă în baza de amenințări CYBER3.',
 x8_h="VPN Lite", x8_p="Filtru de domenii malițioase pe tot dispozitivul.", x8_d='Un filtru DNS local care blochează domenii malițioase și de reclamă la nivelul întregului dispozitiv (toate aplicațiile), <b>on-device</b>, fără a ruta traficul printr-un server.',
 x9_h="Digital Footprint", x9_p="Vezi cât de expusă e identitatea ta.", x9_d="""Un raport de expunere a identității din breșele cunoscute: în ce breșe ești, ce date ți-au scăpat, un scor de expunere (0–100) și recomandări clare. Privat — k-anonimitate, on-device.""",
 xdr_why_tag="DE CE CONTEAZĂ", xdr_why_sum="De ce contează un strat XDR de endpoint pentru o instituție publică",
 xdr_why_body='<ul><li>Acoperă vectorul de atac dominant în sectorul public — <b>angajatul și stația de lucru</b>: phishing, scam, linkuri/atașamente malițioase, parole compromise.</li><li>Protejează personalul aflat în teren sau în telemuncă, nu doar în perimetrul fizic.</li><li><b>Confidențialitate prin design</b> (k-anonimitate, procesare on-device) — esențială pentru date publice și conformitate GDPR.</li><li>Fără conturi, fără reclame, fără SDK-uri de publicitate — fără scurgeri de date către terți.</li><li>Telemetria de endpoint hrănește același SOC, închizând bucla: detecție rețea ↔ detecție endpoint.</li></ul><div class="adv">Disponibilitate: Android (aplicație completă), Windows (scanare PC, Scam Shield, Web Protection, verificare parole — autonom, fără Java). Aplicația iOS este în dezvoltare.</div>',
 pkg_kicker="PACHETE", pkg_h2="Dimensionat pentru instituția ta",
 pkg_p="Pentru o instituție de nivel județean sau cu mai multe sedii, soluția se dimensionează modular. Mai jos, o structurare orientativă — configurația exactă (număr de senzori, sedii, endpoint-uri) se stabilește după o evaluare inițială a mediului.",
 pkg_dsum="Recomandat pentru",
 pk1_b="ESENȚIAL", pk1_h="Esențial", pk1_p="SOC administrat 24/7 + 1 senzor la sediul principal + VAS programat lunar.", pk1_d="Sediu central, infrastructură IT concentrată. Obții monitorizare autonomă 24/7 și o imagine periodică a vulnerabilităților, fără să-ți construiești un SOC propriu.",
 pk2_b="EXTINS", pk2_h="Extins", pk2_p="SOC + senzori la toate sediile + VAS bilunar + CYBER3 XDR pe stațiile critice.", pk2_d="Instituții multi-sediu cu expunere ridicată. Acoperire de rețea peste tot, plus XDR de endpoint pe stațiile cele mai importante.",
 pk3_b="RECOMANDAT", pk3_h="Complet", pk3_p="SOC + senzori la toate sediile + VAS continuu + CYBER3 XDR pe toate endpoint-urile și mobilele + raportare unificată.", pk3_d="Nivel județean, date sensibile ale cetățenilor, conformitate strictă. Apărare completă pe straturi — perimetru și fiecare stație — sub un singur furnizor și un singur raport unificat.",
 pricenote="Prețuri: prezentul document prezintă serviciile și soluția tehnică. Oferta financiară detaliată se elaborează la cerere, în funcție de evaluarea inițială (sedii, senzori, endpoint-uri) și de modalitatea de achiziție aplicabilă instituției.",
 nav_xdr="Endpoint XDR", nav_packages="Pachete",
)
DETAIL["es"] = dict(
 more_label="Ver detalles",
 s1_d='<ul><li>Monitorización 24/7 <b>sin necesidad de analistas de seguridad propios</b> — la plataforma gestiona la rutina, los humanos las excepciones.</li><li>Detección en tiempo real en Suricata IDS, correlación de eventos mediante Cluster 1 SIEM.</li><li>Fusión de contexto de cuatro fuentes en cada alerta: MISP + Suricata + SIEM + la base CYBER3.</li><li>Acción autónoma según la gravedad: registro silencioso → bloqueo automático de IP → alerta urgente → escalado a un humano.</li></ul><div class="adv"><b>Ventaja competitiva:</b> un único proveedor controla toda la cadena — del sensor de red a la decisión — por lo que la respuesta tarda <b>2–11 segundos, no horas</b>, sin un SOC que contratar, formar y mantener despierto a las 3 de la madrugada.</div>',
 s2_d='<ul><li><b>Descubrimiento automático de activos</b> en su red — no puede proteger lo que no sabe que tiene.</li><li>Detección de vulnerabilidades conocidas (CVE) y configuraciones inseguras.</li><li>Escaneos programados, ejecutados de forma segura, según un calendario <b>que usted controla</b>.</li><li>Informes priorizados — remedie primero los riesgos de mayor impacto.</li></ul><div class="adv"><b>Ventaja competitiva:</b> VAS y SOC trabajan juntos — el SOC detiene los ataques en curso mientras VAS <b>reduce proactivamente su superficie de ataque</b> antes de que los atacantes encuentren la brecha.</div>',
 s3_d='<ul><li><b>Sospechoso</b> — evento ambiguo, a vigilar → registrado en silencio.</li><li><b>Confirmado</b> — ataque confirmado → bloqueo automático de la IP de origen.</li><li><b>Grave</b> — evento de alto impacto → se genera una alerta urgente.</li><li><b>Crítico</b> — compromiso crítico → escalado a un analista humano.</li></ul><div class="adv"><b>Ventaja competitiva:</b> la plataforma <b>actúa sin esperar a un humano</b>. Su equipo interviene solo cuando una decisión crítica realmente lo requiere.</div>',
 s4_d='<ul><li>Cuatro señales independientes evaluadas juntas: <b>MISP</b> threat intel, telemetría de red <b>Suricata</b>, correlación <b>Cluster 1 SIEM</b>, la <b>base CYBER3</b>.</li><li>Una decisión contextual de riesgo por alerta — en 2–11 segundos.</li><li>Tecnología propia, controlada de extremo a extremo por ROL PORTAL SERVICES.</li></ul><div class="adv"><b>Ventaja competitiva:</b> el mismo motor impulsa también la aplicación <b>CYBER3 de endpoint (XDR)</b> — red y estaciones comparten <b>una misma inteligencia de amenazas en vivo</b>, cerrando el ciclo entre perímetro y endpoint.</div>',
 s5_d='<ul><li>Instalados inline o pasivos en cada sede — <b>~15 minutos por sede</b>, sin agentes en los equipos.</li><li>Vigilan ARP spoofing, DHCP fraudulento, escaneos, exploits y comportamiento anómalo.</li><li><b>Sus datos permanecen en sus instalaciones</b> — solo los metadatos fluyen al SOC, por una VPN privada cifrada.</li></ul><div class="adv"><b>Ventaja competitiva:</b> privacidad por diseño — pensado para el tratamiento de datos del <b>RGPD y el sector público</b>, con registro de auditoría completo.</div>',
 s6_d='<ul><li>Explicación en lenguaje claro: <b>qué pasó, por qué es una amenaza y qué hizo ya la plataforma</b>.</li><li>Entregada a su equipo por Telegram y email.</li><li>Sin volcados de registros, sin avalanchas de alertas.</li></ul><div class="adv"><b>Ventaja competitiva:</b> cero fatiga de alertas — su personal ve <b>solo lo que requiere atención</b>, ya clasificado y resuelto.</div>',
 n1_d='Sensores dedicados en cada sede capturan e inspeccionan el tráfico en busca de ARP spoofing, DHCP fraudulento, escaneos y exploits — sin agentes en sus equipos. Solo los metadatos salen de su red, por una VPN privada cifrada.',
 n2_d='Los paquetes en bruto se convierten en eventos normalizados y luego se correlacionan en todo el entorno, de modo que señales aisladas se transforman en un único incidente con sentido — no en miles de registros sin conexión.',
 n3_d='El motor propio fusiona cuatro fuentes independientes — MISP threat intel, telemetría Suricata, correlación SIEM y la base CYBER3 — en una única decisión contextual de riesgo en 2–11 segundos.',
 n4_d='Según la gravedad, la plataforma actúa por sí sola: registro silencioso, bloqueo automático de la IP de origen, alerta urgente o escalado a un analista humano — de extremo a extremo en segundos, 24/7.',
 kanon_sum="Cómo decide y actúa la plataforma en cada alerta",
 hc_sum="La plataforma que se vigila — y se repara — a sí misma",
 g1_d='Cartografiamos los activos y la exposición de su institución mediante una evaluación de vulnerabilidades — el resultado es una imagen clara de su estado actual. <b>Sin compromiso, acotada estrictamente a su entorno</b>, y sirve de base para una oferta correctamente dimensionada.',
 g2_d='Instalamos sensores de red en cada sede, inline o pasivos, conectados al SOC por una VPN privada cifrada. <b>Unos 15 minutos por sede, sin agentes en sus equipos.</b> Opcionalmente, desplegamos la app CYBER3 XDR en estaciones y dispositivos móviles según su política.',
 g3_d='La monitorización y respuesta con IA 24/7 entra en funcionamiento. Recibe alertas e informes claros mientras la plataforma hace el resto — bajo un Health Check autónomo que monitoriza, administra y auto-repara toda la flota, <b>sin intervención humana</b>.',
 xdr_kicker="ENDPOINT XDR · CYBER3.AI", xdr_h2="El SOC, extendido a cada estación de trabajo",
 xdr_p='Lo que distingue esta oferta: la app <b>CYBER3.AI</b> se instala en equipos de escritorio, portátiles y dispositivos móviles — convirtiendo cada endpoint en un punto de detección y respuesta conectado al mismo SOC. XDR real, alimentado por la misma inteligencia de amenazas en vivo. La mayoría de las comprobaciones se ejecutan en el dispositivo, por lo que la protección funciona sin conexión y los datos siguen siendo privados (k-anonimato: solo los primeros 4 hex de un hash SHA-256 salen del dispositivo).',
 x1_h="Escaneo de dispositivo / PC", x1_p="Una puntuación de seguridad 0–100 en segundos.", x1_d='<ul><li>Pantalla de bloqueo, USB debugging, nivel de parches, firewall, UAC, permisos de riesgo.</li><li>Escanea aplicaciones y archivos instalados frente a la base de malware en vivo (SHA-256).</li><li>Correcciones y cuarentena con un clic.</li></ul>',
 x2_h="AI Scam Shield", x2_p="Veredicto instantáneo sobre mensajes sospechosos.", x2_d='Pegue cualquier SMS o mensaje sospechoso y obtenga un veredicto instantáneo con una explicación clara: <b>marca suplantada, typosquatting, TLD de riesgo, tácticas de urgencia y de pago.</b>',
 x3_h="Web &amp; Scam Protection", x3_p="Compruebe cualquier enlace antes de abrirlo.", x3_d='Los sitios maliciosos, de phishing, ransomware y exploits se señalan en tiempo real frente a la base de amenazas CYBER3. Un filtro Bloom en el dispositivo resuelve el <b>99% de las comprobaciones al instante y sin conexión.</b>',
 x4_h="Browsing Guard", x4_p="Extensión de navegador que bloquea amenazas en vivo.", x4_d='Una extensión de Chrome / Edge / Firefox que bloquea sitios de scam, phishing y malware, además de anuncios y rastreadores, mientras su personal navega.',
 x5_h="Monitorización de brechas en tiempo real", x5_p="Vigilancia continua del correo institucional.", x5_d='Comprobaciones continuas en segundo plano de las direcciones de correo institucionales, con alertas push en cuanto una aparece en una nueva brecha de datos.',
 x6_h="Comprobación de contraseña y email", x6_p="Compruebe la exposición con k-anonimato.", x6_d='Comprueba si una contraseña o un email apareció en brechas conocidas usando <b>k-anonimato</b> — la contraseña nunca sale del dispositivo.',
 x7_h="Comprobación de número scam", x7_p="¿Está este número reportado como fraude?", x7_d='Comprueba si un número de teléfono está reportado como scam, spam o fraude en la base de amenazas CYBER3.',
 x8_h="VPN Lite", x8_p="Filtro de dominios maliciosos en todo el dispositivo.", x8_d='Un filtro DNS local que bloquea dominios maliciosos y de publicidad en todo el dispositivo (todas las apps), <b>en el dispositivo</b>, sin enrutar el tráfico por un servidor.',
 x9_h="Huella digital", x9_p="Mira cuán expuesta está tu identidad.", x9_d="""Un informe de exposición de identidad a partir de filtraciones conocidas: en qué filtraciones estás, qué datos se filtraron, una puntuación de exposición (0–100) y recomendaciones claras. Privado — k-anonimato, en el dispositivo.""",
 xdr_why_tag="POR QUÉ IMPORTA", xdr_why_sum="Por qué importa una capa XDR de endpoint para una institución pública",
 xdr_why_body='<ul><li>Cubre el vector de ataque dominante en el sector público — <b>el empleado y la estación de trabajo</b>: phishing, scams, enlaces/adjuntos maliciosos, contraseñas comprometidas.</li><li>Protege al personal sobre el terreno o en teletrabajo, no solo dentro del perímetro físico.</li><li><b>Privacidad por diseño</b> (k-anonimato, procesamiento en el dispositivo) — esencial para datos públicos y conformidad con el RGPD.</li><li>Sin cuentas, sin anuncios, sin SDK publicitarios — sin fugas de datos a terceros.</li><li>La telemetría de endpoint alimenta el mismo SOC, cerrando el ciclo: detección de red ↔ detección de endpoint.</li></ul><div class="adv">Disponibilidad: Android (app completa), Windows (escaneo de PC, Scam Shield, Web Protection, comprobación de contraseñas — autónomo, sin Java). La app para iOS está en desarrollo.</div>',
 pkg_kicker="PAQUETES", pkg_h2="Dimensionado para su institución",
 pkg_p="Para una institución de nivel provincial o con varias sedes, la solución escala de forma modular. A continuación, una estructura orientativa — la configuración exacta (número de sensores, sedes, endpoints) se establece tras una evaluación inicial de su entorno.",
 pkg_dsum="Recomendado para",
 pk1_b="ESENCIAL", pk1_h="Esencial", pk1_p="SOC gestionado 24/7 + 1 sensor en la sede principal + VAS programado mensual.", pk1_d="Sede central con infraestructura de TI concentrada. Obtiene monitorización autónoma 24/7 y una imagen periódica de vulnerabilidades sin montar un SOC propio.",
 pk2_b="EXTENDIDO", pk2_h="Extendido", pk2_p="SOC + sensores en todas las sedes + VAS quincenal + CYBER3 XDR en estaciones críticas.", pk2_d="Instituciones con varias sedes y exposición elevada. Cobertura de red en todas partes más XDR de endpoint en las estaciones más importantes.",
 pk3_b="RECOMENDADO", pk3_h="Completo", pk3_p="SOC + sensores en todas las sedes + VAS continuo + CYBER3 XDR en todos los endpoints y móviles + informes unificados.", pk3_d="Nivel provincial, datos sensibles de los ciudadanos, cumplimiento estricto. Defensa completa en capas — perímetro y cada estación — con un único proveedor y un único informe unificado.",
 pricenote="Precios: este documento presenta los servicios y la solución técnica. Una oferta económica detallada se elabora a petición, según la evaluación inicial (sedes, sensores, endpoints) y la modalidad de contratación aplicable a su institución.",
 nav_xdr="Endpoint XDR", nav_packages="Paquetes",
)
DETAIL["it"] = dict(
 more_label="""Vedi dettagli""",
 s1_d="""<ul><li>Monitoraggio 24/7 <b>senza bisogno di analisti di sicurezza propri</b> — la piattaforma gestisce la routine, gli umani le eccezioni.</li><li>Rilevamento in tempo reale su Suricata IDS, correlazione eventi tramite Cluster 1 SIEM.</li><li>Fusione di contesto da quattro fonti a ogni allerta: MISP + Suricata + SIEM + il database CYBER3.</li><li>Azione autonoma in base alla gravità: registrazione silenziosa → blocco IP automatico → allerta urgente → inoltro a un umano.</li></ul><div class="adv"><b>Vantaggio competitivo:</b> un unico fornitore controlla l'intera catena — dal sensore di rete alla decisione — quindi la risposta richiede <b>2–11 secondi, non ore</b>, senza un SOC da assumere, formare e tenere sveglio alle 3 di notte.</div>""",
 s2_d="""<ul><li><b>Scoperta automatica degli asset</b> nella vostra rete — non potete proteggere ciò che non sapete di avere.</li><li>Rilevamento di vulnerabilità note (CVE) e configurazioni non sicure.</li><li>Scansioni pianificate, eseguite in sicurezza, secondo un calendario <b>che controllate voi</b>.</li><li>Reportistica prioritizzata — correggete prima i rischi a maggiore impatto.</li></ul><div class="adv"><b>Vantaggio competitivo:</b> VAS e SOC lavorano insieme — il SOC ferma gli attacchi in corso mentre VAS <b>riduce proattivamente la superficie di attacco</b> prima che gli attaccanti trovino la falla.</div>""",
 s3_d="""<ul><li><b>Sospetto</b> — evento ambiguo, da monitorare → registrato in silenzio.</li><li><b>Confermato</b> — attacco confermato → blocco automatico dell'IP di origine.</li><li><b>Grave</b> — evento ad alto impatto → viene generata un'allerta urgente.</li><li><b>Critico</b> — compromissione critica → inoltro a un analista umano.</li></ul><div class="adv"><b>Vantaggio competitivo:</b> la piattaforma <b>agisce senza attendere un umano</b>. Il vostro team interviene solo quando una decisione critica lo richiede davvero.</div>""",
 s4_d="""<ul><li>Quattro segnali indipendenti valutati insieme: <b>MISP</b> threat intel, telemetria di rete <b>Suricata</b>, correlazione <b>Cluster 1 SIEM</b>, il <b>database CYBER3</b>.</li><li>Una decisione contestuale di rischio per allerta — in 2–11 secondi.</li><li>Tecnologia proprietaria, controllata end-to-end da ROL PORTAL SERVICES.</li></ul><div class="adv"><b>Vantaggio competitivo:</b> lo stesso motore alimenta anche l'app <b>CYBER3 di endpoint (XDR)</b> — rete e postazioni condividono <b>un'unica intelligence sulle minacce in tempo reale</b>, chiudendo il cerchio tra perimetro ed endpoint.</div>""",
 s5_d="""<ul><li>Installati inline o passivi in ogni sede — <b>~15 minuti per sede</b>, senza agenti sui dispositivi.</li><li>Sorvegliano ARP spoofing, DHCP malevolo, scansioni, exploit e comportamenti anomali.</li><li><b>I vostri dati restano presso la vostra sede</b> — solo i metadati fluiscono al SOC, tramite una VPN privata crittografata.</li></ul><div class="adv"><b>Vantaggio competitivo:</b> privacy by design — pensato per il trattamento dei dati del <b>GDPR e del settore pubblico</b>, con audit trail completo.</div>""",
 s6_d="""<ul><li>Spiegazione in linguaggio chiaro: <b>cosa è successo, perché è una minaccia e cosa ha già fatto la piattaforma</b>.</li><li>Recapitata al vostro team via Telegram ed e-mail.</li><li>Niente dump di log, niente valanghe di allerte.</li></ul><div class="adv"><b>Vantaggio competitivo:</b> zero affaticamento da allerte — il personale vede <b>solo ciò che richiede attenzione</b>, già triato e gestito.</div>""",
 n1_d="""Sensori dedicati in ogni sede catturano e ispezionano il traffico per ARP spoofing, DHCP malevolo, scansioni ed exploit — senza agenti sui dispositivi. Dalla rete escono solo metadati, tramite una VPN privata crittografata.""",
 n2_d="""I pacchetti grezzi diventano eventi normalizzati, poi correlati su tutto l'ambiente, così segnali isolati si trasformano in un unico incidente significativo — non in migliaia di log scollegati.""",
 n3_d="""Il motore proprietario fonde quattro fonti indipendenti — MISP threat intel, telemetria Suricata, correlazione SIEM e il database CYBER3 — in un'unica decisione contestuale di rischio in 2–11 secondi.""",
 n4_d="""In base alla gravità, la piattaforma agisce da sola: registrazione silenziosa, blocco automatico dell'IP di origine, allerta urgente o inoltro a un analista umano — end-to-end in secondi, 24/7.""",
 kanon_sum="""Come la piattaforma decide e agisce a ogni allerta""",
 hc_sum="""La piattaforma che si sorveglia — e si ripara — da sola""",
 g1_d="""Mappiamo gli asset e l'esposizione della vostra istituzione con una valutazione delle vulnerabilità — il risultato è un quadro chiaro dello stato attuale. <b>Senza impegno, circoscritta strettamente al vostro ambiente</b>, e costituisce la base per un'offerta dimensionata correttamente.""",
 g2_d="""Installiamo sensori di rete in ogni sede, inline o passivi, collegati al SOC tramite una VPN privata crittografata. <b>Circa 15 minuti per sede, senza agenti sui dispositivi.</b> Su richiesta, distribuiamo l'app CYBER3 XDR su postazioni e dispositivi mobili secondo la vostra policy.""",
 g3_d="""Il monitoraggio e la risposta IA 24/7 entrano in funzione. Ricevete allerte e report chiari mentre la piattaforma fa il resto — sotto un Health Check autonomo che monitora, amministra e auto-ripara l'intera flotta, <b>senza intervento umano</b>.""",
 xdr_kicker="""ENDPOINT XDR · CYBER3.AI""", xdr_h2="""Il SOC, esteso a ogni postazione di lavoro""",
 xdr_p="""Ciò che distingue questa offerta: l'app <b>CYBER3.AI</b> si installa su desktop, laptop e dispositivi mobili — trasformando ogni endpoint in un punto di rilevamento e risposta connesso allo stesso SOC. XDR reale, alimentato dalla stessa intelligence sulle minacce in tempo reale. La maggior parte dei controlli viene eseguita sul dispositivo, quindi la protezione funziona anche offline e i dati restano privati (k-anonimato: solo i primi 4 hex di un hash SHA-256 lasciano il dispositivo).""",
 x1_h="""Scansione dispositivo / PC""", x1_p="""Un punteggio di sicurezza 0–100 in pochi secondi.""", x1_d="""<ul><li>Schermata di blocco, USB debugging, livello di patch, firewall, UAC, permessi rischiosi.</li><li>Scansiona app e file installati rispetto al database malware in tempo reale (SHA-256).</li><li>Correzioni e quarantena con un clic.</li></ul>""",
 x2_h="""AI Scam Shield""", x2_p="""Verdetto istantaneo sui messaggi sospetti.""", x2_d="""Incollate qualsiasi SMS o messaggio sospetto e ottenete un verdetto istantaneo con spiegazione chiara: <b>brand imitato, typosquatting, TLD rischioso, tattiche di urgenza e di pagamento.</b>""",
 x3_h="""Web &amp; Scam Protection""", x3_p="""Controllate ogni link prima di aprirlo.""", x3_d="""I siti malevoli, di phishing, ransomware ed exploit sono segnalati in tempo reale rispetto al database delle minacce CYBER3. Un filtro Bloom sul dispositivo risolve il <b>99% dei controlli all'istante e offline.</b>""",
 x4_h="""Browsing Guard""", x4_p="""Estensione browser che blocca le minacce in tempo reale.""", x4_d="""Un'estensione Chrome / Edge / Firefox che blocca siti di scam, phishing e malware, oltre a pubblicità e tracker, mentre il personale naviga.""",
 x5_h="""Monitoraggio violazioni in tempo reale""", x5_p="""Sorveglianza continua della posta istituzionale.""", x5_d="""Controlli continui in background degli indirizzi e-mail istituzionali, con avvisi push non appena uno compare in una nuova violazione di dati.""",
 x6_h="""Controllo password ed e-mail""", x6_p="""Verificate l'esposizione con k-anonimato.""", x6_d="""Verifica se una password o un'e-mail è comparsa in violazioni note usando il <b>k-anonimato</b> — la password non lascia mai il dispositivo.""",
 x7_h="""Controllo numero scam""", x7_p="""Questo numero è segnalato come frode?""", x7_d="""Verifica se un numero di telefono è segnalato come scam, spam o frode nel database delle minacce CYBER3.""",
 x8_h="""VPN Lite""", x8_p="""Filtro di domini malevoli sull'intero dispositivo.""", x8_d="""Un filtro DNS locale che blocca domini malevoli e pubblicitari sull'intero dispositivo (tutte le app), <b>sul dispositivo</b>, senza instradare il traffico attraverso un server.""",
 x9_h="Impronta digitale", x9_p="Scopri quanto è esposta la tua identità.", x9_d="""Un report di esposizione dell'identità dalle violazioni note: in quali violazioni sei, quali dati sono trapelati, un punteggio di esposizione (0–100) e raccomandazioni chiare. Privato — k-anonimato, sul dispositivo.""",
 xdr_why_tag="""PERCHÉ CONTA""", xdr_why_sum="""Perché un livello XDR di endpoint conta per un'istituzione pubblica""",
 xdr_why_body="""<ul><li>Copre il vettore di attacco dominante nel settore pubblico — <b>il dipendente e la postazione di lavoro</b>: phishing, scam, link/allegati malevoli, password compromesse.</li><li>Protegge il personale sul campo o in telelavoro, non solo all'interno del perimetro fisico.</li><li><b>Privacy by design</b> (k-anonimato, elaborazione sul dispositivo) — essenziale per i dati pubblici e la conformità al GDPR.</li><li>Nessun account, nessuna pubblicità, nessun SDK pubblicitario — nessuna fuga di dati verso terzi.</li><li>La telemetria di endpoint alimenta lo stesso SOC, chiudendo il cerchio: rilevamento di rete ↔ rilevamento di endpoint.</li></ul><div class="adv">Disponibilità: Android (app completa), Windows (scansione PC, Scam Shield, Web Protection, controllo password — autonomo, senza Java). L'app per iOS è in sviluppo.</div>""",
 pkg_kicker="""PACCHETTI""", pkg_h2="""Dimensionato per la vostra istituzione""",
 pkg_p="""Per un'istituzione a livello provinciale o con più sedi, la soluzione scala in modo modulare. Di seguito una struttura orientativa — la configurazione esatta (numero di sensori, sedi, endpoint) si stabilisce dopo una valutazione iniziale del vostro ambiente.""",
 pkg_dsum="""Consigliato per""",
 pk1_b="""ESSENZIALE""", pk1_h="""Essenziale""", pk1_p="""SOC gestito 24/7 + 1 sensore nella sede principale + VAS pianificato mensile.""", pk1_d="""Sede centrale con infrastruttura IT concentrata. Ottenete monitoraggio autonomo 24/7 e un quadro periodico delle vulnerabilità senza allestire un SOC proprio.""",
 pk2_b="""ESTESO""", pk2_h="""Esteso""", pk2_p="""SOC + sensori in tutte le sedi + VAS bisettimanale + CYBER3 XDR sulle postazioni critiche.""", pk2_d="""Istituzioni con più sedi ed esposizione elevata. Copertura di rete ovunque più XDR di endpoint sulle postazioni più importanti.""",
 pk3_b="""CONSIGLIATO""", pk3_h="""Completo""", pk3_p="""SOC + sensori in tutte le sedi + VAS continuo + CYBER3 XDR su tutti gli endpoint e mobili + reportistica unificata.""", pk3_d="""Livello provinciale, dati sensibili dei cittadini, conformità rigorosa. Difesa completa a strati — perimetro e ogni postazione — con un unico fornitore e un unico report unificato.""",
 pricenote="""Prezzi: il presente documento presenta i servizi e la soluzione tecnica. Un'offerta economica dettagliata viene elaborata su richiesta, in base alla valutazione iniziale (sedi, sensori, endpoint) e alla modalità di acquisto applicabile alla vostra istituzione.""",
 nav_xdr="""Endpoint XDR""", nav_packages="""Pacchetti""",
)
DETAIL["de"] = dict(
 more_label="Details ansehen",
 s1_d='<ul><li>24/7-Überwachung <b>ohne eigene Sicherheitsanalysten</b> — die Plattform übernimmt die Routine, Menschen die Ausnahmen.</li><li>Echtzeit-Erkennung auf Suricata IDS, Ereigniskorrelation über Cluster 1 SIEM.</li><li>Kontextfusion aus vier Quellen bei jedem Alarm: MISP + Suricata + SIEM + die CYBER3-Datenbank.</li><li>Vom Schweregrad gesteuerte autonome Aktion: stille Protokollierung → automatische IP-Sperre → dringender Alarm → Eskalation an einen Menschen.</li></ul><div class="adv"><b>Wettbewerbsvorteil:</b> ein einziger Anbieter besitzt die gesamte Kette — vom Netzwerksensor bis zur Entscheidung — daher dauert die Reaktion <b>2–11 Sekunden, nicht Stunden</b>, ohne ein SOC, das eingestellt, geschult und um 3 Uhr morgens wachgehalten werden muss.</div>',
 s2_d='<ul><li><b>Automatische Asset-Erkennung</b> in Ihrem Netzwerk — Sie können nicht schützen, was Sie nicht kennen.</li><li>Erkennung bekannter Schwachstellen (CVE) und unsicherer Konfigurationen.</li><li>Geplante Scans, sicher ausgeführt, nach einem von <b>Ihnen gesteuerten Zeitplan</b>.</li><li>Priorisierte Berichte — beheben Sie zuerst die Risiken mit der größten Wirkung.</li></ul><div class="adv"><b>Wettbewerbsvorteil:</b> VAS und SOC arbeiten zusammen — das SOC stoppt laufende Angriffe, während VAS Ihre <b>Angriffsfläche proaktiv verkleinert</b>, bevor Angreifer die Lücke finden.</div>',
 s3_d='<ul><li><b>Verdächtig</b> — mehrdeutiges Ereignis, zu beobachten → still protokolliert.</li><li><b>Bestätigt</b> — bestätigter Angriff → automatische Sperre der Quell-IP.</li><li><b>Schwer</b> — Ereignis mit hoher Wirkung → ein dringender Alarm wird ausgelöst.</li><li><b>Kritisch</b> — kritische Kompromittierung → Eskalation an einen menschlichen Analysten.</li></ul><div class="adv"><b>Wettbewerbsvorteil:</b> die Plattform <b>handelt, ohne auf einen Menschen zu warten</b>. Ihr Team wird nur einbezogen, wenn eine kritische Entscheidung es wirklich erfordert.</div>',
 s4_d='<ul><li>Vier unabhängige Signale gemeinsam bewertet: <b>MISP</b> threat intel, <b>Suricata</b>-Netzwerktelemetrie, <b>Cluster 1 SIEM</b>-Korrelation, die <b>CYBER3-Datenbank</b>.</li><li>Eine kontextbezogene Risikoentscheidung pro Alarm — in 2–11 Sekunden.</li><li>Proprietäre Technologie, end-to-end im Besitz von ROL PORTAL SERVICES.</li></ul><div class="adv"><b>Wettbewerbsvorteil:</b> dieselbe Engine treibt auch die <b>CYBER3-Endpunkt-App (XDR)</b> an — Netzwerk und Arbeitsplätze teilen <b>eine gemeinsame Live-Bedrohungsintelligenz</b> und schließen die Lücke zwischen Perimeter und Endpunkt.</div>',
 s5_d='<ul><li>Inline oder passiv an jedem Standort installiert — <b>~15 Minuten pro Standort</b>, keine Agenten auf den Endgeräten.</li><li>Überwachen ARP-Spoofing, Rogue-DHCP, Scans, Exploits und anomales Verhalten.</li><li><b>Ihre Daten bleiben bei Ihnen vor Ort</b> — nur Metadaten fließen über ein verschlüsseltes privates VPN zum SOC.</li></ul><div class="adv"><b>Wettbewerbsvorteil:</b> Privacy by Design — konzipiert für die Datenverarbeitung der <b>DSGVO und des öffentlichen Sektors</b>, mit vollständigem Audit-Trail.</div>',
 s6_d='<ul><li>Erklärung in klarer Sprache: <b>was passiert ist, warum es eine Bedrohung ist und was die Plattform bereits getan hat</b>.</li><li>An Ihr Team per Telegram und E-Mail zugestellt.</li><li>Keine Roh-Logs, keine Alarmfluten.</li></ul><div class="adv"><b>Wettbewerbsvorteil:</b> keine Alarmmüdigkeit — Ihr Personal sieht <b>nur, was Aufmerksamkeit braucht</b>, bereits triagiert und bearbeitet.</div>',
 n1_d='Dedizierte Sensoren an jedem Standort erfassen und prüfen den Datenverkehr auf ARP-Spoofing, Rogue-DHCP, Scans und Exploits — ohne Agenten auf Ihren Endgeräten. Nur Metadaten verlassen Ihr Netzwerk, über ein verschlüsseltes privates VPN.',
 n2_d='Rohpakete werden zu normalisierten Ereignissen und dann über die gesamte Umgebung korreliert, sodass isolierte Signale zu einem einzigen, aussagekräftigen Vorfall werden — nicht zu Tausenden unverbundener Logs.',
 n3_d='Die proprietäre Engine fusioniert vier unabhängige Quellen — MISP threat intel, Suricata-Telemetrie, SIEM-Korrelation und die CYBER3-Datenbank — zu einer kontextbezogenen Risikoentscheidung in 2–11 Sekunden.',
 n4_d='Je nach Schweregrad handelt die Plattform selbst: stille Protokollierung, automatische Sperre der Quell-IP, dringender Alarm oder Eskalation an einen menschlichen Analysten — end-to-end in Sekunden, 24/7.',
 kanon_sum="Wie die Plattform bei jedem Alarm entscheidet und handelt",
 hc_sum="Die Plattform, die sich selbst überwacht — und repariert",
 g1_d='Wir erfassen die Assets und die Exposition Ihrer Einrichtung mit einer Schwachstellenbewertung — das Ergebnis ist ein klares Bild Ihres aktuellen Zustands. <b>Unverbindlich, streng auf Ihre Umgebung begrenzt</b>, und Grundlage für ein korrekt dimensioniertes Angebot.',
 g2_d='Wir installieren Netzwerksensoren an jedem Standort, inline oder passiv, über ein verschlüsseltes privates VPN mit dem SOC verbunden. <b>Etwa 15 Minuten pro Standort, ohne Agenten auf Ihren Endgeräten.</b> Optional verteilen wir die CYBER3-XDR-App auf Arbeitsplätzen und Mobilgeräten gemäß Ihrer Richtlinie.',
 g3_d='Die KI-Überwachung und -Reaktion rund um die Uhr geht live. Sie erhalten klare Alarme und Berichte, während die Plattform den Rest erledigt — unter einem autonomen Health Check, der die gesamte Flotte überwacht, verwaltet und selbst repariert, <b>ohne menschliches Eingreifen</b>.',
 xdr_kicker="ENDPOINT XDR · CYBER3.AI", xdr_h2="Das SOC, erweitert auf jeden Arbeitsplatz",
 xdr_p='Was dieses Angebot auszeichnet: die <b>CYBER3.AI</b>-App wird auf Desktops, Laptops und Mobilgeräten installiert — und macht jeden Endpunkt zu einem Erkennungs- und Reaktionspunkt, der mit demselben SOC verbunden ist. Echtes XDR, gespeist von derselben Live-Bedrohungsintelligenz. Die meisten Prüfungen laufen auf dem Gerät, sodass der Schutz auch offline funktioniert und die Daten privat bleiben (k-Anonymität: nur die ersten 4 Hex eines SHA-256-Hashes verlassen das Gerät).',
 x1_h="Geräte- / PC-Scan", x1_p="Ein Sicherheitsscore von 0–100 in Sekunden.", x1_d='<ul><li>Sperrbildschirm, USB-Debugging, Patch-Stand, Firewall, UAC, riskante Berechtigungen.</li><li>Scannt installierte Apps und Dateien gegen die Live-Malware-Datenbank (SHA-256).</li><li>Ein-Klick-Behebung und Quarantäne.</li></ul>',
 x2_h="AI Scam Shield", x2_p="Sofortiges Urteil zu verdächtigen Nachrichten.", x2_d='Fügen Sie eine verdächtige SMS oder Nachricht ein und erhalten Sie ein sofortiges Urteil mit klarer Erklärung: <b>imitierte Marke, Typosquatting, riskante TLD, Dringlichkeits- und Zahlungstaktiken.</b>',
 x3_h="Web &amp; Scam Protection", x3_p="Prüfen Sie jeden Link, bevor Sie ihn öffnen.", x3_d='Bösartige, Phishing-, Ransomware- und Exploit-Seiten werden in Echtzeit gegen die CYBER3-Bedrohungsdatenbank markiert. Ein Bloom-Filter auf dem Gerät löst <b>99% der Prüfungen sofort und offline.</b>',
 x4_h="Browsing Guard", x4_p="Browser-Erweiterung, die Bedrohungen live blockiert.", x4_d='Eine Chrome- / Edge- / Firefox-Erweiterung, die Scam-, Phishing- und Malware-Seiten sowie Werbung und Tracker blockiert, während Ihr Personal surft.',
 x5_h="Echtzeit-Überwachung von Datenlecks", x5_p="Kontinuierliche Überwachung institutioneller E-Mails.", x5_d='Kontinuierliche Hintergrundprüfungen institutioneller E-Mail-Adressen, mit Push-Alarmen, sobald eine in einem neuen Datenleck auftaucht.',
 x6_h="Passwort- &amp; E-Mail-Prüfung", x6_p="Prüfen Sie die Exposition mit k-Anonymität.", x6_d='Prüft, ob ein Passwort oder eine E-Mail in bekannten Datenlecks auftauchte, mittels <b>k-Anonymität</b> — das Passwort verlässt nie das Gerät.',
 x7_h="Scam-Nummern-Prüfung", x7_p="Ist diese Nummer als Betrug gemeldet?", x7_d='Prüft, ob eine Telefonnummer in der CYBER3-Bedrohungsdatenbank als Scam, Spam oder Betrug gemeldet ist.',
 x8_h="VPN Lite", x8_p="Geräteweiter Filter für bösartige Domains.", x8_d='Ein lokaler DNS-Filter, der bösartige und Werbe-Domains auf dem gesamten Gerät (alle Apps) blockiert, <b>auf dem Gerät</b>, ohne den Datenverkehr über einen Server zu leiten.',
 x9_h="Digitaler Fußabdruck", x9_p="Sieh, wie exponiert deine Identität ist.", x9_d="""Ein Bericht zur Identitäts-Exposition aus bekannten Lecks: in welchen Lecks du bist, welche Daten betroffen sind, ein Expositions-Score (0–100) und klare Empfehlungen. Privat — k-Anonymität, auf dem Gerät.""",
 xdr_why_tag="WARUM ES ZÄHLT", xdr_why_sum="Warum eine Endpunkt-XDR-Schicht für eine öffentliche Einrichtung zählt",
 xdr_why_body='<ul><li>Deckt den dominierenden Angriffsvektor im öffentlichen Sektor ab — <b>den Mitarbeiter und den Arbeitsplatz</b>: Phishing, Scams, bösartige Links/Anhänge, kompromittierte Passwörter.</li><li>Schützt Personal im Außendienst oder Homeoffice, nicht nur innerhalb des physischen Perimeters.</li><li><b>Privacy by Design</b> (k-Anonymität, Verarbeitung auf dem Gerät) — wesentlich für öffentliche Daten und DSGVO-Konformität.</li><li>Keine Konten, keine Werbung, keine Werbe-SDKs — kein Datenabfluss an Dritte.</li><li>Endpunkt-Telemetrie speist dasselbe SOC und schließt den Kreis: Netzwerkerkennung ↔ Endpunkterkennung.</li></ul><div class="adv">Verfügbarkeit: Android (vollständige App), Windows (PC-Scan, Scam Shield, Web Protection, Passwortprüfung — eigenständig, ohne Java). Eine iOS-App ist in Entwicklung.</div>',
 pkg_kicker="PAKETE", pkg_h2="Auf Ihre Einrichtung zugeschnitten",
 pkg_p="Für eine Einrichtung auf Kreisebene oder mit mehreren Standorten skaliert die Lösung modular. Nachfolgend eine orientierende Struktur — die genaue Konfiguration (Anzahl Sensoren, Standorte, Endpunkte) wird nach einer Erstbewertung Ihrer Umgebung festgelegt.",
 pkg_dsum="Empfohlen für",
 pk1_b="ESSENZIELL", pk1_h="Essenziell", pk1_p="Verwaltetes 24/7-SOC + 1 Sensor am Hauptstandort + monatlich geplantes VAS.", pk1_d="Zentrale mit konzentrierter IT-Infrastruktur. Sie erhalten autonome 24/7-Überwachung und ein regelmäßiges Schwachstellenbild, ohne ein eigenes SOC aufzubauen.",
 pk2_b="ERWEITERT", pk2_h="Erweitert", pk2_p="SOC + Sensoren an allen Standorten + zweiwöchentliches VAS + CYBER3 XDR auf kritischen Arbeitsplätzen.", pk2_d="Einrichtungen mit mehreren Standorten und erhöhter Exposition. Netzwerkabdeckung überall plus Endpunkt-XDR auf den wichtigsten Arbeitsplätzen.",
 pk3_b="EMPFOHLEN", pk3_h="Komplett", pk3_p="SOC + Sensoren an allen Standorten + kontinuierliches VAS + CYBER3 XDR auf allen Endpunkten und Mobilgeräten + einheitliches Reporting.", pk3_d="Kreisebene, sensible Bürgerdaten, strenge Compliance. Vollständige mehrschichtige Verteidigung — Perimeter und jeder Arbeitsplatz — mit einem Anbieter und einem einheitlichen Bericht.",
 pricenote="Preise: dieses Dokument stellt die Leistungen und die technische Lösung vor. Ein detailliertes Finanzangebot wird auf Anfrage erstellt, basierend auf der Erstbewertung (Standorte, Sensoren, Endpunkte) und der für Ihre Einrichtung geltenden Beschaffungsart.",
 nav_xdr="Endpoint XDR", nav_packages="Pakete",
)
DETAIL["fr"] = dict(
 more_label="""Voir les détails""",
 s1_d="""<ul><li>Surveillance 24/7 <b>sans analystes de sécurité internes</b> — la plateforme gère la routine, les humains les exceptions.</li><li>Détection en temps réel sur Suricata IDS, corrélation d'événements via Cluster 1 SIEM.</li><li>Fusion de contexte de quatre sources à chaque alerte : MISP + Suricata + SIEM + la base CYBER3.</li><li>Action autonome selon la gravité : journalisation silencieuse → blocage IP automatique → alerte urgente → escalade vers un humain.</li></ul><div class="adv"><b>Avantage concurrentiel :</b> un seul fournisseur possède toute la chaîne — du capteur réseau à la décision — la réponse prend donc <b>2–11 secondes, pas des heures</b>, sans SOC à recruter, former et maintenir éveillé à 3 h du matin.</div>""",
 s2_d="""<ul><li><b>Découverte automatique des actifs</b> sur votre réseau — vous ne pouvez pas protéger ce que vous ignorez posséder.</li><li>Détection des vulnérabilités connues (CVE) et des configurations non sécurisées.</li><li>Scans planifiés, exécutés en toute sécurité, selon un calendrier <b>que vous contrôlez</b>.</li><li>Rapports priorisés — corrigez d'abord les risques à plus fort impact.</li></ul><div class="adv"><b>Avantage concurrentiel :</b> VAS et SOC travaillent ensemble — le SOC arrête les attaques en cours tandis que VAS <b>réduit proactivement votre surface d'attaque</b> avant que les attaquants ne trouvent la faille.</div>""",
 s3_d="""<ul><li><b>Suspect</b> — événement ambigu, à surveiller → journalisé en silence.</li><li><b>Confirmé</b> — attaque confirmée → blocage automatique de l'IP source.</li><li><b>Grave</b> — événement à fort impact → une alerte urgente est déclenchée.</li><li><b>Critique</b> — compromission critique → escalade vers un analyste humain.</li></ul><div class="adv"><b>Avantage concurrentiel :</b> la plateforme <b>agit sans attendre un humain</b>. Votre équipe n'intervient que lorsqu'une décision critique l'exige vraiment.</div>""",
 s4_d="""<ul><li>Quatre signaux indépendants évalués ensemble : <b>MISP</b> threat intel, télémétrie réseau <b>Suricata</b>, corrélation <b>Cluster 1 SIEM</b>, la <b>base CYBER3</b>.</li><li>Une décision contextuelle de risque par alerte — en 2–11 secondes.</li><li>Technologie propriétaire, maîtrisée de bout en bout par ROL PORTAL SERVICES.</li></ul><div class="adv"><b>Avantage concurrentiel :</b> le même moteur propulse aussi l'application <b>CYBER3 d'endpoint (XDR)</b> — réseau et postes partagent <b>une même intelligence des menaces en direct</b>, bouclant la boucle entre périmètre et endpoint.</div>""",
 s5_d="""<ul><li>Installés inline ou passifs sur chaque site — <b>~15 minutes par site</b>, sans agents sur les postes.</li><li>Surveillent l'ARP spoofing, le DHCP pirate, les scans, les exploits et les comportements anormaux.</li><li><b>Vos données restent dans vos locaux</b> — seules les métadonnées circulent vers le SOC, via un VPN privé chiffré.</li></ul><div class="adv"><b>Avantage concurrentiel :</b> confidentialité dès la conception — pensé pour le traitement des données du <b>RGPD et du secteur public</b>, avec piste d'audit complète.</div>""",
 s6_d="""<ul><li>Explication en langage clair : <b>ce qui s'est passé, pourquoi c'est une menace et ce que la plateforme a déjà fait</b>.</li><li>Transmise à votre équipe par Telegram et e-mail.</li><li>Pas de vidage de journaux, pas de déluge d'alertes.</li></ul><div class="adv"><b>Avantage concurrentiel :</b> zéro fatigue d'alerte — votre personnel ne voit <b>que ce qui requiert son attention</b>, déjà trié et traité.</div>""",
 n1_d="""Des capteurs dédiés sur chaque site capturent et inspectent le trafic pour l'ARP spoofing, le DHCP pirate, les scans et les exploits — sans agents sur vos postes. Seules les métadonnées quittent votre réseau, via un VPN privé chiffré.""",
 n2_d="""Les paquets bruts deviennent des événements normalisés, puis corrélés sur tout le parc, de sorte que des signaux isolés se transforment en un incident unique et pertinent — pas en milliers de journaux déconnectés.""",
 n3_d="""Le moteur propriétaire fusionne quatre sources indépendantes — MISP threat intel, télémétrie Suricata, corrélation SIEM et la base CYBER3 — en une seule décision contextuelle de risque en 2–11 secondes.""",
 n4_d="""Selon la gravité, la plateforme agit d'elle-même : journalisation silencieuse, blocage automatique de l'IP source, alerte urgente ou escalade vers un analyste humain — de bout en bout en secondes, 24/7.""",
 kanon_sum="""Comment la plateforme décide et agit à chaque alerte""",
 hc_sum="""La plateforme qui se surveille — et se répare — elle-même""",
 g1_d="""Nous cartographions les actifs et l'exposition de votre institution par une évaluation de vulnérabilités — le résultat est une image claire de votre état actuel. <b>Sans engagement, strictement limitée à votre environnement</b>, elle sert de base à une offre correctement dimensionnée.""",
 g2_d="""Nous installons des capteurs réseau sur chaque site, inline ou passifs, reliés au SOC via un VPN privé chiffré. <b>Environ 15 minutes par site, sans agents sur vos postes.</b> En option, nous déployons l'application CYBER3 XDR sur les postes et les mobiles selon votre politique.""",
 g3_d="""La surveillance et la réponse par IA 24/7 entrent en service. Vous recevez des alertes et des rapports clairs pendant que la plateforme fait le reste — sous un Health Check autonome qui surveille, administre et auto-répare toute la flotte, <b>sans intervention humaine</b>.""",
 xdr_kicker="""ENDPOINT XDR · CYBER3.AI""", xdr_h2="""Le SOC, étendu à chaque poste de travail""",
 xdr_p="""Ce qui distingue cette offre : l'application <b>CYBER3.AI</b> s'installe sur les ordinateurs de bureau, portables et mobiles — transformant chaque endpoint en point de détection et de réponse connecté au même SOC. Un vrai XDR, alimenté par la même intelligence des menaces en direct. La plupart des vérifications s'exécutent sur l'appareil, donc la protection fonctionne hors ligne et les données restent privées (k-anonymat : seuls les 4 premiers hex d'un hachage SHA-256 quittent l'appareil).""",
 x1_h="""Analyse appareil / PC""", x1_p="""Un score de sécurité 0–100 en quelques secondes.""", x1_d="""<ul><li>Écran de verrouillage, USB debugging, niveau de correctifs, pare-feu, UAC, permissions à risque.</li><li>Analyse les applications et fichiers installés face à la base de malwares en direct (SHA-256).</li><li>Corrections et quarantaine en un clic.</li></ul>""",
 x2_h="""AI Scam Shield""", x2_p="""Verdict instantané sur les messages suspects.""", x2_d="""Collez n'importe quel SMS ou message suspect et obtenez un verdict instantané avec une explication claire : <b>marque usurpée, typosquatting, TLD à risque, tactiques d'urgence et de paiement.</b>""",
 x3_h="""Web &amp; Scam Protection""", x3_p="""Vérifiez chaque lien avant de l'ouvrir.""", x3_d="""Les sites malveillants, de phishing, de ransomware et d'exploit sont signalés en temps réel face à la base de menaces CYBER3. Un filtre Bloom sur l'appareil résout <b>99 % des vérifications instantanément et hors ligne.</b>""",
 x4_h="""Browsing Guard""", x4_p="""Extension de navigateur qui bloque les menaces en direct.""", x4_d="""Une extension Chrome / Edge / Firefox qui bloque les sites de scam, de phishing et de malware, ainsi que les publicités et traceurs, pendant que votre personnel navigue.""",
 x5_h="""Surveillance des fuites en temps réel""", x5_p="""Veille continue sur la messagerie institutionnelle.""", x5_d="""Vérifications continues en arrière-plan des adresses e-mail institutionnelles, avec alertes push dès qu'une apparaît dans une nouvelle fuite de données.""",
 x6_h="""Vérification mot de passe &amp; e-mail""", x6_p="""Vérifiez l'exposition par k-anonymat.""", x6_d="""Vérifie si un mot de passe ou un e-mail est apparu dans des fuites connues via le <b>k-anonymat</b> — le mot de passe ne quitte jamais l'appareil.""",
 x7_h="""Vérification de numéro scam""", x7_p="""Ce numéro est-il signalé comme fraude ?""", x7_d="""Vérifie si un numéro de téléphone est signalé comme scam, spam ou fraude dans la base de menaces CYBER3.""",
 x8_h="""VPN Lite""", x8_p="""Filtre de domaines malveillants sur tout l'appareil.""", x8_d="""Un filtre DNS local qui bloque les domaines malveillants et publicitaires sur tout l'appareil (toutes les applications), <b>sur l'appareil</b>, sans router le trafic par un serveur.""",
 x9_h="Empreinte numérique", x9_p="Voyez à quel point votre identité est exposée.", x9_d="""Un rapport d'exposition de l'identité à partir des fuites connues : dans quelles fuites vous êtes, quelles données ont fuité, un score d'exposition (0–100) et des recommandations claires. Privé — k-anonymat, sur l'appareil.""",
 xdr_why_tag="""POURQUOI C'EST IMPORTANT""", xdr_why_sum="""Pourquoi une couche XDR d'endpoint compte pour une institution publique""",
 xdr_why_body="""<ul><li>Couvre le vecteur d'attaque dominant dans le secteur public — <b>l'employé et le poste de travail</b> : phishing, scams, liens/pièces jointes malveillants, mots de passe compromis.</li><li>Protège le personnel sur le terrain ou en télétravail, pas seulement à l'intérieur du périmètre physique.</li><li><b>Confidentialité dès la conception</b> (k-anonymat, traitement sur l'appareil) — essentielle pour les données publiques et la conformité RGPD.</li><li>Pas de comptes, pas de publicités, pas de SDK publicitaires — aucune fuite de données vers des tiers.</li><li>La télémétrie d'endpoint alimente le même SOC, bouclant la boucle : détection réseau ↔ détection endpoint.</li></ul><div class="adv">Disponibilité : Android (application complète), Windows (analyse PC, Scam Shield, Web Protection, vérification de mots de passe — autonome, sans Java). Une application iOS est en développement.</div>""",
 pkg_kicker="""FORFAITS""", pkg_h2="""Dimensionné pour votre institution""",
 pkg_p="""Pour une institution départementale ou multi-sites, la solution évolue de façon modulaire. Ci-dessous une structure indicative — la configuration exacte (nombre de capteurs, sites, endpoints) est établie après une évaluation initiale de votre environnement.""",
 pkg_dsum="""Recommandé pour""",
 pk1_b="""ESSENTIEL""", pk1_h="""Essentiel""", pk1_p="""SOC géré 24/7 + 1 capteur au site principal + VAS planifié mensuel.""", pk1_d="""Site central avec infrastructure informatique concentrée. Vous obtenez une surveillance autonome 24/7 et une image régulière des vulnérabilités sans monter votre propre SOC.""",
 pk2_b="""ÉTENDU""", pk2_h="""Étendu""", pk2_p="""SOC + capteurs sur tous les sites + VAS bimensuel + CYBER3 XDR sur les postes critiques.""", pk2_d="""Institutions multi-sites à exposition élevée. Couverture réseau partout, plus XDR d'endpoint sur les postes les plus importants.""",
 pk3_b="""RECOMMANDÉ""", pk3_h="""Complet""", pk3_p="""SOC + capteurs sur tous les sites + VAS continu + CYBER3 XDR sur tous les endpoints et mobiles + reporting unifié.""", pk3_d="""Niveau départemental, données sensibles des citoyens, conformité stricte. Défense complète en couches — périmètre et chaque poste — avec un seul fournisseur et un seul rapport unifié.""",
 pricenote="""Tarifs : ce document présente les services et la solution technique. Une offre financière détaillée est établie sur demande, en fonction de l'évaluation initiale (sites, capteurs, endpoints) et du mode de passation applicable à votre institution.""",
 nav_xdr="""Endpoint XDR""", nav_packages="""Forfaits""",
)
DETAIL["ru"] = dict(
 more_label="Подробнее",
 s1_d='<ul><li>Мониторинг 24/7 <b>без собственных аналитиков безопасности</b> — платформа берёт на себя рутину, люди — исключения.</li><li>Обнаружение в реальном времени на Suricata IDS, корреляция событий через Cluster 1 SIEM.</li><li>Слияние контекста из четырёх источников по каждому сигналу: MISP + Suricata + SIEM + база CYBER3.</li><li>Автономное действие по серьёзности: тихое журналирование → автоблокировка IP → срочный сигнал → эскалация человеку.</li></ul><div class="adv"><b>Конкурентное преимущество:</b> один поставщик владеет всей цепочкой — от сетевого датчика до решения — поэтому реакция занимает <b>2–11 секунд, а не часы</b>, без SOC, который нужно нанимать, обучать и держать бодрым в 3 часа ночи.</div>',
 s2_d='<ul><li><b>Автоматическое обнаружение активов</b> в вашей сети — нельзя защитить то, о чём не знаешь.</li><li>Выявление известных уязвимостей (CVE) и небезопасных конфигураций.</li><li>Плановые сканы, выполняемые безопасно, по контролируемому <b>вами расписанию</b>.</li><li>Приоритизированные отчёты — устраняйте сначала риски наибольшего воздействия.</li></ul><div class="adv"><b>Конкурентное преимущество:</b> VAS и SOC работают вместе — SOC останавливает идущие атаки, а VAS <b>проактивно сокращает поверхность атаки</b> раньше, чем злоумышленники найдут брешь.</div>',
 s3_d='<ul><li><b>Подозрительно</b> — неоднозначное событие, под наблюдение → тихо журналируется.</li><li><b>Подтверждено</b> — подтверждённая атака → автоблокировка IP-источника.</li><li><b>Серьёзно</b> — событие высокого воздействия → поднимается срочный сигнал.</li><li><b>Критично</b> — критическая компрометация → эскалация аналитику-человеку.</li></ul><div class="adv"><b>Конкурентное преимущество:</b> платформа <b>действует, не дожидаясь человека</b>. Ваша команда подключается только когда критическое решение этого действительно требует.</div>',
 s4_d='<ul><li>Четыре независимых сигнала, оценённых вместе: <b>MISP</b> threat intel, сетевая телеметрия <b>Suricata</b>, корреляция <b>Cluster 1 SIEM</b>, <b>база CYBER3</b>.</li><li>Одно контекстное решение о риске на сигнал — за 2–11 секунд.</li><li>Собственная технология, под полным контролем ROL PORTAL SERVICES.</li></ul><div class="adv"><b>Конкурентное преимущество:</b> тот же движок питает и <b>приложение CYBER3 для конечных устройств (XDR)</b> — сеть и рабочие места используют <b>единую актуальную разведку угроз</b>, замыкая цикл периметр ↔ конечная точка.</div>',
 s5_d='<ul><li>Устанавливаются inline или пассивно на каждом объекте — <b>~15 минут на объект</b>, без агентов на устройствах.</li><li>Следят за ARP-спуфингом, чужим DHCP, сканированием, эксплойтами и аномальным поведением.</li><li><b>Ваши данные остаются на вашей территории</b> — в SOC уходят только метаданные, по зашифрованному частному VPN.</li></ul><div class="adv"><b>Конкурентное преимущество:</b> приватность по умолчанию — создано для обработки данных по <b>GDPR и для госсектора</b>, с полным аудит-трейлом.</div>',
 s6_d='<ul><li>Объяснение простым языком: <b>что произошло, почему это угроза и что платформа уже сделала</b>.</li><li>Доставляется вашей команде через Telegram и e-mail.</li><li>Без сырых логов, без шквала оповещений.</li></ul><div class="adv"><b>Конкурентное преимущество:</b> ноль усталости от оповещений — персонал видит <b>только то, что требует внимания</b>, уже отсортированное и обработанное.</div>',
 n1_d='Выделенные датчики на каждом объекте захватывают и анализируют трафик на ARP-спуфинг, чужой DHCP, сканирование и эксплойты — без агентов на устройствах. Из сети уходят только метаданные, по зашифрованному частному VPN.',
 n2_d='Сырые пакеты превращаются в нормализованные события, затем коррелируются по всей среде, так что изолированные сигналы становятся единым осмысленным инцидентом — а не тысячами разрозненных логов.',
 n3_d='Собственный движок объединяет четыре независимых источника — MISP threat intel, телеметрию Suricata, корреляцию SIEM и базу CYBER3 — в одно контекстное решение о риске за 2–11 секунд.',
 n4_d='По серьёзности платформа действует сама: тихое журналирование, автоблокировка IP-источника, срочный сигнал или эскалация аналитику-человеку — сквозь за секунды, 24/7.',
 kanon_sum="Как платформа решает и действует по каждому сигналу",
 hc_sum="Платформа, которая сама себя контролирует — и чинит",
 g1_d='Мы составляем карту активов и экспозиции вашего учреждения через оценку уязвимостей — результат это ясная картина текущего состояния. <b>Без обязательств, строго в рамках вашей среды</b>, и служит основой для корректно рассчитанного предложения.',
 g2_d='Мы устанавливаем сетевые датчики на каждом объекте, inline или пассивно, подключённые к SOC по зашифрованному частному VPN. <b>Примерно 15 минут на объект, без агентов на устройствах.</b> По желанию разворачиваем приложение CYBER3 XDR на рабочих местах и мобильных согласно вашей политике.',
 g3_d='Круглосуточный ИИ-мониторинг и реагирование запускаются. Вы получаете ясные оповещения и отчёты, а платформа делает остальное — под автономным Health Check, который мониторит, администрирует и самовосстанавливает весь парк, <b>без участия человека</b>.',
 xdr_kicker="ENDPOINT XDR · CYBER3.AI", xdr_h2="SOC, расширенный на каждое рабочее место",
 xdr_p='Что отличает это предложение: приложение <b>CYBER3.AI</b> устанавливается на настольные ПК, ноутбуки и мобильные устройства — превращая каждую конечную точку в точку обнаружения и реагирования, подключённую к тому же SOC. Настоящий XDR, питаемый той же актуальной разведкой угроз. Большинство проверок выполняется на устройстве, поэтому защита работает и офлайн, а данные остаются приватными (k-анонимность: устройство покидают лишь первые 4 hex хеша SHA-256).',
 x1_h="Сканирование устройства / ПК", x1_p="Оценка безопасности 0–100 за секунды.", x1_d='<ul><li>Экран блокировки, USB debugging, уровень патчей, межсетевой экран, UAC, рискованные разрешения.</li><li>Сканирует установленные приложения и файлы по актуальной базе вредоносного ПО (SHA-256).</li><li>Исправления и карантин в один клик.</li></ul>',
 x2_h="AI Scam Shield", x2_p="Мгновенный вердикт по подозрительным сообщениям.", x2_d='Вставьте любой подозрительный SMS или сообщение и получите мгновенный вердикт с понятным объяснением: <b>поддельный бренд, тайпсквоттинг, рискованный TLD, тактики срочности и оплаты.</b>',
 x3_h="Web &amp; Scam Protection", x3_p="Проверьте любую ссылку перед открытием.", x3_d='Вредоносные, фишинговые, ransomware- и эксплойт-сайты помечаются в реальном времени по базе угроз CYBER3. Фильтр Блума на устройстве решает <b>99% проверок мгновенно и офлайн.</b>',
 x4_h="Browsing Guard", x4_p="Браузерное расширение, блокирующее угрозы вживую.", x4_d='Расширение Chrome / Edge / Firefox, которое блокирует сайты scam, фишинга и вредоносного ПО, а также рекламу и трекеры во время работы персонала в сети.',
 x5_h="Мониторинг утечек в реальном времени", x5_p="Непрерывный контроль ведомственной почты.", x5_d='Непрерывные фоновые проверки ведомственных адресов e-mail с push-оповещениями в момент появления адреса в новой утечке данных.',
 x6_h="Проверка пароля и e-mail", x6_p="Проверьте экспозицию через k-анонимность.", x6_d='Проверяет, появлялся ли пароль или e-mail в известных утечках, с помощью <b>k-анонимности</b> — пароль никогда не покидает устройство.',
 x7_h="Проверка номера на мошенничество", x7_p="Этот номер помечен как мошеннический?", x7_d='Проверяет, помечен ли телефонный номер как scam, спам или мошенничество в базе угроз CYBER3.',
 x8_h="VPN Lite", x8_p="Фильтр вредоносных доменов на всём устройстве.", x8_d='Локальный DNS-фильтр, блокирующий вредоносные и рекламные домены на всём устройстве (все приложения), <b>на устройстве</b>, не маршрутизируя трафик через сервер.',
 x9_h="Цифровой след", x9_p="Узнайте, насколько уязвима ваша личность.", x9_d="""Отчёт об экспозиции личности по известным утечкам: в каких утечках вы есть, какие данные утекли, оценка экспозиции (0–100) и понятные рекомендации. Приватно — k-анонимность, на устройстве.""",
 xdr_why_tag="ПОЧЕМУ ЭТО ВАЖНО", xdr_why_sum="Почему слой XDR для конечных точек важен для госучреждения",
 xdr_why_body='<ul><li>Закрывает доминирующий вектор атаки в госсекторе — <b>сотрудника и рабочее место</b>: фишинг, мошенничество, вредоносные ссылки/вложения, скомпрометированные пароли.</li><li>Защищает персонал в поле или на удалёнке, а не только внутри физического периметра.</li><li><b>Приватность по умолчанию</b> (k-анонимность, обработка на устройстве) — критична для публичных данных и соответствия GDPR.</li><li>Без аккаунтов, без рекламы, без рекламных SDK — без утечки данных третьим лицам.</li><li>Телеметрия конечных точек питает тот же SOC, замыкая цикл: сетевое обнаружение ↔ обнаружение на конечной точке.</li></ul><div class="adv">Доступность: Android (полное приложение), Windows (скан ПК, Scam Shield, Web Protection, проверка паролей — автономно, без Java). Приложение для iOS в разработке.</div>',
 pkg_kicker="ПАКЕТЫ", pkg_h2="Под размер вашего учреждения",
 pkg_p="Для учреждения районного уровня или с несколькими объектами решение масштабируется модульно. Ниже ориентировочная структура — точная конфигурация (число датчиков, объектов, конечных точек) определяется после начальной оценки вашей среды.",
 pkg_dsum="Рекомендуется для",
 pk1_b="БАЗОВЫЙ", pk1_h="Базовый", pk1_p="Управляемый SOC 24/7 + 1 датчик на главном объекте + плановый VAS ежемесячно.", pk1_d="Центральный офис с концентрированной ИТ-инфраструктурой. Вы получаете автономный мониторинг 24/7 и регулярную картину уязвимостей, не разворачивая собственный SOC.",
 pk2_b="РАСШИРЕННЫЙ", pk2_h="Расширенный", pk2_p="SOC + датчики на всех объектах + VAS раз в две недели + CYBER3 XDR на критичных рабочих местах.", pk2_d="Учреждения с несколькими объектами и повышенной экспозицией. Сетевое покрытие везде плюс XDR конечных точек на самых важных рабочих местах.",
 pk3_b="РЕКОМЕНДУЕТСЯ", pk3_h="Полный", pk3_p="SOC + датчики на всех объектах + непрерывный VAS + CYBER3 XDR на всех конечных точках и мобильных + единая отчётность.", pk3_d="Районный уровень, чувствительные данные граждан, строгое соответствие. Полная многоуровневая защита — периметр и каждое рабочее место — с одним поставщиком и единым отчётом.",
 pricenote="Цены: данный документ представляет услуги и техническое решение. Подробное финансовое предложение готовится по запросу, исходя из начальной оценки (объекты, датчики, конечные точки) и применимого к учреждению способа закупки.",
 nav_xdr="Endpoint XDR", nav_packages="Пакеты",
)
DETAIL["zh"] = dict(
 more_label="查看详情",
 s1_d='<ul><li>7×24 监控，<b>无需自有安全分析师</b>——平台处理常规，人工处理例外。</li><li>基于 Suricata IDS 的实时检测，通过 Cluster 1 SIEM 进行事件关联。</li><li>每条告警进行四来源情境融合：MISP + Suricata + SIEM + CYBER3 数据库。</li><li>按严重程度的自主行动：静默记录 → 自动拦截 IP → 紧急告警 → 升级给人工。</li></ul><div class="adv"><b>竞争优势：</b>单一供应商掌握整条链路——从网络传感器到决策——因此响应仅需 <b>2–11 秒，而非数小时</b>，无需雇佣、培训并在凌晨 3 点保持清醒的 SOC。</div>',
 s2_d='<ul><li>网络中的<b>自动资产发现</b>——无法保护你不知道拥有的东西。</li><li>检测已知漏洞（CVE）和不安全配置。</li><li>计划扫描，安全执行，按<b>你掌控的日程</b>。</li><li>优先级报告——先修复影响最大的风险。</li></ul><div class="adv"><b>竞争优势：</b>VAS 与 SOC 协同——SOC 阻止进行中的攻击，而 VAS 在攻击者发现缺口之前<b>主动缩小你的攻击面</b>。</div>',
 s3_d='<ul><li><b>可疑</b>——含糊事件，需跟踪 → 静默记录。</li><li><b>已确认</b>——确认攻击 → 自动拦截源 IP。</li><li><b>严重</b>——高影响事件 → 发出紧急告警。</li><li><b>关键</b>——关键性入侵 → 升级给人工分析师。</li></ul><div class="adv"><b>竞争优势：</b>平台<b>无需等待人工即可行动</b>。只有当关键决策确实需要时，你的团队才介入。</div>',
 s4_d='<ul><li>四个独立信号共同评分：<b>MISP</b> 威胁情报、<b>Suricata</b> 网络遥测、<b>Cluster 1 SIEM</b> 关联、<b>CYBER3 数据库</b>。</li><li>每条告警一个情境化风险决策——2–11 秒内完成。</li><li>专有技术，由 ROL PORTAL SERVICES 端到端掌控。</li></ul><div class="adv"><b>竞争优势：</b>同一引擎也驱动 <b>CYBER3 终端应用（XDR）</b>——网络与工作站共享<b>同一实时威胁情报</b>，闭合边界与终端检测之间的环路。</div>',
 s5_d='<ul><li>在每个站点以 inline 或被动方式安装——<b>每站点约 15 分钟</b>，终端上无代理。</li><li>监视 ARP 欺骗、恶意 DHCP、扫描、漏洞利用和异常行为。</li><li><b>你的数据留在你的现场</b>——仅元数据通过加密专用 VPN 流向 SOC。</li></ul><div class="adv"><b>竞争优势：</b>隐私优先设计——为 <b>GDPR 与公共部门</b>数据处理而构建，具备完整审计跟踪。</div>',
 s6_d='<ul><li>清晰语言的解释：<b>发生了什么、为何是威胁，以及平台已经采取的措施</b>。</li><li>通过 Telegram 和电子邮件送达你的团队。</li><li>没有原始日志堆，没有告警风暴。</li></ul><div class="adv"><b>竞争优势：</b>零告警疲劳——你的员工只看到<b>需要关注的内容</b>，且已分级并处理。</div>',
 n1_d='每个站点的专用传感器捕获并检查流量，发现 ARP 欺骗、恶意 DHCP、扫描和漏洞利用——终端上无代理。仅元数据离开你的网络，通过加密专用 VPN。',
 n2_d='原始数据包转化为规范化事件，再在整个环境中关联，使孤立信号汇成一个有意义的单一事件——而非数千条互不相连的日志。',
 n3_d='专有引擎将四个独立来源——MISP 威胁情报、Suricata 遥测、SIEM 关联和 CYBER3 数据库——融合为单一情境化风险决策，2–11 秒内完成。',
 n4_d='按严重程度，平台自行行动：静默记录、自动拦截源 IP、紧急告警或升级给人工分析师——端到端数秒，7×24。',
 kanon_sum="平台如何对每条告警进行决策与行动",
 hc_sum="自我监控——并自我修复——的平台",
 g1_d='我们通过漏洞评估梳理贵机构的资产与暴露面——结果是对现状的清晰呈现。<b>无需承诺，严格限定于贵方环境</b>，并为合理规模的报价奠定基础。',
 g2_d='我们在每个站点安装网络传感器，inline 或被动，通过加密专用 VPN 连接到 SOC。<b>每站点约 15 分钟，终端上无代理。</b>可选地，按贵方策略在工作站和移动设备上部署 CYBER3 XDR 应用。',
 g3_d='7×24 的 AI 监控与响应上线。你收到清晰的告警和报告，其余交给平台——在自主 Health Check 之下运行，它监控、管理并自我修复整支舰队，<b>无需人工介入</b>。',
 xdr_kicker="终端 XDR · CYBER3.AI", xdr_h2="将 SOC 扩展到每一台工作站",
 xdr_p='本方案的独到之处：<b>CYBER3.AI</b> 应用安装于台式机、笔记本和移动设备——使每个终端成为连接到同一 SOC 的检测与响应点。真正的 XDR，由同一实时威胁情报驱动。大多数检查在设备上运行，因此保护可离线工作且数据保持私密（k-匿名：仅 SHA-256 哈希的前 4 位十六进制离开设备）。',
 x1_h="设备 / PC 扫描", x1_p="数秒内给出 0–100 安全评分。", x1_d='<ul><li>锁屏、USB 调试、补丁级别、防火墙、UAC、风险权限。</li><li>对照实时恶意软件库（SHA-256）扫描已安装的应用与文件。</li><li>一键修复与隔离。</li></ul>',
 x2_h="AI Scam Shield", x2_p="对可疑消息的即时判定。", x2_d='粘贴任何可疑短信或消息，即获即时判定与清晰解释：<b>仿冒品牌、域名仿冒、风险 TLD、紧迫与付款套路。</b>',
 x3_h="Web &amp; Scam Protection", x3_p="打开任何链接前先检查。", x3_d='恶意、钓鱼、勒索软件与漏洞利用站点会对照 CYBER3 威胁库实时标记。设备端 Bloom 过滤器即时离线解决 <b>99% 的检查。</b>',
 x4_h="Browsing Guard", x4_p="实时拦截威胁的浏览器扩展。", x4_d='一款 Chrome / Edge / Firefox 扩展，在员工浏览时拦截诈骗、钓鱼与恶意站点，以及广告与追踪器。',
 x5_h="实时数据泄露监控", x5_p="对机构邮箱的持续监视。", x5_d='对机构电子邮件地址进行持续的后台检查，一旦出现在新的数据泄露中即推送告警。',
 x6_h="密码与邮箱泄露检查", x6_p="以 k-匿名检查暴露情况。", x6_d='使用 <b>k-匿名</b> 检查密码或邮箱是否出现在已知泄露中——密码绝不离开设备。',
 x7_h="诈骗号码检查", x7_p="这个号码被举报为诈骗吗？", x7_d='检查某电话号码是否在 CYBER3 威胁库中被举报为诈骗、垃圾或欺诈。',
 x8_h="VPN Lite", x8_p="覆盖全设备的恶意域名过滤。", x8_d='本地 DNS 过滤器，在整台设备（所有应用）上拦截恶意与广告域名，<b>在设备端</b>，不经服务器转发流量。',
 x9_h="数字足迹", x9_p="看看你的身份暴露程度。", x9_d="""基于已知泄露的身份暴露报告：你出现在哪些泄露中、哪些数据外泄、暴露评分（0–100）以及清晰建议。隐私——k-匿名、在设备端。""",
 xdr_why_tag="为何重要", xdr_why_sum="为何终端 XDR 层对公共机构很重要",
 xdr_why_body='<ul><li>覆盖公共部门主导的攻击向量——<b>员工与工作站</b>：钓鱼、诈骗、恶意链接/附件、被盗密码。</li><li>保护在外或远程办公的人员，不仅限于物理边界之内。</li><li><b>隐私优先设计</b>（k-匿名、设备端处理）——对公共数据与 GDPR 合规至关重要。</li><li>无账户、无广告、无广告 SDK——不向第三方泄露数据。</li><li>终端遥测反哺同一 SOC，闭合环路：网络检测 ↔ 终端检测。</li></ul><div class="adv">可用性：Android（完整应用）、Windows（PC 扫描、Scam Shield、Web Protection、密码检查——独立运行，无需 Java）。iOS 应用正在开发中。</div>',
 pkg_kicker="套餐", pkg_h2="按贵机构规模定制",
 pkg_p="对于县级或多站点机构，方案以模块化方式扩展。下面是一个指示性结构——确切配置（传感器、站点、终端数量）在对贵方环境进行初始评估后确定。",
 pkg_dsum="适合",
 pk1_b="基础", pk1_h="基础", pk1_p="托管 7×24 SOC + 主站点 1 个传感器 + 每月计划 VAS。", pk1_d="IT 基础设施集中的中心办公点。无需自建 SOC 即可获得 7×24 自主监控与定期漏洞画像。",
 pk2_b="扩展", pk2_h="扩展", pk2_p="SOC + 所有站点传感器 + 双周 VAS + 关键工作站的 CYBER3 XDR。", pk2_d="暴露较高的多站点机构。处处网络覆盖，外加最重要工作站上的终端 XDR。",
 pk3_b="推荐", pk3_h="完整", pk3_p="SOC + 所有站点传感器 + 持续 VAS + 所有终端与移动设备的 CYBER3 XDR + 统一报告。", pk3_d="县级、敏感公民数据、严格合规。完整的多层防御——边界与每台工作站——由单一供应商提供并统一报告。",
 pricenote="价格：本文件介绍服务与技术方案。详细的财务报价应要求提供，依据初始评估（站点、传感器、终端）以及适用于贵机构的采购方式。",
 nav_xdr="终端 XDR", nav_packages="套餐",
)

def _hide(x):
    return (x.replace("Wazuh SIEM", "Cluster 1 SIEM").replace("Wazuh", "Cluster 1 SIEM")
             .replace("Suricata IDS", "Cluster 1 IDS/IPS").replace("Suricata", "Cluster 1 IDS/IPS")
             .replace("CyberBot AI", "CYBER3 AI Context Fusion Engine").replace("CyberBot", "CYBER3 AI Context Fusion Engine")
             .replace("CYBER3 AI Context Engine", "CYBER3 AI Context Fusion Engine")) if isinstance(x, str) else x
for lang in LANGS:
    TR[lang].update(EXTRA[lang])
    if lang in DETAIL:
        TR[lang].update(DETAIL[lang])
    TR[lang].update(OVR.get(lang, {}))   # 7 straturi + MLEO în hero și carduri
    for k, v in list(TR[lang].items()):
        TR[lang][k] = [_hide(i) for i in v] if isinstance(v, list) else _hide(v)

for lang in LANGS:
    out_dir = BASE if lang == "en" else os.path.join(BASE, lang)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        # denumirea canonică a stratului 4 (7 straturi, 17 sep 2026)
        f.write(page(lang, TR[lang]).replace("CYBER3 AI Context Fusion Engine", "CYBER3 Context Fusion Engine"))
    print("scris:", os.path.join(PATH[lang], "index.html"))
print("GATA")


# ==================================================================
# Scut Împăratului Constantin (Chi-Rho / Labarum) — DURABILITATE 11 iul 2026
# Post-process: după build, convertește orice 🛡️ din output în scutul cu cruce,
# DOAR în textul HTML (nu meta/title/script). Idempotent. Vezi shieldify.py.
# ==================================================================
def _constantine_shieldify(_base):
    import re, glob, os
    _SH = ('<svg class="cshield" viewBox="0 0 24 24">'
           '<path d="M12 2.1 L20.6 5 V11 C20.6 16.6 16.8 20.5 12 21.9 C7.2 20.5 3.4 16.6 3.4 11 V5 Z" fill="rgba(212,175,55,.14)" stroke="#d4af37" stroke-width="1.3"/>'
           '<g fill="none" stroke="#f2d778" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">'
           '<path d="M12 5.2 V18.2"/><path d="M12 5.7 h2.2 a2 2 0 0 1 0 3.9 H12"/>'
           '<path d="M8 11 L16 15.6"/><path d="M16 11 L8 15.6"/></g></svg>')
    _CSS = '.cshield{width:1.28em;height:1.28em;vertical-align:-.30em;display:inline-block}'
    _RX = re.compile('\U0001F6E1️?(?=[^<>]*(?:<|$))')
    _tot = 0
    for _f in glob.glob(os.path.join(_base, "**", "*.html"), recursive=True):
        _s = open(_f, encoding="utf-8").read()
        _prot = []
        _p = re.sub(r'<(script|style|title)\b[^>]*>.*?</\1>',
                    lambda m: (_prot.append(m.group(0)), "\x00%d\x00" % (len(_prot) - 1))[1],
                    _s, flags=re.S | re.I)
        _c = len(_RX.findall(_p))
        if not _c:
            continue
        _p = _RX.sub(_SH, _p)
        _p = re.sub(r"\x00(\d+)\x00", lambda m: _prot[int(m.group(1))], _p)
        if ".cshield{" not in _p and "</style>" in _p:
            _p = _p.replace("</style>", _CSS + "</style>", 1)
        if _p != _s:
            open(_f, "w", encoding="utf-8").write(_p)
            _tot += _c
    print("Scut Constantin: %d scuturi convertite in output" % _tot)

_constantine_shieldify(BASE)
