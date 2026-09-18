# -*- coding: utf-8 -*-
# Secțiunea #defense a fasterup.ai: cascada de 7 straturi + Capabilities Status + Multi Layer Enforcement Orchestrator.
# Public: fără contoare de blocări (decizie operator 18 sep 2026), fără nume de furnizori (Suricata/Wazuh/CyberBot).
# Denumirile de produs (Inline IPS, Active Response, L2 Shield, CYBER3 …, Multi Layer Enforcement Orchestrator) NU se traduc.
import html

NAMES = ["Inline IPS", "Active Response", "L2 Shield", "CYBER3 Context Fusion Engine",
         "CYBER3 Edge", "CYBER3 EDR/XDR for Desktop", "CYBER3 Mobile Protection"]
COLORS = ["#3b82f6", "#f59e0b", "#22d3ee", "#34d399", "#a78bfa", "#2dd4bf", "#fb7185"]
FUNNEL = [100, 82, 70, 60, 52, 46, 42]
# Timp de răspuns per strat; None = „timp real” (tradus). 2–11 s = intervalul comunicat public pentru decizia autonomă.
RT = ["< 10 ms", "2–11 s", "< 1 ms", "2–11 s", "< 50 ms", None, None]
MLEO = "Multi Layer Enforcement Orchestrator"

D = {
 "en": dict(
   h2="Cascade blocking. Seven complementary layers.",
   p="Every threat passes through a cascade of seven defense layers: from the wire to Ethernet, then the cloud and the endpoint. Whatever slips past one layer is caught by the next. The layers are complementary, not redundant: each covers an angle the others cannot see.",
   realtime="real-time", rt_short="response", rt_long="response time",
   top="Traffic + threats enter", top_cnt="100% inspected",
   bottom="Reaches the network / the user", bottom_z="traffic inspected across 7 layers",
   zones=["Network", "Host", "Ethernet", "AI", "Cloud", "Desktop", "Mobile"],
   layers=[
    ("Network · L3–L7", "inline inspection at the wire · signatures + anomalies · IOC indicators", "Detects and <c>stops the packet at the wire</c>, in milliseconds, before it enters the client's network."),
    ("Host · L3", "firewall DROP rule · escalation to a fleet-wide permanent block", "Automatic response to an alert: a <c>DROP rule in the firewall</c> for the attacker's IP. Native fallback, independent of AI."),
    ("Ethernet · L2", "native Ethernet · anti-ARP-spoof (gateway IP↔MAC pin) · anti-rogue-DHCP · dead-man anti-blackhole", "<c>The only Ethernet-level layer.</c> Stops MITM, ARP poisoning and rogue DHCP — attacks the IP layers <c>cannot see</c>."),
    ("AI · L3–L7", "multi-source fusion: network + host + threat intel + CYBER3 DB", "Autonomous decision from fused context; blocks even <c>outbound connections to C2</c> (command and control)."),
    ("Cloud · anywhere", "DNS-shield · edge IOC (2M+ indicators) · browser extension", "Web and DNS protection <c>anywhere, even off-network</c>: dangerous domains and URLs are blocked before the connection is made."),
    ("Desktop · workstation", "behavioral detection · XDR telemetry → SOC · quarantine", "Covers threats that reach <c>the workstation</c> (USB, files, processes), beyond the network."),
    ("Mobile · device", "anti-scam / anti-phishing · DNS filtering · VPN", "Protects the user <c>on the move</c>: the last layer, on the personal device.")],
   orch="Orchestrator", rollout="In rollout", rollout_sub="stages 0–1",
   m_tag="Concept · being implemented", m_small="MLEO · THE CORE THAT LINKS THE 7 LAYERS",
   m_lead="Until now, each layer <b>detects and blocks independently</b>. MLEO is the core that <b>correlates signals across layers and decides which layer enforces each threat</b>, based on a unified device identity: the same machine seen as an <b>IP at Layer 3</b> and as a <b>MAC at Layer 2</b>.",
   box1=("Layer 3 · layers 1 · 2 · 4", "IP-based blocks", "Inline IPS, Active Response and CYBER3 Context Fusion Engine: who attacked, on which port, when."),
   core=("MLEO · unified identity", "One source of truth", "MAC ↔ IP ↔ VLAN ↔ port<br>↔ physical location ↔ criticality"),
   box3=("Layer 2 · layer 3", "MAC identity", "L2 Shield: ARP table with history, Ethernet anomalies, the real device behind the IP."),
   out=("Enforcement on the right layer", ["drop list on the sensor (L3)", "VLAN quarantine on the switch (L2)", "blocked once, not on every layer separately"]),
   solves_h="What it solves",
   problems=[
    ("Evasion by changing IP", "An attacker blocked on one IP takes another and carries on. At L3 it looks like a new actor; at L2 it is the same MAC — and MLEO recognizes it."),
    ("Correct isolation during ARP spoofing", "Spoofed traffic appears to come from the victim. Directional correlation isolates the attacker, not the machine the traffic seems to come from."),
    ("One picture, not fragmented blocks", "The same device is no longer blocked separately on 3–4 layers with no link between them."),
    ("Tracing over time", "Starting from an IP seen 24 hours ago, you find the MAC and the physical port where the device sits.")],
   princ_h="Safety principles",
   chips=["observe before enforce", "allowlist with absolute precedence", "transactional rollback", "VLAN quarantine, not shutdown", "fail-safe on every layer"],
   stages_h="Staged rollout", st_now="in progress", st_next="next", st_plan="planned",
   stages=["Collection: ARP, MAC tables, blocks from every layer",
           "Reconciliation table MAC ↔ IP ↔ VLAN ↔ port",
           "Every L3 block gains its L2 identity",
           "Same MAC, different IPs: report only, in observation",
           "First enforcement: VLAN quarantine, with allowlist and rollback",
           "New MAC on a port with history; spoofed ARP + L3 block",
           "Reverse direction L2 → L3, preventive"],
   risk3="stages 0–3 never touch the client network", risk4="preconditions: allowlist + tested rollback",
   notes=[
    ("Why a cascade?", "No layer is perfect on its own. A packet stopped by the IPS never reaches Active Response; one that slips through is caught by the CYBER3 Context Fusion Engine; an L2 attack (ARP spoofing), invisible to the IP layers, is stopped by L2 Shield."),
    ("Autonomous, no human in the loop", "Detection → context fusion → autonomous decision in 2–11 seconds → action: temporary block, escalation to a permanent block, notification. The allowlist protects legitimate equipment at every step."),
    ("One organism", "MLEO is not a new layer. It is the orchestrator that links the existing layers, so seven layers that see separately become one organism that sees the same device at every level.")],
   tagline="7 layers · MLEO · defense in depth"),

 "ro": dict(
   h2="Blocare în cascadă. Șapte straturi complementare.",
   p="Fiecare amenințare trece printr-o cascadă de șapte straturi de apărare: de la fir la Ethernet, apoi în cloud și pe endpoint. Ce scapă unui strat e prins de următorul. Straturile sunt complementare, nu redundante: fiecare acoperă un unghi pe care celelalte nu-l văd.",
   realtime="timp real", rt_short="răspuns", rt_long="timp de răspuns",
   top="Trafic + amenințări intră", top_cnt="100% inspectat",
   bottom="Ajunge în rețea / la utilizator", bottom_z="trafic inspectat pe 7 straturi",
   zones=["Rețea", "Gazdă", "Ethernet", "AI", "Cloud", "Desktop", "Mobil"],
   layers=[
    ("Rețea · L3–L7", "inspecție inline la fir · semnături + anomalii · indicatori IOC", "Detectează și <c>oprește pachetul la fir</c>, în milisecunde, înainte să intre în rețeaua clientului."),
    ("Gazdă · L3", "regulă DROP în firewall · escaladare la blocare permanentă pe flotă", "Răspuns automat la alertă: <c>regulă DROP în firewall</c> pentru IP-ul atacatorului. Fallback nativ, independent de AI."),
    ("Ethernet · L2", "nativ Ethernet · anti-ARP-spoof (pin gateway IP↔MAC) · anti-DHCP fals · dead-man anti-blackhole", "<c>Singurul strat la nivel Ethernet.</c> Oprește MITM, ARP poisoning și DHCP fals — atacuri pe care straturile IP <c>nu le văd</c>."),
    ("AI · L3–L7", "fuziune multi-sursă: rețea + gazdă + threat intel + CYBER3 DB", "Decizie autonomă din context fuzionat; blochează inclusiv <c>conexiunile ieșite către C2</c> (comandă și control)."),
    ("Cloud · oriunde", "DNS-shield · IOC la edge (2M+ indicatori) · extensie de browser", "Protecție web și DNS <c>oriunde, inclusiv în afara rețelei</c>: domeniile și URL-urile periculoase sunt blocate înainte de conectare."),
    ("Desktop · stație", "detecție comportamentală · telemetrie XDR → SOC · carantină", "Acoperă amenințările ajunse <c>pe stație</c> (USB, fișiere, procese), dincolo de rețea."),
    ("Mobil · dispozitiv", "anti-scam / anti-phishing · filtrare DNS · VPN", "Protejează utilizatorul <c>în mobilitate</c>: ultimul strat, pe dispozitivul personal.")],
   orch="Orchestrator", rollout="In rollout", rollout_sub="etapele 0–1",
   m_tag="Concept · în curs de implementare", m_small="MLEO · NUCLEUL CARE LEAGĂ CELE 7 STRATURI",
   m_lead="Până acum, fiecare strat <b>detectează și blochează independent</b>. MLEO e nucleul care <b>corelează semnalele dintre straturi și decide pe ce strat se execută fiecare amenințare</b>, pe baza unei identități unificate a dispozitivului: același echipament văzut ca <b>IP la Layer 3</b> și ca <b>MAC la Layer 2</b>.",
   box1=("Layer 3 · straturile 1 · 2 · 4", "Blocări pe IP", "Inline IPS, Active Response și CYBER3 Context Fusion Engine: cine a atacat, pe ce port, când."),
   core=("MLEO · identitate unificată", "O singură sursă de adevăr", "MAC ↔ IP ↔ VLAN ↔ port<br>↔ locație fizică ↔ criticitate"),
   box3=("Layer 2 · stratul 3", "Identitate MAC", "L2 Shield: tabela ARP cu istoric, anomalii Ethernet, dispozitivul real din spatele IP-ului."),
   out=("Enforcement pe stratul potrivit", ["drop list pe senzor (L3)", "carantină VLAN pe switch (L2)", "blocat o singură dată, nu pe fiecare strat în parte"]),
   solves_h="Ce rezolvă",
   problems=[
    ("Evaziunea prin schimbare de IP", "Atacatorul blocat pe un IP ia altul și continuă. La L3 pare alt actor; la L2 e același MAC — iar MLEO îl recunoaște."),
    ("Izolarea corectă la ARP spoofing", "Traficul fals pare că vine de la victimă. Corelația direcțională izolează atacatorul, nu stația de la care pare să vină traficul."),
    ("O imagine unică, nu blocări fragmentate", "Același dispozitiv nu mai e blocat separat pe 3–4 straturi, fără legătură între ele."),
    ("Urmărire în timp", "Pornind de la un IP de acum 24 de ore, afli MAC-ul și portul fizic unde se află dispozitivul.")],
   princ_h="Principii de siguranță",
   chips=["observare înainte de enforcement", "allowlist cu precedență absolută", "rollback tranzacțional", "carantină VLAN, nu shutdown", "fail-safe pe fiecare strat"],
   stages_h="Implementare pe etape", st_now="în lucru", st_next="următor", st_plan="planificat",
   stages=["Colectare: ARP, tabele MAC, blocări de pe fiecare strat",
           "Tabela de reconciliere MAC ↔ IP ↔ VLAN ↔ port",
           "Fiecare blocare L3 primește identitatea L2",
           "Același MAC cu IP-uri diferite: doar raportare, în observare",
           "Primul enforcement: carantină VLAN, cu allowlist și rollback",
           "MAC nou pe port cu istoric; ARP fals + blocare L3",
           "Direcția inversă L2 → L3, preventiv"],
   risk3="etapele 0–3 nu ating rețeaua clientului", risk4="precondiții: allowlist + rollback testat",
   notes=[
    ("De ce „în cascadă”?", "Niciun strat nu e perfect singur. Un pachet oprit de IPS nu mai ajunge la Active Response; unul scăpat e prins de CYBER3 Context Fusion Engine; un atac L2 (ARP spoofing), invizibil pentru straturile IP, e oprit de L2 Shield."),
    ("Autonom, fără om", "Detecție → fuziune de context → decizie autonomă în 2–11 secunde → acțiune: blocare temporară, escaladare la blocare permanentă, notificare. Allowlist-ul protejează echipamentele legitime la fiecare pas."),
    ("Un singur organism", "MLEO nu e un strat nou. E orchestratorul care leagă straturile existente, astfel încât cele 7 straturi care văd separat devin un singur organism care vede același dispozitiv pe toate nivelurile.")],
   tagline="7 straturi · MLEO · defense in depth"),

 "es": dict(
   h2="Bloqueo en cascada. Siete capas complementarias.",
   p="Cada amenaza atraviesa una cascada de siete capas de defensa: del cable a Ethernet, luego la nube y el endpoint. Lo que escapa a una capa lo detiene la siguiente. Las capas son complementarias, no redundantes: cada una cubre un ángulo que las demás no ven.",
   realtime="tiempo real", rt_short="respuesta", rt_long="tiempo de respuesta",
   top="Entran tráfico + amenazas", top_cnt="100% inspeccionado",
   bottom="Llega a la red / al usuario", bottom_z="tráfico inspeccionado en 7 capas",
   zones=["Red", "Host", "Ethernet", "IA", "Nube", "Escritorio", "Móvil"],
   layers=[
    ("Red · L3–L7", "inspección inline en el cable · firmas + anomalías · indicadores IOC", "Detecta y <c>detiene el paquete en el cable</c>, en milisegundos, antes de que entre en la red del cliente."),
    ("Host · L3", "regla DROP en el firewall · escalado a bloqueo permanente en toda la flota", "Respuesta automática a una alerta: una <c>regla DROP en el firewall</c> para la IP del atacante. Respaldo nativo, independiente de la IA."),
    ("Ethernet · L2", "Ethernet nativo · anti-ARP-spoof (pin IP↔MAC del gateway) · anti-DHCP falso · dead-man anti-blackhole", "<c>La única capa a nivel Ethernet.</c> Detiene MITM, envenenamiento ARP y DHCP falso — ataques que las capas IP <c>no ven</c>."),
    ("IA · L3–L7", "fusión multifuente: red + host + inteligencia de amenazas + CYBER3 DB", "Decisión autónoma a partir del contexto fusionado; bloquea incluso <c>las conexiones salientes hacia C2</c> (comando y control)."),
    ("Nube · en cualquier lugar", "DNS-shield · IOC en el edge (2M+ indicadores) · extensión de navegador", "Protección web y DNS <c>en cualquier lugar, incluso fuera de la red</c>: los dominios y URLs peligrosos se bloquean antes de conectar."),
    ("Escritorio · estación", "detección de comportamiento · telemetría XDR → SOC · cuarentena", "Cubre las amenazas que llegan <c>a la estación</c> (USB, archivos, procesos), más allá de la red."),
    ("Móvil · dispositivo", "anti-fraude / anti-phishing · filtrado DNS · VPN", "Protege al usuario <c>en movilidad</c>: la última capa, en el dispositivo personal.")],
   orch="Orquestador", rollout="In rollout", rollout_sub="etapas 0–1",
   m_tag="Concepto · en implementación", m_small="MLEO · EL NÚCLEO QUE UNE LAS 7 CAPAS",
   m_lead="Hasta ahora, cada capa <b>detecta y bloquea de forma independiente</b>. MLEO es el núcleo que <b>correlaciona las señales entre capas y decide en qué capa se ejecuta cada amenaza</b>, a partir de una identidad unificada del dispositivo: el mismo equipo visto como <b>IP en la capa 3</b> y como <b>MAC en la capa 2</b>.",
   box1=("Capa 3 · capas 1 · 2 · 4", "Bloqueos por IP", "Inline IPS, Active Response y CYBER3 Context Fusion Engine: quién atacó, en qué puerto, cuándo."),
   core=("MLEO · identidad unificada", "Una única fuente de verdad", "MAC ↔ IP ↔ VLAN ↔ puerto<br>↔ ubicación física ↔ criticidad"),
   box3=("Capa 2 · capa 3", "Identidad MAC", "L2 Shield: tabla ARP con historial, anomalías Ethernet, el dispositivo real detrás de la IP."),
   out=("Enforcement en la capa adecuada", ["drop list en el sensor (L3)", "cuarentena VLAN en el switch (L2)", "bloqueado una sola vez, no en cada capa por separado"]),
   solves_h="Qué resuelve",
   problems=[
    ("Evasión por cambio de IP", "Un atacante bloqueado en una IP toma otra y continúa. En L3 parece otro actor; en L2 es la misma MAC, y MLEO lo reconoce."),
    ("Aislamiento correcto ante ARP spoofing", "El tráfico falso parece venir de la víctima. La correlación direccional aísla al atacante, no al equipo del que parece venir el tráfico."),
    ("Una sola imagen, no bloqueos fragmentados", "El mismo dispositivo ya no se bloquea por separado en 3–4 capas sin relación entre ellas."),
    ("Seguimiento en el tiempo", "A partir de una IP vista hace 24 horas, obtienes la MAC y el puerto físico donde está el dispositivo.")],
   princ_h="Principios de seguridad",
   chips=["observar antes de aplicar", "allowlist con precedencia absoluta", "rollback transaccional", "cuarentena VLAN, no apagado", "fail-safe en cada capa"],
   stages_h="Implementación por etapas", st_now="en curso", st_next="siguiente", st_plan="planificado",
   stages=["Recopilación: ARP, tablas MAC, bloqueos de cada capa",
           "Tabla de reconciliación MAC ↔ IP ↔ VLAN ↔ puerto",
           "Cada bloqueo L3 recibe su identidad L2",
           "Misma MAC, IPs distintas: solo informe, en observación",
           "Primer enforcement: cuarentena VLAN, con allowlist y rollback",
           "MAC nueva en un puerto con historial; ARP falso + bloqueo L3",
           "Dirección inversa L2 → L3, preventiva"],
   risk3="las etapas 0–3 no tocan la red del cliente", risk4="condiciones previas: allowlist + rollback probado",
   notes=[
    ("¿Por qué en cascada?", "Ninguna capa es perfecta por sí sola. Un paquete detenido por el IPS ya no llega a Active Response; uno que escapa lo detiene CYBER3 Context Fusion Engine; un ataque L2 (ARP spoofing), invisible para las capas IP, lo detiene L2 Shield."),
    ("Autónomo, sin intervención humana", "Detección → fusión de contexto → decisión autónoma en 2–11 segundos → acción: bloqueo temporal, escalado a bloqueo permanente, notificación. La allowlist protege los equipos legítimos en cada paso."),
    ("Un solo organismo", "MLEO no es una capa nueva. Es el orquestador que une las capas existentes: siete capas que ven por separado se convierten en un solo organismo que ve el mismo dispositivo en todos los niveles.")],
   tagline="7 capas · MLEO · defensa en profundidad"),

 "it": dict(
   h2="Blocco a cascata. Sette livelli complementari.",
   p="Ogni minaccia attraversa una cascata di sette livelli di difesa: dal filo a Ethernet, poi il cloud e l'endpoint. Ciò che sfugge a un livello viene fermato dal successivo. I livelli sono complementari, non ridondanti: ciascuno copre un angolo che gli altri non vedono.",
   realtime="tempo reale", rt_short="risposta", rt_long="tempo di risposta",
   top="Entrano traffico + minacce", top_cnt="100% ispezionato",
   bottom="Raggiunge la rete / l'utente", bottom_z="traffico ispezionato su 7 livelli",
   zones=["Rete", "Host", "Ethernet", "IA", "Cloud", "Desktop", "Mobile"],
   layers=[
    ("Rete · L3–L7", "ispezione inline sul filo · firme + anomalie · indicatori IOC", "Rileva e <c>ferma il pacchetto sul filo</c>, in millisecondi, prima che entri nella rete del cliente."),
    ("Host · L3", "regola DROP nel firewall · escalation a blocco permanente su tutta la flotta", "Risposta automatica a un allarme: una <c>regola DROP nel firewall</c> per l'IP dell'attaccante. Fallback nativo, indipendente dall'IA."),
    ("Ethernet · L2", "Ethernet nativo · anti-ARP-spoof (pin IP↔MAC del gateway) · anti-DHCP fasullo · dead-man anti-blackhole", "<c>L'unico livello a livello Ethernet.</c> Ferma MITM, ARP poisoning e DHCP fasullo — attacchi che i livelli IP <c>non vedono</c>."),
    ("IA · L3–L7", "fusione multi-sorgente: rete + host + threat intel + CYBER3 DB", "Decisione autonoma dal contesto fuso; blocca perfino <c>le connessioni in uscita verso il C2</c> (comando e controllo)."),
    ("Cloud · ovunque", "DNS-shield · IOC sull'edge (2M+ indicatori) · estensione browser", "Protezione web e DNS <c>ovunque, anche fuori rete</c>: domini e URL pericolosi vengono bloccati prima della connessione."),
    ("Desktop · postazione", "rilevamento comportamentale · telemetria XDR → SOC · quarantena", "Copre le minacce arrivate <c>sulla postazione</c> (USB, file, processi), oltre la rete."),
    ("Mobile · dispositivo", "anti-truffa / anti-phishing · filtro DNS · VPN", "Protegge l'utente <c>in mobilità</c>: l'ultimo livello, sul dispositivo personale.")],
   orch="Orchestratore", rollout="In rollout", rollout_sub="fasi 0–1",
   m_tag="Concept · in fase di implementazione", m_small="MLEO · IL NUCLEO CHE UNISCE I 7 LIVELLI",
   m_lead="Finora ogni livello <b>rileva e blocca in modo indipendente</b>. MLEO è il nucleo che <b>correla i segnali tra i livelli e decide su quale livello eseguire ogni minaccia</b>, sulla base di un'identità unificata del dispositivo: la stessa macchina vista come <b>IP al Layer 3</b> e come <b>MAC al Layer 2</b>.",
   box1=("Layer 3 · livelli 1 · 2 · 4", "Blocchi su IP", "Inline IPS, Active Response e CYBER3 Context Fusion Engine: chi ha attaccato, su quale porta, quando."),
   core=("MLEO · identità unificata", "Un'unica fonte di verità", "MAC ↔ IP ↔ VLAN ↔ porta<br>↔ posizione fisica ↔ criticità"),
   box3=("Layer 2 · livello 3", "Identità MAC", "L2 Shield: tabella ARP con storico, anomalie Ethernet, il dispositivo reale dietro l'IP."),
   out=("Enforcement sul livello giusto", ["drop list sul sensore (L3)", "quarantena VLAN sullo switch (L2)", "bloccato una sola volta, non su ogni livello separatamente"]),
   solves_h="Cosa risolve",
   problems=[
    ("Evasione tramite cambio di IP", "Un attaccante bloccato su un IP ne prende un altro e continua. Al L3 sembra un nuovo attore; al L2 è lo stesso MAC, e MLEO lo riconosce."),
    ("Isolamento corretto con ARP spoofing", "Il traffico falso sembra provenire dalla vittima. La correlazione direzionale isola l'attaccante, non la macchina da cui il traffico sembra provenire."),
    ("Un'unica visione, non blocchi frammentati", "Lo stesso dispositivo non viene più bloccato separatamente su 3–4 livelli senza legame tra loro."),
    ("Tracciamento nel tempo", "Partendo da un IP visto 24 ore fa, trovi il MAC e la porta fisica dove si trova il dispositivo.")],
   princ_h="Principi di sicurezza",
   chips=["osservare prima di applicare", "allowlist con precedenza assoluta", "rollback transazionale", "quarantena VLAN, non spegnimento", "fail-safe su ogni livello"],
   stages_h="Implementazione per fasi", st_now="in corso", st_next="prossima", st_plan="pianificata",
   stages=["Raccolta: ARP, tabelle MAC, blocchi da ogni livello",
           "Tabella di riconciliazione MAC ↔ IP ↔ VLAN ↔ porta",
           "Ogni blocco L3 riceve la sua identità L2",
           "Stesso MAC, IP diversi: solo segnalazione, in osservazione",
           "Primo enforcement: quarantena VLAN, con allowlist e rollback",
           "Nuovo MAC su una porta con storico; ARP falso + blocco L3",
           "Direzione inversa L2 → L3, preventiva"],
   risk3="le fasi 0–3 non toccano la rete del cliente", risk4="prerequisiti: allowlist + rollback testato",
   notes=[
    ("Perché a cascata?", "Nessun livello è perfetto da solo. Un pacchetto fermato dall'IPS non arriva ad Active Response; uno che sfugge viene fermato da CYBER3 Context Fusion Engine; un attacco L2 (ARP spoofing), invisibile ai livelli IP, viene fermato da L2 Shield."),
    ("Autonomo, senza intervento umano", "Rilevamento → fusione del contesto → decisione autonoma in 2–11 secondi → azione: blocco temporaneo, escalation a blocco permanente, notifica. L'allowlist protegge le apparecchiature legittime a ogni passo."),
    ("Un unico organismo", "MLEO non è un nuovo livello. È l'orchestratore che unisce i livelli esistenti: sette livelli che vedono separatamente diventano un unico organismo che vede lo stesso dispositivo a ogni livello.")],
   tagline="7 livelli · MLEO · difesa in profondità"),

 "de": dict(
   h2="Blockierung in Kaskade. Sieben komplementäre Schichten.",
   p="Jede Bedrohung durchläuft eine Kaskade aus sieben Verteidigungsschichten: von der Leitung über Ethernet bis in die Cloud und auf den Endpunkt. Was einer Schicht entgeht, fängt die nächste ab. Die Schichten ergänzen sich statt sich zu wiederholen: Jede deckt einen Winkel ab, den die anderen nicht sehen.",
   realtime="Echtzeit", rt_short="Reaktion", rt_long="Reaktionszeit",
   top="Datenverkehr + Bedrohungen treten ein", top_cnt="100 % geprüft",
   bottom="Erreicht das Netzwerk / den Nutzer", bottom_z="Datenverkehr über 7 Schichten geprüft",
   zones=["Netzwerk", "Host", "Ethernet", "KI", "Cloud", "Desktop", "Mobil"],
   layers=[
    ("Netzwerk · L3–L7", "Inline-Prüfung auf der Leitung · Signaturen + Anomalien · IOC-Indikatoren", "Erkennt und <c>stoppt das Paket auf der Leitung</c>, in Millisekunden, bevor es ins Netzwerk des Kunden gelangt."),
    ("Host · L3", "DROP-Regel in der Firewall · Eskalation zur dauerhaften Sperre in der gesamten Flotte", "Automatische Reaktion auf einen Alarm: eine <c>DROP-Regel in der Firewall</c> für die IP des Angreifers. Nativer Rückfall, unabhängig von der KI."),
    ("Ethernet · L2", "natives Ethernet · Anti-ARP-Spoof (Gateway-IP↔MAC-Pin) · Anti-Rogue-DHCP · Dead-Man-Schutz gegen Blackhole", "<c>Die einzige Schicht auf Ethernet-Ebene.</c> Stoppt MITM, ARP-Poisoning und Rogue-DHCP — Angriffe, die die IP-Schichten <c>nicht sehen</c>."),
    ("KI · L3–L7", "Multi-Quellen-Fusion: Netzwerk + Host + Threat Intel + CYBER3 DB", "Autonome Entscheidung aus fusioniertem Kontext; blockiert sogar <c>ausgehende Verbindungen zu C2</c> (Command and Control)."),
    ("Cloud · überall", "DNS-Shield · Edge-IOC (2 Mio.+ Indikatoren) · Browser-Erweiterung", "Web- und DNS-Schutz <c>überall, auch außerhalb des Netzwerks</c>: gefährliche Domains und URLs werden vor dem Verbindungsaufbau blockiert."),
    ("Desktop · Arbeitsplatz", "Verhaltenserkennung · XDR-Telemetrie → SOC · Quarantäne", "Deckt Bedrohungen ab, die <c>den Arbeitsplatz</c> erreichen (USB, Dateien, Prozesse), jenseits des Netzwerks."),
    ("Mobil · Gerät", "Anti-Scam / Anti-Phishing · DNS-Filterung · VPN", "Schützt den Nutzer <c>unterwegs</c>: die letzte Schicht, auf dem persönlichen Gerät.")],
   orch="Orchestrator", rollout="In rollout", rollout_sub="Stufen 0–1",
   m_tag="Konzept · in Umsetzung", m_small="MLEO · DER KERN, DER DIE 7 SCHICHTEN VERBINDET",
   m_lead="Bisher <b>erkennt und blockiert jede Schicht unabhängig</b>. MLEO ist der Kern, der <b>Signale schichtübergreifend korreliert und entscheidet, auf welcher Schicht jede Bedrohung durchgesetzt wird</b> — auf Basis einer einheitlichen Geräteidentität: dasselbe Gerät, gesehen als <b>IP auf Layer 3</b> und als <b>MAC auf Layer 2</b>.",
   box1=("Layer 3 · Schichten 1 · 2 · 4", "IP-basierte Sperren", "Inline IPS, Active Response und CYBER3 Context Fusion Engine: wer angegriffen hat, auf welchem Port, wann."),
   core=("MLEO · einheitliche Identität", "Eine einzige Quelle der Wahrheit", "MAC ↔ IP ↔ VLAN ↔ Port<br>↔ physischer Standort ↔ Kritikalität"),
   box3=("Layer 2 · Schicht 3", "MAC-Identität", "L2 Shield: ARP-Tabelle mit Verlauf, Ethernet-Anomalien, das reale Gerät hinter der IP."),
   out=("Durchsetzung auf der richtigen Schicht", ["Drop-Liste auf dem Sensor (L3)", "VLAN-Quarantäne am Switch (L2)", "einmal blockiert, nicht auf jeder Schicht einzeln"]),
   solves_h="Was es löst",
   problems=[
    ("Umgehung durch IP-Wechsel", "Ein auf einer IP gesperrter Angreifer nimmt eine andere und macht weiter. Auf L3 wirkt er wie ein neuer Akteur; auf L2 ist es dieselbe MAC — und MLEO erkennt sie."),
    ("Richtige Isolierung bei ARP-Spoofing", "Gefälschter Verkehr scheint vom Opfer zu kommen. Die gerichtete Korrelation isoliert den Angreifer, nicht den Rechner, von dem der Verkehr zu kommen scheint."),
    ("Ein Gesamtbild statt verstreuter Sperren", "Dasselbe Gerät wird nicht mehr getrennt auf 3–4 Schichten ohne Zusammenhang blockiert."),
    ("Rückverfolgung über die Zeit", "Ausgehend von einer IP von vor 24 Stunden finden Sie die MAC und den physischen Port, an dem das Gerät hängt.")],
   princ_h="Sicherheitsprinzipien",
   chips=["beobachten vor durchsetzen", "Allowlist mit absolutem Vorrang", "transaktionaler Rollback", "VLAN-Quarantäne statt Abschaltung", "Fail-safe auf jeder Schicht"],
   stages_h="Umsetzung in Stufen", st_now="in Arbeit", st_next="als Nächstes", st_plan="geplant",
   stages=["Erfassung: ARP, MAC-Tabellen, Sperren aus jeder Schicht",
           "Abgleichstabelle MAC ↔ IP ↔ VLAN ↔ Port",
           "Jede L3-Sperre erhält ihre L2-Identität",
           "Gleiche MAC, verschiedene IPs: nur Meldung, im Beobachtungsmodus",
           "Erste Durchsetzung: VLAN-Quarantäne, mit Allowlist und Rollback",
           "Neue MAC an einem Port mit Vorgeschichte; gefälschtes ARP + L3-Sperre",
           "Umgekehrte Richtung L2 → L3, präventiv"],
   risk3="Stufen 0–3 greifen nie ins Kundennetz ein", risk4="Voraussetzungen: Allowlist + getesteter Rollback",
   notes=[
    ("Warum eine Kaskade?", "Keine Schicht ist allein perfekt. Ein vom IPS gestopptes Paket erreicht Active Response nicht mehr; eines, das durchrutscht, fängt die CYBER3 Context Fusion Engine ab; ein L2-Angriff (ARP-Spoofing), unsichtbar für die IP-Schichten, wird von L2 Shield gestoppt."),
    ("Autonom, ohne menschliches Eingreifen", "Erkennung → Kontextfusion → autonome Entscheidung in 2–11 Sekunden → Aktion: temporäre Sperre, Eskalation zur dauerhaften Sperre, Benachrichtigung. Die Allowlist schützt legitime Geräte bei jedem Schritt."),
    ("Ein Organismus", "MLEO ist keine neue Schicht. Es ist der Orchestrator, der die vorhandenen Schichten verbindet: Sieben Schichten, die getrennt sehen, werden zu einem Organismus, der dasselbe Gerät auf jeder Ebene erkennt.")],
   tagline="7 Schichten · MLEO · Defense in Depth"),

 "fr": dict(
   h2="Blocage en cascade. Sept couches complémentaires.",
   p="Chaque menace traverse une cascade de sept couches de défense : du fil à Ethernet, puis le cloud et le poste final. Ce qui échappe à une couche est arrêté par la suivante. Les couches sont complémentaires, non redondantes : chacune couvre un angle que les autres ne voient pas.",
   realtime="temps réel", rt_short="réponse", rt_long="temps de réponse",
   top="Trafic + menaces entrants", top_cnt="100 % inspecté",
   bottom="Atteint le réseau / l'utilisateur", bottom_z="trafic inspecté sur 7 couches",
   zones=["Réseau", "Hôte", "Ethernet", "IA", "Cloud", "Poste", "Mobile"],
   layers=[
    ("Réseau · L3–L7", "inspection en ligne sur le fil · signatures + anomalies · indicateurs IOC", "Détecte et <c>arrête le paquet sur le fil</c>, en millisecondes, avant qu'il n'entre dans le réseau du client."),
    ("Hôte · L3", "règle DROP dans le pare-feu · escalade vers un blocage permanent sur toute la flotte", "Réponse automatique à une alerte : une <c>règle DROP dans le pare-feu</c> pour l'IP de l'attaquant. Repli natif, indépendant de l'IA."),
    ("Ethernet · L2", "Ethernet natif · anti-ARP-spoof (pin IP↔MAC de la passerelle) · anti-DHCP pirate · dead-man anti-blackhole", "<c>La seule couche au niveau Ethernet.</c> Arrête le MITM, l'empoisonnement ARP et le DHCP pirate — des attaques que les couches IP <c>ne voient pas</c>."),
    ("IA · L3–L7", "fusion multi-sources : réseau + hôte + threat intel + CYBER3 DB", "Décision autonome à partir du contexte fusionné ; bloque même <c>les connexions sortantes vers un C2</c> (commande et contrôle)."),
    ("Cloud · partout", "DNS-shield · IOC en périphérie (2M+ indicateurs) · extension de navigateur", "Protection web et DNS <c>partout, même hors réseau</c> : les domaines et URL dangereux sont bloqués avant la connexion."),
    ("Poste · station de travail", "détection comportementale · télémétrie XDR → SOC · quarantaine", "Couvre les menaces arrivées <c>sur le poste</c> (USB, fichiers, processus), au-delà du réseau."),
    ("Mobile · appareil", "anti-arnaque / anti-phishing · filtrage DNS · VPN", "Protège l'utilisateur <c>en mobilité</c> : la dernière couche, sur l'appareil personnel.")],
   orch="Orchestrateur", rollout="In rollout", rollout_sub="étapes 0–1",
   m_tag="Concept · en cours d'implémentation", m_small="MLEO · LE NOYAU QUI RELIE LES 7 COUCHES",
   m_lead="Jusqu'ici, chaque couche <b>détecte et bloque de façon indépendante</b>. MLEO est le noyau qui <b>corrèle les signaux entre les couches et décide sur quelle couche chaque menace est traitée</b>, à partir d'une identité unifiée de l'appareil : la même machine vue comme <b>IP en couche 3</b> et comme <b>MAC en couche 2</b>.",
   box1=("Couche 3 · couches 1 · 2 · 4", "Blocages sur IP", "Inline IPS, Active Response et CYBER3 Context Fusion Engine : qui a attaqué, sur quel port, quand."),
   core=("MLEO · identité unifiée", "Une seule source de vérité", "MAC ↔ IP ↔ VLAN ↔ port<br>↔ emplacement physique ↔ criticité"),
   box3=("Couche 2 · couche 3", "Identité MAC", "L2 Shield : table ARP avec historique, anomalies Ethernet, l'appareil réel derrière l'IP."),
   out=("Enforcement sur la bonne couche", ["drop list sur le capteur (L3)", "quarantaine VLAN sur le switch (L2)", "bloqué une seule fois, pas sur chaque couche séparément"]),
   solves_h="Ce que cela résout",
   problems=[
    ("L'évasion par changement d'IP", "Un attaquant bloqué sur une IP en prend une autre et continue. En L3, il semble être un nouvel acteur ; en L2, c'est la même MAC — et MLEO la reconnaît."),
    ("Une isolation correcte lors d'un ARP spoofing", "Le trafic usurpé semble venir de la victime. La corrélation directionnelle isole l'attaquant, pas la machine dont le trafic semble provenir."),
    ("Une vue unique, pas des blocages fragmentés", "Le même appareil n'est plus bloqué séparément sur 3–4 couches sans lien entre elles."),
    ("Un suivi dans le temps", "À partir d'une IP vue il y a 24 heures, vous retrouvez la MAC et le port physique où se trouve l'appareil.")],
   princ_h="Principes de sécurité",
   chips=["observer avant d'appliquer", "allowlist à priorité absolue", "rollback transactionnel", "quarantaine VLAN, pas d'arrêt", "fail-safe sur chaque couche"],
   stages_h="Déploiement par étapes", st_now="en cours", st_next="suivante", st_plan="planifiée",
   stages=["Collecte : ARP, tables MAC, blocages de chaque couche",
           "Table de réconciliation MAC ↔ IP ↔ VLAN ↔ port",
           "Chaque blocage L3 reçoit son identité L2",
           "Même MAC, IP différentes : signalement seul, en observation",
           "Premier enforcement : quarantaine VLAN, avec allowlist et rollback",
           "Nouvelle MAC sur un port avec historique ; ARP usurpé + blocage L3",
           "Sens inverse L2 → L3, préventif"],
   risk3="les étapes 0–3 ne touchent jamais le réseau du client", risk4="prérequis : allowlist + rollback testé",
   notes=[
    ("Pourquoi en cascade ?", "Aucune couche n'est parfaite seule. Un paquet arrêté par l'IPS n'atteint plus Active Response ; celui qui passe est arrêté par CYBER3 Context Fusion Engine ; une attaque L2 (ARP spoofing), invisible pour les couches IP, est arrêtée par L2 Shield."),
    ("Autonome, sans intervention humaine", "Détection → fusion du contexte → décision autonome en 2–11 secondes → action : blocage temporaire, escalade vers un blocage permanent, notification. L'allowlist protège les équipements légitimes à chaque étape."),
    ("Un seul organisme", "MLEO n'est pas une nouvelle couche. C'est l'orchestrateur qui relie les couches existantes : sept couches qui voient séparément deviennent un seul organisme qui voit le même appareil à tous les niveaux.")],
   tagline="7 couches · MLEO · défense en profondeur"),

 "ru": dict(
   h2="Блокировка каскадом. Семь взаимодополняющих слоёв.",
   p="Каждая угроза проходит каскад из семи слоёв защиты: от провода до Ethernet, затем облако и конечное устройство. То, что прошло мимо одного слоя, перехватывает следующий. Слои дополняют друг друга, а не дублируют: каждый закрывает угол, который не видят остальные.",
   realtime="реальное время", rt_short="отклик", rt_long="время отклика",
   top="Входят трафик + угрозы", top_cnt="100% проверено",
   bottom="Достигает сети / пользователя", bottom_z="трафик проверен на 7 слоях",
   zones=["Сеть", "Хост", "Ethernet", "ИИ", "Облако", "Десктоп", "Мобильный"],
   layers=[
    ("Сеть · L3–L7", "инлайн-проверка на проводе · сигнатуры + аномалии · индикаторы IOC", "Обнаруживает и <c>останавливает пакет на проводе</c> за миллисекунды, до того как он попадёт в сеть клиента."),
    ("Хост · L3", "правило DROP в брандмауэре · эскалация до постоянной блокировки по всему парку", "Автоматический ответ на тревогу: <c>правило DROP в брандмауэре</c> для IP атакующего. Встроенный резерв, независимый от ИИ."),
    ("Ethernet · L2", "нативный Ethernet · анти-ARP-спуфинг (пин IP↔MAC шлюза) · анти-поддельный DHCP · dead-man против blackhole", "<c>Единственный слой на уровне Ethernet.</c> Останавливает MITM, ARP-отравление и поддельный DHCP — атаки, которые IP-слои <c>не видят</c>."),
    ("ИИ · L3–L7", "слияние многих источников: сеть + хост + threat intel + CYBER3 DB", "Автономное решение на основе объединённого контекста; блокирует даже <c>исходящие соединения к C2</c> (командным серверам)."),
    ("Облако · везде", "DNS-щит · IOC на периферии (2M+ индикаторов) · расширение браузера", "Веб- и DNS-защита <c>где угодно, даже вне сети</c>: опасные домены и URL блокируются до установки соединения."),
    ("Десктоп · рабочая станция", "поведенческое обнаружение · телеметрия XDR → SOC · карантин", "Закрывает угрозы, дошедшие <c>до рабочей станции</c> (USB, файлы, процессы), за пределами сети."),
    ("Мобильный · устройство", "анти-скам / анти-фишинг · DNS-фильтрация · VPN", "Защищает пользователя <c>в движении</c>: последний слой, на личном устройстве.")],
   orch="Оркестратор", rollout="In rollout", rollout_sub="этапы 0–1",
   m_tag="Концепция · внедряется", m_small="MLEO · ЯДРО, СВЯЗЫВАЮЩЕЕ 7 СЛОЁВ",
   m_lead="До сих пор каждый слой <b>обнаруживал и блокировал независимо</b>. MLEO — это ядро, которое <b>сопоставляет сигналы между слоями и решает, на каком слое обрабатывать каждую угрозу</b>, на основе единой идентичности устройства: одна и та же машина видна как <b>IP на уровне 3</b> и как <b>MAC на уровне 2</b>.",
   box1=("Уровень 3 · слои 1 · 2 · 4", "Блокировки по IP", "Inline IPS, Active Response и CYBER3 Context Fusion Engine: кто атаковал, на каком порту, когда."),
   core=("MLEO · единая идентичность", "Единый источник истины", "MAC ↔ IP ↔ VLAN ↔ порт<br>↔ физическое место ↔ критичность"),
   box3=("Уровень 2 · слой 3", "Идентичность MAC", "L2 Shield: ARP-таблица с историей, аномалии Ethernet, реальное устройство за IP-адресом."),
   out=("Применение на нужном слое", ["drop-список на сенсоре (L3)", "карантинная VLAN на коммутаторе (L2)", "блокируется один раз, а не на каждом слое отдельно"]),
   solves_h="Что это решает",
   problems=[
    ("Обход через смену IP", "Атакующий, заблокированный по одному IP, берёт другой и продолжает. На L3 он выглядит как новый участник; на L2 это тот же MAC — и MLEO его узнаёт."),
    ("Правильная изоляция при ARP-спуфинге", "Поддельный трафик выглядит так, будто идёт от жертвы. Направленная корреляция изолирует атакующего, а не машину, от которой якобы идёт трафик."),
    ("Единая картина вместо разрозненных блокировок", "Одно и то же устройство больше не блокируется отдельно на 3–4 слоях без связи между ними."),
    ("Отслеживание во времени", "По IP-адресу, замеченному 24 часа назад, вы находите MAC и физический порт, где находится устройство.")],
   princ_h="Принципы безопасности",
   chips=["наблюдение до применения", "allowlist с абсолютным приоритетом", "транзакционный откат", "карантинная VLAN, а не отключение", "fail-safe на каждом слое"],
   stages_h="Поэтапное внедрение", st_now="в работе", st_next="далее", st_plan="запланировано",
   stages=["Сбор: ARP, таблицы MAC, блокировки со всех слоёв",
           "Таблица сверки MAC ↔ IP ↔ VLAN ↔ порт",
           "Каждая блокировка L3 получает свою идентичность L2",
           "Один MAC, разные IP: только отчёт, в режиме наблюдения",
           "Первое применение: карантинная VLAN, с allowlist и откатом",
           "Новый MAC на порту с историей; поддельный ARP + блокировка L3",
           "Обратное направление L2 → L3, превентивно"],
   risk3="этапы 0–3 не затрагивают сеть клиента", risk4="условия: allowlist + проверенный откат",
   notes=[
    ("Почему каскад?", "Ни один слой не идеален сам по себе. Пакет, остановленный IPS, не доходит до Active Response; проскочивший перехватывает CYBER3 Context Fusion Engine; атаку L2 (ARP-спуфинг), невидимую для IP-слоёв, останавливает L2 Shield."),
    ("Автономно, без участия человека", "Обнаружение → слияние контекста → автономное решение за 2–11 секунд → действие: временная блокировка, эскалация до постоянной, уведомление. Allowlist защищает легитимное оборудование на каждом шаге."),
    ("Единый организм", "MLEO — не новый слой. Это оркестратор, связывающий существующие слои: семь слоёв, видящих по отдельности, становятся единым организмом, который видит одно и то же устройство на всех уровнях.")],
   tagline="7 слоёв · MLEO · эшелонированная защита"),

 "zh": dict(
   h2="级联拦截。七层互补防御。",
   p="每个威胁都要穿过七层防御组成的级联:从链路到以太网,再到云端和终端。某一层漏过的,由下一层拦截。各层互补而非冗余:每一层都覆盖其他层看不到的角度。",
   realtime="实时", rt_short="响应", rt_long="响应时间",
   top="流量 + 威胁进入", top_cnt="100% 检测",
   bottom="到达网络 / 用户", bottom_z="流量经 7 层检测",
   zones=["网络", "主机", "以太网", "AI", "云端", "桌面", "移动"],
   layers=[
    ("网络 · L3–L7", "链路内联检测 · 特征 + 异常 · IOC 指标", "在链路上<c>检测并拦截数据包</c>,毫秒级完成,在其进入客户网络之前。"),
    ("主机 · L3", "防火墙 DROP 规则 · 升级为全舰队永久封禁", "对告警的自动响应:为攻击者 IP 写入<c>防火墙 DROP 规则</c>。原生兜底,不依赖 AI。"),
    ("以太网 · L2", "原生以太网 · 反 ARP 欺骗(网关 IP↔MAC 绑定)· 反伪造 DHCP · 防黑洞 dead-man", "<c>唯一的以太网层防护。</c>阻止中间人、ARP 投毒和伪造 DHCP——IP 层<c>看不到</c>的攻击。"),
    ("AI · L3–L7", "多源融合:网络 + 主机 + 威胁情报 + CYBER3 DB", "基于融合上下文自主决策;甚至拦截<c>通往 C2 的出站连接</c>(命令与控制)。"),
    ("云端 · 随处", "DNS 防护盾 · 边缘 IOC(200万+ 指标)· 浏览器扩展", "<c>随处可用,即使在网络之外</c>的 Web 与 DNS 防护:危险域名和网址在连接前即被拦截。"),
    ("桌面 · 工作站", "行为检测 · XDR 遥测 → SOC · 隔离", "覆盖到达<c>工作站</c>的威胁(USB、文件、进程),超越网络边界。"),
    ("移动 · 设备", "反诈骗 / 反钓鱼 · DNS 过滤 · VPN", "在<c>移动中</c>保护用户:最后一层,位于个人设备上。")],
   orch="编排器", rollout="In rollout", rollout_sub="阶段 0–1",
   m_tag="概念 · 实施中", m_small="MLEO · 连接 7 层的核心",
   m_lead="到目前为止,每一层都<b>独立检测和拦截</b>。MLEO 是<b>在各层之间关联信号、并决定每个威胁由哪一层执行处置</b>的核心,其基础是统一的设备身份:同一台设备在<b>第 3 层被视为 IP</b>,在<b>第 2 层被视为 MAC</b>。",
   box1=("第 3 层 · 第 1 · 2 · 4 层", "基于 IP 的封禁", "Inline IPS、Active Response 与 CYBER3 Context Fusion Engine:谁发起攻击、在哪个端口、何时。"),
   core=("MLEO · 统一身份", "唯一的事实来源", "MAC ↔ IP ↔ VLAN ↔ 端口<br>↔ 物理位置 ↔ 关键程度"),
   box3=("第 2 层 · 第 3 层", "MAC 身份", "L2 Shield:带历史的 ARP 表、以太网异常、IP 背后的真实设备。"),
   out=("在正确的层执行处置", ["传感器上的 drop 列表(L3)", "交换机上的隔离 VLAN(L2)", "只封禁一次,而不是在每一层分别封禁"]),
   solves_h="解决什么问题",
   problems=[
    ("通过更换 IP 规避", "在一个 IP 上被封禁的攻击者换一个 IP 继续。在 L3 看似新的参与者;在 L2 仍是同一个 MAC——MLEO 能识别它。"),
    ("ARP 欺骗时的正确隔离", "伪造的流量看起来来自受害者。方向性关联隔离的是攻击者,而不是流量看似来自的那台机器。"),
    ("统一视图,而非零散封禁", "同一设备不再在 3–4 层上被彼此无关地分别封禁。"),
    ("随时间追溯", "从 24 小时前出现的 IP 出发,即可找到设备的 MAC 和所在物理端口。")],
   princ_h="安全原则",
   chips=["先观察后执行", "allowlist 绝对优先", "事务性回滚", "隔离 VLAN,而非关闭端口", "每层均 fail-safe"],
   stages_h="分阶段实施", st_now="进行中", st_next="下一步", st_plan="已规划",
   stages=["采集:ARP、MAC 表、各层封禁记录",
           "对账表 MAC ↔ IP ↔ VLAN ↔ 端口",
           "每条 L3 封禁都获得其 L2 身份",
           "同一 MAC、不同 IP:仅报告,处于观察模式",
           "首次执行:隔离 VLAN,配合 allowlist 与回滚",
           "有历史记录端口上的新 MAC;伪造 ARP + L3 封禁",
           "反向 L2 → L3,预防性"],
   risk3="阶段 0–3 不触碰客户网络", risk4="前提:allowlist + 已测试的回滚",
   notes=[
    ("为什么是级联?", "没有哪一层单独是完美的。被 IPS 拦下的数据包不会再到达 Active Response;漏过的由 CYBER3 Context Fusion Engine 拦截;IP 层看不到的 L2 攻击(ARP 欺骗)由 L2 Shield 阻止。"),
    ("自主运行,无需人工", "检测 → 上下文融合 → 2–11 秒内自主决策 → 行动:临时封禁、升级为永久封禁、通知。allowlist 在每一步保护合法设备。"),
    ("一个有机整体", "MLEO 不是新的一层,而是连接现有各层的编排器:原本各自为战的七层,成为一个在所有层级都能看到同一设备的有机整体。")],
   tagline="7 层 · MLEO · 纵深防御"),
}


# MLEO prezentat OPERAȚIONAL (operator 18 sep, seara): fără „concept / în implementare / in rollout / Active”.
# Etapele devin lanțul de enforcement MLEO: treptele 0–3 = vizibilitate, 4–6 = enforcement.
OPS = {
 "en": dict(m_tag="Proprietary orchestrator · 7 layers", tile_l="orchestrates 7 / 7 layers",
   m_lead="Without orchestration, each layer would <b>detect and block on its own</b>. MLEO is the core that <b>correlates signals across layers and decides which layer enforces each threat</b>, based on a unified device identity: the same machine seen as an <b>IP at Layer 3</b> and as a <b>MAC at Layer 2</b>.",
   stages_h="The MLEO enforcement chain", ph_vis="visibility", ph_enf="enforcement",
   stages=["Continuous collection: ARP, MAC tables, blocks from every layer",
           "Reconciliation table MAC ↔ IP ↔ VLAN ↔ port, with IP history",
           "Every L3 block gains its L2 identity (MAC, VLAN, port, criticality)",
           "Same MAC, different IPs within 15 min: IP-change evasion alert",
           "Enforcement: port moved to a quarantine VLAN, with allowlist and rollback",
           "New MAC on a port with block history; spoofed ARP + L3 block: port isolation",
           "Reverse direction L2 → L3: anomalous MAC resolved to IP and dropped preventively"],
   risk3="steps 0–3 give full visibility without touching the client network"),
 "ro": dict(m_tag="Orchestrator proprietar · 7 straturi", tile_l="orchestrează 7 / 7 straturi",
   m_lead="Fără orchestrare, fiecare strat ar <b>detecta și bloca pe cont propriu</b>. MLEO este nucleul care <b>corelează semnalele dintre straturi și decide pe ce strat se execută fiecare amenințare</b>, pe baza unei identități unificate a dispozitivului: același echipament văzut ca <b>IP la Layer 3</b> și ca <b>MAC la Layer 2</b>.",
   stages_h="Lanțul de enforcement MLEO", ph_vis="vizibilitate", ph_enf="enforcement",
   stages=["Colectare continuă: ARP, tabele MAC, blocări de pe fiecare strat",
           "Tabela de reconciliere MAC ↔ IP ↔ VLAN ↔ port, cu istoric de IP",
           "Fiecare blocare L3 primește identitatea L2 (MAC, VLAN, port, criticitate)",
           "Același MAC cu IP-uri diferite în 15 minute: alertă de evaziune prin schimbare de IP",
           "Enforcement: portul mutat în VLAN de carantină, cu allowlist și rollback",
           "MAC nou pe un port cu istoric de blocări; ARP fals + blocare L3: izolarea portului",
           "Direcția inversă L2 → L3: MAC-ul anormal rezolvat la IP și blocat preventiv"],
   risk3="treptele 0–3 dau vizibilitate completă fără să atingă rețeaua clientului"),
 "es": dict(m_tag="Orquestador propio · 7 capas", tile_l="orquesta 7 / 7 capas",
   m_lead="Sin orquestación, cada capa <b>detectaría y bloquearía por su cuenta</b>. MLEO es el núcleo que <b>correlaciona las señales entre capas y decide en qué capa se ejecuta cada amenaza</b>, a partir de una identidad unificada del dispositivo: el mismo equipo visto como <b>IP en la capa 3</b> y como <b>MAC en la capa 2</b>.",
   stages_h="La cadena de enforcement de MLEO", ph_vis="visibilidad", ph_enf="enforcement",
   stages=["Recopilación continua: ARP, tablas MAC, bloqueos de cada capa",
           "Tabla de reconciliación MAC ↔ IP ↔ VLAN ↔ puerto, con historial de IP",
           "Cada bloqueo L3 recibe su identidad L2 (MAC, VLAN, puerto, criticidad)",
           "Misma MAC, IPs distintas en 15 minutos: alerta de evasión por cambio de IP",
           "Enforcement: el puerto pasa a una VLAN de cuarentena, con allowlist y rollback",
           "MAC nueva en un puerto con historial de bloqueos; ARP falso + bloqueo L3: aislamiento del puerto",
           "Dirección inversa L2 → L3: la MAC anómala se resuelve a IP y se bloquea de forma preventiva"],
   risk3="los pasos 0–3 dan visibilidad total sin tocar la red del cliente"),
 "it": dict(m_tag="Orchestratore proprietario · 7 livelli", tile_l="orchestra 7 / 7 livelli",
   m_lead="Senza orchestrazione, ogni livello <b>rileverebbe e bloccherebbe per conto proprio</b>. MLEO è il nucleo che <b>correla i segnali tra i livelli e decide su quale livello eseguire ogni minaccia</b>, sulla base di un'identità unificata del dispositivo: la stessa macchina vista come <b>IP al Layer 3</b> e come <b>MAC al Layer 2</b>.",
   stages_h="La catena di enforcement MLEO", ph_vis="visibilità", ph_enf="enforcement",
   stages=["Raccolta continua: ARP, tabelle MAC, blocchi da ogni livello",
           "Tabella di riconciliazione MAC ↔ IP ↔ VLAN ↔ porta, con storico IP",
           "Ogni blocco L3 riceve la sua identità L2 (MAC, VLAN, porta, criticità)",
           "Stesso MAC, IP diversi in 15 minuti: allarme di evasione tramite cambio di IP",
           "Enforcement: porta spostata in una VLAN di quarantena, con allowlist e rollback",
           "Nuovo MAC su una porta con storico di blocchi; ARP falso + blocco L3: isolamento della porta",
           "Direzione inversa L2 → L3: il MAC anomalo viene risolto in IP e bloccato preventivamente"],
   risk3="i passi 0–3 danno visibilità completa senza toccare la rete del cliente"),
 "de": dict(m_tag="Eigener Orchestrator · 7 Schichten", tile_l="orchestriert 7 / 7 Schichten",
   m_lead="Ohne Orchestrierung würde jede Schicht <b>für sich allein erkennen und blockieren</b>. MLEO ist der Kern, der <b>Signale schichtübergreifend korreliert und entscheidet, auf welcher Schicht jede Bedrohung durchgesetzt wird</b> — auf Basis einer einheitlichen Geräteidentität: dasselbe Gerät, gesehen als <b>IP auf Layer 3</b> und als <b>MAC auf Layer 2</b>.",
   stages_h="Die MLEO-Durchsetzungskette", ph_vis="Sichtbarkeit", ph_enf="Durchsetzung",
   stages=["Kontinuierliche Erfassung: ARP, MAC-Tabellen, Sperren aus jeder Schicht",
           "Abgleichstabelle MAC ↔ IP ↔ VLAN ↔ Port, mit IP-Verlauf",
           "Jede L3-Sperre erhält ihre L2-Identität (MAC, VLAN, Port, Kritikalität)",
           "Gleiche MAC, verschiedene IPs innerhalb von 15 Minuten: Alarm wegen Umgehung durch IP-Wechsel",
           "Durchsetzung: Port in ein Quarantäne-VLAN verschoben, mit Allowlist und Rollback",
           "Neue MAC an einem Port mit Sperrhistorie; gefälschtes ARP + L3-Sperre: Port-Isolierung",
           "Umgekehrte Richtung L2 → L3: anomale MAC wird zur IP aufgelöst und präventiv gesperrt"],
   risk3="Schritte 0–3 liefern volle Sichtbarkeit, ohne das Kundennetz zu berühren"),
 "fr": dict(m_tag="Orchestrateur propriétaire · 7 couches", tile_l="orchestre 7 / 7 couches",
   m_lead="Sans orchestration, chaque couche <b>détecterait et bloquerait de son côté</b>. MLEO est le noyau qui <b>corrèle les signaux entre les couches et décide sur quelle couche chaque menace est traitée</b>, à partir d'une identité unifiée de l'appareil : la même machine vue comme <b>IP en couche 3</b> et comme <b>MAC en couche 2</b>.",
   stages_h="La chaîne d'enforcement MLEO", ph_vis="visibilité", ph_enf="enforcement",
   stages=["Collecte continue : ARP, tables MAC, blocages de chaque couche",
           "Table de réconciliation MAC ↔ IP ↔ VLAN ↔ port, avec historique d'IP",
           "Chaque blocage L3 reçoit son identité L2 (MAC, VLAN, port, criticité)",
           "Même MAC, IP différentes en 15 minutes : alerte d'évasion par changement d'IP",
           "Enforcement : port déplacé dans un VLAN de quarantaine, avec allowlist et rollback",
           "Nouvelle MAC sur un port avec historique de blocages ; ARP usurpé + blocage L3 : isolation du port",
           "Sens inverse L2 → L3 : la MAC anormale est résolue en IP et bloquée à titre préventif"],
   risk3="les étapes 0–3 offrent une visibilité complète sans toucher au réseau du client"),
 "ru": dict(m_tag="Собственный оркестратор · 7 слоёв", tile_l="оркеструет 7 / 7 слоёв",
   m_lead="Без оркестрации каждый слой <b>обнаруживал бы и блокировал сам по себе</b>. MLEO — это ядро, которое <b>сопоставляет сигналы между слоями и решает, на каком слое обрабатывать каждую угрозу</b>, на основе единой идентичности устройства: одна и та же машина видна как <b>IP на уровне 3</b> и как <b>MAC на уровне 2</b>.",
   stages_h="Цепочка применения MLEO", ph_vis="видимость", ph_enf="применение",
   stages=["Непрерывный сбор: ARP, таблицы MAC, блокировки со всех слоёв",
           "Таблица сверки MAC ↔ IP ↔ VLAN ↔ порт, с историей IP",
           "Каждая блокировка L3 получает свою идентичность L2 (MAC, VLAN, порт, критичность)",
           "Один MAC, разные IP за 15 минут: тревога об обходе через смену IP",
           "Применение: порт переводится в карантинную VLAN, с allowlist и откатом",
           "Новый MAC на порту с историей блокировок; поддельный ARP + блокировка L3: изоляция порта",
           "Обратное направление L2 → L3: аномальный MAC сопоставляется с IP и блокируется превентивно"],
   risk3="шаги 0–3 дают полную видимость, не затрагивая сеть клиента"),
 "zh": dict(m_tag="自有编排器 · 7 层", tile_l="编排 7 / 7 层",
   m_lead="如果没有编排,每一层都会<b>各自检测、各自拦截</b>。MLEO 是<b>在各层之间关联信号、并决定每个威胁由哪一层执行处置</b>的核心,其基础是统一的设备身份:同一台设备在<b>第 3 层被视为 IP</b>,在<b>第 2 层被视为 MAC</b>。",
   stages_h="MLEO 执行链", ph_vis="可见性", ph_enf="执行",
   stages=["持续采集:ARP、MAC 表、各层封禁记录",
           "对账表 MAC ↔ IP ↔ VLAN ↔ 端口,含 IP 历史",
           "每条 L3 封禁都获得其 L2 身份(MAC、VLAN、端口、关键程度)",
           "15 分钟内同一 MAC、不同 IP:更换 IP 规避告警",
           "执行:端口移入隔离 VLAN,配合 allowlist 与回滚",
           "有封禁历史的端口出现新 MAC;伪造 ARP + L3 封禁:隔离端口",
           "反向 L2 → L3:异常 MAC 解析为 IP 并预防性封禁"],
   risk3="第 0–3 步提供完整可见性,且不触碰客户网络"),
}
for _l, _o in OPS.items():
    D[_l].update(_o)


def _c(s):
    return s.replace("<c>", '<span class="c">').replace("</c>", "</span>")


def _e(s):
    return html.escape(s, quote=False)


def defense_section(lang, kicker):
    d = D.get(lang, D["en"])
    rts = [r if r else d["realtime"] for r in RT]

    caps = ""
    for i in range(7):
        caps += ('<div class="d7-cap" style="--c:%s"><div class="d7-top"><span class="d7-no">%d</span>%s</div>'
                 '<div class="d7-cnm">%s</div>'
                 '<div class="d7-ln"><span class="d7-act"><i class="d7-led"></i>Active</span>'
                 '<span><span class="d7-rtl">%s </span><span class="d7-rt">%s</span></span></div></div>\n') % (
            COLORS[i], i + 1, _e(d["zones"][i]), _e(NAMES[i]), _e(d["rt_short"]), _e(rts[i]))
    caps += ('<div class="d7-cap d7-mleo" style="--c:#D4AF37"><div class="d7-top"><span class="d7-no">⬡</span>%s</div>'
             '<div class="d7-cnm">%s</div>'
             '<div class="d7-ln"><span class="d7-orch">%s</span>'
             '<span class="d7-rt">L2 ↔ L3</span></div></div>\n') % (_e(d["orch"]), MLEO, _e(d["tile_l"]))

    rows = ""
    for i in range(7):
        lvl, mech, exp = d["layers"][i]
        c = COLORS[i]
        rows += ('<div class="d7-row" style="--c:%s">'
                 '<div class="d7-num">%d</div>'
                 '<div class="d7-mid"><div class="d7-nm">%s<span class="d7-badge">%s</span></div>'
                 '<div class="d7-mech">%s</div><div class="d7-exp">%s</div>'
                 '<div class="d7-fnl" style="width:%d%%"></div></div>'
                 '<div class="d7-right"><span class="d7-act"><i class="d7-led"></i>Active</span>'
                 '<span class="d7-rt2">%s</span><span class="d7-vs">%s</span></div></div>\n') % (
            c, i + 1, _e(NAMES[i]), _e(lvl), _e(mech), _c(exp), FUNNEL[i], _e(rts[i]), _e(d["rt_long"]))

    probs = "".join("<li><b>%s</b>%s</li>" % (_e(h), _e(p)) for h, p in d["problems"])
    chips = "".join("<span>%s</span>" % _e(c) for c in d["chips"])
    st = []
    for i, txt in enumerate(d["stages"]):
        cls, word = ("", d["ph_vis"]) if i <= 3 else ("enf", d["ph_enf"])
        if i == 4:
            cls = "enf gate"
        risk = ""
        if i == 3:
            risk = '<span class="d7-risk">%s</span>' % _e(d["risk3"])
        if i == 4:
            risk = '<span class="d7-risk">%s</span>' % _e(d["risk4"])
        st.append('<li class="%s"><span class="d7-sn">%d</span><span>%s%s</span><span class="d7-ss">%s</span></li>' % (
            cls, i, _e(txt), risk, _e(word)))
    stages = "".join(st)
    notes = "".join('<div class="d7-note"><h3>%s</h3><p>%s</p></div>' % (_e(h), _e(p)) for h, p in d["notes"])
    b1, core, b3 = d["box1"], d["core"], d["box3"]
    out_items = '<span class="d7-sep">·</span>'.join("<span>%s</span>" % _e(x) for x in d["out"][1])

    return """
  <div id="defense" class="d7-block">
  <div class="d7-status" aria-labelledby="d7-st-h">
    <div class="d7-st-head"><h3 id="d7-st-h">Capabilities Status</h3><span class="d7-sum"><i class="d7-led"></i>7 / 7 Active</span></div>
    <div class="d7-caps">
%(caps)s    </div>
  </div>

  <div class="d7-cascade">
    <canvas id="d7-rain" aria-hidden="true"></canvas>
    <div class="d7-rows">
      <div class="d7-in"><span>◤ %(top)s</span><span class="d7-in-r">%(top_cnt)s</span></div>
%(rows)s      <div class="d7-outb"><span>◣ %(bottom)s</span><span class="d7-outb-r">%(bottom_z)s</span></div>
    </div>
  </div>

  <div class="d7-mleo-sec">
    <p class="d7-mtag"><span class="d7-hex">⬡</span>%(m_tag)s</p>
    <h3 class="d7-mh">%(mleo)s<small>%(m_small)s</small></h3>
    <p class="d7-ml">%(m_lead)s</p>
    <div class="d7-corr">
      <div class="d7-cbox"><p class="d7-k">%(b1k)s</p><p class="d7-t">%(b1t)s</p><p class="d7-d">%(b1d)s</p></div>
      <div class="d7-arr" aria-hidden="true">⇄</div>
      <div class="d7-cbox d7-core"><p class="d7-k">%(ck)s</p><p class="d7-t">%(ct)s</p><p class="d7-id">%(cid)s</p></div>
      <div class="d7-arr" aria-hidden="true">⇄</div>
      <div class="d7-cbox"><p class="d7-k">%(b3k)s</p><p class="d7-t">%(b3t)s</p><p class="d7-d">%(b3d)s</p></div>
    </div>
    <div class="d7-out"><b>%(out_h)s</b>%(out_items)s</div>
    <div class="d7-mcols">
      <div><h4>%(solves_h)s</h4><ul class="d7-prob">%(probs)s</ul></div>
      <div><h4>%(princ_h)s</h4><div class="d7-chips">%(chips)s</div>
        <h4>%(stages_h)s</h4><ol class="d7-stages">%(stages)s</ol></div>
    </div>
  </div>

  <div class="d7-foot">%(notes)s</div>
  <p class="d7-tag">FasterUp NEXTGEN SOC · <b>%(tagline)s</b></p>
  <script src="/defense7.js" defer></script>
  </div>
""" % dict(caps=caps, rows=rows,
           top=_e(d["top"]), top_cnt=_e(d["top_cnt"]), bottom=_e(d["bottom"]), bottom_z=_e(d["bottom_z"]),
           m_tag=_e(d["m_tag"]), mleo=MLEO, m_small=_e(d["m_small"]), m_lead=d["m_lead"],
           b1k=_e(b1[0]), b1t=_e(b1[1]), b1d=_e(b1[2]), ck=_e(core[0]), ct=_e(core[1]), cid=core[2],
           b3k=_e(b3[0]), b3t=_e(b3[1]), b3d=_e(b3[2]), out_h=_e(d["out"][0]), out_items=out_items,
           solves_h=_e(d["solves_h"]), probs=probs, princ_h=_e(d["princ_h"]), chips=chips,
           stages_h=_e(d["stages_h"]), stages=stages, notes=notes, tagline=_e(d["tagline"]))


# Titlul capitolului Tehnologie = cascada; fraza finală leagă straturile de MLEO.
P_ADD = {
 "en": " MLEO orchestrates them as a single organism.",
 "ro": " MLEO le orchestrează ca pe un singur organism.",
 "es": " MLEO las orquesta como un solo organismo.",
 "it": " MLEO li orchestra come un unico organismo.",
 "de": " MLEO orchestriert sie als einen einzigen Organismus.",
 "fr": " MLEO les orchestre comme un seul organisme.",
 "ru": " MLEO оркеструет их как единый организм.",
 "zh": "MLEO 将它们编排为一个有机整体。",
}


def defense_head(lang):
    d = D.get(lang, D["en"])
    return _e(d["h2"]), _e(d["p"] + P_ADD.get(lang, P_ADD["en"]))
