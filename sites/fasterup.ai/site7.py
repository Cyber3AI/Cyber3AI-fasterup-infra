# -*- coding: utf-8 -*-
# fasterup.ai — actualizarea „7 straturi + MLEO” (operator 18 sep 2026, seara):
#  OVR[lang]  = suprascrieri ale textelor existente (hero, carduri servicii) aliniate la cele 7 straturi + MLEO
#  PKG[lang]  = pachetele Standard / Extins / Complet cu capabilități crescătoare
import html

OVR = {
 "en": dict(
   sub="FasterUp detects, decides and responds to cyber threats in real time — seven complementary defense layers, from the wire to the workstation and the phone, orchestrated by MLEO into a single autonomous decision. Managed Security Operations Center and Vulnerability Assessment, deployed at your premises.",
   stat3b="7", stat3="complementary defense layers, orchestrated by MLEO",
   s1_p="Fully managed, autonomous monitoring on seven complementary defense layers. FasterUp detects intrusions, network anomalies, command-and-control, data exfiltration and policy violations — the AI engine decides, and MLEO enforces on the right layer: block, notify or escalate, in seconds.",
   s3_p="Every alert is scored by AI across all sources. By severity, FasterUp logs, blocks automatically, raises an urgent alert or escalates to a human — and MLEO executes the block on the right layer, from the firewall to a quarantine VLAN. No analyst required to act.",
   s5_p="Dedicated sensors at your sites — inline or passive — run the first network layers on the spot: Inline IPS at the wire, Active Response in the firewall and L2 Shield at Ethernet level, against ARP spoofing, rogue DHCP, scanning and exploits — without touching your workstations."),
 "ro": dict(
   sub="FasterUp detectează, decide și răspunde la amenințările cibernetice în timp real — șapte straturi complementare de apărare, de la fir la stația de lucru și telefon, orchestrate de MLEO într-o singură decizie autonomă. Centru de Operațiuni de Securitate administrat și Evaluare de Vulnerabilități, instalate la sediul tău.",
   stat3b="7", stat3="straturi complementare de apărare, orchestrate de MLEO",
   s1_p="Monitorizare autonomă, complet administrată, pe șapte straturi complementare de apărare. FasterUp detectează intruziuni, anomalii de rețea, comandă-și-control, exfiltrare de date și încălcări de politici — motorul AI decide, iar MLEO execută pe stratul potrivit: blochează, notifică sau escaladează, în secunde.",
   s3_p="Fiecare alertă e evaluată de AI pe toate sursele. În funcție de severitate, FasterUp înregistrează, blochează automat, ridică o alertă urgentă sau escaladează către un analist — iar MLEO execută blocarea pe stratul potrivit, de la firewall la VLAN-ul de carantină. Fără să fie nevoie de om ca să acționeze.",
   s5_p="Senzori dedicați la sediile tale — inline sau pasivi — rulează pe loc primele straturi de rețea: Inline IPS la fir, Active Response în firewall și L2 Shield la nivel Ethernet, împotriva ARP spoofing, DHCP fals, scanărilor și exploit-urilor — fără să atingă stațiile de lucru."),
 "es": dict(
   sub="FasterUp detecta, decide y responde a las amenazas cibernéticas en tiempo real — siete capas de defensa complementarias, del cable a la estación de trabajo y al teléfono, orquestadas por MLEO en una sola decisión autónoma. Centro de Operaciones de Seguridad gestionado y Evaluación de Vulnerabilidades, instalados en tus instalaciones.",
   stat3b="7", stat3="capas de defensa complementarias, orquestadas por MLEO",
   s1_p="Monitorización autónoma y totalmente gestionada en siete capas de defensa complementarias. FasterUp detecta intrusiones, anomalías de red, comando y control, exfiltración de datos y violaciones de políticas — el motor de IA decide y MLEO ejecuta en la capa adecuada: bloquear, notificar o escalar, en segundos.",
   s3_p="Cada alerta es evaluada por IA en todas las fuentes. Según la gravedad, FasterUp registra, bloquea automáticamente, lanza una alerta urgente o escala a un analista — y MLEO ejecuta el bloqueo en la capa adecuada, del firewall a una VLAN de cuarentena. Sin necesidad de que actúe una persona.",
   s5_p="Sensores dedicados en tus sedes — inline o pasivos — ejecutan in situ las primeras capas de red: Inline IPS en el cable, Active Response en el firewall y L2 Shield a nivel Ethernet, contra ARP spoofing, DHCP falso, escaneos y exploits — sin tocar las estaciones de trabajo."),
 "it": dict(
   sub="FasterUp rileva, decide e risponde alle minacce informatiche in tempo reale — sette livelli di difesa complementari, dal filo alla postazione e al telefono, orchestrati da MLEO in un'unica decisione autonoma. Security Operations Center gestito e Valutazione delle Vulnerabilità, installati presso la tua sede.",
   stat3b="7", stat3="livelli di difesa complementari, orchestrati da MLEO",
   s1_p="Monitoraggio autonomo e completamente gestito su sette livelli di difesa complementari. FasterUp rileva intrusioni, anomalie di rete, comando e controllo, esfiltrazione di dati e violazioni delle policy — il motore IA decide e MLEO esegue sul livello giusto: blocca, notifica o escala, in pochi secondi.",
   s3_p="Ogni allarme è valutato dall'IA su tutte le fonti. In base alla gravità, FasterUp registra, blocca automaticamente, lancia un allarme urgente o escala a un analista — e MLEO esegue il blocco sul livello giusto, dal firewall a una VLAN di quarantena. Nessun intervento umano necessario.",
   s5_p="Sensori dedicati nelle tue sedi — inline o passivi — eseguono sul posto i primi livelli di rete: Inline IPS sul filo, Active Response nel firewall e L2 Shield a livello Ethernet, contro ARP spoofing, DHCP fasullo, scansioni ed exploit — senza toccare le postazioni di lavoro."),
 "de": dict(
   sub="FasterUp erkennt Cyberbedrohungen, entscheidet und reagiert in Echtzeit — sieben komplementäre Verteidigungsschichten, von der Leitung bis zum Arbeitsplatz und Telefon, von MLEO zu einer einzigen autonomen Entscheidung orchestriert. Verwaltetes Security Operations Center und Schwachstellenbewertung, bei Ihnen vor Ort installiert.",
   stat3b="7", stat3="komplementäre Verteidigungsschichten, orchestriert von MLEO",
   s1_p="Vollständig verwaltete, autonome Überwachung auf sieben komplementären Verteidigungsschichten. FasterUp erkennt Einbrüche, Netzwerkanomalien, Command-and-Control, Datenabfluss und Richtlinienverstöße — die KI entscheidet, und MLEO setzt auf der richtigen Schicht durch: blockieren, benachrichtigen oder eskalieren, in Sekunden.",
   s3_p="Jeder Alarm wird von der KI über alle Quellen bewertet. Je nach Schwere protokolliert FasterUp, blockiert automatisch, löst einen dringenden Alarm aus oder eskaliert an einen Analysten — und MLEO führt die Sperre auf der richtigen Schicht aus, von der Firewall bis zum Quarantäne-VLAN. Kein menschliches Eingreifen nötig.",
   s5_p="Dedizierte Sensoren an Ihren Standorten — inline oder passiv — betreiben die ersten Netzwerkschichten direkt vor Ort: Inline IPS auf der Leitung, Active Response in der Firewall und L2 Shield auf Ethernet-Ebene, gegen ARP-Spoofing, Rogue-DHCP, Scans und Exploits — ohne die Arbeitsplätze zu berühren."),
 "fr": dict(
   sub="FasterUp détecte, décide et répond aux cybermenaces en temps réel — sept couches de défense complémentaires, du fil au poste de travail et au téléphone, orchestrées par MLEO en une seule décision autonome. Centre des opérations de sécurité géré et évaluation des vulnérabilités, installés dans vos locaux.",
   stat3b="7", stat3="couches de défense complémentaires, orchestrées par MLEO",
   s1_p="Surveillance autonome et entièrement gérée sur sept couches de défense complémentaires. FasterUp détecte les intrusions, les anomalies réseau, le command-and-control, l'exfiltration de données et les violations de politique — l'IA décide et MLEO applique sur la bonne couche : bloquer, notifier ou escalader, en quelques secondes.",
   s3_p="Chaque alerte est évaluée par l'IA sur toutes les sources. Selon la gravité, FasterUp journalise, bloque automatiquement, lève une alerte urgente ou escalade vers un analyste — et MLEO exécute le blocage sur la bonne couche, du pare-feu au VLAN de quarantaine. Aucune intervention humaine nécessaire.",
   s5_p="Des capteurs dédiés sur vos sites — en ligne ou passifs — exécutent sur place les premières couches réseau : Inline IPS sur le fil, Active Response dans le pare-feu et L2 Shield au niveau Ethernet, contre l'ARP spoofing, le DHCP pirate, les scans et les exploits — sans toucher aux postes de travail."),
 "ru": dict(
   sub="FasterUp обнаруживает киберугрозы, принимает решения и реагирует в реальном времени — семь взаимодополняющих слоёв защиты, от провода до рабочей станции и телефона, которые MLEO оркеструет в единое автономное решение. Управляемый центр мониторинга безопасности и оценка уязвимостей — прямо на вашей площадке.",
   stat3b="7", stat3="взаимодополняющих слоёв защиты под управлением MLEO",
   s1_p="Полностью управляемый автономный мониторинг на семи взаимодополняющих слоях защиты. FasterUp обнаруживает вторжения, сетевые аномалии, командные серверы, утечку данных и нарушения политик — ИИ принимает решение, а MLEO применяет его на нужном слое: блокировка, уведомление или эскалация за секунды.",
   s3_p="Каждая тревога оценивается ИИ по всем источникам. В зависимости от серьёзности FasterUp записывает событие, блокирует автоматически, поднимает срочную тревогу или передаёт аналитику — а MLEO выполняет блокировку на нужном слое, от брандмауэра до карантинной VLAN. Участие человека не требуется.",
   s5_p="Выделенные сенсоры на ваших площадках — инлайн или пассивные — выполняют первые сетевые слои на месте: Inline IPS на проводе, Active Response в брандмауэре и L2 Shield на уровне Ethernet, против ARP-спуфинга, поддельного DHCP, сканирования и эксплойтов — не затрагивая рабочие станции."),
 "zh": dict(
   sub="FasterUp 实时检测、决策并响应网络威胁——七层互补防御,从链路到工作站和手机,由 MLEO 编排为一个自主决策。托管安全运营中心与漏洞评估,部署在您的现场。",
   stat3b="7", stat3="层互补防御,由 MLEO 编排",
   s1_p="在七层互补防御上进行完全托管的自主监控。FasterUp 检测入侵、网络异常、命令与控制、数据外泄和策略违规——AI 引擎决策,MLEO 在正确的层执行:拦截、通知或升级,只需数秒。",
   s3_p="每条告警都由 AI 结合所有来源进行评估。根据严重程度,FasterUp 会记录、自动拦截、发出紧急告警或升级给分析师——并由 MLEO 在正确的层执行拦截,从防火墙到隔离 VLAN。无需人工介入即可处置。",
   s5_p="部署在您各站点的专用传感器——内联或被动——在现场运行前几层网络防护:链路上的 Inline IPS、防火墙中的 Active Response 以及以太网层的 L2 Shield,抵御 ARP 欺骗、伪造 DHCP、扫描和漏洞利用——无需触碰工作站。"),
}

# Pachete: Standard (fost „Esențial”) / Extins / Complet — fiecare cu capabilități crescătoare.
PKG = {
 "en": dict(
   p="Each package includes everything in the previous one and adds layers and capabilities. The exact configuration (sensors, sites, workstations, phones) is set after an initial assessment of your environment.",
   inc=["Includes", "Everything in Standard, plus", "Everything in Extended, plus"],
   tiers=[
    ["Managed 24/7 SOC · autonomous response in 2–11 s", "Inline sensor at the main site", "Layers 1–4: Inline IPS · Active Response · L2 Shield · CYBER3 Context Fusion Engine", "MLEO: L3 ↔ L2 correlation and enforcement on the right layer", "Monthly scheduled VAS", "Plain-language alerts (Telegram, email) + client portal with NIS2 reports", "Autonomous 24/7 sensor Health Check"],
    ["Inline sensors at every site", "Layer 5 · CYBER3 Edge: DNS-shield and edge IOC for the whole organization", "Layer 6 · CYBER3 EDR/XDR for Desktop on critical workstations", "Client console: workstation isolation, remote scans, fleet status", "CYBER3 Global Scan of the internal network", "MLEO across all sites", "Bi-weekly VAS"],
    ["CYBER3 EDR/XDR for Desktop on every workstation", "Layer 7 · CYBER3 Mobile Protection on staff phones", "MLEO across all 7 layers: network, cloud, workstation, phone", "Continuous VAS", "Breach and identity monitoring for the organization's accounts", "Unified network + endpoint + mobile reporting (NIS2 Art. 21/23)"]]),
 "ro": dict(
   p="Fiecare pachet include tot ce are cel anterior și adaugă straturi și capabilități. Configurația exactă (senzori, sedii, stații, telefoane) se stabilește după o evaluare inițială a mediului.",
   inc=["Include", "Tot din Standard, plus", "Tot din Extins, plus"],
   tiers=[
    ["SOC administrat 24/7 · răspuns autonom în 2–11 s", "Senzor inline la sediul principal", "Straturile 1–4: Inline IPS · Active Response · L2 Shield · CYBER3 Context Fusion Engine", "MLEO: corelare L3 ↔ L2 și enforcement pe stratul potrivit", "VAS programat lunar", "Alerte explicate (Telegram, email) + portal client cu rapoarte NIS2", "Health Check autonom al senzorului, 24/7"],
    ["Senzori inline la toate sediile", "Stratul 5 · CYBER3 Edge: DNS-shield și IOC la edge pentru toată organizația", "Stratul 6 · CYBER3 EDR/XDR for Desktop pe stațiile critice", "Consola client: izolarea stației, scanări la distanță, starea flotei", "CYBER3 Global Scan al rețelei interne", "MLEO pe toate sediile", "VAS bilunar"],
    ["CYBER3 EDR/XDR for Desktop pe toate stațiile", "Stratul 7 · CYBER3 Mobile Protection pe telefoanele personalului", "MLEO pe toate cele 7 straturi: rețea, cloud, stație, telefon", "VAS continuu", "Monitorizarea breșelor și a identității pentru conturile instituției", "Raportare unificată rețea + endpoint + mobil (NIS2 Art. 21/23)"]]),
 "es": dict(
   p="Cada paquete incluye todo lo del anterior y añade capas y capacidades. La configuración exacta (sensores, sedes, estaciones, teléfonos) se define tras una evaluación inicial del entorno.",
   inc=["Incluye", "Todo lo de Standard, más", "Todo lo de Extendido, más"],
   tiers=[
    ["SOC gestionado 24/7 · respuesta autónoma en 2–11 s", "Sensor inline en la sede principal", "Capas 1–4: Inline IPS · Active Response · L2 Shield · CYBER3 Context Fusion Engine", "MLEO: correlación L3 ↔ L2 y enforcement en la capa adecuada", "VAS programado mensual", "Alertas explicadas (Telegram, email) + portal de cliente con informes NIS2", "Health Check autónomo del sensor, 24/7"],
    ["Sensores inline en todas las sedes", "Capa 5 · CYBER3 Edge: DNS-shield e IOC en el edge para toda la organización", "Capa 6 · CYBER3 EDR/XDR for Desktop en las estaciones críticas", "Consola de cliente: aislamiento de la estación, escaneos remotos, estado de la flota", "CYBER3 Global Scan de la red interna", "MLEO en todas las sedes", "VAS quincenal"],
    ["CYBER3 EDR/XDR for Desktop en todas las estaciones", "Capa 7 · CYBER3 Mobile Protection en los teléfonos del personal", "MLEO en las 7 capas: red, nube, estación, teléfono", "VAS continuo", "Monitorización de brechas e identidad de las cuentas de la organización", "Informes unificados red + endpoint + móvil (NIS2 Art. 21/23)"]]),
 "it": dict(
   p="Ogni pacchetto include tutto ciò che offre il precedente e aggiunge livelli e capacità. La configurazione esatta (sensori, sedi, postazioni, telefoni) si definisce dopo una valutazione iniziale dell'ambiente.",
   inc=["Include", "Tutto di Standard, più", "Tutto di Esteso, più"],
   tiers=[
    ["SOC gestito 24/7 · risposta autonoma in 2–11 s", "Sensore inline nella sede principale", "Livelli 1–4: Inline IPS · Active Response · L2 Shield · CYBER3 Context Fusion Engine", "MLEO: correlazione L3 ↔ L2 ed enforcement sul livello giusto", "VAS programmato mensile", "Allarmi spiegati (Telegram, email) + portale cliente con report NIS2", "Health Check autonomo del sensore, 24/7"],
    ["Sensori inline in tutte le sedi", "Livello 5 · CYBER3 Edge: DNS-shield e IOC sull'edge per tutta l'organizzazione", "Livello 6 · CYBER3 EDR/XDR for Desktop sulle postazioni critiche", "Console cliente: isolamento della postazione, scansioni remote, stato della flotta", "CYBER3 Global Scan della rete interna", "MLEO su tutte le sedi", "VAS quindicinale"],
    ["CYBER3 EDR/XDR for Desktop su tutte le postazioni", "Livello 7 · CYBER3 Mobile Protection sui telefoni del personale", "MLEO su tutti i 7 livelli: rete, cloud, postazione, telefono", "VAS continuo", "Monitoraggio di violazioni e identità per gli account dell'organizzazione", "Reportistica unificata rete + endpoint + mobile (NIS2 Art. 21/23)"]]),
 "de": dict(
   p="Jedes Paket enthält alles aus dem vorherigen und fügt Schichten und Fähigkeiten hinzu. Die genaue Konfiguration (Sensoren, Standorte, Arbeitsplätze, Telefone) wird nach einer ersten Bewertung Ihrer Umgebung festgelegt.",
   inc=["Enthält", "Alles aus Standard, plus", "Alles aus Erweitert, plus"],
   tiers=[
    ["Verwaltetes SOC rund um die Uhr · autonome Reaktion in 2–11 s", "Inline-Sensor am Hauptstandort", "Schichten 1–4: Inline IPS · Active Response · L2 Shield · CYBER3 Context Fusion Engine", "MLEO: L3 ↔ L2-Korrelation und Durchsetzung auf der richtigen Schicht", "Monatlich geplante Schwachstellenbewertung", "Verständliche Alarme (Telegram, E-Mail) + Kundenportal mit NIS2-Berichten", "Autonomer 24/7-Health-Check des Sensors"],
    ["Inline-Sensoren an allen Standorten", "Schicht 5 · CYBER3 Edge: DNS-Shield und Edge-IOC für die gesamte Organisation", "Schicht 6 · CYBER3 EDR/XDR for Desktop auf kritischen Arbeitsplätzen", "Kundenkonsole: Isolierung von Arbeitsplätzen, Remote-Scans, Flottenstatus", "CYBER3 Global Scan des internen Netzwerks", "MLEO über alle Standorte", "Zweiwöchentliche Schwachstellenbewertung"],
    ["CYBER3 EDR/XDR for Desktop auf allen Arbeitsplätzen", "Schicht 7 · CYBER3 Mobile Protection auf den Telefonen der Mitarbeitenden", "MLEO über alle 7 Schichten: Netzwerk, Cloud, Arbeitsplatz, Telefon", "Kontinuierliche Schwachstellenbewertung", "Überwachung von Datenlecks und Identitäten für die Konten der Organisation", "Einheitliches Reporting Netzwerk + Endpunkt + Mobil (NIS2 Art. 21/23)"]]),
 "fr": dict(
   p="Chaque offre inclut tout ce que propose la précédente et ajoute des couches et des capacités. La configuration exacte (capteurs, sites, postes, téléphones) est définie après une évaluation initiale de votre environnement.",
   inc=["Inclut", "Tout Standard, plus", "Tout Étendu, plus"],
   tiers=[
    ["SOC géré 24/7 · réponse autonome en 2–11 s", "Capteur en ligne sur le site principal", "Couches 1–4 : Inline IPS · Active Response · L2 Shield · CYBER3 Context Fusion Engine", "MLEO : corrélation L3 ↔ L2 et enforcement sur la bonne couche", "Évaluation des vulnérabilités mensuelle programmée", "Alertes expliquées (Telegram, e-mail) + portail client avec rapports NIS2", "Health Check autonome du capteur, 24/7"],
    ["Capteurs en ligne sur tous les sites", "Couche 5 · CYBER3 Edge : DNS-shield et IOC en périphérie pour toute l'organisation", "Couche 6 · CYBER3 EDR/XDR for Desktop sur les postes critiques", "Console client : isolation du poste, analyses à distance, état de la flotte", "CYBER3 Global Scan du réseau interne", "MLEO sur tous les sites", "Évaluation des vulnérabilités bimensuelle"],
    ["CYBER3 EDR/XDR for Desktop sur tous les postes", "Couche 7 · CYBER3 Mobile Protection sur les téléphones du personnel", "MLEO sur les 7 couches : réseau, cloud, poste, téléphone", "Évaluation des vulnérabilités continue", "Surveillance des fuites et de l'identité pour les comptes de l'organisation", "Rapports unifiés réseau + endpoint + mobile (NIS2 art. 21/23)"]]),
 "ru": dict(
   p="Каждый пакет включает всё из предыдущего и добавляет слои и возможности. Точная конфигурация (сенсоры, площадки, рабочие станции, телефоны) определяется после первичной оценки вашей среды.",
   inc=["Включает", "Всё из Standard, плюс", "Всё из Расширенного, плюс"],
   tiers=[
    ["Управляемый SOC 24/7 · автономный ответ за 2–11 с", "Инлайн-сенсор на главной площадке", "Слои 1–4: Inline IPS · Active Response · L2 Shield · CYBER3 Context Fusion Engine", "MLEO: корреляция L3 ↔ L2 и применение на нужном слое", "Плановая ежемесячная оценка уязвимостей", "Понятные тревоги (Telegram, e-mail) + клиентский портал с отчётами NIS2", "Автономный Health Check сенсора 24/7"],
    ["Инлайн-сенсоры на всех площадках", "Слой 5 · CYBER3 Edge: DNS-щит и IOC на периферии для всей организации", "Слой 6 · CYBER3 EDR/XDR for Desktop на критичных рабочих станциях", "Клиентская консоль: изоляция станции, удалённые проверки, состояние парка", "CYBER3 Global Scan внутренней сети", "MLEO на всех площадках", "Оценка уязвимостей раз в две недели"],
    ["CYBER3 EDR/XDR for Desktop на всех рабочих станциях", "Слой 7 · CYBER3 Mobile Protection на телефонах сотрудников", "MLEO на всех 7 слоях: сеть, облако, рабочая станция, телефон", "Непрерывная оценка уязвимостей", "Мониторинг утечек и идентичности для учётных записей организации", "Единая отчётность сеть + endpoint + мобильные (NIS2 ст. 21/23)"]]),
 "zh": dict(
   p="每个方案都包含上一方案的全部内容,并增加防御层与能力。具体配置(传感器、站点、工作站、手机)在对环境进行初步评估后确定。",
   inc=["包含", "Standard 的全部内容,另加", "扩展版的全部内容,另加"],
   tiers=[
    ["7×24 托管 SOC · 2–11 秒自主响应", "主站点的内联传感器", "第 1–4 层:Inline IPS · Active Response · L2 Shield · CYBER3 Context Fusion Engine", "MLEO:L3 ↔ L2 关联,并在正确的层执行", "每月定期漏洞评估", "通俗易懂的告警(Telegram、邮件)+ 含 NIS2 报告的客户门户", "传感器 7×24 自主健康检查"],
    ["所有站点部署内联传感器", "第 5 层 · CYBER3 Edge:面向整个组织的 DNS 防护盾与边缘 IOC", "第 6 层 · 关键工作站部署 CYBER3 EDR/XDR for Desktop", "客户控制台:隔离工作站、远程扫描、终端群状态", "内部网络的 CYBER3 Global Scan", "MLEO 覆盖所有站点", "每两周漏洞评估"],
    ["所有工作站部署 CYBER3 EDR/XDR for Desktop", "第 7 层 · 员工手机部署 CYBER3 Mobile Protection", "MLEO 覆盖全部 7 层:网络、云端、工作站、手机", "持续漏洞评估", "组织账户的泄露与身份监测", "网络 + 终端 + 移动统一报告(NIS2 第 21/23 条)"]]),
}


def _e(s):
    return html.escape(s, quote=False)


def packages_section(lang, T):
    """Pachetele cu capabilități crescătoare; numele Extins/Complet + badge-urile + „Recomandat pentru” vin din TR existent."""
    d = PKG.get(lang, PKG["en"])
    names = ["Standard", T["pk2_h"], T["pk3_h"]]
    badges = ["STANDARD", T["pk2_b"], T["pk3_b"]]
    dets = [T["pk1_d"], T["pk2_d"], T["pk3_d"]]
    cards = []
    for i in range(3):
        items = "".join("<li>%s</li>" % _e(x) for x in d["tiers"][i])
        feat = " feature" if i == 2 else ""
        bstyle = "" if i == 2 else ' style="background:#1E4C95"'
        cards.append(
            '    <article class="card pk7%s"><div class="badge"%s>%s</div><h3>%s</h3>\n'
            '      <p class="pk7-inc">%s</p><ul class="pk7-list">%s</ul>\n'
            '      <details class="more"><summary>%s</summary><div class="body">%s</div></details></article>' % (
                feat, bstyle, badges[i], names[i], _e(d["inc"][i]), items, T["pkg_dsum"], dets[i]))
    return ('\n<section id="packages" class="section alt">\n  <div class="head">\n    <div class="kicker">%s</div>\n'
            '    <h2>%s</h2>\n    <p>%s</p>\n  </div>\n  <div class="cards pk7-cards">\n%s\n  </div>\n'
            '  <p class="pricenote">%s</p>\n</section>\n') % (T["pkg_kicker"], T["pkg_h2"], _e(d["p"]), "\n".join(cards), T["pricenote"])
