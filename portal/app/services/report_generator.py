# -*- coding: utf-8 -*-
"""PDF report generator — client-facing reports with reportlab.

v3 (03 aug 2026): reconstructie completa a celor doua generatoare.
  generate_pdf         — RAPORT ALERTE. Nou: sectiunea VEDETA "Atacuri blocate / IP
                         blocate" pe date REALE de active-response (firewall-drop),
                         cu GRAFICE COLORATE (reportlab.graphics), separata clar de
                         "evenimente nivel 10+". Include R2 (nota context senzor),
                         R13 (port->serviciu), R14 (MITRE integral), R15 (audit=CYBER3),
                         R16 (anexa actiuni per terminal) si R17 (denumiri integrale).
  generate_c3scan_pdf  — RAPORT SCAN. Nou: Cap.2 (VAS) "Remediere pas-cu-pas" (pasi
                         numerotati per tip de vulnerabilitate) si Cap.3 (MATCH) cu
                         tabel imbogatit + concluzii oneste.

REGULA GENERIC: niciun nume real de client/organizatie/locatie/persoana in continut.
Doar termeni generici ("Beneficiar", "reteaua beneficiarului", codul senzorului).
"""
import os
import io
import re as _re_mod
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, Image
)
from reportlab.graphics.shapes import Drawing, String, Rect
from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend

log = logging.getLogger(__name__)

# FasterUp brand colors (matching portal)
PHOS = colors.HexColor('#00b86f')      # primary green (dim variant for print)
PHOS_BRIGHT = colors.HexColor('#00ff9c')
INK = colors.HexColor('#1a1a1a')
INK_DIM = colors.HexColor('#5a5a5a')
AMBER = colors.HexColor('#d48d1a')
RED = colors.HexColor('#c91f3e')
ORANGE = colors.HexColor('#e05c2a')
BLUE = colors.HexColor('#2f6db5')      # intern / lateral
SLATE = colors.HexColor('#7a8691')     # neutru / detectat-neblocat
LINE = colors.HexColor('#cccccc')
BG_ALT = colors.HexColor('#f5f7f6')

SEV_COLORS = {'low': PHOS, 'medium': AMBER, 'high': ORANGE, 'critical': RED}

# ---- i18n ----
T = {
    'en': {
        'report_title': 'Security Operations Report',
        's_exec': 'Executive Summary',
        's_kpi': 'Key Indicators',
        's_sev': 'Alert Severity Distribution',
        's_threats': 'Threat Typology',
        's_mitre': 'MITRE ATT&amp;CK Coverage',
        's_ips': 'Top Source IPs',
        's_targets': 'Targeted Services & Hosts',
        's_evo': 'Alert Evolution',
        's_incidents': 'Incident Annex (level 10+)',
        's_nis2': 'NIS2 Compliance',
        's_recs': 'Recommendations',
        'sev_low': 'Low (1-6)', 'sev_med': 'Medium (7-9)', 'sev_high': 'High (10-12)', 'sev_crit': 'Critical (13+)',
        'exec_text': ("During the reporting period ({days} days), the security monitoring platform processed "
                      "<b><font color='#00b86f'>{total:,} security events</font></b> from your network, of which "
                      "<b><font color='#d48d1a'>{heightened:,} required heightened attention</font></b> (level 7+). "
                      "The sensor <b><font color='#c91f3e'>blocked {real_blocks:,} attacks in real time</font></b> "
                      "(firewall-drop active response). Separately, {events_l10:,} events reached the response "
                      "threshold (level 10+) and {significant} qualify as candidates for NIS2 significant-incident "
                      "assessment. Sensor availability over the period: <b>{avail}</b>."),
        'mitre_tactics': 'Top tactics observed', 'mitre_tech': 'Top techniques observed',
        'tbl_technique': 'Technique', 'tbl_count': 'Alerts', 'tbl_tactic': 'Tactic',
        'tbl_port': 'Port', 'tbl_service': 'Service', 'tbl_host': 'Internal host',
        'tbl_time': 'Time (UTC)', 'tbl_lvl': 'Lvl', 'tbl_desc': 'Description', 'tbl_src': 'Source', 'tbl_dst': 'Destination',
        'nis2_intro': ('This chapter supports the obligations of NIS2 (Directive (EU) 2022/2555). It summarizes incident classification for the period and maps the '
                       'security measures provided by the FasterUp SOC service to NIS2 Art. 21(2).'),
        'nis2_class': 'Incident classification (period)',
        'nis2_deadlines': 'Reporting obligations for significant incidents (Art. 23)',
        'nis2_measures': 'Security measures mapping (Art. 21(2))',
        'nis2_l12': 'Significant-incident candidates (level 12+)',
        'nis2_l10': 'Incidents handled (level 10+)',
        'step': 'Step', 'deadline': 'Deadline', 'to': 'Addressee',
        'no_incidents': 'No incidents level 10+ in the period.',
        'no_data': 'No data in period.',
        'evo_legend': 'per-bin alert counts: critical / high / medium / low',
        'commitment': ('This report was generated automatically by the FasterUp SOC platform from live sensor data. '
                       'For questions or incident response support, contact your SOC analyst.'),
        's_cyber3': 'CYBER3 platform activity',
    },
    'ro': {
        'report_title': 'Raport Operatiuni de Securitate',
        's_exec': 'Sumar Executiv',
        's_kpi': 'Indicatori Cheie',
        's_sev': 'Distributia Alertelor pe Severitate',
        's_threats': 'Tipologia Amenintarilor',
        's_mitre': 'Acoperire MITRE ATT&amp;CK',
        's_ips': 'Top IP-uri Sursa',
        's_targets': 'Servicii si Gazde Vizate',
        's_evo': 'Evolutia Alertelor',
        's_incidents': 'Anexa Incidente (nivel 10+)',
        's_nis2': 'Conformitate NIS2',
        's_recs': 'Recomandari',
        'sev_low': 'Scazut (1-6)', 'sev_med': 'Mediu (7-9)', 'sev_high': 'Ridicat (10-12)', 'sev_crit': 'Critic (13+)',
        'exec_text': ("In perioada raportata ({days} zile), platforma de monitorizare a procesat "
                      "<b><font color='#00b86f'>{total:,} evenimente de securitate</font></b> din reteaua dvs., dintre care "
                      "<b><font color='#d48d1a'>{heightened:,} au necesitat atentie sporita</font></b> (nivel 7+). "
                      "Senzorul a <b><font color='#c91f3e'>blocat {real_blocks:,} atacuri in timp real</font></b> "
                      "(active-response firewall-drop). Separat, {events_l10:,} evenimente au atins pragul de raspuns "
                      "(nivel 10+) si {significant} se califica drept candidate pentru evaluare ca incident semnificativ "
                      "NIS2. Disponibilitatea senzorului in perioada: <b>{avail}</b>."),
        'mitre_tactics': 'Top tactici observate', 'mitre_tech': 'Top tehnici observate',
        'tbl_technique': 'Tehnica', 'tbl_count': 'Alerte', 'tbl_tactic': 'Tactica',
        'tbl_port': 'Port', 'tbl_service': 'Serviciu', 'tbl_host': 'Gazda interna',
        'tbl_time': 'Timp (UTC)', 'tbl_lvl': 'Niv', 'tbl_desc': 'Descriere', 'tbl_src': 'Sursa', 'tbl_dst': 'Destinatie',
        'nis2_intro': ('Acest capitol sustine obligatiile NIS2 (Directiva (UE) 2022/2555). Sumarizeaza clasificarea incidentelor din perioada si mapeaza masurile '
                       'de securitate furnizate de serviciul FasterUp SOC pe Art. 21(2) NIS2.'),
        'nis2_class': 'Clasificarea incidentelor (perioada)',
        'nis2_deadlines': 'Obligatii de raportare pentru incidente semnificative (Art. 23)',
        'nis2_measures': 'Maparea masurilor de securitate (Art. 21(2))',
        'nis2_l12': 'Candidate incident semnificativ (nivel 12+)',
        'nis2_l10': 'Incidente gestionate (nivel 10+)',
        'step': 'Pas', 'deadline': 'Termen', 'to': 'Destinatar',
        'no_incidents': 'Niciun incident nivel 10+ in perioada.',
        'no_data': 'Fara date in perioada.',
        'evo_legend': 'numar alerte per interval: critic / ridicat / mediu / scazut',
        'commitment': ('Acest raport a fost generat automat de platforma FasterUp SOC din datele live ale senzorului. '
                       'Pentru intrebari sau suport in raspunsul la incidente, contactati analistul SOC.'),
        's_cyber3': 'Activitate platforma CYBER3',
    },
}


def _brand(org):
    """Client-facing brand derived from the client's ORGANIZATION.
      ICI_SOC         -> ('ICISOC', 'ICISOC')                                      (inlocuieste FasterUp)
      FASTERUP_DIRECT -> ('FasterUp SOC', 'FasterUp Security Operations Center')   (RAMANE FasterUp)
      default         -> ('CYBER3', 'CYBER3')
    NOTA: 'CYBER3' si 'CYBER3 Scan' (platforma + numele scanerului) NU sunt afectate.
    Returns (brand_short, brand_long)."""
    o = str(org or '').upper()
    if o == 'ICI_SOC':
        return ('ICISOC', 'ICISOC')
    if o == 'FASTERUP_DIRECT':
        return ('FasterUp SOC', 'FasterUp Security Operations Center')
    return ('CYBER3', 'CYBER3')


def _org_from_sensor(code):
    """Fallback org inference from a sensor/client code when the payload lacks
    'organization' (ex. raportul SCAN construit de api_c3scan). Conventie:
    ICISOC* -> ICI_SOC, F0xx -> FASTERUP_DIRECT."""
    import re as _re
    c = str(code or '').upper()
    if c.startswith('ICISOC'):
        return 'ICI_SOC'
    if _re.fullmatch(r'F\d{2,3}', c):
        return 'FASTERUP_DIRECT'
    return None


# ============================================================================
# SECTIUNEA VEDETA "Atacuri blocate (extern)" — i18n + paleta COLORATA.
# Blocari REALE (active-response firewall-drop, rule.id=651), pe sursa EXTERNA
# (IP public). REGULA FINALA operator: NU exista sectiune de blocari INTERNE
# (intern = 0 pe toti senzorii, verificat exhaustiv) — nu se pune deloc.
# Aceste chei se contopesc in T[lang] (sursa unica; docx le citeste din T).
# ============================================================================
BLOCKED_T_KEYS = {
    'en': {
        's_blocked': 'Blocked Attacks (external)',
        'blk_intro': ('This is what you pay for: during the period the inline sensor actively blocked '
                      '<b><font color="#c91f3e">{ext:,} external attack events</font></b> in real time '
                      '(active-response firewall-drop) from <b>{ips:,}</b> distinct public source IPs. '
                      'Every entry below is a real firewall block, not a passive alert.'),
        'blk_intro_mirror': ('This sensor operates in <b>mirror / monitoring</b> mode and does not block '
                             'traffic itself; blocking is performed upstream. The figures below reflect '
                             'detections, provided for transparency.'),
        'blk_none': ('This inline sensor was active and blocking throughout the period, but <b>no external '
                     'attack reached it</b> — the client edge (firewall/router) blocks inbound traffic '
                     'before it arrives, and/or the sensor sits on an internal segment. A good outcome, '
                     'reported honestly (nothing is invented).'),
        'blk_kpi_ext': 'External events blocked', 'blk_kpi_ips': 'Distinct attacker IPs',
        'blk_kpi_total': 'Total firewall-drops', 'blk_kpi_country': 'Top origin',
        'blk_top_ips': 'Top external attackers blocked', 'blk_timeline': 'Blocking activity over time',
        'blk_by_threat': 'Blocked attacks by threat type', 'blk_events': 'Events',
        'blk_first': 'First seen (UTC)', 'blk_last': 'Last seen (UTC)',
        'tbl_country': 'Country',
        'blk_geo_note': ('Country attribution is best-effort: geolocation is available only for a subset '
                         'of blocked events; the rest are shown without a country.'),
        'blk_edge_note': ('"Blocked" = real active-response firewall-drop (Wazuh rule 651) on a public '
                          'source IP. Internal/self and scanner traffic is excluded.'),
    },
    'ro': {
        's_blocked': 'Atacuri Blocate (extern)',
        'blk_intro': ('Aceasta este valoarea platita: in perioada, senzorul inline a blocat activ, in timp '
                      'real, <b><font color="#c91f3e">{ext:,} evenimente de atac extern</font></b> '
                      '(active-response firewall-drop) de la <b>{ips:,}</b> adrese IP publice distincte. '
                      'Fiecare intrare de mai jos este o blocare reala de firewall, nu o simpla alerta.'),
        'blk_intro_mirror': ('Acest senzor functioneaza in mod <b>mirror / monitorizare</b> si nu blocheaza '
                             'el insusi traficul; blocarea se face in amonte. Cifrele de mai jos reflecta '
                             'detectii, oferite pentru transparenta.'),
        'blk_none': ('Acest senzor inline a fost activ si a blocat pe tot parcursul perioadei, dar <b>niciun '
                     'atac extern nu a ajuns la el</b> — edge-ul clientului (firewall/router) blocheaza '
                     'traficul de intrare inainte sa ajunga, si/sau senzorul este pozitionat pe un segment '
                     'intern. Un rezultat bun, raportat onest (nu se inventeaza nimic).'),
        'blk_kpi_ext': 'Evenimente externe blocate', 'blk_kpi_ips': 'IP-uri atacatoare distincte',
        'blk_kpi_total': 'Total firewall-drop', 'blk_kpi_country': 'Origine principala',
        'blk_top_ips': 'Top atacatori externi blocati', 'blk_timeline': 'Activitatea de blocare in timp',
        'blk_by_threat': 'Atacuri blocate, pe tip de amenintare', 'blk_events': 'Evenimente',
        'blk_first': 'Prima aparitie (UTC)', 'blk_last': 'Ultima aparitie (UTC)',
        'tbl_country': 'Tara',
        'blk_geo_note': ('Atribuirea tarii este best-effort: geolocalizarea este disponibila doar pentru un '
                         'subset din evenimentele blocate; restul sunt afisate fara tara.'),
        'blk_edge_note': ('"Blocat" = active-response firewall-drop REAL (regula Wazuh 651) pe IP sursa '
                          'public. Traficul intern/propriu si cel al scanerului este exclus.'),
    },
}
for _lang, _keys in BLOCKED_T_KEYS.items():
    T[_lang].update(_keys)

# Paleta COLORATA dedicata blocarilor (cald->rece, distincta de restul raportului)
BLK_PALETTE = [
    colors.HexColor('#c91f3e'),  # rosu (cel mai agresiv)
    colors.HexColor('#e05c2a'),  # portocaliu-inchis
    colors.HexColor('#d48d1a'),  # chihlimbar
    colors.HexColor('#e0b100'),  # galben-auriu
    colors.HexColor('#7a9e2f'),  # verde-oliv
    colors.HexColor('#2f9e8f'),  # teal
    colors.HexColor('#2f6f9e'),  # albastru
    colors.HexColor('#6a4c9c'),  # violet
]
BLK_RED = colors.HexColor('#c91f3e')
BLK_RED_DK = colors.HexColor('#8f1329')


# ============================================================================
# R16 — i18n anexa "Actiuni imediate per terminal" (sursa unica; api_reports o importa)
# ============================================================================
R16_L = {
    'ro': {
        'title': 'Anexa — Actiuni imediate per terminal',
        'intro': ('Pentru fiecare gazda interna a Beneficiarului vizata de trafic ostil in perioada, '
                  'sunt listate mai jos elementele necesare unei actiuni imediate. Coloanele marcate '
                  '„nedeterminabil" reprezinta informatii pe care senzorul de retea NU le poate stabili '
                  'singur (necesita inventar de active / scanare autentificata).'),
        'c_ip': 'IP intern', 'c_name': 'Nume gazda', 'c_type': 'Tip', 'c_exp': 'Expunere',
        'c_svc': 'Servicii vizate', 'c_al': 'Alerte', 'c_lvl': 'Nivel max',
        'undet': 'nedeterminabil',
        'exp_pub': 'expus (trafic din Internet observat)',
        'exp_priv': 'intern (doar trafic LAN observat)',
        'exp_undet': 'nedeterminabil',
        'correction': ('Corectie de interpretare: o alerta de atac catre UN server web (ex. o singura '
                       'gazda pe port 80/443) NU inseamna ca toate gazdele din retea sunt vulnerabile. '
                       'Fiecare terminal se evalueaza individual; expunerea si vulnerabilitatea reala '
                       'se confirma prin scanare (CYBER3 Scan), nu se deduc din volumul de alerte.'),
        'undet_note': ('Nota: „Nume gazda" si „Tip" apar ca „nedeterminabil" cand senzorul de retea nu '
                       'are aceasta informatie. Ele se completeaza automat cand este atasat raportul de '
                       'descoperire CYBER3 Scan (discovery.json) pentru acelasi senzor.'),
        'none': 'Nicio gazda interna vizata in perioada.',
    },
    'en': {
        'title': 'Annex — Immediate actions per endpoint',
        'intro': ('For each internal Beneficiary host targeted by hostile traffic in the period, the '
                  'elements needed for immediate action are listed below. Columns marked "undetermined" '
                  'are values the network sensor CANNOT establish on its own (they require an asset '
                  'inventory / authenticated scan).'),
        'c_ip': 'Internal IP', 'c_name': 'Host name', 'c_type': 'Type', 'c_exp': 'Exposure',
        'c_svc': 'Targeted services', 'c_al': 'Alerts', 'c_lvl': 'Max level',
        'undet': 'undetermined',
        'exp_pub': 'exposed (Internet traffic observed)',
        'exp_priv': 'internal (LAN traffic only)',
        'exp_undet': 'undetermined',
        'correction': ('Interpretation note: an attack alert against ONE web server (e.g. a single host '
                       'on port 80/443) does NOT mean every host on the network is vulnerable. Each '
                       'endpoint is assessed individually; real exposure and vulnerability are confirmed '
                       'by scanning (CYBER3 Scan), not inferred from alert volume.'),
        'undet_note': ('Note: "Host name" and "Type" show "undetermined" when the network sensor lacks '
                       'that information. They are auto-filled when the CYBER3 Scan discovery report '
                       '(discovery.json) for the same sensor is attached.'),
        'none': 'No internal host targeted in the period.',
    },
}


# ============================================================================
# R17 — denumiri INTEGRALE (fara prescurtari) in coloane / etichete
# ============================================================================
LABELS_INTEGRAL = {
    'ro': {
        'lvl_full': 'Nivel',
        'evo_crit': 'Critic', 'evo_high': 'Ridicat', 'evo_med': 'Mediu', 'evo_low': 'Scazut',
        'mitre_col': 'Tehnica ATT&amp;CK (ID)',
        'soc_activity': 'Activitate Centru de Operatiuni de Securitate (SOC)',
        'act': {
            'AR': 'Raspuns automat (Active Response) — blocare firewall',
            'IOC': 'Indicator de compromitere (Indicator of Compromise)',
            'MISP': 'Platforma de partajare a informatiilor despre amenintari (MISP)',
            'VAS': 'Evaluare de vulnerabilitati (Vulnerability Assessment)',
            'C2': 'Comanda si control (Command and Control)',
            'RMM': 'Unealta de administrare/acces la distanta (Remote Monitoring & Management)',
            'DLS': 'Securitate la nivel de document (Document Level Security)',
        },
    },
    'en': {
        'lvl_full': 'Level',
        'evo_crit': 'Critical', 'evo_high': 'High', 'evo_med': 'Medium', 'evo_low': 'Low',
        'mitre_col': 'ATT&amp;CK Technique (ID)',
        'soc_activity': 'Security Operations Center (SOC) Activity',
        'act': {
            'AR': 'Automated response (Active Response) — firewall block',
            'IOC': 'Indicator of Compromise',
            'MISP': 'Malware Information Sharing Platform (MISP)',
            'VAS': 'Vulnerability Assessment',
            'C2': 'Command and Control',
            'RMM': 'Remote Monitoring & Management tool',
            'DLS': 'Document Level Security',
        },
    },
}


def expand_activity(text, lang='ro'):
    """R17 — inlocuieste acronimele izolate cu denumirea integrala (prima aparitie)."""
    acts = LABELS_INTEGRAL.get(lang, LABELS_INTEGRAL['ro'])['act']
    out = str(text or '')
    for ac, full in acts.items():
        out = _re_mod.sub(r'\b' + _re_mod.escape(ac) + r'\b', full, out, count=1)
    return out


from reportlab.pdfgen import canvas as _rlcanvas

_BRAND_RED = colors.HexColor('#E4002B')
_BRAND_BLACK = colors.HexColor('#000000')
_BRAND_GRAY = colors.HexColor('#707070')
_BRAND_RULE = colors.HexColor('#c8c8c8')
_SERVICES_LINE = ("AI Autonomous Cybersecurity Platform \u00b7 Managed SOC & Vulnerability Assessment "
                  "\u00b7 Security LLM \u00b7 Autonomous Monitoring & Response")
_CERT_LINE = ("ISO/IEC 27001:2022 \u00b7 GDPR \u00b7 NIS2 \u00b7 AI Act      \u00b7      "
              "ROL PORTAL SERVICES SRL \u00b7 contact@rol.ro")


def _header_footer(canvas, doc):
    """Antet FasterUp.AI / CYBER3.AI pe FIECARE pagina (formatul livrat la ICISOC)."""
    canvas.saveState()
    W = A4[0]; top = A4[1]
    y = top - 12*mm
    def wB(txt, sz): return canvas.stringWidth(txt, "Helvetica-Bold", sz)
    def wR(txt, sz): return canvas.stringWidth(txt, "Helvetica", sz)
    p1a, p1b, sep, p2a, p2b = "FasterUp", ".AI", "      \u00b7      ", "CYBER3", ".AI"
    tw = wB(p1a,13)+wB(p1b,13)+wR(sep,13)+wB(p2a,13)+wB(p2b,13)
    x = (W - tw)/2.0
    canvas.setFont("Helvetica-Bold",13); canvas.setFillColor(_BRAND_RED); canvas.drawString(x,y,p1a); x+=wB(p1a,13)
    canvas.setFillColor(_BRAND_BLACK); canvas.drawString(x,y,p1b); x+=wB(p1b,13)
    canvas.setFont("Helvetica",13); canvas.setFillColor(_BRAND_GRAY); canvas.drawString(x,y,sep); x+=wR(sep,13)
    canvas.setFont("Helvetica-Bold",13); canvas.setFillColor(_BRAND_RED); canvas.drawString(x,y,p2a); x+=wB(p2a,13)
    canvas.setFillColor(_BRAND_BLACK); canvas.drawString(x,y,p2b)
    canvas.setFont("Helvetica-Oblique",7); canvas.setFillColor(_BRAND_GRAY)
    canvas.drawCentredString(W/2.0, y-5*mm, _SERVICES_LINE)
    canvas.setFont("Helvetica",8); canvas.setFillColor(_BRAND_GRAY)
    canvas.drawCentredString(W/2.0, y-9*mm, _CERT_LINE)
    canvas.setStrokeColor(_BRAND_RULE); canvas.setLineWidth(0.6)
    canvas.line(20*mm, y-11.5*mm, W-20*mm, y-11.5*mm)
    canvas.restoreState()


class NumberedCanvas(_rlcanvas.Canvas):
    """Subsol 'Pagina X din Y' (2 treceri: numara paginile, apoi le deseneaza)."""
    def __init__(self, *args, **kw):
        _rlcanvas.Canvas.__init__(self, *args, **kw)
        self._saved_page_states = []
    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()
    def save(self):
        n = len(self._saved_page_states)
        for st in self._saved_page_states:
            self.__dict__.update(st)
            self.setFont("Helvetica", 8); self.setFillColor(_BRAND_GRAY)
            self.drawCentredString(A4[0]/2.0, 10*mm, "Pagina %d din %d" % (self._pageNumber, n))
            _rlcanvas.Canvas.showPage(self)
        _rlcanvas.Canvas.save(self)


def _styles(lang='en'):
    base = getSampleStyleSheet()
    styles = {}
    styles['h1'] = ParagraphStyle('h1', parent=base['Heading1'],
        fontSize=22, textColor=INK, spaceAfter=12, spaceBefore=0,
        fontName='Helvetica-Bold', leading=26)
    styles['h2'] = ParagraphStyle('h2', parent=base['Heading2'],
        fontSize=14, textColor=PHOS, spaceAfter=8, spaceBefore=14,
        fontName='Helvetica-Bold', leading=18, borderPadding=(0, 0, 4, 0),
        borderColor=LINE, borderWidth=0)
    styles['h3'] = ParagraphStyle('h3', parent=base['Heading3'],
        fontSize=11, textColor=INK, spaceAfter=4, spaceBefore=8,
        fontName='Helvetica-Bold', leading=14)
    styles['body'] = ParagraphStyle('body', parent=base['BodyText'],
        fontSize=10.5, textColor=INK, spaceAfter=6, leading=15,
        alignment=TA_JUSTIFY, fontName='Helvetica')
    styles['small'] = ParagraphStyle('small', fontSize=8.5, textColor=INK,
        fontName='Helvetica', leading=11)
    styles['small_dim'] = ParagraphStyle('small_dim', fontSize=8.5, textColor=INK_DIM,
        fontName='Helvetica', leading=11)
    styles['kpi_label'] = ParagraphStyle('kpi_label', fontSize=8, textColor=INK_DIM,
        fontName='Helvetica', alignment=TA_CENTER, leading=10)
    styles['kpi_value'] = ParagraphStyle('kpi_value', fontSize=22, textColor=PHOS,
        fontName='Helvetica-Bold', alignment=TA_CENTER, leading=26, spaceAfter=2)
    styles['meta'] = ParagraphStyle('meta', fontSize=9, textColor=INK_DIM,
        fontName='Helvetica-Oblique', alignment=TA_LEFT)
    styles['accent'] = ParagraphStyle('accent', fontSize=11, textColor=PHOS,
        fontName='Helvetica-Bold', alignment=TA_LEFT, leading=14)
    return styles


def _kpi_table(kpis: List[Dict], styles):
    """4-up KPI row."""
    cells = []
    for k in kpis:
        vcolor = k.get('color')
        if vcolor:
            try:
                vstyle = ParagraphStyle('kpi_v_c', parent=styles['kpi_value'],
                                        textColor=colors.HexColor(vcolor) if isinstance(vcolor, str) else vcolor)
            except Exception:
                vstyle = styles['kpi_value']
        else:
            vstyle = styles['kpi_value']
        cells.append([
            Paragraph(str(k['value']), vstyle),
            Paragraph(k['label'], styles['kpi_label'])
        ])
    row = []
    for c in cells:
        inner = Table([[p] for p in c], colWidths=[3.8*cm], rowHeights=[1.1*cm, 0.7*cm])
        inner.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), BG_ALT),
            ('LINEABOVE', (0,0), (-1,0), 1.5, PHOS),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        row.append(inner)

    tbl = Table([row], colWidths=[4.2*cm]*len(row))
    tbl.setStyle(TableStyle([
        ('LEFTPADDING', (0,0), (-1,-1), 2),
        ('RIGHTPADDING', (0,0), (-1,-1), 2),
    ]))
    return tbl


def _bar_row(name, count, max_count, styles, color=PHOS, name_w=6.5):
    """Horizontal bar row (threat typology / MITRE)."""
    pct = (count / max_count) if max_count else 0
    bar_w = (13.5 - name_w - 2) * cm * pct
    bar_cell = Table([[' ']], colWidths=[max(bar_w, 0.1*cm)], rowHeights=[0.25*cm])
    bar_cell.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), color),
        ('LEFTPADDING', (0,0), (-1,-1), 0), ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ('TOPPADDING', (0,0), (-1,-1), 0), ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    row = Table(
        [[Paragraph(name, styles['small']), bar_cell, Paragraph(str(count), styles['accent'])]],
        colWidths=[name_w*cm, (13.5 - name_w)*cm, 2*cm]
    )
    row.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('LINEBELOW', (0,0), (-1,-1), 0.3, LINE),
        ('ALIGN', (2,0), (2,0), 'RIGHT'),
    ]))
    return row


def _grid_table(headers, rows, col_widths, styles, num_cols=()):
    data = [headers]
    for r in rows:
        data.append([Paragraph(str(c), styles['small']) if not isinstance(c, Paragraph) else c for c in r])
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ('BACKGROUND', (0,0), (-1,0), INK),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 8.5),
        ('FONTSIZE', (0,1), (-1,-1), 8.5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LINEBELOW', (0,0), (-1,-1), 0.3, LINE),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, BG_ALT]),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]
    for c in num_cols:
        style.append(('ALIGN', (c,0), (c,-1), 'RIGHT'))
    tbl.setStyle(TableStyle(style))
    return tbl


def _severity_table(severity: Dict, t, styles):
    labels = [t['sev_low'], t['sev_med'], t['sev_high'], t['sev_crit']]
    keys = ['low', 'medium', 'high', 'critical']
    vals = [severity.get(k, 0) for k in keys]
    cells = []
    for lbl, val, key in zip(labels, vals, keys):
        v_style = ParagraphStyle(f'sev_{key}', fontSize=18, textColor=SEV_COLORS[key],
                                 fontName='Helvetica-Bold', alignment=TA_CENTER, leading=22)
        inner = Table([[Paragraph(f'{val:,}', v_style)], [Paragraph(lbl, styles['kpi_label'])]],
                      colWidths=[3.8*cm], rowHeights=[0.9*cm, 0.6*cm])
        inner.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), BG_ALT),
            ('LINEABOVE', (0,0), (-1,0), 1.5, SEV_COLORS[key]),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        cells.append(inner)
    tbl = Table([cells], colWidths=[4.2*cm]*4)
    tbl.setStyle(TableStyle([
        ('LEFTPADDING', (0,0), (-1,-1), 2), ('RIGHTPADDING', (0,0), (-1,-1), 2),
    ]))
    return tbl


def _evolution_table(evolution: Dict, t, styles, lang='en'):
    """Compact evolution table — one row per bin with colored counts (R17 integral labels)."""
    bins = evolution.get('bins', [])
    if not bins:
        return Paragraph(t['no_data'], styles['small_dim'])
    li = LABELS_INTEGRAL.get(lang, LABELS_INTEGRAL['en'])
    headers = ['', li['evo_crit'], li['evo_high'], li['evo_med'], li['evo_low']]
    rows = []
    for b in bins:
        rows.append([
            b.get('label', ''),
            Paragraph(f"<font color='#c91f3e'>{b.get('critical', 0)}</font>", styles['small']),
            Paragraph(f"<font color='#e05c2a'>{b.get('high', 0)}</font>", styles['small']),
            Paragraph(f"<font color='#d48d1a'>{b.get('medium', 0)}</font>", styles['small']),
            Paragraph(f"<font color='#00b86f'>{b.get('low', 0)}</font>", styles['small']),
        ])
    return _grid_table(headers, rows, [3*cm, 2.2*cm, 2.2*cm, 2.2*cm, 2.2*cm], styles, num_cols=(1,2,3,4))


# ===========================================================================
# SECTIUNEA VEDETA — "Atacuri blocate (extern)": GRAFICE COLORATE.
# Consuma payload['blocked'] produs de api_reports._blocked_external:
#   {mode('inline'|'mirror'), total_651, external_events, external_ips,
#    top_country, top_ips[{ip,count,country,first,last}], threats[{name,count}],
#    timeline{interval,bins[{label,count}]}, countries[], geo_partial, zero_floor}
# REGULA FINALA operator: NU exista sectiune de blocari INTERNE (intern=0). Nu se pune.
# ===========================================================================
def _hbar_blocked(items, styles, max_rows=10, name_w=5.6):
    """Bare orizontale COLORATE — top IP-uri externe blocate (gradient rosu pe intensitate)."""
    if not items:
        return Paragraph('-', styles['small_dim'])
    rows = []
    mx = max((it.get('count', 0) for it in items), default=1) or 1
    for it in items[:max_rows]:
        cnt = it.get('count', 0)
        pct = cnt / mx if mx else 0
        col = BLK_RED if pct >= 0.66 else (colors.HexColor('#e05c2a') if pct >= 0.33 else AMBER)
        bar_w = max((13.5 - name_w - 2) * cm * pct, 0.08 * cm)
        bar = Table([[' ']], colWidths=[bar_w], rowHeights=[0.26 * cm])
        bar.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), col),
            ('LEFTPADDING', (0, 0), (-1, -1), 0), ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        geo = it.get('country') or '-'
        label = f'<font name="Courier">{it.get("ip", "-")}</font>'
        if geo and geo != '-':
            label += f'  <font color="#5a5a5a" size="7.5">{geo}</font>'
        row = Table([[Paragraph(label, styles['small']), bar,
                      Paragraph(f'<b>{cnt:,}</b>', styles['accent'])]],
                    colWidths=[name_w * cm, (13.5 - name_w) * cm, 2 * cm])
        row.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3), ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('LINEBELOW', (0, 0), (-1, -1), 0.3, LINE), ('ALIGN', (2, 0), (2, 0), 'RIGHT'),
        ]))
        rows.append(row)
    wrap = Table([[r] for r in rows], colWidths=[13.9 * cm])
    wrap.setStyle(TableStyle([('LEFTPADDING', (0, 0), (-1, -1), 0), ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                              ('TOPPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 0)]))
    return wrap


def _timeline_blocked(timeline, styles):
    """Bare VERTICALE colorate — evolutia blocarilor in timp (reportlab.graphics, vector)."""
    bins = (timeline or {}).get('bins', [])
    if not bins:
        return Paragraph('-', styles['small_dim'])
    if len(bins) > 31:  # esantionare pt lizibilitate
        step = len(bins) // 31 + 1
        bins = bins[::step]
    data = [[b.get('count', 0) for b in bins]]
    labels = [b.get('label', '') for b in bins]
    d = Drawing(460, 150)
    bc = VerticalBarChart()
    bc.x, bc.y, bc.width, bc.height = 30, 24, 415, 108
    bc.data = data
    bc.bars[0].fillColor = BLK_RED
    bc.bars[0].strokeColor = BLK_RED_DK
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max(max(data[0]), 1) * 1.15
    bc.valueAxis.labels.fontSize = 6
    bc.categoryAxis.categoryNames = labels
    bc.categoryAxis.labels.fontSize = 5.5
    bc.categoryAxis.labels.angle = 90
    bc.categoryAxis.labels.dy = -6
    bc.categoryAxis.labels.boxAnchor = 'e'
    bc.barWidth = 5
    bc.groupSpacing = 2
    d.add(bc)
    return d


def _donut_blocked(threats, hole=0.55):
    """Donut/pie COLORAT — defalcare blocari pe tip amenintare (reportlab.graphics, vector)."""
    items = [x for x in (threats or []) if x.get('count', 0) > 0][:8]
    if not items:
        return None
    d = Drawing(460, 170)
    pie = Pie()
    pie.x, pie.y = 20, 12
    pie.width = pie.height = 145
    pie.data = [x['count'] for x in items]
    pie.innerRadiusFraction = hole
    pie.sideLabels = 0
    pie.slices.strokeColor = colors.white
    pie.slices.strokeWidth = 1.2
    for i in range(len(items)):
        pie.slices[i].fillColor = BLK_PALETTE[i % len(BLK_PALETTE)]
    d.add(pie)
    total = sum(x['count'] for x in items) or 1
    leg = Legend()
    leg.x, leg.y = 185, 150
    leg.deltay = 15
    leg.fontSize = 7.5
    leg.alignment = 'right'
    leg.dxTextSpace = 6
    leg.columnMaximum = 8
    leg.colorNamePairs = [
        (BLK_PALETTE[i % len(BLK_PALETTE)], (x['name'][:34] + '  ' + f"{100.0*x['count']/total:.0f}%"))
        for i, x in enumerate(items)
    ]
    d.add(leg)
    return d


def _blocked_kpis(blk, t, styles):
    return _kpi_table([
        {'value': f"{blk.get('external_events', 0):,}", 'label': t['blk_kpi_ext'], 'color': RED},
        {'value': f"{blk.get('external_ips', 0):,}", 'label': t['blk_kpi_ips']},
        {'value': f"{blk.get('total_651', 0):,}", 'label': t['blk_kpi_total']},
        {'value': (blk.get('top_country') or '-'), 'label': t['blk_kpi_country']},
    ], styles)


def render_blocked_section(story, blocked, t, styles, h2, grid_table=None):
    """SECTIUNEA VEDETA 'Atacuri blocate (extern)' — REAL active-response, colorata.
    Onest: mirror (nu blocheaza) / inline-cu-0-externe (edge client absoarbe) primesc
    doar nota de context, fara cifre inventate."""
    grid_table = grid_table or _grid_table
    blk = blocked or {}
    story.append(h2(t['s_blocked']))
    mode = blk.get('mode', 'inline')  # 'inline' | 'mirror'
    ext = blk.get('external_events', 0)

    # ONESTITATE: senzor inline dar 0 (sub prag) atacuri externe -> DOAR nota de context.
    if mode != 'mirror' and ext <= blk.get('zero_floor', 2):
        note = Table([[Paragraph(t['blk_none'], styles['small'])]], colWidths=[16.9 * cm])
        note.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BG_ALT), ('LINEABOVE', (0, 0), (-1, 0), 1.5, PHOS),
            ('LEFTPADDING', (0, 0), (-1, -1), 8), ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6), ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(note)
        return

    # intro onest, adaptat pe mod
    if mode == 'mirror':
        story.append(Paragraph(t['blk_intro_mirror'], styles['body']))
    else:
        story.append(Paragraph(t['blk_intro'].format(
            ext=ext, ips=blk.get('external_ips', 0)), styles['body']))
    story.append(Spacer(1, 3 * mm))

    story.append(_blocked_kpis(blk, t, styles))
    story.append(Spacer(1, 4 * mm))

    # GRAFIC 1 — top IP-uri externe blocate (bare orizontale colorate)
    if blk.get('top_ips'):
        story.append(Paragraph(t['blk_top_ips'], styles['h3']))
        story.append(_hbar_blocked(blk['top_ips'], styles))
        story.append(Spacer(1, 4 * mm))

    # GRAFIC 2 — evolutia blocarilor (bare verticale colorate)
    if (blk.get('timeline') or {}).get('bins'):
        story.append(Paragraph(t['blk_timeline'], styles['h3']))
        story.append(_timeline_blocked(blk['timeline'], styles))
        story.append(Spacer(1, 3 * mm))

    # GRAFIC 3 — donut pe tip amenintare
    donut = _donut_blocked(blk.get('threats'))
    if donut is not None:
        story.append(Paragraph(t['blk_by_threat'], styles['h3']))
        story.append(donut)
        story.append(Spacer(1, 2 * mm))

    # tabel top-IP (IP / tara / prima / ultima / evenimente) — completeaza graficul
    if blk.get('top_ips'):
        rows = [[Paragraph(f'<font name="Courier">{i["ip"]}</font>', styles['small']),
                 i.get('country', '-'), i.get('first', '-'), i.get('last', '-'),
                 f"{i.get('count', 0):,}"] for i in blk['top_ips'][:12]]
        story.append(grid_table(
            [t['tbl_src'], t.get('tbl_country', 'Country'), t['blk_first'], t['blk_last'], t['blk_events']],
            rows, [3.6 * cm, 3.0 * cm, 3.1 * cm, 3.1 * cm, 2.0 * cm], styles, num_cols=(4,)))

    # note de onestitate
    if blk.get('geo_partial'):
        story.append(Spacer(1, 1 * mm))
        story.append(Paragraph(t['blk_geo_note'], styles['small_dim']))
    story.append(Spacer(1, 1 * mm))
    story.append(Paragraph(t['blk_edge_note'], styles['small_dim']))


# ===========================================================================
# R16 — anexa "Actiuni imediate per terminal" (render)
# ===========================================================================
def r16_section(story, rows, styles, grid_table=None, lang='ro'):
    """R16 — adauga sectiunea in `story`. host_names/host_types vin din discovery.json
    (intern), altfel „nedeterminabil". Niciun nume real tiparit."""
    grid_table = grid_table or _grid_table
    tt = R16_L.get(lang, R16_L['ro'])
    import xml.sax.saxutils as _xml
    story.append(Paragraph(tt['title'], styles['h2']))
    story.append(Paragraph(tt['intro'], styles['body']))
    story.append(Spacer(1, 2 * mm))

    if rows:
        data_rows = []
        for r in rows[:30]:
            data_rows.append([
                Paragraph('<font name="Courier" size="8">%s</font>' % _xml.escape(str(r['ip'])), styles['small']),
                _xml.escape(str(r['name'])[:22]),
                _xml.escape(str(r['type'])[:16]),
                _xml.escape(str(r['exposure'])[:30]),
                _xml.escape(str(r['services'])[:34]),
                str(r['alerts']),
                str(r['max_level']),
            ])
        tbl = grid_table(
            [tt['c_ip'], tt['c_name'], tt['c_type'], tt['c_exp'], tt['c_svc'], tt['c_al'], tt['c_lvl']],
            data_rows,
            [2.6 * cm, 2.6 * cm, 2.0 * cm, 3.4 * cm, 3.6 * cm, 1.4 * cm, 1.4 * cm],
            styles, num_cols=(5, 6))
        story.append(tbl)
        if len(rows) > 30:
            story.append(Paragraph('… +%d' % (len(rows) - 30), styles['small_dim']))
    else:
        story.append(Paragraph(tt['none'], styles['small_dim']))

    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("<b><font color='#c91f3e'>&#9888; </font></b>" + tt['correction'], styles['small']))
    story.append(Spacer(1, 1 * mm))
    story.append(Paragraph(tt['undet_note'], styles['small_dim']))
    story.append(Spacer(1, 4 * mm))
    return story


def generate_pdf(client_data: Dict[str, Any], lang: str = 'en') -> bytes:
    """Generate a PDF report as bytes from the payload built in api_reports."""
    t = T.get(lang, T['en'])
    brand_short, brand_long = _brand(client_data.get('organization'))
    plat = 'platforma CYBER3' if lang == 'ro' else 'CYBER3 platform'
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=40*mm, bottomMargin=20*mm,
        title=f"Security Report — {client_data.get('client_name', 'Client')}",
        author=client_data.get("client_name", "Client")
    )
    styles = _styles(lang)
    story = []
    sec = 0

    def h2(title):
        nonlocal sec
        sec += 1
        return Paragraph(f"{sec} · {title}", styles['h2'])

    story.append(Spacer(1, 2*mm))

    # --- TITLE BLOCK ---
    story.append(Paragraph(client_data['client_name'], styles['h1']))
    story.append(Paragraph(
        f"{client_data['period']['label']} · {t['report_title']}",
        styles['meta']
    ))
    story.append(Spacer(1, 8*mm))

    # --- Executive Summary (onestitate: blocari reale != nivel 10+) ---
    story.append(h2(t['s_exec']))
    s = client_data['summary']
    avail = (client_data.get('availability') or {}).get('display', '-')
    real_blocks = s.get('real_blocks', s.get('attacks_blocked', 0))
    events_l10 = s.get('events_l10', s.get('attacks_blocked', 0))
    summary_text = t['exec_text'].format(
        days=(client_data.get('period') or {}).get('days', '-'),
        total=s.get('events_processed', 0),
        heightened=s.get('heightened_attention', 0),
        real_blocks=real_blocks,
        events_l10=events_l10,
        significant=s.get('significant_candidates', 0),
        avail=avail,
    )
    story.append(Paragraph(summary_text, styles['body']))
    story.append(Spacer(1, 4*mm))

    # --- R2: nota de context pentru senzor atipic ---
    if client_data.get('sensor_note'):
        story.append(Paragraph("<b>&#9432; </b>" + client_data['sensor_note'], styles['small']))
        story.append(Spacer(1, 3*mm))

    # --- KPIs ---
    story.append(h2(t['s_kpi']))
    story.append(_kpi_table(client_data['kpis'], styles))
    story.append(Spacer(1, 4*mm))

    # --- Severity distribution ---
    if client_data.get('severity'):
        story.append(h2(t['s_sev']))
        story.append(_severity_table(client_data['severity'], t, styles))
        story.append(Spacer(1, 4*mm))

    # --- SECTIUNEA VEDETA: Atacuri blocate (extern) — date REALE, colorata ---
    if client_data.get('blocked'):
        render_blocked_section(story, client_data['blocked'], t, styles, h2, _grid_table)
        story.append(Spacer(1, 4*mm))

    # --- Threat Typology ---
    story.append(h2(t['s_threats']))
    max_count = max((x['count'] for x in client_data['threats']), default=1)
    for x in client_data['threats']:
        story.append(_bar_row(x['name'], x['count'], max_count, styles))
    story.append(Spacer(1, 4*mm))

    # --- MITRE ATT&CK ---
    mitre = client_data.get('mitre') or {}
    if mitre.get('tactics') or mitre.get('techniques'):
        story.append(h2(t['s_mitre']))
        if mitre.get('tactics'):
            story.append(Paragraph(t['mitre_tactics'], styles['h3']))
            mx = max((x['count'] for x in mitre['tactics']), default=1)
            for x in mitre['tactics'][:6]:
                story.append(_bar_row(x['name'], x['count'], mx, styles, color=AMBER))
            story.append(Spacer(1, 2*mm))
        if mitre.get('techniques'):
            story.append(Paragraph(t['mitre_tech'], styles['h3']))
            rows = [[f"{x.get('id','')}", x['name'][:55], f"{x['count']:,}"] for x in mitre['techniques'][:10]]
            story.append(_grid_table(['ID', t['tbl_technique'], t['tbl_count']],
                                     rows, [2.4*cm, 10*cm, 2.4*cm], styles, num_cols=(2,)))
        story.append(Spacer(1, 4*mm))

    # --- Top Source IPs ---
    story.append(h2(t['s_ips']))
    ip_rows = []
    for i in client_data['top_ips']:
        ip_rows.append([
            Paragraph(f'<font name="Courier">{i["ip"]}</font>', styles['small']),
            i.get('country', '-'),
            i.get('context', '-'),
            f"{i.get('attempts', 0):,}",
            str(i.get('max_level', '-')),
        ])
    story.append(_grid_table(['IP', t.get('tbl_country', 'Country') if lang == 'en' else 'Tara',
                              'Context', t['tbl_count'], t['tbl_lvl']],
                             ip_rows, [4*cm, 2.4*cm, 4.6*cm, 2.4*cm, 1.4*cm], styles, num_cols=(3,4)))
    story.append(Spacer(1, 4*mm))

    # --- Targeted services & hosts ---
    targets = client_data.get('targets') or {}
    if targets.get('ports') or targets.get('hosts'):
        story.append(h2(t['s_targets']))
        if targets.get('ports'):
            rows = [[p.get('port', ''), p.get('service', '-'), f"{p.get('count', 0):,}"]
                    for p in targets['ports'][:8]]
            story.append(_grid_table([t['tbl_port'], t['tbl_service'], t['tbl_count']],
                                     rows, [3*cm, 6*cm, 3*cm], styles, num_cols=(2,)))
            story.append(Spacer(1, 2*mm))
        if targets.get('hosts'):
            rows = [[Paragraph(f'<font name="Courier">{h_.get("ip","")}</font>', styles['small']),
                     f"{h_.get('count', 0):,}"] for h_ in targets['hosts'][:6]]
            story.append(_grid_table([t['tbl_host'], t['tbl_count']], rows,
                                     [6*cm, 3*cm], styles, num_cols=(1,)))
        story.append(Spacer(1, 4*mm))

    # --- Evolution ---
    story.append(h2(t['s_evo']))
    story.append(Paragraph(t['evo_legend'], styles['small_dim']))
    story.append(Spacer(1, 1*mm))
    story.append(_evolution_table(client_data.get('evolution') or {}, t, styles, lang))
    story.append(Spacer(1, 4*mm))

    # --- Incident annex (R17: denumiri integrale la Nivel / Tehnica ATT&CK) ---
    li = LABELS_INTEGRAL.get(lang, LABELS_INTEGRAL['en'])
    story.append(PageBreak())
    story.append(h2(t['s_incidents']))
    incidents = client_data.get('incidents') or []
    if incidents:
        rows = []
        for i in incidents:
            rows.append([
                i.get('timestamp', ''), str(i.get('level', '')),
                i.get('description', ''),
                Paragraph(f'<font name="Courier" size="7.5">{i.get("src_ip","-")}</font>', styles['small']),
                Paragraph(f'<font name="Courier" size="7.5">{i.get("dest_ip","-")}</font>', styles['small']),
                i.get('mitre', ''),
            ])
        story.append(_grid_table(
            [t['tbl_time'], li['lvl_full'], t['tbl_desc'], t['tbl_src'], t['tbl_dst'], li['mitre_col']],
            rows, [3.1*cm, 0.9*cm, 6.2*cm, 2.6*cm, 2.6*cm, 1.6*cm], styles, num_cols=(1,)))
    else:
        story.append(Paragraph(t['no_incidents'], styles['body']))
    story.append(Spacer(1, 4*mm))

    # --- R16: anexa actiuni imediate per terminal ---
    r16_section(story, client_data.get('r16_rows', []), styles, _grid_table, lang)

    # --- NIS2 chapter ---
    nis2 = client_data.get('nis2') or {}
    story.append(h2(t['s_nis2']))
    story.append(Paragraph(t['nis2_intro'].replace('FasterUp SOC', brand_short), styles['body']))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(t['nis2_class'], styles['h3']))
    rows = [
        [t['nis2_l12'], str(nis2.get('significant_candidates', 0))],
        [t['nis2_l10'], str(nis2.get('high_incidents', 0))],
    ]
    story.append(_grid_table(['', t['tbl_count']], rows, [11*cm, 3*cm], styles, num_cols=(1,)))
    story.append(Spacer(1, 1*mm))
    story.append(Paragraph(nis2.get('note_classification', ''), styles['small_dim']))
    story.append(Spacer(1, 2*mm))
    if nis2.get('reporting_deadlines'):
        story.append(Paragraph(t['nis2_deadlines'], styles['h3']))
        rows = [[d.get('step', ''), d.get('deadline', ''), d.get('to', '')]
                for d in nis2['reporting_deadlines']]
        story.append(_grid_table([t['step'], t['deadline'], t['to']],
                                 rows, [5*cm, 4.5*cm, 5*cm], styles))
        story.append(Spacer(1, 2*mm))
    if nis2.get('measures'):
        story.append(Paragraph(t['nis2_measures'], styles['h3']))
        rows = [[m.get('art', ''), m.get('measure', ''), m.get('status', '')]
                for m in nis2['measures']]
        story.append(_grid_table(['Art.', 'Measure' if lang == 'en' else 'Masura',
                                  'Status / ' + brand_short],
                                 rows, [2.2*cm, 5*cm, 8*cm], styles))
    story.append(Spacer(1, 4*mm))

    # --- Recommendations ---
    story.append(h2(t['s_recs']))
    for i, rec in enumerate(client_data['recommendations'], 1):
        story.append(Paragraph(f"<b><font color='#d48d1a'>REC {i:02d}:</font></b> {rec}", styles['body']))
        story.append(Spacer(1, 2*mm))

    # --- R15: activitate platforma CYBER3 (nu recomandare catre client) ---
    if client_data.get('cyber3_activity'):
        story.append(Spacer(1, 2*mm))
        story.append(h2(t['s_cyber3']))
        story.append(Paragraph(client_data['cyber3_activity'], styles['body']))

    story.append(Spacer(1, 6*mm))
    story.append(Paragraph(t['commitment'].replace('FasterUp SOC', brand_short), styles['small_dim']))

    # Build
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer, canvasmaker=NumberedCanvas)
    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes


# ===========================================================================
# RAPORT SCAN — remediere pas-cu-pas (Cap.2) + MATCH imbogatit (Cap.3)
# ===========================================================================
def _remediation_api():
    """Import lazy al bibliotecii de remediere (productie: app.services; test: local)."""
    try:
        from app.services.remediation_lib import get_remediation, remediation_key
        return get_remediation, remediation_key
    except Exception:
        from remediation_lib import get_remediation, remediation_key
        return get_remediation, remediation_key


def _sev_band_scan(sev):
    try:
        sev = int(sev)
    except Exception:
        return 'low'
    return 'critical' if sev >= 8 else 'high' if 6 <= sev < 8 else 'medium' if 4 <= sev < 6 else 'low'


def build_remediation_groups(findings, lang='ro'):
    """Grupeaza findings pe cheia de remediere; ordoneaza KEV/critic intai."""
    get_remediation, remediation_key = _remediation_api()
    groups = {}
    for f in findings or []:
        key = remediation_key(f)
        g = groups.get(key)
        sev = f.get('sev', 0) or 0
        if g is None:
            g = {'key': key, 'block': get_remediation(f, lang), 'hosts': [], 'maxsev': sev, 'rep': f}
            groups[key] = g
        if sev > g['maxsev']:
            g['maxsev'] = sev
            g['block'] = get_remediation(f, lang)
            g['rep'] = f
        ip = f.get('host') or f.get('ip')
        if ip and ip not in g['hosts']:
            g['hosts'].append(ip)
    out = list(groups.values())
    for g in out:
        g['count'] = len(g['hosts'])
    out.sort(key=lambda g: (g['block'].get('is_kev', False), g['maxsev'], g['count']), reverse=True)
    return out


def render_remediation_section(findings, styles, lang='ro'):
    """Flowables pentru subsectiunea de remediere numerotata (sub tabelul de findings)."""
    import xml.sax.saxutils as _sax
    def _esc(x):
        return _sax.escape(str(x if x is not None else ''))
    L = ('en' if str(lang).lower().startswith('en') else 'ro')
    TT = {
        'ro': {'h': 'Remediere pas-cu-pas', 'affected': 'Gazde afectate',
               'none': 'Nicio constatare de remediat.',
               'more': '… +{n} gazde', 'kev': 'EXPLOATAT-IN-LUME (KEV)',
               'intro': ('Pasii sunt ordonati pe tip de vulnerabilitate, cele mai grave intai. Fiecare bloc '
                         'listeaza gazdele afectate din reteaua beneficiarului si actiunile concrete, in ordine.')},
        'en': {'h': 'Step-by-step remediation', 'affected': 'Affected hosts',
               'none': 'Nothing to remediate.',
               'more': '… +{n} hosts', 'kev': 'EXPLOITED-IN-THE-WILD (KEV)',
               'intro': ('Steps are grouped by vulnerability type, most severe first. Each block lists the '
                         'affected hosts in the beneficiary network and the concrete actions, in order.')},
    }[L]

    flow = []
    groups = build_remediation_groups(findings, lang)
    if not groups:
        flow.append(Paragraph(TT['none'], styles['small_dim']))
        return flow

    flow.append(Paragraph('<b>' + _esc(TT['h']) + '</b>', styles['h3']))
    flow.append(Paragraph(TT['intro'], styles['small_dim']))
    flow.append(Spacer(1, 2 * mm))

    step_style = ParagraphStyle('rem_step', parent=styles['small'], leftIndent=14, firstLineIndent=-14,
                                spaceAfter=2, leading=12)
    sev_col = {'critical': RED, 'high': ORANGE, 'medium': AMBER, 'low': PHOS}

    for g in groups:
        blk = g['block']
        band = _sev_band_scan(g['maxsev'])
        col = sev_col.get(band, PHOS)
        kev_tag = ('  <font color="#c91f3e"><b>[' + _esc(TT['kev']) + ']</b></font>') if blk.get('is_kev') else ''
        refs = ('  <font color="#5a5a5a">[' + _esc(', '.join(blk['refs'])) + ']</font>') if blk.get('refs') else ''
        chunk = []
        chunk.append(Paragraph(
            ('<font color="%s"><b>%s</b></font> — <b>%s</b>  '
             '<font color="#5a5a5a">(%d)</font>%s%s') % (
                col.hexval() if hasattr(col, 'hexval') else '#000000',
                _esc(band.upper()), _esc(blk['label']), g['count'], kev_tag, refs),
            styles['body']))
        if blk.get('why'):
            chunk.append(Paragraph('<i>' + _esc(blk['why']) + '</i>', styles['small_dim']))
        hosts = g['hosts']
        shown = ', '.join(_esc(h) for h in hosts[:14])
        more = (('  ' + TT['more'].format(n=len(hosts) - 14)) if len(hosts) > 14 else '')
        chunk.append(Paragraph(
            '<b>' + _esc(TT['affected']) + ':</b> <font name="Courier" size="8">' + shown + '</font>' + _esc(more),
            styles['small']))
        chunk.append(Spacer(1, 1 * mm))
        for i, st in enumerate(blk['steps'], 1):
            chunk.append(Paragraph('<b>%d.</b>&nbsp;%s' % (i, _esc(st)), step_style))
        chunk.append(Spacer(1, 3 * mm))
        if len(blk['steps']) <= 7:
            flow.append(KeepTogether(chunk))
        else:
            flow.extend(chunk)
    return flow


def build_match_conclusions(rows, stats, days, alerts_total, lang):
    """Concluzii ONESTE din randurile de MATCH."""
    ro = not str(lang).lower().startswith('en')
    c = []
    if rows:
        top = rows[0]
        if ro:
            c.append("{} gazda/gazde sunt SIMULTAN vulnerabile si sub alertare activa (ultimele {} zile) "
                     "— prioritate MAXIMA de remediere. Cap de lista: {} — „{}”, {} alerte, nivel max {}.".format(
                         stats['match'], days, top['ip'], str(top['vuln_top'])[:70], top['alerts'], top['maxlevel']))
        else:
            c.append("{} host(s) are BOTH vulnerable and under active alerting (last {} days) — top remediation "
                     "priority. Lead: {} — \"{}\", {} alerts, max level {}.".format(
                         stats['match'], days, top['ip'], str(top['vuln_top'])[:70], top['alerts'], top['maxlevel']))
        c.append(("Corelarea leaga vulnerabilitatea scanata de alertele reale pe ACELASI IP. O alerta pe un serviciu "
                  "(ex. un server web) NU inseamna ca toate serviciile gazdei sunt vulnerabile — indica doar unde "
                  "expunerea scanata si traficul de alerta coincid pe aceeasi gazda.") if ro else
                 ("The correlation links the scanned vulnerability to real alerts on the SAME IP. An alert on one "
                  "service (e.g. a web server) does NOT mean every service on the host is vulnerable — it only marks "
                  "where the scanned exposure and the alert traffic coincide on the same host."))
    else:
        c.append(("Nicio gazda nu este, in aceasta perioada, simultan vulnerabila si sub alertare activa — bine. "
                  "Nu exista suprapunere intre expunerile scanate si traficul de alerta pe acelasi IP.") if ro else
                 ("No host is currently both vulnerable and under active alerting — good. There is no overlap between "
                  "the scanned exposures and the alert traffic on the same IP."))
    if stats.get('kev'):
        km = stats.get('kev_matched', 0)
        if ro:
            c.append("{} gazda/gazde au vulnerabilitati EXPLOATATE-IN-LUME (CISA KEV){} — corectati IMEDIAT "
                     "(ex. SMBv1/EternalBlue, Telnet in clar, versiuni de software cu RCE public).".format(
                         stats['kev'], (", dintre care {} sunt si sub alertare".format(km) if km else "")))
        else:
            c.append("{} host(s) have actively EXPLOITED-IN-THE-WILD vulnerabilities (CISA KEV){} — patch NOW "
                     "(e.g. SMBv1/EternalBlue, cleartext Telnet, software with public RCE).".format(
                         stats['kev'], (", {} of them also under alerting".format(km) if km else "")))
    c.append(("{} gazde vulnerabile fara alerte inca -> corectie proactiva inainte sa fie exploatate; "
              "{} IP-uri alertate fara vulnerabilitate cunoscuta la scanare -> de monitorizat/investigat de analist.").format(
                  stats['vuln_only'], stats['alert_only']) if ro else
             ("{} vulnerable hosts with no alerts yet -> patch proactively before they are exploited; "
              "{} alerted IPs with no known scanned vulnerability -> for analyst monitoring/investigation.").format(
                  stats['vuln_only'], stats['alert_only']))
    if stats.get('excluded_infra'):
        c.append(("Din corelatie au fost excluse {} adrese ale infrastructurii proprii (SOC / tuneluri / "
                  "IP-ul de scanare al senzorului), ca activitatea propriei platforme sa nu fie raportata "
                  "drept atac sau vulnerabilitate a beneficiarului.").format(stats['excluded_infra']) if ro else
                 ("{} of our own infrastructure addresses (SOC / tunnels / the sensor's scanning IP) were "
                  "excluded from the correlation so our own platform activity is not reported as an attack or "
                  "a beneficiary vulnerability.").format(stats['excluded_infra']))
    c.append(("Alertele corelate sunt cele vazute inline de senzor si asociate gazdei vulnerabile prin acelasi IP; "
              "corelarea confirma suprapunerea expunere-alerta pe gazda, nu originea sau directia traficului "
              "(interna vs externa) — aceasta se stabileste din investigatia fiecarei alerte. Unde echipamentul de "
              "perimetru al beneficiarului blocheaza atacurile externe inainte de senzor, corelarea cu surse externe "
              "poate fi limitata.") if ro else
             ("The correlated alerts are those seen inline by the sensor and tied to the vulnerable host by the same IP; "
              "the correlation confirms the exposure-alert overlap on that host, not the origin or direction of the "
              "traffic (internal vs external) — that is established by investigating each alert. Where the beneficiary's "
              "edge blocks external attacks upstream of the sensor, external-source correlation may be limited."))
    return c


# REGULA DE EXCLUDERE OBLIGATORIE (MATCH): infrastructura NOASTRA nu apare niciodata
# ca „gazda a beneficiarului”. Excludem retelele proprii + IP-ul de scan/mgmt al senzorului.
import ipaddress as _ipaddr_match
INFRA_NETS = ('10.0.0.0/24', '10.1.0.0/16', '10.242.0.0/16')
_SCANNER_SIG_RE = _re_mod.compile(
    r'(ET\s+SCAN|nmap|masscan|nikto|CYBER3[- ]?Scan|user[-_ ]?agent.*scan|port\s*scan)', _re_mod.I)


def _match_in_nets(ip, nets):
    try:
        a = _ipaddr_match.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        try:
            if a in _ipaddr_match.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def detect_scanner_ips(amap, findings):
    """Auto-detectie ONESTA a IP-ului de scan/mgmt al senzorului pe LAN-ul clientului
    (ex. F001 = 192.168.255.1): sursa INTERNA care emite semnaturi de scanare/recon
    (ET SCAN / Nmap / CYBER3-Scan / port scan) si NU e ea insasi gazda vulnerabila scanata."""
    vuln_hosts = {(f.get('host') or f.get('ip')) for f in (findings or [])}
    out = set()
    for ip, e in (amap or {}).items():
        if ip in vuln_hosts:
            continue
        if _SCANNER_SIG_RE.search(str((e or {}).get('sig', '') or '')):
            out.add(ip)
    return out


def build_match(findings, amap, alerts_total, days, lang,
                exclude_ips=None, exclude_nets=INFRA_NETS, auto_scanner=True):
    """Coreleaza pe IP intern cea mai severa constatare VAS cu alertele SOC reale.
    amap[ip] = {count, maxlevel, sig}. Intoarce rows + stats + conclusions.

    EXCLUDERE (obligatorie): scoate din AMBELE laturi infrastructura proprie
    (`exclude_nets`) + IP-urile de scaner/mgmt (`exclude_ips` + auto-detectie)."""
    excl = set(exclude_ips or ())
    if auto_scanner:
        excl |= detect_scanner_ips(amap, findings)

    def _excluded(ip):
        return (not ip) or (ip in excl) or _match_in_nets(ip, exclude_nets or ())

    best, kev_ips = {}, set()
    for f in findings or []:
        ip = f.get('host') or f.get('ip')
        if _excluded(ip):
            continue
        cat = str(f.get('category', ''))
        if cat == 'CVE-KEV':
            kev_ips.add(ip)
        if ip not in best or (f.get('sev', 0) or 0) > (best[ip].get('sev', 0) or 0):
            best[ip] = f
    amap_f = {ip: e for ip, e in (amap or {}).items() if not _excluded(ip)}
    excluded_alerted = len([1 for ip in (amap or {}) if _excluded(ip)])
    vuln_ips = set(best)
    alerted = set(amap_f)
    match_ips = vuln_ips & alerted
    rows = []
    for ip in match_ips:
        f = best[ip]
        al = amap_f[ip]
        rows.append({
            'ip': ip, 'vuln_top': f.get('title', '-'), 'vuln_cat': f.get('category', '-'),
            'sev_name': f.get('severity', '-'), 'sev': f.get('sev', 0) or 0,
            'kev': ip in kev_ips, 'alerts': al.get('count', 0),
            'maxlevel': al.get('maxlevel', 0), 'sig': al.get('sig', '') or '',
        })
    rows.sort(key=lambda r: (r['kev'], r['sev'], r['maxlevel'], r['alerts']), reverse=True)
    stats = {
        'vuln_total': len(vuln_ips), 'alerted_total': len(alerted), 'match': len(rows),
        'vuln_only': len(vuln_ips - alerted), 'alert_only': len(alerted - vuln_ips),
        'kev': len(kev_ips), 'kev_matched': sum(1 for r in rows if r['kev']),
        'excluded_infra': excluded_alerted,
    }
    concl = build_match_conclusions(rows, stats, days, alerts_total, lang)
    return {'rows': rows, 'conclusions': concl, 'stats': stats,
            'period_days': days, 'alerts_total': alerts_total}


def render_match_section(match, styles, lang='ro'):
    """Flowables pentru tabelul MATCH imbogatit (fara concluzii — acelea raman separate)."""
    import xml.sax.saxutils as _sax
    def _esc(x):
        return _sax.escape(str(x if x is not None else ''))
    L = ('en' if str(lang).lower().startswith('en') else 'ro')
    H = {
        'ro': {'ip': 'Gazda', 'vuln': 'Vulnerabilitate principala', 'sev': 'Sev', 'al': 'Alerte',
               'lvl': 'Niv max', 'kev': 'KEV', 'sig': 'Semnatura alertei (SOC)',
               'none': 'Nicio gazda nu este simultan vulnerabila si sub alertare activa in aceasta perioada.',
               'legend': 'Randurile rosii = KEV (exploatat-in-lume). Ordine = prioritate de remediere.'},
        'en': {'ip': 'Host', 'vuln': 'Top vulnerability', 'sev': 'Sev', 'al': 'Alerts',
               'lvl': 'Max lvl', 'kev': 'KEV', 'sig': 'Alert signature (SOC)',
               'none': 'No host is currently both vulnerable and under active alerting.',
               'legend': 'Red rows = KEV (exploited-in-the-wild). Order = remediation priority.'},
    }[L]
    flow = []
    rows_data = (match or {}).get('rows', []) or []
    if not rows_data:
        flow.append(Paragraph(H['none'], styles['small_dim']))
        return flow
    body = []
    for r in rows_data[:30]:
        body.append([
            Paragraph('<font name="Courier" size="8">' + _esc(str(r.get('ip', '-'))[:16]) + '</font>', styles['small']),
            _esc(str(r.get('vuln_top', '-'))[:52]),
            _esc(str(r.get('sev_name', '-'))[:8]),
            str(r.get('alerts', 0)),
            str(r.get('maxlevel', '-')),
            ('DA' if r.get('kev') else '-') if L == 'ro' else ('YES' if r.get('kev') else '-'),
            Paragraph('<font size="8">' + _esc(str(r.get('sig', '') or '-')[:44]) + '</font>', styles['small']),
        ])
    tbl = _grid_table([H['ip'], H['vuln'], H['sev'], H['al'], H['lvl'], H['kev'], H['sig']], body,
                      [2.4 * cm, 4.7 * cm, 1.5 * cm, 1.4 * cm, 1.4 * cm, 1.1 * cm, 4.5 * cm],
                      styles, num_cols=(3, 4))
    extra = []
    for idx, r in enumerate(rows_data[:30], start=1):
        if r.get('kev'):
            extra.append(('TEXTCOLOR', (0, idx), (-1, idx), RED))
            extra.append(('FONTNAME', (5, idx), (5, idx), 'Helvetica-Bold'))
    if extra:
        tbl.setStyle(TableStyle(extra))
    flow.append(tbl)
    flow.append(Spacer(1, 1 * mm))
    flow.append(Paragraph(H['legend'], styles['small_dim']))
    return flow


def generate_c3scan_pdf(data, lang='en'):
    """CYBER3 Scan VAS report (separat). report_type: 'scan' (VAS), 'match' (MATCH+Concluzii),
    'full' (toate). Capitole: Cap.1 = VAS, Cap.2 = MATCH, Cap.3 = Concluzii. Fara Discovery."""
    import re as _re
    L = {
      'en': dict(sub='CYBER3 Scan · Vulnerability Assessment + Alert ↔ Vulnerability MATCH',
                 sub_scan='CYBER3 Scan · Vulnerability Assessment',
                 sub_match='CYBER3 Scan · Alert ↔ Vulnerability MATCH',
                 d_h='CYBER3 Scan Autonomous Network Discovery', v_h='Vulnerability assessment (VAS)',
                 m_h='Alert ↔ Vulnerability MATCH', concl_h='Conclusions & priorities', kpi_h='Key figures',
                 sev_h='Findings by severity', roles_h='Devices discovered by type', find_h='Findings',
                 total='Findings', crit='Critical', high='High', med='Medium', low='Low',
                 c_sev='Severity', c_cat='Category', c_find='Finding', c_host='Host', c_ip='Host', c_vendor='Vendor',
                 c_role='Role', c_svc='Services', c_vuln='Top vulnerability', c_al='Alerts', c_lvl='Max lvl', c_kev='KEV',
                 d_kp_hosts='Hosts', d_kp_mac='Real MAC', d_kp_vlan='VLANs', d_kp_sub='Subnets', d_kp_ven='Vendors', d_kp_role='Roles',
                 d_intro='This is what sets CYBER3 Scan apart. It was given NOTHING — no IP ranges, no VLAN list, no network map, no agent on any client device. Sitting inline on the sensor, it mapped the entire client network on its own.',
                 d_intro2='In a single autonomous pass it discovered {hosts} live hosts across {vlans} VLAN(s) and {subnets} subnet(s); {mac} answered with their real hardware MAC; {vendors} distinct manufacturers and {roles} device roles were identified; {hostnames} hostnames recovered. No other VA scanner does this without being told the network first.',
                 v_intro='Authorized, non-destructive vulnerability assessment on {hosts} discovered hosts, profile "{level}", on {when}. {total} finding(s): {critical} critical, {high} high, {medium} medium, {low} low. {kev} flagged as actively exploited in the wild (CISA KEV).',
                 m_intro='The MATCH joins what the network HAS (VAS vulnerabilities) with what is HAPPENING to it (SOC alerts — Suricata/Wazuh, last {days} days, {alerts} alerts) by host IP. A vulnerable host that is also under attack is the top priority. This correlation is performed automatically on the on-premises sensor.',
                 m_none='No host is currently both vulnerable and under active alerting — good. Monitor and patch KEV items proactively.',
                 d_note='Discovery is passive + active (tagged ARP) + reliable connect-scan, fully inline. No agent on client hosts, no IPs supplied — the network is mapped from the wire.',
                 none='No findings.'),
      'ro': dict(sub='CYBER3 Scan · Evaluare vulnerabilitati + MATCH alerte ↔ vulnerabilitati',
                 sub_scan='CYBER3 Scan · Evaluare vulnerabilitati',
                 sub_match='CYBER3 Scan · MATCH alerte ↔ vulnerabilitati',
                 d_h='CYBER3 Scan Autonomous Network Discovery', v_h='Evaluare de vulnerabilitati (VAS)',
                 m_h='MATCH alerte ↔ vulnerabilitati', concl_h='Concluzii & prioritati', kpi_h='Cifre cheie',
                 sev_h='Constatari dupa severitate', roles_h='Echipamente descoperite, pe tip', find_h='Constatari',
                 total='Constatari', crit='Critice', high='Mari', med='Medii', low='Mici',
                 c_sev='Severitate', c_cat='Categorie', c_find='Constatare', c_host='Gazda', c_ip='Gazda', c_vendor='Producator',
                 c_role='Rol', c_svc='Servicii', c_vuln='Vulnerabilitate principala', c_al='Alerte', c_lvl='Nivel max', c_kev='KEV',
                 d_kp_hosts='Gazde', d_kp_mac='MAC real', d_kp_vlan='VLAN-uri', d_kp_sub='Subretele', d_kp_ven='Producatori', d_kp_role='Roluri',
                 d_intro='Aici sta diferentiatorul CYBER3 Scan. Nu a primit NIMIC — nicio clasa de IP, nicio lista de VLAN-uri, nicio harta de retea, niciun agent pe vreun echipament al clientului. Stand inline pe senzor, a cartografiat singur intreaga retea a clientului.',
                 d_intro2='Intr-o singura trecere autonoma a descoperit {hosts} gazde active in {vlans} VLAN-uri si {subnets} subretele; {mac} au raspuns cu MAC-ul hardware real; au fost identificati {vendors} producatori distincti si {roles} roluri de echipament; {hostnames} hostname-uri recuperate. Niciun alt scanner de vulnerabilitati nu face asta fara sa i se spuna intai reteaua.',
                 v_intro='Evaluare de vulnerabilitati autorizata, non-distructiva, pe {hosts} gazde descoperite, profil "{level}", la {when}. {total} constatari: {critical} critice, {high} mari, {medium} medii, {low} mici. {kev} marcate ca exploatate activ in lume (CISA KEV).',
                 m_intro='MATCH-ul imbina ce ARE reteaua (vulnerabilitati VAS) cu ce I SE INTAMPLA (alerte SOC — Suricata/Wazuh, ultimele {days} zile, {alerts} alerte) dupa IP-ul gazdei. O gazda vulnerabila care este SI sub atac este prioritatea maxima. Corelarea se face automat pe senzorul on-premises.',
                 m_none='Nicio gazda nu este in acest moment si vulnerabila si sub alertare activa — bine. Monitorizati si corectati proactiv elementele KEV.',
                 d_note='Descoperirea e pasiva + activa (ARP tag-uit) + connect-scan fiabil, complet inline. Niciun agent pe gazdele clientului, niciun IP furnizat — reteaua e cartografiata direct de pe fir.',
                 none='Nicio constatare.'),
    }
    t = L.get(lang, L['en'])
    rt = data.get('report_type', 'full')   # 'scan' | 'match' | 'full'
    org = data.get('organization') or _org_from_sensor(data.get('sensor'))
    brand_short, brand_long = _brand(org)
    plat = 'platforma CYBER3' if lang == 'ro' else 'CYBER3 platform'
    def deemoji(x): return _re.sub(r'^[^\x00-\x7F]+\s*', '', str(x or '')).strip()
    buf = io.BytesIO()
    title_kind = {'scan': 'SCAN REPORT', 'match': 'MATCH REPORT'}.get(rt, 'REPORT')
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm, topMargin=40*mm,
        bottomMargin=20*mm, title="CYBER3 Scan " + title_kind + " - " + str(data.get('sensor', 'Sensor')),
        author=brand_long)
    styles = _styles(lang)
    story = []
    sec = [0]
    def h2(title):
        sec[0] += 1
        return Paragraph(str(sec[0]) + " · " + title, styles['h2'])
    import xml.sax.saxutils as _x
    c = data.get('counts', {}) or {}
    total = data.get('total', sum(c.values()) if c else 0)
    disc = data.get('discovery', {}) or {}
    match = data.get('match', {}) or {}
    subt = {'scan': t['sub_scan'], 'match': t['sub_match']}.get(rt, t['sub'])

    story.append(Paragraph(
        f"<b><font size='13' color='#00b86f'>{brand_short}</font></b>"
        f" <font size='9' color='#5a5a5a'>· {plat}</font>",
        styles['accent']))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(str(data.get('sensor', 'Sensor')) + "  —  " + title_kind, styles['h1']))
    story.append(Paragraph(str(data.get('scan_time', '-')) + " · " + subt, styles['meta']))
    story.append(Spacer(1, 8*mm))

    # ===== Cap.1 — VAS (doar SCAN REPORT / full) =====
    if rt in ('scan', 'full'):
        story.append(h2(t['v_h']))
        story.append(Paragraph(t['v_intro'].format(hosts=data.get('hosts_scanned', '-'), level=data.get('level', '-'),
            when=data.get('scan_time', '-'), total=total, critical=c.get('critical', 0), high=c.get('high', 0),
            medium=c.get('medium', 0), low=c.get('low', 0), kev=data.get('kev', 0)), styles['body']))
        story.append(Spacer(1, 3*mm))
        story.append(_kpi_table([
            {'value': total, 'label': t['total']},
            {'value': c.get('critical', 0), 'label': t['crit'], 'color': RED},
            {'value': c.get('high', 0), 'label': t['high'], 'color': ORANGE},
            {'value': data.get('kev', 0), 'label': 'CISA KEV', 'color': RED},
        ], styles))
        story.append(Spacer(1, 3*mm))
        sev_order = [('critical', t['crit']), ('high', t['high']), ('medium', t['med']), ('low', t['low'])]
        mx = max([c.get(k, 0) for k, _ in sev_order] + [1])
        for k, lbl in sev_order:
            col = AMBER if k in ('critical', 'high') else PHOS
            story.append(_bar_row(lbl, c.get(k, 0), mx, styles, color=col))
        story.append(Spacer(1, 3*mm))
        findings = data.get('findings', []) or []
        if findings:
            rows = [[_x.escape(str(f.get('severity', '-'))), _x.escape(str(f.get('category', '-'))[:18]),
                     _x.escape(str(f.get('title', '-'))[:54]), _x.escape(str(f.get('host', '-'))[:24])]
                    for f in findings[:55]]
            story.append(_grid_table([t['c_sev'], t['c_cat'], t['c_find'], t['c_host']], rows,
                                     [2.2*cm, 2.8*cm, 7.4*cm, 3.1*cm], styles))
            if len(findings) > 55:
                story.append(Paragraph("… +" + str(len(findings) - 55), styles['small_dim']))
            # --- Remediere pas-cu-pas (cerinta operator #2) ---
            story.append(Spacer(1, 3*mm))
            for fl in render_remediation_section(findings, styles, lang):
                story.append(fl)
        else:
            story.append(Paragraph(t['none'], styles['small_dim']))
        story.append(Spacer(1, 6*mm))

    # ===== Cap.2 — MATCH + CONCLUZII (doar MATCH REPORT / full) =====
    if rt in ('match', 'full'):
        story.append(h2(t['m_h']))
        story.append(Paragraph(t['m_intro'].format(days=match.get('period_days', 30),
            alerts=match.get('alerts_total', 0)), styles['body']))
        story.append(Spacer(1, 3*mm))
        # tabel MATCH imbogatit (KEV colorat rosu) + legenda
        for fl in render_match_section(match, styles, lang):
            story.append(fl)
        story.append(Spacer(1, 4*mm))
        story.append(h2(t['concl_h']))
        for line in (match.get('conclusions', []) or []):
            story.append(Paragraph("• " + _x.escape(str(line)), styles['body']))
        story.append(Spacer(1, 4*mm))

    story.append(Paragraph("CYBER3 Scan · " + brand_long, styles['small_dim']))
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer, canvasmaker=NumberedCanvas)
    pdf = buf.getvalue()
    buf.close()
    return pdf
