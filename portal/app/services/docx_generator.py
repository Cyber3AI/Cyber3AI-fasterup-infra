"""Word (.docx) report generator — mirrors report_generator.py (PDF) 1:1.

Two entry points, same payloads as the PDF path so NO query is duplicated:
  - generate_docx(client_data, lang)        -> ALERTS report  (mirror of generate_pdf)
  - generate_c3scan_docx(data, lang)        -> SCAN report     (mirror of generate_c3scan_pdf)

Both return the .docx as bytes (like generate_pdf returns PDF bytes), so the
callers in api_reports.py / api_c3scan.py can write them next to the PDF.

DEPENDENCY: python-docx (`pip install python-docx`) — NOT yet installed on the
portal venv (verified 2026-08). matplotlib is OPTIONAL: if present, the "blocked
attacks" section renders true colored PNG charts; if absent, it degrades to
native colored bars (colored block-glyph runs) — no hard dependency, no fake data.

GENERIC RULE honored: nothing here prints a real client/org/person/location name.
`client_data['client_name']` is the SENSOR CODE (set in api_reports _build_client_data
to client_code); the scan report uses `data['sensor']` (also the code). Callers must
keep passing codes, never organization names.
"""
import io
import logging

log = logging.getLogger(__name__)

# python-docx is imported lazily inside the entry points so that importing this
# module never explodes on a box where the wheel is not installed yet.
try:
    import docx  # noqa: F401
    _HAVE_DOCX = True
except Exception:  # pragma: no cover
    _HAVE_DOCX = False

# ---------- brand palette (hex, mirrors report_generator.py) ----------
PHOS = '00B86F'
AMBER = 'D48D1A'
ORANGE = 'E05C2A'
RED = 'C91F3E'
INK = '1A1A1A'
INK_DIM = '5A5A5A'
HEAD_BG = '1A1A1A'      # table header background (INK)
ZEBRA = 'F5F7F6'        # alt row background (BG_ALT)
WHITE = 'FFFFFF'

SEV_HEX = {'low': PHOS, 'medium': AMBER, 'high': ORANGE, 'critical': RED}


# ======================================================================
#  low-level docx helpers (shading, bars, tables) — no external deps
# ======================================================================
def _hex(c, default=None):
    """Normalize a color for RGBColor.from_string: strip a leading '#', validate 6 hex
    digits. Payload-supplied colors (e.g. '#c91f3e' on the blocked-KPI) arrive with '#'."""
    s = str(c or '').lstrip('#').strip()
    if len(s) == 6:
        try:
            int(s, 16)
            return s.upper()
        except ValueError:
            pass
    return (default if default is not None else INK)


def _oxml(tag):
    from docx.oxml import OxmlElement
    return OxmlElement(tag)


def _qn(tag):
    from docx.oxml.ns import qn
    return qn(tag)


def _shade(cell, hex_fill):
    """Set a table-cell background fill (Word shading)."""
    tcPr = cell._tc.get_or_add_tcPr()
    shd = _oxml('w:shd')
    shd.set(_qn('w:val'), 'clear')
    shd.set(_qn('w:color'), 'auto')
    shd.set(_qn('w:fill'), hex_fill)
    tcPr.append(shd)


def _set_cell_margins(cell, top=40, bottom=40, left=80, right=80):
    tcPr = cell._tc.get_or_add_tcPr()
    m = _oxml('w:tcMar')
    for name, val in (('top', top), ('bottom', bottom), ('start', left), ('end', right)):
        node = _oxml('w:' + name)
        node.set(_qn('w:w'), str(val))
        node.set(_qn('w:type'), 'dxa')
        m.append(node)
    tcPr.append(m)


def _no_table_borders(table):
    from docx.oxml.ns import qn
    tblPr = table._tbl.tblPr
    borders = _oxml('w:tblBorders')
    for edge in ('top', 'left', 'bottom', 'right', 'insideH', 'insideV'):
        e = _oxml('w:' + edge)
        e.set(qn('w:val'), 'nil')
        borders.append(e)
    tblPr.append(borders)


def _cell_text(cell, text, *, bold=False, size=8.5, color=INK, align=None, font='Calibri'):
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    cell.text = ''
    p = cell.paragraphs[0]
    if align == 'right':
        p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    elif align == 'center':
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(str(text))
    run.bold = bold
    run.font.size = Pt(size)
    run.font.name = font
    run.font.color.rgb = RGBColor.from_string(_hex(color))
    return p


def _heading(doc, text, sec=None):
    """Numbered green section heading, mirror of styles['h2']."""
    from docx.shared import Pt, RGBColor
    p = doc.add_paragraph()
    p.space_before = Pt(10)
    label = f"{sec} · {text}" if sec is not None else text
    run = p.add_run(label)
    run.bold = True
    run.font.size = Pt(14)
    run.font.name = 'Calibri'
    run.font.color.rgb = RGBColor.from_string(PHOS)
    return p


def _subhead(doc, text):
    from docx.shared import Pt, RGBColor
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(11)
    run.font.name = 'Calibri'
    run.font.color.rgb = RGBColor.from_string(INK)
    return p


def _body(doc, text, *, size=10.5, color=INK, italic=False):
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    run = p.add_run(text)
    run.italic = italic
    run.font.size = Pt(size)
    run.font.name = 'Calibri'
    run.font.color.rgb = RGBColor.from_string(_hex(color))
    return p


def _dim(doc, text):
    return _body(doc, text, size=8.5, color=INK_DIM, italic=True)


def _kpi_row(doc, kpis):
    """4-up KPI band: value (big, green) over label (small, dim)."""
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    n = len(kpis) or 1
    tbl = doc.add_table(rows=2, cols=n)
    _no_table_borders(tbl)
    for i, k in enumerate(kpis):
        vc = tbl.cell(0, i)
        _shade(vc, ZEBRA)
        _set_cell_margins(vc, top=80, bottom=20)
        pv = vc.paragraphs[0]
        pv.alignment = WD_ALIGN_PARAGRAPH.CENTER
        rv = pv.add_run(str(k['value']))
        rv.bold = True
        rv.font.size = Pt(20)
        rv.font.name = 'Calibri'
        rv.font.color.rgb = RGBColor.from_string(_hex(k.get('color'), PHOS))
        lc = tbl.cell(1, i)
        _shade(lc, ZEBRA)
        _set_cell_margins(lc, top=0, bottom=60)
        pl = lc.paragraphs[0]
        pl.alignment = WD_ALIGN_PARAGRAPH.CENTER
        rl = pl.add_run(k['label'])
        rl.font.size = Pt(8)
        rl.font.name = 'Calibri'
        rl.font.color.rgb = RGBColor.from_string(INK_DIM)
    return tbl


def _sev_row(doc, severity, labels):
    """Severity distribution band — 4 colored numbers (mirror _severity_table)."""
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    keys = ['low', 'medium', 'high', 'critical']
    tbl = doc.add_table(rows=2, cols=4)
    _no_table_borders(tbl)
    for i, key in enumerate(keys):
        vc = tbl.cell(0, i)
        _shade(vc, ZEBRA)
        pv = vc.paragraphs[0]
        pv.alignment = WD_ALIGN_PARAGRAPH.CENTER
        rv = pv.add_run(f"{severity.get(key, 0):,}")
        rv.bold = True
        rv.font.size = Pt(18)
        rv.font.name = 'Calibri'
        rv.font.color.rgb = RGBColor.from_string(SEV_HEX[key])
        lc = tbl.cell(1, i)
        _shade(lc, ZEBRA)
        pl = lc.paragraphs[0]
        pl.alignment = WD_ALIGN_PARAGRAPH.CENTER
        rl = pl.add_run(labels[i])
        rl.font.size = Pt(8)
        rl.font.name = 'Calibri'
        rl.font.color.rgb = RGBColor.from_string(INK_DIM)
    return tbl


def _bar(doc, name, count, max_count, color=PHOS, width=38):
    """Horizontal bar as a colored block-glyph run (native, no image needed).
    Mirror of report_generator._bar_row. Reliable in every Word renderer."""
    from docx.shared import Pt, RGBColor
    pct = (count / max_count) if max_count else 0
    blocks = max(1, int(round(pct * width))) if count else 0
    p = doc.add_paragraph()
    r1 = p.add_run(f"{name}  ")
    r1.font.size = Pt(9)
    r1.font.name = 'Calibri'
    r1.font.color.rgb = RGBColor.from_string(INK)
    rb = p.add_run('█' * blocks)
    rb.font.size = Pt(9)
    rb.font.name = 'Calibri'
    rb.font.color.rgb = RGBColor.from_string(_hex(color))
    rc = p.add_run(f"  {count:,}")
    rc.bold = True
    rc.font.size = Pt(9)
    rc.font.name = 'Calibri'
    rc.font.color.rgb = RGBColor.from_string(PHOS)
    return p


def _grid(doc, headers, rows, *, num_cols=(), col_colors=None, widths=None):
    """Header-shaded, zebra-striped table (mirror of _grid_table).
    `rows` cells are plain strings; `col_colors` optionally maps col->hex for a
    colored count column (used by evolution)."""
    from docx.shared import Pt, Cm
    ncol = len(headers)
    tbl = doc.add_table(rows=1, cols=ncol)
    _no_table_borders(tbl)
    hdr = tbl.rows[0].cells
    for c, htext in enumerate(headers):
        _shade(hdr[c], HEAD_BG)
        _set_cell_margins(hdr[c])
        _cell_text(hdr[c], htext, bold=True, size=8.5, color=WHITE,
                   align=('right' if c in num_cols else None))
    for ri, row in enumerate(rows):
        cells = tbl.add_row().cells
        for c, val in enumerate(row):
            if ri % 2 == 1:
                _shade(cells[c], ZEBRA)
            _set_cell_margins(cells[c])
            color = INK
            if col_colors and c in col_colors:
                color = col_colors[c]
            _cell_text(cells[c], val, size=8.5, color=color,
                       align=('right' if c in num_cols else None))
    if widths:
        for c, w in enumerate(widths):
            for row in tbl.rows:
                row.cells[c].width = Cm(w)
    return tbl


# ---- optional matplotlib colored charts (blocked-attacks "vedeta") ----
def _try_chart_png(kind, series, title=''):
    """Return PNG bytes for a colored chart, or None if matplotlib absent.
    kind: 'bar_h' | 'donut' | 'stacked_bar'. series = list of (label, value, hex)."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except Exception:
        return None
    try:
        fig = None
        if kind == 'donut':
            labels = [s[0] for s in series]
            vals = [s[1] for s in series]
            cols = ['#' + s[2] for s in series]
            fig, ax = plt.subplots(figsize=(4.2, 3.0), dpi=150)
            ax.pie(vals, labels=labels, colors=cols, autopct='%1.0f%%',
                   wedgeprops=dict(width=0.42), textprops={'fontsize': 8})
            ax.set_title(title, fontsize=10)
        elif kind == 'stacked_bar':
            # series: list of dicts {label, segments:[(val,hex)]}
            fig, ax = plt.subplots(figsize=(6.4, 2.6), dpi=150)
            xs = range(len(series))
            bottoms = [0] * len(series)
            # transpose by segment index (assumes uniform segment order)
            seg_n = max(len(s['segments']) for s in series)
            for si in range(seg_n):
                vals, cols = [], []
                for s in series:
                    seg = s['segments'][si] if si < len(s['segments']) else (0, INK_DIM)
                    vals.append(seg[0]); cols.append('#' + seg[1])
                ax.bar(xs, vals, bottom=bottoms, color=cols, width=0.8)
                bottoms = [b + v for b, v in zip(bottoms, vals)]
            ax.set_xticks(list(xs))
            ax.set_xticklabels([s['label'] for s in series], rotation=60, fontsize=6, ha='right')
            ax.set_title(title, fontsize=10)
        else:  # bar_h
            labels = [s[0] for s in series]
            vals = [s[1] for s in series]
            cols = ['#' + s[2] for s in series]
            fig, ax = plt.subplots(figsize=(6.4, max(2.0, 0.4 * len(series))), dpi=150)
            ax.barh(labels, vals, color=cols)
            ax.invert_yaxis()
            ax.set_title(title, fontsize=10)
            for i, v in enumerate(vals):
                ax.text(v, i, f' {v:,}', va='center', fontsize=7)
        fig.tight_layout()
        b = io.BytesIO()
        fig.savefig(b, format='png', bbox_inches='tight')
        plt.close(fig)
        return b.getvalue()
    except Exception:
        log.warning('chart render failed', exc_info=True)
        return None


def _add_image(doc, png_bytes, width_cm=15.0):
    from docx.shared import Cm
    doc.add_picture(io.BytesIO(png_bytes), width=Cm(width_cm))


def _new_doc(title, author):
    from docx import Document
    from docx.shared import Cm
    d = Document()
    d.core_properties.title = title
    d.core_properties.author = author
    for s in d.sections:
        s.top_margin = s.bottom_margin = Cm(2)
        s.left_margin = s.right_margin = Cm(2)
    return d


# ======================================================================
#  i18n  (titles kept in sync with report_generator.T / L)
# ======================================================================
def _T():
    """Alert-report titles — imported from report_generator so they never drift.
    Falls back to a local copy if the module is not importable in this context."""
    try:
        from app.services.report_generator import T
        return T
    except Exception:
        try:
            from report_generator import T
            return T
        except Exception:
            return None


def _brand(org):
    """Client-facing brand derived from the client's ORGANIZATION (mirror of
    report_generator._brand). ICI_SOC -> 'ICISOC'; FASTERUP_DIRECT -> keep FasterUp;
    default -> 'CYBER3'. 'CYBER3'/'CYBER3 Scan' are never affected.
    Returns (brand_short, brand_long)."""
    o = str(org or '').upper()
    if o == 'ICI_SOC':
        return ('ICISOC', 'ICISOC')
    if o == 'FASTERUP_DIRECT':
        return ('FasterUp SOC', 'FasterUp Security Operations Center')
    return ('CYBER3', 'CYBER3')


def _org_from_sensor(code):
    """Fallback org inference from a sensor/client code (ICISOC* -> ICI_SOC,
    F0xx -> FASTERUP_DIRECT) when the SCAN payload lacks 'organization'."""
    import re as _re
    c = str(code or '').upper()
    if c.startswith('ICISOC'):
        return 'ICI_SOC'
    if _re.fullmatch(r'F\d{2,3}', c):
        return 'FASTERUP_DIRECT'
    return None


# ======================================================================
#  ENTRY 1 — ALERTS report (mirror of generate_pdf)
# ======================================================================
def generate_docx(client_data, lang='en'):
    if not _HAVE_DOCX:
        raise RuntimeError('python-docx not installed: pip install python-docx')
    T = _T()
    t = (T or {}).get(lang, (T or {}).get('en', {})) if T else {}

    def tx(k, default=''):
        v = t.get(k, default)
        # strip reportlab HTML entities used in T (&amp;)
        return v.replace('&amp;', '&') if isinstance(v, str) else v

    brand_short, brand_long = _brand(client_data.get('organization'))
    plat = 'platforma CYBER3' if lang == 'ro' else 'CYBER3 platform'

    doc = _new_doc(f"Security Report - {client_data.get('client_name', 'Client')}",
                   client_data.get('client_name', 'Client'))
    sec = [0]

    def h(title):
        sec[0] += 1
        return _heading(doc, title, sec[0])

    # --- ANTET / brand header (brand-ul organizatiei + platforma CYBER3) ---
    from docx.shared import Pt, RGBColor
    ap = doc.add_paragraph()
    ar = ap.add_run(brand_short)
    ar.bold = True; ar.font.size = Pt(13); ar.font.name = 'Calibri'
    ar.font.color.rgb = RGBColor.from_string(PHOS)
    ar2 = ap.add_run('   ·  ' + plat)
    ar2.font.size = Pt(9); ar2.font.name = 'Calibri'
    ar2.font.color.rgb = RGBColor.from_string(INK_DIM)

    # --- TITLE ---
    p = doc.add_paragraph()
    r = p.add_run(client_data['client_name'])
    r.bold = True; r.font.size = Pt(22); r.font.name = 'Calibri'
    r.font.color.rgb = RGBColor.from_string(INK)
    _dim(doc, f"{client_data['period']['label']} · {tx('report_title', 'Security Operations Report')}")

    # --- Executive summary (honest wording: level-10+ events, not "blocked") ---
    h(tx('s_exec', 'Executive Summary'))
    s = client_data['summary']
    avail = (client_data.get('availability') or {}).get('display', '-')
    exec_tmpl = tx('exec_text', '{total} events, {heightened} heightened, {real_blocks} blocked.')
    # strip reportlab <b>/<font> tags for Word
    import re as _re
    exec_plain = _re.sub(r'<[^>]+>', '', exec_tmpl)
    try:
        exec_txt = exec_plain.format(
            days=(client_data.get('period') or {}).get('days', '-'),
            total=s.get('events_processed', 0),
            heightened=s.get('heightened_attention', 0),
            # ONESTITATE: blocari REALE (active-response) vs evenimente nivel 10+
            real_blocks=s.get('real_blocks', s.get('attacks_blocked', 0)),
            events_l10=s.get('events_l10', s.get('attacks_blocked', 0)),
            blocked=s.get('events_l10', s.get('attacks_blocked', 0)),
            significant=s.get('significant_candidates', 0),
            avail=avail)
    except Exception:
        exec_txt = exec_plain
    _body(doc, exec_txt)

    # --- R2: nota de context pentru senzor atipic ---
    if client_data.get('sensor_note'):
        _dim(doc, client_data['sensor_note'])

    # --- KPIs ---
    h(tx('s_kpi', 'Key Indicators'))
    _kpi_row(doc, client_data['kpis'])

    # --- Blocked attacks (VEDETA) — rendered only if the payload carries it.
    # Owned by the blocked-attacks agent; this mirror renders it when present so
    # the two outputs stay identical. Never fabricated here.
    _render_blocked_section(doc, client_data, lang, h)

    # --- Severity ---
    if client_data.get('severity'):
        h(tx('s_sev', 'Alert Severity Distribution'))
        labels = [tx('sev_low', 'Low'), tx('sev_med', 'Medium'),
                  tx('sev_high', 'High'), tx('sev_crit', 'Critical')]
        _sev_row(doc, client_data['severity'], labels)

    # --- Threat typology ---
    h(tx('s_threats', 'Threat Typology'))
    threats = client_data.get('threats', [])
    mx = max((x['count'] for x in threats), default=1)
    for x in threats:
        _bar(doc, x['name'], x['count'], mx)

    # --- MITRE ---
    mitre = client_data.get('mitre') or {}
    if mitre.get('tactics') or mitre.get('techniques'):
        h(tx('s_mitre', 'MITRE ATT&CK Coverage'))
        if mitre.get('tactics'):
            _subhead(doc, tx('mitre_tactics', 'Top tactics observed'))
            mxt = max((x['count'] for x in mitre['tactics']), default=1)
            for x in mitre['tactics'][:6]:
                _bar(doc, x['name'], x['count'], mxt, color=AMBER)
        if mitre.get('techniques'):
            _subhead(doc, tx('mitre_tech', 'Top techniques observed'))
            rows = [[x.get('id', ''), x['name'][:55], f"{x['count']:,}"]
                    for x in mitre['techniques'][:10]]
            _grid(doc, ['ID', tx('tbl_technique', 'Technique'), tx('tbl_count', 'Alerts')],
                  rows, num_cols=(2,))

    # --- Top source IPs ---
    h(tx('s_ips', 'Top Source IPs'))
    ip_rows = [[i['ip'], i.get('country', '-'), i.get('context', '-'),
                f"{i.get('attempts', 0):,}", str(i.get('max_level', '-'))]
               for i in client_data['top_ips']]
    country_hdr = 'Country' if lang == 'en' else 'Tara'
    _grid(doc, ['IP', country_hdr, 'Context', tx('tbl_count', 'Alerts'), tx('tbl_lvl', 'Lvl')],
          ip_rows, num_cols=(3, 4))

    # --- Targeted services & hosts (R13 port->service already applied upstream) ---
    targets = client_data.get('targets') or {}
    if targets.get('ports') or targets.get('hosts'):
        h(tx('s_targets', 'Targeted Services & Hosts'))
        if targets.get('ports'):
            rows = [[p.get('port', ''), p.get('service', '-'), f"{p.get('count', 0):,}"]
                    for p in targets['ports'][:8]]
            _grid(doc, [tx('tbl_port', 'Port'), tx('tbl_service', 'Service'),
                        tx('tbl_count', 'Alerts')], rows, num_cols=(2,))
        if targets.get('hosts'):
            rows = [[h_.get('ip', ''), f"{h_.get('count', 0):,}"] for h_ in targets['hosts'][:6]]
            _grid(doc, [tx('tbl_host', 'Internal host'), tx('tbl_count', 'Alerts')],
                  rows, num_cols=(1,))

    # --- Evolution (colored counts) ---
    h(tx('s_evo', 'Alert Evolution'))
    _dim(doc, tx('evo_legend', 'per-bin alert counts: critical / high / medium / low'))
    bins = (client_data.get('evolution') or {}).get('bins', [])
    if bins:
        rows = [[b.get('label', ''), str(b.get('critical', 0)), str(b.get('high', 0)),
                 str(b.get('medium', 0)), str(b.get('low', 0))] for b in bins]
        _grid(doc, ['', 'crit', 'high', 'med', 'low'], rows, num_cols=(1, 2, 3, 4),
              col_colors={1: RED, 2: ORANGE, 3: AMBER, 4: PHOS})
    else:
        _dim(doc, tx('no_data', 'No data in period.'))

    # --- Incident annex ---
    doc.add_page_break()
    h(tx('s_incidents', 'Incident Annex (level 10+)'))
    incidents = client_data.get('incidents') or []
    if incidents:
        rows = [[i.get('timestamp', ''), str(i.get('level', '')), i.get('description', ''),
                 i.get('src_ip', '-'), i.get('dest_ip', '-'), i.get('mitre', '')]
                for i in incidents]
        _grid(doc, [tx('tbl_time', 'Time (UTC)'), tx('tbl_lvl', 'Lvl'), tx('tbl_desc', 'Description'),
                    tx('tbl_src', 'Source'), tx('tbl_dst', 'Destination'), 'MITRE'],
              rows, num_cols=(1,))
    else:
        _body(doc, tx('no_incidents', 'No incidents level 10+ in the period.'))

    # --- R16: anexa actiuni imediate per terminal ---
    _render_r16_annex(doc, client_data.get('r16_rows', []), lang)

    # --- NIS2 ---
    nis2 = client_data.get('nis2') or {}
    h(tx('s_nis2', 'NIS2 Compliance'))
    _body(doc, tx('nis2_intro', '').replace('FasterUp SOC', brand_short))
    _subhead(doc, tx('nis2_class', 'Incident classification (period)'))
    _grid(doc, ['', tx('tbl_count', 'Alerts')],
          [[tx('nis2_l12', 'Significant-incident candidates (level 12+)'),
            str(nis2.get('significant_candidates', 0))],
           [tx('nis2_l10', 'Incidents handled (level 10+)'),
            str(nis2.get('high_incidents', 0))]], num_cols=(1,))
    if nis2.get('note_classification'):
        _dim(doc, nis2['note_classification'])
    if nis2.get('reporting_deadlines'):
        _subhead(doc, tx('nis2_deadlines', 'Reporting obligations (Art. 23)'))
        rows = [[d.get('step', ''), d.get('deadline', ''), d.get('to', '')]
                for d in nis2['reporting_deadlines']]
        _grid(doc, [tx('step', 'Step'), tx('deadline', 'Deadline'), tx('to', 'Addressee')], rows)
    if nis2.get('measures'):
        _subhead(doc, tx('nis2_measures', 'Security measures mapping (Art. 21(2))'))
        rows = [[m.get('art', ''), m.get('measure', ''), m.get('status', '')]
                for m in nis2['measures']]
        _grid(doc, ['Art.', 'Measure' if lang == 'en' else 'Masura',
                    'Status / ' + brand_short], rows)

    # --- Recommendations ---
    h(tx('s_recs', 'Recommendations'))
    for i, rec in enumerate(client_data.get('recommendations', []), 1):
        _body(doc, f"REC {i:02d}: {rec}")

    # --- R15: activitate platforma CYBER3 (nu recomandare catre client) ---
    if client_data.get('cyber3_activity'):
        h(tx('s_cyber3', 'CYBER3 platform activity'))
        _body(doc, client_data['cyber3_activity'])

    _dim(doc, tx('commitment', '').replace('FasterUp SOC', brand_short))

    return _to_bytes(doc)


def _render_r16_annex(doc, rows, lang):
    """R16 — anexa 'Actiuni imediate per terminal' (mirror al PDF r16_section).
    Marcheaza explicit ce NU poate determina senzorul ('nedeterminabil')."""
    try:
        from app.services.report_generator import R16_L
    except Exception:
        try:
            from report_generator import R16_L
        except Exception:
            return
    tt = R16_L.get(lang, R16_L['ro'])
    _subhead(doc, tt['title'])
    _body(doc, tt['intro'])
    if rows:
        grid = [[str(r['ip']), str(r['name'])[:22], str(r['type'])[:16], str(r['exposure'])[:30],
                 str(r['services'])[:34], str(r['alerts']), str(r['max_level'])] for r in rows[:30]]
        _grid(doc, [tt['c_ip'], tt['c_name'], tt['c_type'], tt['c_exp'], tt['c_svc'],
                    tt['c_al'], tt['c_lvl']], grid, num_cols=(5, 6))
        if len(rows) > 30:
            _dim(doc, '… +%d' % (len(rows) - 30))
    else:
        _dim(doc, tt['none'])
    _body(doc, '⚠ ' + tt['correction'], size=8.5)
    _dim(doc, tt['undet_note'])


def _blk_strip(s):
    import re as _re
    return _re.sub(r'<[^>]+>', '', str(s or ''))


def _render_blocked_section(doc, client_data, lang, h):
    """SECTIUNEA VEDETA 'Atacuri blocate (extern)' — mirror 1:1 al PDF-ului.
    Consuma payload['blocked'] produs de api_reports._blocked_external:
      {mode('inline'|'mirror'), total_651, external_events, external_ips, top_country,
       top_ips[{ip,count,country,first,last}], threats[{name,count}],
       timeline{interval,bins[{label,count}]}, geo_partial, zero_floor}
    Onest: mirror / inline-cu-0-externe primesc doar nota de context, fara cifre inventate.
    Textele (blk_*) vin din report_generator.T ca sursa unica. NU exista sectiune interna."""
    b = client_data.get('blocked')
    if not b:
        return
    T = _T()
    t = (T or {}).get(lang, (T or {}).get('en', {})) if T else {}

    def tx(k, default=''):
        v = t.get(k, default)
        return _blk_strip(v) if isinstance(v, str) else v

    h(tx('s_blocked', 'Blocked Attacks (external)'))
    mode = b.get('mode', 'inline')
    ext = b.get('external_events', 0)

    # ONESTITATE: senzor inline dar 0 (sub prag) atacuri externe -> DOAR nota de context.
    if mode != 'mirror' and ext <= b.get('zero_floor', 2):
        _body(doc, tx('blk_none'))
        return

    if mode == 'mirror':
        _body(doc, tx('blk_intro_mirror'))
    else:
        intro = tx('blk_intro', '{ext} external attacks blocked from {ips} IPs.')
        try:
            intro = intro.format(ext=ext, ips=b.get('external_ips', 0))
        except Exception:
            pass
        _body(doc, intro)

    # KPI band (colored)
    _kpi_row(doc, [
        {'value': f"{ext:,}", 'label': tx('blk_kpi_ext', 'External events blocked'), 'color': RED},
        {'value': f"{b.get('external_ips', 0):,}", 'label': tx('blk_kpi_ips', 'Distinct attacker IPs')},
        {'value': f"{b.get('total_651', 0):,}", 'label': tx('blk_kpi_total', 'Total firewall-drops')},
        {'value': (b.get('top_country') or '-'), 'label': tx('blk_kpi_country', 'Top origin')},
    ])

    # GRAFIC 1 — top IP-uri blocate (PNG colorat daca matplotlib, altfel bare native)
    top_ips = b.get('top_ips') or []
    if top_ips:
        series = [(str(i.get('ip', '-')), i.get('count', 0), RED) for i in top_ips[:10]]
        png = _try_chart_png('bar_h', series, tx('blk_top_ips', 'Top external attackers blocked'))
        if png:
            _add_image(doc, png)
        else:
            _subhead(doc, tx('blk_top_ips', 'Top external attackers blocked'))
            mx = max((i.get('count', 0) for i in top_ips), default=1)
            for i in top_ips[:10]:
                _bar(doc, str(i.get('ip', '-')), i.get('count', 0), mx, color=RED)

    # GRAFIC 2 — donut pe tip amenintare
    threats = [x for x in (b.get('threats') or []) if x.get('count', 0) > 0][:8]
    if threats:
        pal = [RED, ORANGE, AMBER, 'E0B100', '7A9E2F', '2F9E8F', '2F6F9E', '6A4C9C']
        series = [(str(x['name'])[:24], x['count'], pal[i % len(pal)]) for i, x in enumerate(threats)]
        png = _try_chart_png('donut', series, tx('blk_by_threat', 'Blocked attacks by threat type'))
        if png:
            _add_image(doc, png)
        else:
            _subhead(doc, tx('blk_by_threat', 'Blocked attacks by threat type'))
            mx = max((x['count'] for x in threats), default=1)
            for i, x in enumerate(threats):
                _bar(doc, str(x['name'])[:34], x['count'], mx, color=pal[i % len(pal)])

    # GRAFIC 3 — evolutia blocarilor in timp (bare native colorate)
    bins = (b.get('timeline') or {}).get('bins') or []
    if bins and sum(bb.get('count', 0) for bb in bins):
        _subhead(doc, tx('blk_timeline', 'Blocking activity over time'))
        mx = max((bb.get('count', 0) for bb in bins), default=1)
        for bb in bins:
            _bar(doc, bb.get('label', ''), bb.get('count', 0), mx, color=RED)

    # tabel top-IP (detaliu)
    if top_ips:
        rows = [[str(i.get('ip', '-')), str(i.get('country', '-')), str(i.get('first', '-')),
                 str(i.get('last', '-')), f"{i.get('count', 0):,}"] for i in top_ips[:12]]
        _grid(doc, [tx('tbl_src', 'Source'), tx('tbl_country', 'Country'),
                    tx('blk_first', 'First seen'), tx('blk_last', 'Last seen'),
                    tx('blk_events', 'Events')], rows, num_cols=(4,))

    # note de onestitate
    if b.get('geo_partial'):
        _dim(doc, tx('blk_geo_note'))
    _dim(doc, tx('blk_edge_note'))


# ======================================================================
#  ENTRY 2 — SCAN report (mirror of generate_c3scan_pdf)
# ======================================================================
# Local copy of the scan L dict (the PDF keeps it inside the function, so it
# cannot be imported; kept identical here — see spec_r12_docx.md maintenance note).
_SCAN_L = {
    'en': dict(sub='CYBER3 Scan · Vulnerability Assessment + Alert ↔ Vulnerability MATCH',
               sub_scan='CYBER3 Scan · Vulnerability Assessment',
               sub_match='CYBER3 Scan · Alert ↔ Vulnerability MATCH',
               d_h='CYBER3 Scan Autonomous Network Discovery', v_h='Vulnerability assessment (VAS)',
               m_h='Alert ↔ Vulnerability MATCH', concl_h='Conclusions & priorities', kpi_h='Key figures',
               sev_h='Findings by severity', roles_h='Devices discovered by type', find_h='Findings',
               steps_h='Remediation steps (per finding)',
               total='Findings', crit='Critical', high='High', med='Medium', low='Low',
               c_sev='Severity', c_cat='Category', c_find='Finding', c_host='Host', c_ip='Host', c_vendor='Vendor',
               c_role='Role', c_svc='Services', c_vuln='Top vulnerability', c_al='Alerts', c_lvl='Max lvl', c_kev='KEV',
               c_step='Step', c_action='Action',
               d_kp_hosts='Hosts', d_kp_mac='Real MAC', d_kp_vlan='VLANs', d_kp_sub='Subnets', d_kp_ven='Vendors', d_kp_role='Roles',
               d_intro='This is what sets CYBER3 Scan apart. It was given NOTHING - no IP ranges, no VLAN list, no network map, no agent on any client device. Sitting inline on the sensor, it mapped the entire beneficiary network on its own.',
               d_intro2='In a single autonomous pass it discovered {hosts} live hosts across {vlans} VLAN(s) and {subnets} subnet(s); {mac} answered with their real hardware MAC; {vendors} distinct manufacturers and {roles} device roles were identified; {hostnames} hostnames recovered.',
               v_intro='Authorized, non-destructive vulnerability assessment on {hosts} discovered hosts, profile "{level}", on {when}. {total} finding(s): {critical} critical, {high} high, {medium} medium, {low} low. {kev} flagged as actively exploited in the wild (CISA KEV).',
               m_intro='The MATCH joins what the network HAS (VAS vulnerabilities) with what is HAPPENING to it (SOC alerts, last {days} days, {alerts} alerts) by host IP. A vulnerable host that is also under attack is the top priority.',
               m_none='No host is currently both vulnerable and under active alerting - good.',
               d_note='Discovery is passive + active (tagged ARP) + reliable connect-scan, fully inline. No agent on beneficiary hosts, no IPs supplied - the network is mapped from the wire.',
               none='No findings.'),
    'ro': dict(sub='CYBER3 Scan · Evaluare vulnerabilitati + MATCH alerte ↔ vulnerabilitati',
               sub_scan='CYBER3 Scan · Evaluare vulnerabilitati',
               sub_match='CYBER3 Scan · MATCH alerte ↔ vulnerabilitati',
               d_h='CYBER3 Scan Autonomous Network Discovery', v_h='Evaluare de vulnerabilitati (VAS)',
               m_h='MATCH alerte ↔ vulnerabilitati', concl_h='Concluzii & prioritati', kpi_h='Cifre cheie',
               sev_h='Constatari dupa severitate', roles_h='Echipamente descoperite, pe tip', find_h='Constatari',
               steps_h='Pasi de remediere (per constatare)',
               total='Constatari', crit='Critice', high='Mari', med='Medii', low='Mici',
               c_sev='Severitate', c_cat='Categorie', c_find='Constatare', c_host='Gazda', c_ip='Gazda', c_vendor='Producator',
               c_role='Rol', c_svc='Servicii', c_vuln='Vulnerabilitate principala', c_al='Alerte', c_lvl='Nivel max', c_kev='KEV',
               c_step='Pas', c_action='Actiune',
               d_kp_hosts='Gazde', d_kp_mac='MAC real', d_kp_vlan='VLAN-uri', d_kp_sub='Subretele', d_kp_ven='Producatori', d_kp_role='Roluri',
               d_intro='Aici sta diferentiatorul CYBER3 Scan. Nu a primit NIMIC - nicio clasa de IP, nicio lista de VLAN-uri, nicio harta de retea, niciun agent pe vreun echipament al beneficiarului. Stand inline pe senzor, a cartografiat singur intreaga retea a beneficiarului.',
               d_intro2='Intr-o singura trecere autonoma a descoperit {hosts} gazde active in {vlans} VLAN-uri si {subnets} subretele; {mac} au raspuns cu MAC-ul hardware real; au fost identificati {vendors} producatori distincti si {roles} roluri de echipament; {hostnames} hostname-uri recuperate.',
               v_intro='Evaluare de vulnerabilitati autorizata, non-distructiva, pe {hosts} gazde descoperite, profil "{level}", la {when}. {total} constatari: {critical} critice, {high} mari, {medium} medii, {low} mici. {kev} marcate ca exploatate activ in lume (CISA KEV).',
               m_intro='MATCH-ul imbina ce ARE reteaua (vulnerabilitati VAS) cu ce I SE INTAMPLA (alerte SOC, ultimele {days} zile, {alerts} alerte) dupa IP-ul gazdei. O gazda vulnerabila care este SI sub atac este prioritatea maxima.',
               m_none='Nicio gazda nu este in acest moment si vulnerabila si sub alertare activa - bine.',
               d_note='Descoperirea e pasiva + activa (ARP tag-uit) + connect-scan fiabil, complet inline. Niciun agent pe gazdele beneficiarului, niciun IP furnizat - reteaua e cartografiata direct de pe fir.',
               none='Nicio constatare.'),
}


def generate_c3scan_docx(data, lang='en'):
    if not _HAVE_DOCX:
        raise RuntimeError('python-docx not installed: pip install python-docx')
    import re as _re
    t = _SCAN_L.get(lang, _SCAN_L['en'])
    rt = data.get('report_type', 'full')
    org = data.get('organization') or _org_from_sensor(data.get('sensor'))
    brand_short, brand_long = _brand(org)
    plat = 'platforma CYBER3' if lang == 'ro' else 'CYBER3 platform'

    def deemoji(x):
        return _re.sub(r'^[^\x00-\x7F]+\s*', '', str(x or '')).strip()

    title_kind = {'scan': 'SCAN REPORT', 'match': 'MATCH REPORT'}.get(rt, 'REPORT')
    doc = _new_doc('CYBER3 Scan ' + title_kind + ' - ' + str(data.get('sensor', 'Sensor')),
                   brand_long)
    sec = [0]

    def h(title):
        sec[0] += 1
        return _heading(doc, title, sec[0])

    c = data.get('counts', {}) or {}
    total = data.get('total', sum(c.values()) if c else 0)
    disc = data.get('discovery', {}) or {}
    match = data.get('match', {}) or {}
    subt = {'scan': t['sub_scan'], 'match': t['sub_match']}.get(rt, t['sub'])

    from docx.shared import Pt, RGBColor
    # --- ANTET / brand header (brand-ul organizatiei + platforma CYBER3) ---
    ap = doc.add_paragraph()
    aar = ap.add_run(brand_short)
    aar.bold = True; aar.font.size = Pt(13); aar.font.name = 'Calibri'
    aar.font.color.rgb = RGBColor.from_string(PHOS)
    aar2 = ap.add_run('   ·  ' + plat)
    aar2.font.size = Pt(9); aar2.font.name = 'Calibri'
    aar2.font.color.rgb = RGBColor.from_string(INK_DIM)
    p = doc.add_paragraph()
    r = p.add_run(str(data.get('sensor', 'Sensor')) + '  —  ' + title_kind)
    r.bold = True; r.font.size = Pt(22); r.font.name = 'Calibri'
    r.font.color.rgb = RGBColor.from_string(INK)
    _dim(doc, str(data.get('scan_time', '-')) + ' · ' + subt)

    # ===== Cap.1 — VAS (scan/full) =====
    if rt in ('scan', 'full'):
        h(t['v_h'])
        _body(doc, t['v_intro'].format(
            hosts=data.get('hosts_scanned', '-'), level=data.get('level', '-'),
            when=data.get('scan_time', '-'), total=total, critical=c.get('critical', 0),
            high=c.get('high', 0), medium=c.get('medium', 0), low=c.get('low', 0),
            kev=data.get('kev', 0)))
        _kpi_row(doc, [
            {'value': total, 'label': t['total']},
            {'value': c.get('critical', 0), 'label': t['crit'], 'color': RED},
            {'value': c.get('high', 0), 'label': t['high'], 'color': ORANGE},
            {'value': data.get('kev', 0), 'label': 'CISA KEV', 'color': RED},
        ])
        sev_order = [('critical', t['crit'], RED), ('high', t['high'], ORANGE),
                     ('medium', t['med'], AMBER), ('low', t['low'], PHOS)]
        mx = max([c.get(k, 0) for k, _, _ in sev_order] + [1])
        for k, lbl, col in sev_order:
            _bar(doc, lbl, c.get(k, 0), mx, color=col)
        findings = data.get('findings', []) or []
        if findings:
            rows = [[str(f.get('severity', '-')), str(f.get('category', '-'))[:18],
                     str(f.get('title', '-'))[:54], str(f.get('host', '-'))[:24]]
                    for f in findings[:55]]
            _grid(doc, [t['c_sev'], t['c_cat'], t['c_find'], t['c_host']], rows)
            if len(findings) > 55:
                _dim(doc, '… +' + str(len(findings) - 55))
            # --- Step-by-step remediation per finding (operator requirement #2) ---
            _render_remediation_steps(doc, findings, t, lang)
        else:
            _dim(doc, t['none'])

    # ===== Cap.2 — MATCH + Conclusions (match/full) =====
    if rt in ('match', 'full'):
        h(t['m_h'])
        _body(doc, t['m_intro'].format(days=match.get('period_days', 30),
                                       alerts=match.get('alerts_total', 0)))
        mrows = match.get('rows', []) or []
        if mrows:
            rows = [[str(rr.get('ip', '-'))[:16], str(rr.get('vuln_top', '-'))[:46],
                     str(rr.get('sev_name', '-'))[:8], str(rr.get('alerts', 0)),
                     str(rr.get('maxlevel', '-')), ('DA' if rr.get('kev') else '-')]
                    for rr in mrows[:30]]
            _grid(doc, [t['c_ip'], t['c_vuln'], t['c_sev'], t['c_al'], t['c_lvl'], t['c_kev']],
                  rows, num_cols=(3, 4))
        else:
            _dim(doc, t['m_none'])
        h(t['concl_h'])
        for line in (match.get('conclusions', []) or []):
            _body(doc, '• ' + str(line))

    _dim(doc, 'CYBER3 Scan · ' + brand_long)
    return _to_bytes(doc)


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


def _render_remediation_steps(doc, findings, t, lang):
    """Numbered, concrete remediation steps per vulnerability (Cap.2 VAS) — PARITATE
    cu PDF-ul: grupare pe tip de vulnerabilitate via remediation_lib, KEV/critic intai,
    fiecare grup cu gazde afectate + pasi NUMEROTATI. Fallback onest pe categorii noi."""
    if not findings:
        return
    try:
        get_remediation, remediation_key = _remediation_api()
    except Exception:
        get_remediation = None
    _subhead(doc, t.get('steps_h', 'Remediation steps'))
    L = 'en' if str(lang).lower().startswith('en') else 'ro'
    aff = 'Affected hosts' if L == 'en' else 'Gazde afectate'
    kev_tag = 'EXPLOITED-IN-THE-WILD (KEV)' if L == 'en' else 'EXPLOATAT-IN-LUME (KEV)'
    sev_col = {'critical': RED, 'high': ORANGE, 'medium': AMBER, 'low': PHOS}

    if get_remediation is None:
        # fallback minimal: per finding, split one-liner
        import re as _re
        for f in findings[:20]:
            _body(doc, f"[{str(f.get('severity','-')).upper()}] {str(f.get('title','-'))[:70]}",
                  size=9.5, color=INK)
            parts = [x.strip(' .;•-') for x in _re.split(r'[\n\r]+|(?<=[.;])\s+|•',
                     str(f.get('remediation', ''))) if x.strip(' .;•-')]
            for n, step in enumerate((parts or [str(f.get('remediation', ''))])[:8], 1):
                _body(doc, f"   {n}. {step}", size=9, color=INK_DIM)
        return

    # grupare pe cheia de remediere
    groups = {}
    for f in findings:
        key = remediation_key(f)
        sev = f.get('sev', 0) or 0
        g = groups.get(key)
        if g is None:
            g = {'block': get_remediation(f, lang), 'hosts': [], 'maxsev': sev}
            groups[key] = g
        if sev > g['maxsev']:
            g['maxsev'] = sev
            g['block'] = get_remediation(f, lang)
        ip = f.get('host') or f.get('ip')
        if ip and ip not in g['hosts']:
            g['hosts'].append(ip)
    ordered = sorted(groups.values(),
                     key=lambda g: (g['block'].get('is_kev', False), g['maxsev'], len(g['hosts'])),
                     reverse=True)

    from docx.shared import Pt, RGBColor
    for g in ordered:
        blk = g['block']
        band = _sev_band_scan(g['maxsev'])
        col = sev_col.get(band, PHOS)
        p = doc.add_paragraph()
        r0 = p.add_run(band.upper() + '  ')
        r0.bold = True; r0.font.size = Pt(9.5); r0.font.name = 'Calibri'
        r0.font.color.rgb = RGBColor.from_string(_hex(col, RED) if isinstance(col, str)
                                                 else (col.hexval()[2:].upper()
                                                       if hasattr(col, 'hexval') else RED))
        r1 = p.add_run(str(blk['label']) + '  (%d)' % len(g['hosts']))
        r1.bold = True; r1.font.size = Pt(9.5); r1.font.name = 'Calibri'
        if blk.get('is_kev'):
            rk = p.add_run('  [' + kev_tag + ']')
            rk.bold = True; rk.font.size = Pt(9); rk.font.color.rgb = RGBColor.from_string(RED)
        if blk.get('refs'):
            _dim(doc, '[' + ', '.join(blk['refs']) + ']')
        if blk.get('why'):
            _dim(doc, blk['why'])
        hosts = g['hosts']
        shown = ', '.join(hosts[:14]) + ((' … +%d' % (len(hosts) - 14)) if len(hosts) > 14 else '')
        _body(doc, aff + ': ' + shown, size=9, color=INK)
        for n, step in enumerate(blk['steps'], 1):
            _body(doc, f"   {n}. {step}", size=9, color=INK_DIM)


def _to_bytes(doc):
    buf = io.BytesIO()
    doc.save(buf)
    out = buf.getvalue()
    buf.close()
    return out
