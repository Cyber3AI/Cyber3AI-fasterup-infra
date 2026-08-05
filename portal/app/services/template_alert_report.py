# -*- coding: utf-8 -*-
"""Generator raport ALERTE pe portal folosind SABLONUL ICISOC (modelul livrat).
Umple sablonul Word icisoc101 din payload-ul _build_client_data (aceeasi forma ca DATA_JSON),
parametrizeaza perioada, apoi converteste docx->PDF cu libreoffice headless.
Pastreaza antetul/branding-ul ICISOC din sablon (pentru beneficiar)."""
import os, io, tempfile, subprocess, shutil
from datetime import datetime, timedelta
import docx

ICISOC_TEMPLATE = os.getenv('ICISOC_ALERT_TEMPLATE', '/opt/fasterup-portal/data/templates/ICI-SOC_Raport_Alerte_template.docx')
FASTERUP_TEMPLATE = os.getenv('FASTERUP_ALERT_TEMPLATE', '/opt/fasterup-portal/data/templates/FasterUp_Raport_Alerte_template.docx')
SOFFICE = os.getenv('SOFFICE_BIN', '/usr/bin/soffice')
BLK_MIN = 10
NOISE_SIG = ("attached usb", "usb device", "usb storage", "systemd:", "agent event queue", "event queue is",
             "log file size", "log file rotated", "ossec agent", "integrity checksum", "service exited",
             "wazuh agent", "agent started", "agent stopped", "agent disconnected",
             "host blocked by firewall-drop", "new dpkg", "syslog:")


def _cm(n):
    try:
        return "{:,}".format(int(n))
    except Exception:
        return str(n)


def _period_str(period):
    try:
        s = datetime.fromisoformat(period['start']); e = datetime.fromisoformat(period['end'])
        e_incl = e - timedelta(days=1)
        return "%s – %s" % (s.strftime('%d.%m.%Y'), e_incl.strftime('%d.%m.%Y'))
    except Exception:
        return (period.get('label') or '').replace('Period: ', '').strip() or '—'


def _fill_docx(D, out_path):
    SENSOR = str(D.get('client_name', 'icisoc')).lower()
    per = _period_str(D.get('period', {}))
    tot = D['summary']['events_processed']; l7 = D['summary']['heightened_attention']
    l10 = D['summary']['events_l10']; l12 = D['nis2']['significant_candidates']
    sev = D['severity']; av = D['availability']; blk = D['blocked']
    is_mirror = (blk.get('mode') == 'mirror')
    has_blk = (not is_mirror) and blk.get('external_events', 0) >= BLK_MIN
    inc = D.get('incidents', [])
    org = D.get('organization')
    if org == 'FASTERUP_DIRECT':
        template = FASTERUP_TEMPLATE; brand = 'FasterUp'
    else:
        template = ICISOC_TEMPLATE; brand = 'ICI-SOC'
    d = docx.Document(template)

    def set_para(p, text):
        if p.runs:
            p.runs[0].text = text
            for r in p.runs[1:]:
                r.text = ""
        else:
            p.add_run(text)

    def find(pred):
        return [p for p in d.paragraphs if pred(p.text.strip())]

    # 0) redenumire icisoc101 -> SENSOR + perioada iulie -> perioada reala (global)
    def repl_all(container):
        for p in container.paragraphs:
            t = p.text
            if 'icisoc101' in t or '1–31 iulie 2026' in t or '1-31 iulie 2026' in t:
                set_para(p, t.replace('icisoc101', SENSOR).replace('1–31 iulie 2026', per).replace('1-31 iulie 2026', per))
        for t in getattr(container, 'tables', []):
            for row in t.rows:
                for c in row.cells:
                    for p in c.paragraphs:
                        if 'icisoc101' in p.text:
                            set_para(p, p.text.replace('icisoc101', SENSOR))
    repl_all(d)
    for sec in d.sections:
        for p in sec.footer.paragraphs + sec.header.paragraphs:
            if 'icisoc101' in p.text:
                set_para(p, p.text.replace('icisoc101', SENSOR))

    # 1) paragrafe cu date (perioada parametrizata)
    for p in find(lambda t: t.startswith("În perioada") and "a procesat" in t):
        set_para(p, ("În perioada {per}, ICI-SOC a procesat {t} evenimente de securitate pe senzorul {s}. "
                     "Dintre acestea, {h} au necesitat atenție sporită (nivel 7+), {a} au atins pragul de răspuns (nivel 10+), "
                     "iar {c} se califică drept candidate pentru evaluare ca incident semnificativ NIS2 (nivel 12+). "
                     "Disponibilitatea senzorului în perioadă a fost de {p}%.").format(
            per=per, s=SENSOR, t=_cm(tot), h=_cm(l7), a=_cm(l10), c=_cm(l12), p="{:.2f}".format(av['pct'])))
    for p in find(lambda t: t.startswith("Disponibilitate în perioadă:")):
        set_para(p, "Disponibilitate în perioadă: {p}% (din {s} eșantioane de heartbeat; {n} eșantioane fără activitate).".format(
            p="{:.2f}".format(av['pct']), s=_cm(av['samples']), n=av['non_active_samples']))
    for p in find(lambda t: t.startswith("• Disponibilitatea senzorului a fost")):
        set_para(p, "• Disponibilitatea senzorului a fost {p}% în perioadă ({n} esantioane fara activitate) — acoperire continua.".format(
            p="{:.2f}".format(av['pct']), n=av['non_active_samples']))
    for p in find(lambda t: "Treceti in revista cele" in t):
        set_para(p, "• Treceti in revista cele {t} evenimente de securitate ale perioadei — {h} au necesitat atentie sporita "
                    "(nivel 7+), {a} au atins pragul de raspuns (nivel 10+).".format(t=_cm(tot), h=_cm(l7), a=_cm(l10)))

    # 2) tabele
    def fill(tbl, rows):
        while len(tbl.rows) > 1:
            tbl._tbl.remove(tbl.rows[-1]._tr)
        for rd in rows:
            cells = tbl.add_row().cells
            for i, val in enumerate(rd):
                if i < len(cells):
                    set_para(cells[i].paragraphs[0], str(val))
    T = d.tables
    pond = lambda n: "{:.1f}%".format(100.0 * n / tot if tot else 0)
    fill(T[0], [[_cm(l10), _cm(l12), _cm(tot), "{:.2f}%".format(av['pct'])]])
    fill(T[1], [["Scăzut", "1–6", _cm(sev['low']), pond(sev['low'])], ["Mediu", "7–9", _cm(sev['medium']), pond(sev['medium'])],
               ["Ridicat", "10–12", _cm(sev['high']), pond(sev['high'])], ["Critic", "13+", _cm(sev['critical']), pond(sev['critical'])]])
    _threats = [x for x in D['threats'] if not any(ns in x['name'].lower() for ns in NOISE_SIG)]
    if not _threats:
        _threats = [{'name': 'Nicio semnătură de amenințare de rețea confirmată în perioadă (vezi nota de regim senzor)', 'count': '—'}]
    fill(T[2], [[i + 1, x['name'], (_cm(x['count']) if isinstance(x['count'], int) else x['count'])] for i, x in enumerate(_threats[:8])])
    fill(T[3], [[x['ip'], x['context'], x['country'], _cm(x['attempts']), x['max_level']] for x in D['top_ips'][:8]])
    fill(T[4], [[x['ip'], _cm(x['count'])] for x in D['targets']['hosts'][:6]])
    fill(T[5], [[x['port'], x['service'], _cm(x['count'])] for x in D['targets']['ports'][:8]])
    fill(T[6], [[x['name'], x.get('id', ''), _cm(x['count'])] for x in D['mitre']['techniques'][:10]])
    ct = D['compliance_tags']
    fill(T[7], [["NIST 800-53", _cm(ct.get('nist_800_53', 0))], ["PCI DSS", _cm(ct.get('pci_dss', 0))],
               ["GDPR", _cm(ct.get('gdpr', 0))], ["HIPAA", _cm(ct.get('hipaa', 0))]])
    fill(T[8], [["Candidate incident semnificativ (nivel 12+)", _cm(l12)], ["Incidente gestionate (nivel 10+)", _cm(l10)]])
    fill(T[9], [[m['art'], m['measure'], m['status']] for m in D['nis2']['measures']])
    fill(T[10], [[x['step'], x['deadline']] for x in D['nis2']['reporting_deadlines']])

    # 3) incidente: tabel daca exista
    note = next((p for p in d.paragraphs if p.text.strip().startswith("Nu au fost înregistrate incidente")), None)
    if note is not None and inc:
        set_para(note, "Cele mai relevante incidente de nivel 10+ observate în perioadă (extras; lista completă în anexa de evenimente):")
        itbl = d.add_table(rows=1, cols=5)
        try:
            itbl.style = T[0].style
        except Exception:
            pass
        for i, h in enumerate(["Data/ora", "Niv", "Regulă", "Descriere", "Sursă → Țintă"]):
            set_para(itbl.rows[0].cells[i].paragraphs[0], h)
        for it in inc[:20]:
            c = itbl.add_row().cells
            vals = [it['timestamp'], it['level'], it['rule_id'], it['description'], "%s → %s" % (it.get('src_ip', '-'), it.get('dest_ip', '-'))]
            for i, v in enumerate(vals):
                set_para(c[i].paragraphs[0], str(v))
        note._p.addnext(itbl._tbl)

    # 4) sectiunea "6. Atacuri blocate" DOAR daca are blocari reale
    if has_blk:
        renum = {"6. Acoperire MITRE ATT&CK": "7. Acoperire MITRE ATT&CK", "6.1 Tehnici observate": "7.1 Tehnici observate",
                 "7. Incidente notabile (nivel 10+)": "8. Incidente notabile (nivel 10+)", "8. Disponibilitatea senzorului": "9. Disponibilitatea senzorului",
                 "9. Etichetare conformitate (evenimente mapate)": "10. Etichetare conformitate (evenimente mapate)",
                 "10. Conformitate NIS2 (Directiva (UE) 2022/2555)": "11. Conformitate NIS2 (Directiva (UE) 2022/2555)",
                 "10.1 Clasificarea incidentelor (perioadă)": "11.1 Clasificarea incidentelor (perioadă)",
                 "10.2 Maparea măsurilor de securitate (Art. 21(2))": "11.2 Maparea măsurilor de securitate (Art. 21(2))",
                 "10.3 Obligații de raportare pentru incidente semnificative (Art. 23)": "11.3 Obligații de raportare pentru incidente semnificative (Art. 23)",
                 "11. Recomandări": "12. Recomandări", "12. Referință anexe": "13. Referință anexe"}
        anchor = None
        for p in d.paragraphs:
            t = p.text.strip()
            if t == "6. Acoperire MITRE ATT&CK":
                anchor = p
            if t in renum:
                set_para(p, renum[t])
        h_style = anchor.style
        sub_style = next((p.style for p in d.paragraphs if p.text.strip().startswith("5.1")), h_style)
        body_style = next((p.style for p in d.paragraphs if p.text.strip().startswith("Onestitate")), None)

        def ins_p(text, style=None, bold=False):
            p = anchor.insert_paragraph_before()
            if style is not None:
                p.style = style
            r = p.add_run(text); r.bold = bold; return p

        def ins_table(headers, rows):
            tbl = d.add_table(rows=1, cols=len(headers))
            try:
                tbl.style = T[0].style
            except Exception:
                pass
            for i, h in enumerate(headers):
                set_para(tbl.rows[0].cells[i].paragraphs[0], h)
            for rd in rows:
                c = tbl.add_row().cells
                for i, v in enumerate(rd):
                    set_para(c[i].paragraphs[0], str(v))
            anchor._p.addprevious(tbl._tbl); return tbl
        ins_p("6. Atacuri blocate (extern)", style=h_style)
        ins_p("Aceasta este valoarea livrată beneficiarului: în perioadă, senzorul inline a blocat activ, în timp real, "
              "atacuri venite din Internet prin active-response (firewall-drop, rule.id 651). Spre deosebire de alertele pur "
              "informative, acestea sunt intervenții concrete care au oprit traficul ostil la nivel de rețea.", style=body_style)
        ins_p("Total atacuri externe blocate: {tb}  ·  IP-uri externe unice blocate: {ip}  ·  Țară dominantă: {c}".format(
              tb=_cm(blk['external_events']), ip=_cm(blk['external_ips']), c=blk.get('top_country') or '—'), bold=True)
        ins_p("6.1 Top atacatori externi blocați", style=sub_style)
        ins_table(["IP sursă (extern)", "Țară", "Blocări"],
                  [[x['ip'], (x.get('country') or '—'), _cm(x['count'])] for x in blk['top_ips'][:10]])
        ins_p("6.2 Blocări pe tip de amenințare", style=sub_style)
        ins_table(["Tip de amenințare (semnătură)", "Blocări"],
                  [[x['name'], _cm(x['count'])] for x in blk['threats'][:8]])

    # 5) REBRAND ICI-SOC -> brand (clienti directi FasterUp)
    if brand != 'ICI-SOC':
        def _rb(t):
            return t.replace('ICI-SOC', brand).replace('ICISOC', brand)
        for p in d.paragraphs:
            if 'ICI-SOC' in p.text or 'ICISOC' in p.text:
                set_para(p, _rb(p.text))
        for tb in d.tables:
            for row in tb.rows:
                for c in row.cells:
                    for p in c.paragraphs:
                        if 'ICI-SOC' in p.text or 'ICISOC' in p.text:
                            set_para(p, _rb(p.text))
        for sec in d.sections:
            for p in sec.footer.paragraphs + sec.header.paragraphs:
                if 'ICI-SOC' in p.text or 'ICISOC' in p.text:
                    set_para(p, _rb(p.text))

    d.save(out_path)


def _docx_to_pdf(docx_path, out_dir):
    env = dict(os.environ, HOME=out_dir)
    subprocess.run([SOFFICE, '--headless', '--convert-to', 'pdf', '--outdir', out_dir, docx_path],
                   check=True, capture_output=True, timeout=120, env=env)
    return docx_path[:-5] + '.pdf' if docx_path.endswith('.docx') else docx_path + '.pdf'


def generate_alert_pdf_template(client_data, lang='ro'):
    """Genereaza PDF-ul raportului de alerte in formatul ICISOC (sablon + libreoffice). Intoarce bytes."""
    tmp = tempfile.mkdtemp(prefix='icisocrep_')
    try:
        docx_path = os.path.join(tmp, 'report.docx')
        _fill_docx(client_data, docx_path)
        pdf_path = _docx_to_pdf(docx_path, tmp)
        with open(pdf_path, 'rb') as f:
            return f.read()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def generate_alert_docx_template(client_data, lang='ro'):
    """Genereaza DOCX-ul raportului de alerte in formatul ICISOC (doar sablon umplut). Intoarce bytes."""
    tmp = tempfile.mkdtemp(prefix='icisocrepd_')
    try:
        docx_path = os.path.join(tmp, 'report.docx')
        _fill_docx(client_data, docx_path)
        with open(docx_path, 'rb') as f:
            return f.read()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
