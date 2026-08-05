"""CYBER3 Scan — descoperire rețea + scanare vulnerabilități (produs propriu CYBER3).

Arhitectură DISTRIBUITĂ: scannerul rulează PE senzor (inline pe trunk), portalul
declanșează prin SSH + sudo (wrapper privilegiat) și citește rezultatul JSON. DIFERENȚIATOR:
descoperă rețeaua clientului AUTOMAT, FĂRĂ a primi IP-uri (senzorul vede tot traficul bridge-uit).

ACCES (reutilizat):
- Vizualizare rezultate: utilizator autentificat, filtrat pe organizație.
- Declanșare scan (ENGAGE): DOAR supervisor SAU analist FASTERUP_DIRECT.
NON-distructiv, doar RFC1918, un singur scan odată per senzor. Nivel implicit „mediu (sigur)".
"""
from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required, current_user
import ipaddress, json, os, re, time
from datetime import datetime, timezone
from app.routes.api_scan_common import SENSORS, _ssh, _visible_sensors, _can_generate

bp = Blueprint('c3scan', __name__)

WRAPPER = '/opt/cyber3/c3scan/c3-engage.sh'
SCANS_DIR = '/var/log/cyber3/scans'
REPORTS_DIR = os.getenv('REPORTS_DIR', '/opt/fasterup-portal/data/reports')
LEVELS = {'bland', 'mediu', 'agresiv'}


def _valid_targets(raw):
    """ADD TARGET opțional: doar RFC1918, max 64 intrări. Întoarce (csv|'', err|None)."""
    items = [t.strip() for t in re.split(r'[,\s]+', raw or '') if t.strip()]
    if not items:
        return '', None
    if len(items) > 64:
        return None, 'too many targets (max 64)'
    out = []
    for t in items:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            return None, 'invalid target: {}'.format(t)
        if not net.is_private:
            return None, 'target not in private range (RFC1918): {}'.format(t)
        out.append(str(net) if '/' in t else str(net.network_address))
    return ','.join(out), None


def _sevname(s):
    try: s = int(s)
    except Exception: return 'low'
    return 'critical' if s >= 8 else 'high' if s >= 6 else 'medium' if s >= 4 else 'low'


def _parse_findings(text):
    """findings.json (c3vuln) → listă UI {host, severity(name), category, title, remediation}."""
    import json
    try:
        d = json.loads(text or '{}')
    except ValueError:
        return [], {}
    out = []
    for f in d.get('findings', []):
        out.append({
            'host': f.get('ip', '-'),
            'severity': _sevname(f.get('severity', 0)),
            'sev': int(f.get('severity', 0)) if str(f.get('severity', 0)).isdigit() else 0,
            'category': f.get('category', '-'),
            'title': f.get('title', '-'),
            'remediation': f.get('remediation', ''),
        })
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    out.sort(key=lambda x: (order.get(x['severity'], 9), -x['sev']))
    summ = d.get('summary', {})
    summ['hosts_scanned'] = d.get('hosts_scanned', 0)
    summ['kev_catalog'] = d.get('kev_catalog', '')
    return out, summ


@bp.route('/c3scan/sensors', methods=['GET'])
@login_required
def sensors():
    vis = _visible_sensors()
    out = [{'code': k, 'label': k, 'scan_ok': v.get('scan_ok', True)} for k, v in vis.items()]
    out.sort(key=lambda s: s['code'])
    return jsonify({'sensors': out, 'can_generate': _can_generate()})


@bp.route('/c3scan/scan', methods=['POST'])
@login_required
def start_scan():
    if not _can_generate():
        return jsonify({'error': 'forbidden: scan generation restricted to FasterUp analysts'}), 403
    data = request.get_json(silent=True) or {}
    sensor = str(data.get('sensor', '')).upper()
    level = str(data.get('level', 'mediu')).lower()
    vis = _visible_sensors()
    if sensor not in vis:
        return jsonify({'error': 'unknown_sensor'}), 400
    if level not in LEVELS:
        return jsonify({'error': 'invalid_level'}), 400
    if not vis[sensor].get('scan_ok', True):
        return jsonify({'error': 'scanning_disabled_for_sensor'}), 403
    targets_csv, err = _valid_targets(data.get('targets', ''))
    if err:
        return jsonify({'error': err}), 400
    host = vis[sensor]['host']
    rc, out, _ = _ssh(host, "pgrep -f 'c3scan.py|c3vuln.py' >/dev/null && echo BUSY || echo FREE")
    if 'BUSY' in out:
        return jsonify({'error': 'scan_already_running'}), 409
    scan_id = 'c3-' + str(int(time.time()))
    cmd = "nohup sudo -n {w} {sid} {lvl} '{tgt}' >/dev/null 2>&1 & echo started".format(
        w=WRAPPER, sid=scan_id, lvl=level, tgt=targets_csv)
    rc, out, errs = _ssh(host, cmd, timeout=15)
    if rc != 0 or 'started' not in out:
        return jsonify({'error': 'launch_failed', 'detail': errs or out}), 500
    current_app.logger.info('CYBER3 Scan %s on %s by %s (level=%s, targets=%d)', scan_id, sensor,
                            getattr(current_user, 'username', '?'), level, len(targets_csv.split(',')) if targets_csv else 0)
    return jsonify({'status': 'started', 'scan_id': scan_id, 'sensor': sensor, 'level': level,
                    'targets': targets_csv.split(',') if targets_csv else []})


@bp.route('/c3scan/scan/<scan_id>', methods=['GET'])
@login_required
def scan_status(scan_id):
    scan_id = re.sub(r'[^A-Za-z0-9_-]', '', scan_id)[:40]
    sensor = str(request.args.get('sensor', '')).upper()
    vis = _visible_sensors()
    if sensor not in vis:
        return jsonify({'error': 'unknown_sensor'}), 400
    host = vis[sensor]['host']
    rc, status, _ = _ssh(host, "cat {}/{}.status 2>/dev/null".format(SCANS_DIR, scan_id))
    status = status.strip()
    done = status.startswith('done')
    findings, summ = ([], {})
    if done:
        findings, summ = _parse_findings(_ssh(host, "cat {}/{}.json 2>/dev/null".format(SCANS_DIR, scan_id))[1])
    state = 'done' if done else ('running' if status.startswith('running') else 'unknown')
    return jsonify({'scan_id': scan_id, 'sensor': sensor, 'state': state, 'raw_status': status,
                    'count': len(findings), 'findings': findings, 'summary': summ})


def _counts(summ):
    return {'critical': summ.get('critical', 0), 'high': summ.get('high', 0),
            'medium': summ.get('medium', 0), 'low': summ.get('low', 0)}


def _is_priv(ip):
    if not ip:
        return False
    if ip.startswith(('10.', '192.168.', '127.')):
        return True
    if ip.startswith('172.'):
        try:
            return 16 <= int(ip.split('.')[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


def _alert_map(agent_id, days=30):
    """Alerte SOC (Suricata/Wazuh) per IP intern pentru un senzor (agent.id). Întoarce (map, total)."""
    try:
        from app.services.opensearch_client import get_client as get_opensearch
        from datetime import timedelta
        os_client = get_opensearch()
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        base = [{'range': {'@timestamp': {'gte': since}}}, {'term': {'agent.id': str(agent_id)}}]
        sub = {'mx': {'max': {'field': 'rule.level'}},
               'sig': {'terms': {'field': 'data.alert.signature', 'size': 1}},
               'rd': {'terms': {'field': 'rule.description', 'size': 1}}}
        q = {'size': 0, 'track_total_hits': True, 'query': {'bool': {'must': base}}, 'aggs': {
                'dst': {'terms': {'field': 'data.dest_ip', 'size': 300}, 'aggs': sub},
                'src': {'terms': {'field': 'data.src_ip', 'size': 300}, 'aggs': sub}}}
        r = os_client._search('wazuh-alerts-*', q)
        total = r.get('hits', {}).get('total', {}).get('value', 0)
        a = r.get('aggregations', {})
        amap = {}
        for grp in ('dst', 'src'):
            for b in a.get(grp, {}).get('buckets', []):
                ip = b['key']
                if not _is_priv(ip):
                    continue
                sig_b = b.get('sig', {}).get('buckets', []) or b.get('rd', {}).get('buckets', [])
                e = amap.setdefault(ip, {'count': 0, 'maxlevel': 0, 'sig': ''})
                e['count'] += b['doc_count']
                e['maxlevel'] = max(e['maxlevel'], int(b.get('mx', {}).get('value') or 0))
                if not e['sig'] and sig_b:
                    e['sig'] = str(sig_b[0]['key'])[:60]
        return amap, total
    except Exception:
        current_app.logger.warning('c3scan alert_map failed', exc_info=True)
        return {}, 0


def _deemoji(x):
    return re.sub(r'^[^\x00-\x7F]+\s*', '', str(x or '')).strip()


def _build_discovery(disc_json):
    try:
        d = json.loads(disc_json or '{}')
    except ValueError:
        return {}
    s = d.get('summary', {})
    allh = d.get('hosts', [])
    # distribuție pe tip de echipament (rol, fără emoji), top 10
    rb = {}
    for h in allh:
        r = _deemoji(h.get('role')) or '—'
        rb[r] = rb.get(r, 0) + 1
    role_breakdown = sorted(({'role': k, 'count': v} for k, v in rb.items()), key=lambda x: -x['count'])[:10]
    hl = [h for h in allh if h.get('services')] or allh
    hl = sorted(hl, key=lambda h: (-len(h.get('services', [])), h.get('ip', '')))[:30]
    return {'hosts': s.get('hosts', 0), 'mac_real': s.get('mac_real', 0),
            'vlans': len(s.get('vlans', []) or []), 'subnets': len(s.get('subnets', []) or []),
            'vendors': s.get('with_vendor', 0), 'roles': s.get('with_role', 0),
            'hostnames': s.get('with_hostname', 0), 'with_services': s.get('with_services', 0),
            'role_breakdown': role_breakdown,
            'host_list': [{'ip': h.get('ip'), 'vendor': h.get('vendor'), 'role': h.get('role'),
                           'hostname': h.get('hostname'), 'services': h.get('services', [])} for h in hl]}


def _build_match(findings, amap, alerts_total, days, lang):
    import json as _j  # noqa
    # cea mai severă constatare per IP + flag KEV
    best, kev_ips = {}, set()
    for f in findings:
        ip = f.get('host')
        if not ip:
            continue
        if f.get('category') == 'CVE-KEV':
            kev_ips.add(ip)
        if ip not in best or f.get('sev', 0) > best[ip].get('sev', 0):
            best[ip] = f
    vuln_ips = set(best)
    alerted = set(amap)
    match_ips = vuln_ips & alerted
    rows = []
    for ip in match_ips:
        f = best[ip]; al = amap[ip]
        rows.append({'ip': ip, 'vuln_top': f.get('title', '-'), 'sev_name': f.get('severity', '-'),
                     'sev': f.get('sev', 0), 'kev': ip in kev_ips, 'alerts': al['count'],
                     'maxlevel': al['maxlevel'], 'sig': al['sig']})
    rows.sort(key=lambda r: (r['kev'], r['sev'], r['alerts'], r['maxlevel']), reverse=True)
    vuln_only = len(vuln_ips - alerted)
    alert_only = len(alerted - vuln_ips)
    ro = (lang != 'en')
    concl = []
    if rows:
        top = rows[0]
        if ro:
            concl.append("{} gazde sunt SIMULTAN vulnerabile și sub alertare activă — prioritate MAXIMĂ. "
                         "Cap de listă: {} — „{}” cu {} alerte (nivel max {}).".format(
                             len(rows), top['ip'], top['vuln_top'][:60], top['alerts'], top['maxlevel']))
        else:
            concl.append("{} hosts are BOTH vulnerable and under active alerting — top priority. "
                         "Lead: {} — \"{}\" with {} alerts (max level {}).".format(
                             len(rows), top['ip'], top['vuln_top'][:60], top['alerts'], top['maxlevel']))
    else:
        concl.append("Nicio gazdă nu este simultan vulnerabilă și sub alertare activă în această perioadă." if ro
                     else "No host is currently both vulnerable and under active alerting.")
    if kev_ips:
        concl.append("{} gazde au vulnerabilități EXPLOATATE-ÎN-LUME (CISA KEV) — corectați imediat "
                     "(ex. SMBv1/EternalBlue, Telnet în clar).".format(len(kev_ips)) if ro else
                     "{} hosts have actively EXPLOITED-IN-THE-WILD vulnerabilities (CISA KEV) — patch now.".format(len(kev_ips)))
    concl.append(("{} gazde vulnerabile fără alerte încă → corecție proactivă; {} IP-uri alertate fără "
                  "vulnerabilitate cunoscută → monitorizare/investigare.").format(vuln_only, alert_only) if ro else
                 ("{} vulnerable hosts with no alerts yet → patch proactively; {} alerted IPs with no known "
                  "vulnerability → monitor/investigate.").format(vuln_only, alert_only))
    return {'rows': rows, 'conclusions': concl, 'period_days': days, 'alerts_total': alerts_total}


@bp.route('/c3scan/report', methods=['POST'])
@login_required
def make_report():
    """Raport PDF din ultima scanare (sau scan_id) → 3 capitole: Descoperire + VAS + MATCH/Concluzii."""
    from app.services.report_generator import generate_c3scan_pdf
    data = request.get_json(silent=True) or {}
    sensor = str(data.get('sensor', '')).upper()
    lang = (data.get('lang') or 'ro').lower()
    rtype = str(data.get('report_type', 'full')).lower()
    if rtype not in ('scan', 'match', 'full'):
        rtype = 'full'
    vis = _visible_sensors()
    if sensor not in vis:
        return jsonify({'error': 'unknown_sensor'}), 400
    host = vis[sensor]['host']
    scan_id = re.sub(r'[^A-Za-z0-9_-]', '', str(data.get('scan_id', '')))[:40]
    if not scan_id:
        fn = _ssh(host, "ls -1t {}/*.json 2>/dev/null | grep -v discovery | head -1".format(SCANS_DIR))[1].strip()
        scan_id = fn.split('/')[-1][:-5] if fn else ''
    body = _ssh(host, "cat {}/{}.json 2>/dev/null".format(SCANS_DIR, scan_id))[1] if scan_id else ''
    findings, summ = _parse_findings(body)
    if not body:
        return jsonify({'error': 'no_scan_to_report'}), 404
    disc_json = _ssh(host, "cat {}/{}.discovery.json 2>/dev/null".format(SCANS_DIR, scan_id))[1]
    if not disc_json:
        disc_json = _ssh(host, "cat /var/log/cyber3/discovery.json 2>/dev/null")[1]
    discovery = _build_discovery(disc_json)
    # MATCH cere alertele SOC; raportul SCAN nu (economisim interogarea)
    if rtype == 'scan':
        match, alerts_total = {}, 0
    else:
        amap, alerts_total = _alert_map(vis[sensor].get('agent', ''), days=30)
        match = _build_match(findings, amap, alerts_total, 30, lang)
    when = datetime.now(timezone.utc)
    rpt = {'sensor': sensor, 'scan_time': when.strftime('%Y-%m-%d %H:%M UTC'), 'report_type': rtype,
           'level': '-', 'hosts_scanned': summ.get('hosts_scanned', 0), 'kev': summ.get('kev', 0),
           'kev_catalog': summ.get('kev_catalog', ''), 'counts': _counts(summ),
           'total': summ.get('total', len(findings)), 'findings': findings,
           'discovery': discovery, 'match': match}
    fname = 'Report_{}_c3scan_{}_{}.pdf'.format(re.sub(r'[^A-Za-z0-9]', '', sensor), rtype, when.strftime('%Y%m%d-%H%M%S'))
    path = os.path.join(REPORTS_DIR, fname)
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(path, 'wb') as fh:
            fh.write(generate_c3scan_pdf(rpt, lang))
    except Exception as e:
        current_app.logger.exception('c3scan pdf gen failed')
        return jsonify({'error': 'report_failed', 'detail': str(e)}), 500
    return jsonify({'status': 'ok', 'report': fname, 'download_url': '/api/reports/download/' + fname,
                    'match_count': len(match.get('rows', [])), 'alerts_total': alerts_total})


@bp.route('/c3scan/latest', methods=['GET'])
@login_required
def latest():
    sensor = str(request.args.get('sensor', '')).upper()
    vis = _visible_sensors()
    if sensor not in vis:
        return jsonify({'error': 'unknown_sensor'}), 400
    host = vis[sensor]['host']
    rc, out, _ = _ssh(host, "ls -1t {}/*.json 2>/dev/null | head -1".format(SCANS_DIR))
    fn = out.strip()
    if not fn:
        return jsonify({'sensor': sensor, 'scan_file': None, 'count': 0, 'findings': [], 'summary': {}})
    rc, body, _ = _ssh(host, "cat '{}' 2>/dev/null".format(fn))
    findings, summ = _parse_findings(body)
    return jsonify({'sensor': sensor, 'scan_file': fn.split('/')[-1],
                    'count': len(findings), 'findings': findings, 'summary': summ})
