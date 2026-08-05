"""R12 bundle collection + org-based routing (laptop vs portal).

Two jobs:
  1) BUNDLE (R12): gather every artefact that belongs to one client's report into
     a single per-client/per-month folder: the PDF, the Word (.docx) and the two
     sensor JSON annexes (discovery.json + findings.json). Optionally zip it.
  2) ROUTING: decide WHERE that folder lives based on the client's organization:
        FASTERUP_DIRECT (F001..F010)  -> ONLY on the laptop, never on the portal
        ICI_SOC          (ICISOC*)    -> on the portal reports dir (as today)

WHERE THE JSONs LIVE (verified on infra):
  The scan JSONs are on the SENSOR, not the portal, under
      /var/log/cyber3/scans/<scan_id>.json            -> findings  (c3vuln)
      /var/log/cyber3/scans/<scan_id>.discovery.json  -> discovery (fallback:
      /var/log/cyber3/discovery.json)
  The portal fetches them over SSH (see api_c3scan.py _ssh / SCANS_DIR). This
  module reuses the SAME _ssh helper so no new access path is introduced.

INTEGRATION: drop this next to api_reports.py / api_c3scan.py. `save_report_bundle`
is the single entry the two /generate endpoints call after they have the PDF (and
now DOCX) bytes.

GENERIC RULE: folder names use the CLIENT CODE only (F003, ICISOC107) — never an
organization/person/location name. Org is used purely to pick the root directory.
"""
import os
import re
import json
import zipfile
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# ---- roots (both overridable via env) ----
SCANS_DIR = '/var/log/cyber3/scans'
DISCOVERY_FALLBACK = '/var/log/cyber3/discovery.json'

# Portal side (ICI_SOC): served + listed by api_reports download/list.
PORTAL_REPORTS = os.getenv('REPORTS_DIR', '/opt/fasterup-portal/data/reports')

# Laptop side (FASTERUP_DIRECT): WSL path on the operator's machine. The direct
# clients' reports must NEVER be persisted on the portal, so this root is on the
# laptop and the direct flow is expected to run there (see spec, "execution
# context"). Overridable for a portal-side staging dir that is excluded from the
# served /reports listing.
LAPTOP_ROOT = os.getenv(
    'FASTERUP_DIRECT_ROOT',
    '/mnt/c/Users/acer/Desktop/FasterUpSOCAutonomousPlatform/FasterUpSenzori')

ORG_DIRECT = 'FASTERUP_DIRECT'
ORG_ICI = 'ICI_SOC'


def _safe(name):
    return re.sub(r'[^A-Za-z0-9_.-]', '_', str(name))[:60]


# ======================================================================
#  org resolution
# ======================================================================
def resolve_org_by_agent(client_id, db_path=None):
    """Org for an ALERTS report — from portal.db clients.organization by agent id.
    Returns (code, organization) or (client_id, None)."""
    import sqlite3
    db = db_path or os.getenv('DATABASE_PATH', '/opt/fasterup-portal/data/portal.db')
    try:
        conn = sqlite3.connect(db)
        cur = conn.cursor()
        cur.execute('SELECT code, organization FROM clients WHERE wazuh_agent_id=?',
                    (str(client_id),))
        row = cur.fetchone()
        conn.close()
        return (row[0], row[1]) if row else (str(client_id), None)
    except Exception as e:
        log.warning('resolve_org_by_agent failed: %s', e)
        return (str(client_id), None)


def _org_from_code_prefix(code):
    """Last-resort org inference from the code convention so a DIRECT client can
    NEVER silently misroute onto the portal if a registry/DB lookup fails.
    Convention (verified): F0xx -> FASTERUP_DIRECT, ICISOC1xx -> ICI_SOC."""
    c = str(code).upper()
    if re.fullmatch(r'F\d{2,3}', c):
        return ORG_DIRECT
    if c.startswith('ICISOC'):
        return ORG_ICI
    return None


def resolve_org_by_sensor(sensor, sensors_registry=None):
    """Org for a SCAN report — from the SENSORS registry (api_scan_common), with a
    code-prefix fallback if the registry is unavailable.
    Returns (code, organization)."""
    reg = sensors_registry
    if reg is None:
        try:
            from app.routes.api_scan_common import SENSORS as reg
        except Exception:
            reg = {}
    code = str(sensor).upper()
    meta = reg.get(code, {})
    # registry is authoritative; prefix fallback guarantees a non-None org for
    # any well-formed code so the ABSOLUTE routing rule holds even off-portal.
    return (code, meta.get('org') or _org_from_code_prefix(code))


# ======================================================================
#  destination directory (the routing decision)
# ======================================================================
def destination_dir(organization, code, when=None, make=True):
    """Resolve <root>/<CODE>/<YYYY-MM>/ from the org.

    FASTERUP_DIRECT -> LAPTOP_ROOT (never the portal)
    ICI_SOC / anything else -> PORTAL_REPORTS/<CODE>/<YYYY-MM>

    Returns absolute path. Raises RuntimeError if a direct-client path would ever
    resolve under the portal reports dir (hard guard against leaking direct
    reports onto the portal)."""
    when = when or datetime.now(timezone.utc)
    ym = when.strftime('%Y-%m')
    code_s = _safe(code)

    if organization == ORG_DIRECT:
        root = LAPTOP_ROOT
        dest = os.path.join(root, code_s, ym)
        # GUARD: a direct client's bundle must never land under the portal dir.
        real_portal = os.path.realpath(PORTAL_REPORTS)
        if os.path.realpath(os.path.dirname(dest) or dest).startswith(real_portal):
            raise RuntimeError(
                'refusing to route FASTERUP_DIRECT report under portal reports dir')
    else:
        # ICI_SOC (and safe default): keep on the portal, still per code/month so
        # the bundle stays grouped. The flat REPORTS_DIR download/list still works
        # because we ALSO leave a copy path the API can serve (see save_report_bundle).
        dest = os.path.join(PORTAL_REPORTS, code_s, ym)

    if make:
        os.makedirs(dest, exist_ok=True)
    return dest


def is_direct(organization):
    return organization == ORG_DIRECT


# ======================================================================
#  R12 — collect the sensor JSONs (discovery + findings) into the bundle
# ======================================================================
def collect_scan_jsons(host, scan_id, dest_dir, ssh_func=None):
    """Fetch <scan_id>.json (findings) and <scan_id>.discovery.json (discovery)
    from the sensor over SSH and write them into dest_dir as findings.json /
    discovery.json. Returns dict of what was written (paths) + any misses.

    ssh_func: the api_scan_common._ssh callable (host, cmd)->(rc,out,err). If not
    supplied it is imported. Kept injectable for testing / laptop runners."""
    if ssh_func is None:
        from app.routes.api_scan_common import _ssh as ssh_func
    os.makedirs(dest_dir, exist_ok=True)
    written, missing = {}, []

    def _pull(remote_paths, out_name):
        for rp in remote_paths:
            rc, out, _ = ssh_func(host, "cat {} 2>/dev/null".format(rp))
            if rc == 0 and out.strip():
                # validate it is JSON before saving (don't ship garbage annex)
                try:
                    json.loads(out)
                except ValueError:
                    continue
                path = os.path.join(dest_dir, out_name)
                with open(path, 'w', encoding='utf-8') as fh:
                    fh.write(out)
                written[out_name] = path
                return True
        missing.append(out_name)
        return False

    sid = re.sub(r'[^A-Za-z0-9_.-]', '', str(scan_id))[:60]
    _pull(["{}/{}.json".format(SCANS_DIR, sid)], 'findings.json')
    _pull(["{}/{}.discovery.json".format(SCANS_DIR, sid), DISCOVERY_FALLBACK],
          'discovery.json')
    return {'written': written, 'missing': missing, 'scan_id': sid}


def collect_scan_jsons_local(scan_id, dest_dir, scans_dir=SCANS_DIR):
    """Laptop/on-sensor variant: copy the JSONs from a local mount instead of SSH
    (used when the direct-client runner executes ON the sensor or on a mount)."""
    os.makedirs(dest_dir, exist_ok=True)
    written, missing = {}, []
    sid = re.sub(r'[^A-Za-z0-9_.-]', '', str(scan_id))[:60]
    pairs = [("{}/{}.json".format(scans_dir, sid), 'findings.json'),
             ("{}/{}.discovery.json".format(scans_dir, sid), 'discovery.json')]
    for src, name in pairs:
        if os.path.isfile(src):
            with open(src, 'r', encoding='utf-8', errors='replace') as fi:
                data = fi.read()
            try:
                json.loads(data)
            except ValueError:
                missing.append(name); continue
            dst = os.path.join(dest_dir, name)
            with open(dst, 'w', encoding='utf-8') as fo:
                fo.write(data)
            written[name] = dst
        else:
            missing.append(name)
    return {'written': written, 'missing': missing, 'scan_id': sid}


# ======================================================================
#  the single entry the /generate endpoints call
# ======================================================================
def save_report_bundle(*, organization, code, pdf_bytes=None, docx_bytes=None,
                       base_name=None, when=None, scan_jsons=None, host=None,
                       scan_id=None, ssh_func=None, make_zip=True,
                       serve_flat=True):
    """Write a per-client/per-month bundle and return a manifest.

    organization : 'FASTERUP_DIRECT' | 'ICI_SOC'      (routing)
    code         : client/sensor code (F003 / ICISOC107) — folder + filename base
    pdf_bytes    : report PDF bytes (optional)
    docx_bytes   : report Word bytes (optional)
    base_name    : filename stem (default 'Report_<CODE>_<ts>')
    scan_jsons   : if True, also collect discovery.json + findings.json. Requires
                   either (host + scan_id [+ ssh_func]) for SSH, or a pre-supplied
                   dict {'findings.json':bytes/str, 'discovery.json':...}.
    make_zip     : also produce <base_name>.zip of the whole folder.
    serve_flat   : for ICI_SOC, ALSO drop a copy of the PDF into the flat
                   PORTAL_REPORTS root so the existing /reports/download/<file>
                   and /reports/list endpoints keep working unchanged.

    Returns manifest dict: {dir, files:{...}, zip, organization, on_portal(bool)}.
    """
    when = when or datetime.now(timezone.utc)
    dest = destination_dir(organization, code, when=when, make=True)
    ts = when.strftime('%Y%m%d-%H%M%S')
    stem = _safe(base_name or 'Report_{}_{}'.format(_safe(code), ts))

    files = {}
    if pdf_bytes is not None:
        p = os.path.join(dest, stem + '.pdf')
        with open(p, 'wb') as fh:
            fh.write(pdf_bytes)
        files['pdf'] = p
    if docx_bytes is not None:
        p = os.path.join(dest, stem + '.docx')
        with open(p, 'wb') as fh:
            fh.write(docx_bytes)
        files['docx'] = p

    # ---- R12 annexes ----
    if scan_jsons:
        if isinstance(scan_jsons, dict):
            for name, blob in scan_jsons.items():
                if not name.endswith('.json'):
                    name += '.json'
                p = os.path.join(dest, _safe(name))
                mode = 'wb' if isinstance(blob, (bytes, bytearray)) else 'w'
                with open(p, mode) as fh:
                    fh.write(blob)
                files[name] = p
        elif host and scan_id:
            res = collect_scan_jsons(host, scan_id, dest, ssh_func=ssh_func)
            files.update(res['written'])
            if res['missing']:
                log.warning('R12 bundle %s: missing annexes %s', code, res['missing'])

    # ---- optional zip of the whole month folder's just-written set ----
    zip_path = None
    if make_zip and files:
        zip_path = os.path.join(dest, stem + '.zip')
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
            for f in files.values():
                z.write(f, arcname=os.path.basename(f))

    on_portal = organization != ORG_DIRECT
    # ---- keep the legacy flat portal download working for ICI_SOC ----
    flat_copy = None
    if on_portal and serve_flat and files.get('pdf'):
        os.makedirs(PORTAL_REPORTS, exist_ok=True)
        flat_copy = os.path.join(PORTAL_REPORTS, stem + '.pdf')
        # hardlink if same filesystem, else copy bytes
        try:
            if os.path.abspath(flat_copy) != os.path.abspath(files['pdf']):
                with open(files['pdf'], 'rb') as src, open(flat_copy, 'wb') as dst:
                    dst.write(src.read())
        except Exception as e:
            log.warning('flat portal copy failed: %s', e)
            flat_copy = None

    manifest = {
        'organization': organization,
        'code': code,
        'dir': dest,
        'files': files,
        'zip': zip_path,
        'on_portal': on_portal,
        'flat_pdf': flat_copy,
        'download_name': (stem + '.pdf') if flat_copy else None,
        'generated_at': when.isoformat(),
    }
    log.info('report bundle [%s/%s] -> %s (%d files, portal=%s)',
             organization, code, dest, len(files), on_portal)
    return manifest


# ======================================================================
#  convenience wrappers for the two endpoints
# ======================================================================
def route_alerts_report(client_id, pdf_bytes, docx_bytes, period, lang,
                        db_path=None, when=None):
    """Called by api_reports /reports/generate after building PDF+DOCX."""
    code, org = resolve_org_by_agent(client_id, db_path=db_path)
    when = when or datetime.now(timezone.utc)
    base = 'Report_{}_{}_{}'.format(_safe(code), _safe(period),
                                    when.strftime('%Y%m%d-%H%M%S'))
    return save_report_bundle(organization=org or ORG_ICI, code=code,
                              pdf_bytes=pdf_bytes, docx_bytes=docx_bytes,
                              base_name=base, when=when, scan_jsons=None)


def route_scan_report(sensor, pdf_bytes, docx_bytes, rtype, lang, host,
                      scan_id, ssh_func=None, sensors_registry=None, when=None):
    """Called by api_c3scan /c3scan/report after building PDF+DOCX. Also attaches
    the R12 annexes (discovery.json + findings.json) pulled from the sensor."""
    code, org = resolve_org_by_sensor(sensor, sensors_registry=sensors_registry)
    when = when or datetime.now(timezone.utc)
    base = 'Report_{}_c3scan_{}_{}'.format(re.sub(r'[^A-Za-z0-9]', '', str(sensor)),
                                           rtype, when.strftime('%Y%m%d-%H%M%S'))
    return save_report_bundle(organization=org or ORG_ICI, code=code,
                              pdf_bytes=pdf_bytes, docx_bytes=docx_bytes,
                              base_name=base, when=when, scan_jsons=True,
                              host=host, scan_id=scan_id, ssh_func=ssh_func)
