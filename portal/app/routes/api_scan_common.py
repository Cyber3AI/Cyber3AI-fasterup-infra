"""Helper-e partajate pentru scanare (registru senzori, SSH, vizibilitate, permisiuni).
Helper-e de scanare; folosite de CYBER3 Global Scan (api_c3scan)."""
import subprocess
from flask_login import current_user

# Registru senzori (host VPN, agent Wazuh, organizatie).
SENSORS = {
    'ICISOC101': {'host': '10.1.22.1', 'agent': '003', 'org': 'ICI_SOC',         'scan_ok': True},
    'ICISOC102': {'host': '10.1.25.1', 'agent': '007', 'org': 'ICI_SOC',         'scan_ok': True},
    'ICISOC103': {'host': '10.1.26.1', 'agent': '006', 'org': 'ICI_SOC',         'scan_ok': True},
    'ICISOC104': {'host': '10.1.27.1', 'agent': '008', 'org': 'ICI_SOC',         'scan_ok': True},
    'ICISOC105': {'host': '10.1.28.1', 'agent': '009', 'org': 'ICI_SOC',         'scan_ok': True},
    'ICISOC106': {'host': '10.1.29.1', 'agent': '010', 'org': 'ICI_SOC',         'scan_ok': False},
    'ICISOC108': {'host': '10.1.31.1', 'agent': '013', 'org': 'ICI_SOC',         'scan_ok': True},
    'ICISOC107': {'host': '10.1.30.1', 'agent': '011', 'org': 'ICI_SOC',         'scan_ok': True},
    'ICISOC109': {'host': '10.1.32.1', 'agent': '015', 'org': 'ICI_SOC',         'scan_ok': True},
    'ICISOC110': {'host': '10.1.33.1', 'agent': '016', 'org': 'ICI_SOC',         'scan_ok': True},
    'F001':      {'host': '10.1.1.1',  'agent': '005', 'org': 'FASTERUP_DIRECT', 'scan_ok': True},
    'F002':      {'host': '10.1.2.1',  'agent': '012', 'org': 'FASTERUP_DIRECT', 'scan_ok': True},
    'F003':      {'host': '10.1.3.1',  'agent': '014', 'org': 'FASTERUP_DIRECT', 'scan_ok': True},
    'F004':      {'host': '10.1.4.1',  'agent': '017', 'org': 'FASTERUP_DIRECT', 'scan_ok': True},
    'F005':      {'host': '10.1.5.1',  'agent': '018', 'org': 'FASTERUP_DIRECT', 'scan_ok': True},
}
SSH_USER = 'socadmin'


def _is_supervisor():
    return getattr(current_user, 'role', '') == 'supervisor'


def _visible_sensors():
    """Senzorii vizibili utilizatorului curent, filtrați pe organizație."""
    if _is_supervisor():
        return dict(SENSORS)
    org = getattr(current_user, 'organization', None)
    return {k: v for k, v in SENSORS.items() if v.get('org') == org}


def _can_generate():
    """Generare scan: supervisor sau analist FASTERUP_DIRECT."""
    if not getattr(current_user, 'is_authenticated', False):
        return False
    return _is_supervisor() or getattr(current_user, 'organization', '') == 'FASTERUP_DIRECT'


def _ssh(host, command, timeout=20):
    try:
        r = subprocess.run(
            ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
             '-o', 'StrictHostKeyChecking=accept-new',
             '{}@{}'.format(SSH_USER, host), command],
            capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, '', 'ssh timeout'
    except Exception as e:
        return 1, '', str(e)
