#!/usr/bin/env python3
# CYBER3 — reîmprospătare lunară a listei AWS folosite de CyberBot la excepțiile IOC (C3-FIX-20261014-IOC-AWS).
# Sursă: lista oficială https://ip-ranges.amazonaws.com/ip-ranges.json (service AMAZON, IPv4), comprimată.
# Rulează pe MANAGER (cron root, lunar). CyberBot citește fișierul la fiecare proces nou => fără restart.
# GĂRZI: JSON valid + syncToken; ≥3000 prefixe / ≥1000 rețele comprimate; nu scade cu peste 30% față de lista curentă;
# scriere atomică (tmp + rename), root:wazuh 640. La orice eșec lista curentă rămâne neatinsă.
import json, ipaddress, os, sys, datetime, urllib.request, grp

URL = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
OUT = '/var/ossec/integrations/aws-ipv4.txt'
LOG = '/var/log/cyber3-aws-refresh.log'


def log(m):
    with open(LOG, 'a') as f:
        f.write(f"{datetime.datetime.utcnow().isoformat()}Z {m}\n")


def current_count():
    try:
        return sum(1 for l in open(OUT) if l.strip() and not l.startswith('#'))
    except OSError:
        return 0


try:
    with urllib.request.urlopen(URL, timeout=60) as r:
        j = json.load(r)
    token, created = j['syncToken'], j['createDate']
    nets = [ipaddress.ip_network(p['ip_prefix']) for p in j['prefixes'] if p.get('service') == 'AMAZON']
    col = list(ipaddress.collapse_addresses(nets))
    old = current_count()
    if len(nets) < 3000 or len(col) < 1000:
        log(f"ABORT: prea puține ({len(nets)} prefixe / {len(col)} rețele) — lista curentă păstrată ({old})"); sys.exit(1)
    if old and len(col) < old * 0.7:
        log(f"ABORT: scădere suspectă {old} -> {len(col)} rețele — lista curentă păstrată"); sys.exit(1)
    tmp = OUT + '.tmp'
    with open(tmp, 'w') as f:
        f.write(f"# AWS IPv4 (service AMAZON, ip-ranges.json createDate {created}, syncToken {token}) — comprimat\n")
        f.write('\n'.join(str(n) for n in col) + '\n')
    os.chown(tmp, 0, grp.getgrnam('wazuh').gr_gid)
    os.chmod(tmp, 0o640)
    os.replace(tmp, OUT)
    log(f"OK {len(col)} rețele ({len(nets)} prefixe AMAZON, createDate {created}); înainte {old}")
    print(len(col))
except SystemExit:
    raise
except Exception as e:
    log(f"FAIL {e} — lista curentă păstrată")
    sys.exit(1)
