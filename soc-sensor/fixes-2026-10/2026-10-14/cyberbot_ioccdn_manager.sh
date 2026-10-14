#!/bin/bash
# Rulează PE MANAGER (10.0.0.100) ca root. C3-FIX-20261014-IOC-CDN: CyberBot NU mai blochează IOC (HTTP/TLS) pe IP-uri din
# rețele CDN/cloud partajate (aceleași 45 de game ca PROTECTED_CIDRS din cyber3-permaban.sh) — doar jurnal IOC_CDN.
# Pași: backup → patch pe COPIE → compilare → test prin import cu efecte simulate (fără blocări/mesaje reale) → instalare.
# CyberBot rulează per alertă (fără restart). Revert: cp cyberbot.py.bak-ioccdn-<TS> cyberbot.py
set -u
F=/var/ossec/integrations/cyberbot.py; TS=$(date -u +%Y%m%d-%H%M%S); T=/tmp/cyberbot_ioccdn_$TS.py
grep -q 'C3-FIX-20261014-IOC-CDN' $F && { echo "deja aplicat (md5 $(md5sum $F | cut -c1-12))"; exit 0; }
cp -a $F $F.bak-ioccdn-$TS; cp $F $T; chown "$(stat -c %U $F):$(stat -c %G $F)" $T; chmod 640 $T
SB=$(head -1 $F | sed 's/^#!//')
case "$SB" in "/usr/bin/env "*) PY=$(command -v ${SB#/usr/bin/env });; *) PY=${SB%% *};; esac
[ -x "$PY" ] || PY=$(command -v python3)
echo "shebang: $SB -> interpretor test: $PY ($($PY -V 2>&1)) | integrarea custom-cyberbot: $(grep -m1 -oE '(python3?|/[^ ]*python[0-9.]*)[^ ]*' /var/ossec/integrations/custom-cyberbot 2>/dev/null) | md5 înainte $(md5sum $F | cut -c1-12)"

python3 - "$T" <<'PATCH' || { echo "ABORT: patch eșuat — nimic schimbat"; rm -f $T; exit 2; }
import sys
p = sys.argv[1]; s = open(p).read()
A = "def _is_ioc_alert(alert):\n"
B = ("    if cand in _IOC_WL_EXACT or cand.startswith(_IOC_WL_PREFIX):\n"
     "        log_event('IOC_WHITELIST', f'ip={cand} protejat_nu_blocam agent={agent_name} sig=\"{_sig(alert)[:45]}\"')\n"
     "        return\n")
assert s.count(A) == 1, f"ancora A gasita de {s.count(A)} ori"
assert s.count(B) == 1, f"ancora B gasita de {s.count(B)} ori"
CDN = ("8.8.4.0/24 8.8.8.0/24 142.250.0.0/15 172.217.0.0/16 216.58.192.0/19 172.253.0.0/16 74.125.0.0/16 64.233.160.0/19 "
       "209.85.128.0/17 173.194.0.0/16 108.177.0.0/17 13.64.0.0/11 13.104.0.0/14 20.0.0.0/8 40.64.0.0/10 52.96.0.0/12 "
       "52.112.0.0/14 204.79.197.0/24 131.253.0.0/16 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 "
       "141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 "
       "104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 23.0.0.0/12 23.32.0.0/11 23.64.0.0/14 104.64.0.0/10 "
       "2.16.0.0/13 92.122.0.0/15 95.100.0.0/15 184.24.0.0/13 151.101.0.0/16 199.232.0.0/16 217.156.52.0/24")
helper = ("# C3-FIX-20261014-IOC-CDN: IOC pe un IP din retea CDN/cloud partajata (Google, Microsoft, Cloudflare, Akamai, Fastly, ANAF)\n"
          "# = IP partajat de mii de site-uri legitime; blocarea lui taie trafic legitim. Doar jurnal, fara blocare/mesaj.\n"
          "# Aceleasi game ca PROTECTED_CIDRS din cyber3-permaban.sh (senzori). Caz istoric: 104.21.92.59 (Cloudflare), f001, iul 2026.\n"
          "import ipaddress as _c3_ipa\n"
          f"_IOC_CDN_NETS = [_c3_ipa.ip_network(_c) for _c in \"{CDN}\".split()]\n"
          "def _ioc_is_cdn(ip):\n"
          "    try:\n"
          "        _a = _c3_ipa.ip_address(ip)\n"
          "    except ValueError:\n"
          "        return False\n"
          "    return any(_a in _n for _n in _IOC_CDN_NETS)\n\n")
check = ("    if _ioc_is_cdn(cand):\n"
         "        log_event('IOC_CDN', f'ip={cand} retea_CDN_partajata_nu_blocam agent={agent_name} src={src_ip} sig=\"{_sig(alert)[:45]}\"')\n"
         "        return\n")
s = s.replace(A, helper + A, 1).replace(B, B + check, 1)
open(p, "w").write(s)
print("patch aplicat pe copie (helper + verificare după IOC_WHITELIST)")
PATCH

$PY -m py_compile $T || { echo "ABORT: compilare eșuată — nimic schimbat"; rm -f $T; exit 2; }

cat > /tmp/test_ioccdn_$TS.py <<'TEST'
import sys, importlib.util
sys.path.insert(0, '/var/ossec/integrations')
spec = importlib.util.spec_from_file_location('cb_test', sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
ev = []
m.log_event = lambda t, msg: ev.append((t, msg))
m.block_ip = lambda ip, aid='001': ev.append(('BLOCK', ip)) or True
m.is_duplicate = lambda *a, **k: False
m.mark_sent = lambda *a, **k: None
m.send_telegram = lambda *a, **k: ev.append(('TELEGRAM', ''))
m.resolve_client = lambda *a, **k: {}
def run(dst, sig, port='443', proto='tls'):
    ev.clear()
    al = {'data': {'alert': {'signature': sig}, 'dest_port': port, 'app_proto': proto}, 'rule': {'description': 'CYBER3 MISP IOC'}}
    m.handle_misp_ioc(al, '192.168.1.50', dst, 7, '100240', 'f009', '022')
    return [e[0] for e in ev]
cases = [
  ('104.21.92.59',  'CYBER3 MISP IOC - domeniu in TLS SNI', '443', 'tls',  'IOC_CDN',   'Cloudflare (cazul istoric f001)'),
  ('151.101.1.69',  'CYBER3 MISP IOC - domeniu in HTTP Host', '80', 'http', 'IOC_CDN',   'Fastly'),
  ('23.45.67.89',   'CYBER3 MISP IOC - domeniu in TLS SNI', '443', 'tls',  'IOC_CDN',   'Akamai'),
  ('20.57.198.228', 'CYBER3 MISP IOC - domeniu in TLS SNI', '443', 'tls',  'IOC_CDN',   'Microsoft Azure'),
  ('185.220.101.5', 'CYBER3 MISP IOC - domeniu in TLS SNI', '443', 'tls',  'BLOCK',     'IP dedicat (nu CDN) -> se blochează în continuare'),
  ('8.8.8.8',       'CYBER3 MISP IOC - domeniu in TLS SNI', '443', 'tls',  'IOC_WHITELIST', 'rezolver (lista existentă)'),
  ('193.231.100.130','CYBER3 MISP IOC - domeniu in DNS query','53', 'dns', 'IOC_DNS_ONLY', 'DNS (regula din 30 sep)'),
]
bad = 0
for dst, sig, port, proto, want, why in cases:
    got = run(dst, sig, port, proto)
    ok = want in got and (want == 'BLOCK' or 'BLOCK' not in got)
    bad += not ok
    print(f"  {'OK ' if ok else 'EȘEC'} {dst:16} -> {','.join(got):28} (așteptat {want}; {why})")
sys.exit(1 if bad else 0)
TEST
chmod 644 /tmp/test_ioccdn_$TS.py
echo "test pe copie, cu efecte simulate (nicio blocare/mesaj real):"
sudo -u wazuh $PY /tmp/test_ioccdn_$TS.py $T || { echo "ABORT: test eșuat — fișierul live NESCHIMBAT"; rm -f $T /tmp/test_ioccdn_$TS.py; exit 2; }
install -o "$(stat -c %U $F)" -g "$(stat -c %G $F)" -m "$(stat -c %a $F)" $T $F
rm -f $T /tmp/test_ioccdn_$TS.py
echo "INSTALAT: md5 $(md5sum $F | cut -c1-12) | backup $F.bak-ioccdn-$TS | owner $(stat -c '%U:%G %a' $F)"
echo "CyberBot ultimele 3 evenimente (rulează per alertă, fără restart):"; tail -3 /var/ossec/logs/cyberbot.log | cut -c1-140
