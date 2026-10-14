#!/bin/bash
# Rulează PE MANAGER ca root. C3-FIX-20261014-IOC-AWS: excepțiile IOC din CyberBot includ și AWS (ip-ranges.json oficial,
# service AMAZON, 1.741 rețele comprimate) din /var/ossec/integrations/aws-ipv4.txt. Încărcare leneșă (doar la o alertă IOC).
# Fișier lipsă/ilizibil => doar cele 45 de rețele CDN (comportamentul de azi). Backup → patch pe COPIE → test simulat → instalare.
set -u
F=/var/ossec/integrations/cyberbot.py; A=/var/ossec/integrations/aws-ipv4.txt; TS=$(date -u +%Y%m%d-%H%M%S); T=/tmp/cyberbot_iocaws_$TS.py
grep -q 'C3-FIX-20261014-IOC-AWS' $F && { echo "deja aplicat (md5 $(md5sum $F | cut -c1-12))"; exit 0; }
grep -q 'C3-FIX-20261014-IOC-CDN' $F || { echo "ABORT: lipsește fixul CDN (premisă)"; exit 2; }
install -o root -g wazuh -m 640 /tmp/aws-ipv4.txt $A && echo "lista AWS: $(grep -vc '^#' $A) rețele, sha $(sha256sum $A | cut -c1-12)"
cp -a $F $F.bak-iocaws-$TS; cp $F $T; chown "$(stat -c %U $F):$(stat -c %G $F)" $T; chmod 640 $T
echo "md5 înainte $(md5sum $F | cut -c1-12)"
python3 - "$T" <<'PATCH' || { echo "ABORT: patch eșuat — nimic schimbat"; rm -f $T; exit 2; }
import sys
p = sys.argv[1]; s = open(p).read()
old = ("def _ioc_is_cdn(ip):\n"
       "    try:\n"
       "        _a = _c3_ipa.ip_address(ip)\n"
       "    except ValueError:\n"
       "        return False\n"
       "    return any(_a in _n for _n in _IOC_CDN_NETS)\n")
assert s.count(old) == 1, f"ancora gasita de {s.count(old)} ori"
new = ("# C3-FIX-20261014-IOC-AWS: + AWS (ip-ranges.json oficial, service AMAZON, comprimat) din /var/ossec/integrations/aws-ipv4.txt.\n"
       "# Incarcare lenesa (doar la prima alerta IOC din proces). Fisier lipsa/ilizibil => doar retelele CDN de mai sus.\n"
       "_IOC_AWS_NETS = None\n"
       "def _ioc_aws_nets():\n"
       "    global _IOC_AWS_NETS\n"
       "    if _IOC_AWS_NETS is None:\n"
       "        try:\n"
       "            _IOC_AWS_NETS = [_c3_ipa.ip_network(_l.strip()) for _l in open('/var/ossec/integrations/aws-ipv4.txt')\n"
       "                             if _l.strip() and not _l.startswith('#')]\n"
       "        except Exception:\n"
       "            _IOC_AWS_NETS = []\n"
       "    return _IOC_AWS_NETS\n"
       "def _ioc_is_cdn(ip):\n"
       "    try:\n"
       "        _a = _c3_ipa.ip_address(ip)\n"
       "    except ValueError:\n"
       "        return False\n"
       "    return any(_a in _n for _n in _IOC_CDN_NETS) or any(_a in _n for _n in _ioc_aws_nets())\n")
open(p, "w").write(s.replace(old, new, 1)); print("patch aplicat pe copie")
PATCH
/usr/bin/python3 -m py_compile $T || { echo "ABORT: compilare — nimic schimbat"; rm -f $T; exit 2; }
cat > /tmp/test_iocaws_$TS.py <<'TEST'
import sys, importlib.util, time
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
    m.handle_misp_ioc(al, '192.168.1.50', dst, 7, '100240', 'icisoc105', '009')
    return [e[0] for e in ev]
T = 'CYBER3 MISP IOC - domeniu in TLS SNI'
cases = [
  ('54.86.13.26',   T, '443', 'tls', 'IOC_CDN', 'AWS (blocat azi 14:11, icisoc105)'),
  ('100.57.136.27', T, '443', 'tls', 'IOC_CDN', 'AWS (blocat azi 14:11, icisoc105)'),
  ('104.21.92.59',  T, '443', 'tls', 'IOC_CDN', 'Cloudflare (fixul CDN rămâne)'),
  ('20.57.198.228', T, '443', 'tls', 'IOC_CDN', 'Microsoft Azure'),
  ('185.220.101.5', T, '443', 'tls', 'BLOCK',   'IP dedicat -> se blochează în continuare'),
  ('8.8.8.8',       T, '443', 'tls', 'IOC_WHITELIST', 'rezolver'),
  ('193.231.100.130','CYBER3 MISP IOC - domeniu in DNS query','53','dns','IOC_DNS_ONLY','DNS'),
]
bad = 0
t0 = time.time()
for dst, sig, port, proto, want, why in cases:
    got = run(dst, sig, port, proto)
    ok = want in got and (want == 'BLOCK' or 'BLOCK' not in got)
    bad += not ok
    print(f"  {'OK ' if ok else 'EȘEC'} {dst:16} -> {','.join(got):24} (așteptat {want}; {why})")
print(f"  rețele AWS încărcate: {len(m._ioc_aws_nets())} | durată totală test: {(time.time()-t0)*1000:.0f} ms")
sys.exit(1 if bad or len(m._ioc_aws_nets()) < 1000 else 0)
TEST
chmod 644 /tmp/test_iocaws_$TS.py
echo "test pe copie, efecte simulate (nicio blocare/mesaj real):"
sudo -u wazuh /usr/bin/python3 /tmp/test_iocaws_$TS.py $T || { echo "ABORT: test eșuat — fișierul live NESCHIMBAT"; rm -f $T /tmp/test_iocaws_$TS.py; exit 2; }
install -o "$(stat -c %U $F)" -g "$(stat -c %G $F)" -m "$(stat -c %a $F)" $T $F
rm -f $T /tmp/test_iocaws_$TS.py /tmp/aws-ipv4.txt
echo "INSTALAT: md5 $(md5sum $F | cut -c1-12) | backup $F.bak-iocaws-$TS | $(stat -c '%U:%G %a' $F)"
sleep 20; echo "după instalare: $(tail -1 /var/ossec/logs/cyberbot.log | cut -c1-90) | erori noi: $(tail -200 /var/ossec/logs/cyberbot.log | grep -c '\[ERROR\]')"
