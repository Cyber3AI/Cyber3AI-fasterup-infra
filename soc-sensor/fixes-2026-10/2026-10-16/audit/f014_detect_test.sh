#!/bin/bash
# TEST EMPIRIC DE DETECȚIE pe f014 (laborator, NEINLINE). Trafic generat LOCAL (interfața lo), capturat în pcap, apoi
# trecut prin Suricata în mod offline (-r) cu configurația și regulile reale (suricata.yaml, 3 rule files, dataset 597k).
# Nu atinge instanța Suricata care rulează, nici rețeaua. Totul în /tmp/c3dt, șters la final.
set -u
[ "$(cat /sys/class/net/br0/carrier)" = 0 ] || { echo "ABORT: f014 e cablat inline"; exit 3; }
W=/tmp/c3dt; rm -rf $W; mkdir -p $W/log; cd $W
DS=/etc/suricata/datasets/misp-domains.lst
# domeniu IOC real din dataset (primul care arată a domeniu normal)
DOM=$(head -2000 $DS | while read l; do d=$(echo "$l" | base64 -d 2>/dev/null); case "$d" in *.*) echo "$d"; break;; esac; done)
echo "domeniu IOC din dataset: $DOM"
grep -qxF "$(printf '%s' "$DOM" | base64)" $DS && echo "   (confirmat prezent în dataset ca base64)"
tcpdump -i lo -w $W/t.pcap -U 'port 53 or port 8443 or port 8080 or (tcp[13] & 2 != 0 and dst port 4444)' >/dev/null 2>&1 & TP=$!; sleep 2
# 1) DNS query (stub resolver local 127.0.0.53)
dig +tries=1 +time=2 "$DOM" @127.0.0.53 >/dev/null 2>&1
# 2) TLS SNI
openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 1 -subj "/CN=test" >/dev/null 2>&1
openssl s_server -accept 127.0.0.1:8443 -cert c.pem -key k.pem -quiet >/dev/null 2>&1 & SP=$!; sleep 1
echo | timeout 5 openssl s_client -connect 127.0.0.1:8443 -servername "$DOM" >/dev/null 2>&1
# 3) HTTP Host
python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 & HP=$!; sleep 1
curl -s -m 5 -H "Host: $DOM" http://127.0.0.1:8080/ >/dev/null 2>&1
# 4) masscan-style: 20 SYN cu window 1300, sursă HOME_NET (10.99.99.1) -> destinație externă (127.0.0.1), pe lo
python3 - <<'PY'
import socket, struct, random
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16; return ~s & 0xffff
src, dst = '10.99.99.1', '127.0.0.1'
sk = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW); sk.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for i in range(20):
    sp = 40000 + i
    tcp = struct.pack('!HHLLBBHHH', sp, 4444, random.randint(1, 2**31), 0, 5 << 4, 0x02, 1300, 0, 0)
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), random.randint(0, 65535), 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    sk.sendto(ip + tcp, (dst, 0))
print("   20 SYN window=1300 trimise")
PY
sleep 2; kill $TP $SP $HP 2>/dev/null; wait 2>/dev/null
echo "pcap: $(tcpdump -r $W/t.pcap 2>/dev/null | wc -l) pachete"
# rulare offline cu configurația reală (fără checksum: lo nu calculează checksum-uri reale)
T0=$(date +%s)
suricata -r $W/t.pcap -c /etc/suricata/suricata.yaml -l $W/log -k none --runmode single >$W/run.txt 2>&1
echo "suricata -r: rc=$? în $(( $(date +%s)-T0 )) s | $(grep -oE '[0-9]+ rule files processed. [0-9]+ rules successfully loaded, [0-9]+ rules failed' $W/run.txt $W/log/suricata.log 2>/dev/null | tail -1 | cut -d: -f2-) | erori: $(grep -c '<Error>' $W/log/suricata.log 2>/dev/null)"
echo "ALERTE (sid / acțiune / semnătură):"
cat $W/log/eve*.json 2>/dev/null | grep '"event_type":"alert"' | python3 -c '
import sys, json, collections
c = collections.Counter()
for l in sys.stdin:
    e = json.loads(l); a = e["alert"]; c[(a["signature_id"], a.get("action"), a["signature"][:60])] += 1
for (sid, act, sig), n in sorted(c.items()): print("   %8s  %-8s %3dx  %s" % (sid, act, n, sig))'
[ -s $W/log/fast.log ] && echo "fast.log: $(wc -l < $W/log/fast.log) linii"
cd /; rm -rf $W
