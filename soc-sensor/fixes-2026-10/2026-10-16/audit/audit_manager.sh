#!/bin/bash
# AUDIT READ-ONLY manager 10.0.0.100 (14.10.2026 seara). Nu modifică nimic.
export LC_ALL=C
F=/var/ossec/integrations/cyberbot.py; CL=/var/ossec/logs/cyberbot.log; C=/etc/wazuh-indexer/certs
q(){ curl -sk --cert $C/admin.pem --key $C/admin-key.pem --cacert $C/root-ca.pem -H 'Content-Type: application/json' "https://127.0.0.1:9200/$1" ${2:+-d "$2"}; }
echo "== CyberBot"
echo "md5=$(md5sum $F | cut -c1-12) $(stat -c '%U:%G %a' $F) marcaje: DNS=$(grep -c C3-FIX-20260930-IOC-DNS $F) CDN=$(grep -c C3-FIX-20261014-IOC-CDN $F) AWS=$(grep -c C3-FIX-20261014-IOC-AWS $F) | aws-ipv4: $(grep -vc '^#' /var/ossec/integrations/aws-ipv4.txt) rețele $(stat -c '%U:%G %a' /var/ossec/integrations/aws-ipv4.txt)"
echo "ultima intrare: $(tail -1 $CL | cut -c1-23) (acum $(date -u '+%F %T'))"
echo "ultimele 60 min pe tip: $(awk -v t="[$(date -u -d '-60 min' '+%F %T')" '$0 >= t' $CL | grep -oE '^\[[^]]+\] \[[A-Z_]+\]' | awk '{print $3}' | sort | uniq -c | sort -rn | tr '\n' ' ')"
echo "erori de la 16:45: $(awk '$0 >= "[2026-10-14 16:45"' $CL | grep -c '\[ERROR\]') | IOC de la 16:45: $(awk '$0 >= "[2026-10-14 16:45"' $CL | grep -oE '\[IOC_[A-Z_]+\]' | sort | uniq -c | tr '\n' ' ')"
echo "BLOCK_IP/PERMA de la 16:00 (ținte private?): $(awk '$0 >= "[2026-10-14 16:00"' $CL | grep -E '\[(BLOCK_IP|PERMA_REBLOCK|IOC_BLOCK)\]' | grep -oE 'ip=[0-9.]+' | cut -d= -f2 | grep -cE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') private din $(awk '$0 >= "[2026-10-14 16:00"' $CL | grep -cE '\[(BLOCK_IP|PERMA_REBLOCK|IOC_BLOCK)\]')"
echo "test IMPORT fișier LIVE (efecte simulate, nimic real):"
cat > /tmp/aud_cb_live.py <<'PY'
import sys, importlib.util
sys.path.insert(0, '/var/ossec/integrations')
spec = importlib.util.spec_from_file_location('cb_live', '/var/ossec/integrations/cyberbot.py'); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
ev = []
m.log_event = lambda t, msg: ev.append(t)
m.block_ip = lambda ip, aid='001': ev.append('BLOCK') or True
m.is_duplicate = lambda *a, **k: False
m.mark_sent = lambda *a, **k: None
m.send_telegram = lambda *a, **k: ev.append('TELEGRAM')
m.resolve_client = lambda *a, **k: {}
def run(dst, sig, port, proto):
    ev.clear()
    m.handle_misp_ioc({'data': {'alert': {'signature': sig}, 'dest_port': port, 'app_proto': proto}, 'rule': {'description': 'x'}}, '192.168.1.50', dst, 7, '100240', 'f009', '022')
    return ','.join(ev)
T='CYBER3 MISP IOC - domeniu in TLS SNI'
for dst, sig, port, proto, want in [('54.86.13.26',T,'443','tls','IOC_CDN'),('104.21.92.59',T,'443','tls','IOC_CDN'),
        ('185.220.101.5',T,'443','tls','BLOCK'),('8.8.8.8',T,'443','tls','IOC_WHITELIST'),('193.231.100.130','CYBER3 MISP IOC - domeniu in DNS query','53','dns','IOC_DNS_ONLY')]:
    got = run(dst, sig, port, proto); print(f"   {'OK ' if want in got.split(',') else 'EȘEC'} {dst:16} -> {got}")
print("   is_internal_ip(192.168.1.5)=%s is_internal_ip(109.103.139.130)=%s is_internal_ip(185.220.101.5)=%s" % (m.is_internal_ip('192.168.1.5'), m.is_internal_ip('109.103.139.130'), m.is_internal_ip('185.220.101.5')))
PY
chmod 644 /tmp/aud_cb_live.py; sudo -u wazuh /usr/bin/python3 /tmp/aud_cb_live.py; rm -f /tmp/aud_cb_live.py
echo "== Wazuh manager"
/var/ossec/bin/wazuh-control status 2>/dev/null | grep -v 'is running' | sed 's/^/   NU RULEAZĂ: /'; echo "   servicii care rulează: $(/var/ossec/bin/wazuh-control status 2>/dev/null | grep -c 'is running')"
echo "agenți: $(/var/ossec/bin/agent_control -l | grep -c 'Active') activi; neconectați: $(/var/ossec/bin/agent_control -l | grep -E 'Disconnected|Never' | awk -F'Name: ' '{print $2}' | cut -d, -f1 | tr '\n' ' ')"
echo "analysisd: $(grep -E '^(events_dropped|events_received|alerts_written|event_queue_usage)=' /var/ossec/var/run/wazuh-analysisd.state | tr '\n' ' ')"
echo "remoted: $(grep -E '^(discarded_count|queue_size|recv_breakdown)' /var/ossec/var/run/wazuh-remoted.state 2>/dev/null | tr '\n' ' ')"
echo "alerts.log ultima: $(tail -c 300 /var/ossec/logs/alerts/alerts.json | grep -oE '"timestamp":"[^"]+' | tail -1)"
echo "== Indexer"
echo "health: $(q '_cluster/health' | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["status"], "unassigned", d["unassigned_shards"])')"
q 'wazuh-alerts-*/_search' '{"size":0,"query":{"range":{"timestamp":{"gte":"now-24h"}}},"aggs":{"ag":{"terms":{"field":"agent.name","size":50},"aggs":{"last":{"max":{"field":"timestamp"}},"h1":{"filter":{"range":{"timestamp":{"gte":"now-1h"}}}}}}}}' | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("alerte/agent 24h | ultima | ultima oră:")
for b in sorted(d["aggregations"]["ag"]["buckets"], key=lambda x: x["key"]):
    print("   %-12s %7d  %s  %5d" % (b["key"], b["doc_count"], b["last"].get("value_as_string","")[:16], b["h1"]["doc_count"]))'
q 'wazuh-alerts-*/_search' '{"size":0,"query":{"bool":{"filter":[{"range":{"timestamp":{"gte":"2026-10-14T16:17:00"}}},{"terms":{"data.alert.signature_id":["3900001","3900002","3100010","3100011","3100012","9100901","9100930","9100931"]}}]}},"aggs":{"ag":{"terms":{"field":"agent.name","size":40},"aggs":{"s":{"terms":{"field":"data.alert.signature_id"}}}}}}' | python3 -c '
import json,sys
d=json.load(sys.stdin); b=d["aggregations"]["ag"]["buckets"]
print("alerte CYBER3/MISP de la 16:17 UTC:", ", ".join("%s=%s" % (x["key"], {s["key"]:s["doc_count"] for s in x["s"]["buckets"]}) for x in b) or "0")'
echo "== Cron"
crontab -l -u root | grep -E 'refresh-domains|refresh-aws' | sed 's/^/   /'
echo "/srv: $(sha256sum /srv/cyber3/misp-domains.lst | cut -c1-12) $(wc -l < /srv/cyber3/misp-domains.lst) | aws log: $(tail -1 /var/log/cyber3-aws-refresh.log)"
echo "== Sistem: load $(cut -d' ' -f1-3 /proc/loadavg) mem_avail $(awk '/MemAvailable/{printf "%.1fG",$2/1048576}' /proc/meminfo) swap_used $(free -m | awk '/Swap/{print $3}')M disk / $(df -h / | awk 'END{print $5}') /var $(df -h /var | awk 'END{print $5}')"
