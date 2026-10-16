C=/etc/wazuh-indexer/certs
curl -sk --cert $C/admin.pem --key $C/admin-key.pem --cacert $C/root-ca.pem -H 'Content-Type: application/json' "https://127.0.0.1:9200/wazuh-alerts-*/_search" -d '{"size":0,"query":{"bool":{"filter":[{"range":{"timestamp":{"gte":"now-24h"}}},{"terms":{"agent.name":["icisoc101","icisoc103","icisoc104","icisoc105","icisoc106","icisoc109","icisoc102","icisoc108"]}}]}},
"aggs":{"ag":{"terms":{"field":"agent.name","size":20},"aggs":{"lvl":{"range":{"field":"rule.level","ranges":[{"to":7},{"from":7,"to":10},{"from":10}]}},"hi":{"filter":{"range":{"rule.level":{"gte":10}}},"aggs":{"sig":{"terms":{"field":"data.alert.signature","size":3}}}},"top":{"terms":{"field":"data.alert.signature","size":3}}}}}}' | python3 -c '
import json,sys
d=json.load(sys.stdin)
for b in sorted(d["aggregations"]["ag"]["buckets"], key=lambda x:x["key"]):
    l={x["key"]:x["doc_count"] for x in b["lvl"]["buckets"]}
    print("%-10s total=%-6d <7=%-6s 7-9=%-6s >=10=%-5s" % (b["key"], b["doc_count"], l.get("*-7.0",0), l.get("7.0-10.0",0), l.get("10.0-*",0)))
    print("    top:", "; ".join("%dx %s" % (x["doc_count"], x["key"][:55]) for x in b["top"]["buckets"]))
    if b["hi"]["doc_count"]: print("    >=10:", "; ".join("%dx %s" % (x["doc_count"], x["key"][:55]) for x in b["hi"]["sig"]["buckets"]))'
