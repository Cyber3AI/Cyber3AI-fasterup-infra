#!/usr/bin/env python3
"""CYBER3 SOC — receiver de pe senzor (Faza 2, calea PRIMARĂ a punții CYBER3→SOC).

Endpoint-urile CYBER3 din LAN-ul clientului descoperă senzorul (broadcast UDP) și îi trimit
evenimente de securitate (HTTP). Receiver-ul le scrie în /var/log/cyber3/events.json, de unde
agentul Wazuh al senzorului le expediază la manager (canalul existent, prin VPN) — fără transport nou.

Doar scrie un log + răspunde la descoperire. NU atinge Suricata/bridge-ul (internetul clientului
neafectat). Alert-only: evenimentele nu declanșează nicio acțiune pe senzor.

Config (env, din /etc/default/cyber3-soc-receiver):
  CYBER3_ORG        organizația senzorului (ex. ICI_SOC) — eticheta pusă pe evenimente
  CYBER3_HTTP_PORT  port HTTP (implicit 8765)
  CYBER3_UDP_PORT   port descoperire UDP (implicit 8766)
  CYBER3_LOG        fișier eveniment (implicit /var/log/cyber3/events.json)
"""
import json, os, socket, threading, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# CYBER3_ORG = doar FALLBACK (când edge-ul e inaccesibil ȘI tokenul nu e în cache).
# În mod normal org-ul e REZOLVAT AUTORITAR din tokenul dispozitivului (edge /v1/soc/whoami),
# deci senzorul NU mai trebuie configurat per client.
ORG = os.environ.get("CYBER3_ORG", "NECONFIGURAT")
EDGE = os.environ.get("CYBER3_EDGE", "https://cyber3-edge.cyber3.workers.dev").rstrip("/")
HTTP_PORT = int(os.environ.get("CYBER3_HTTP_PORT", "8765"))
UDP_PORT = int(os.environ.get("CYBER3_UDP_PORT", "8766"))
LOG = os.environ.get("CYBER3_LOG", "/var/log/cyber3/events.json")
MAXBYTES = 8 * 1024 * 1024
TYPES = {"pc_scan", "threat", "breach", "backup", "heartbeat"}
DISCOVER = b"CYBER3-SOC-DISCOVER"
UA = "cyber3-soc-receiver/1.0"  # Cloudflare blochează UA implicit Python-urllib
TTL_OK, TTL_BAD = 3600, 300

os.makedirs(os.path.dirname(LOG), exist_ok=True)
_lock = threading.Lock()
_org_cache = {}        # token -> (org|None, expiry)
_cache_lock = threading.Lock()


def resolve_org(token):
    """Org-ul autoritar al dispozitivului, dedus din token via edge (cache 1h; negativ 5min)."""
    if not token:
        return None
    now = time.time()
    with _cache_lock:
        hit = _org_cache.get(token)
        if hit and hit[1] > now:
            return hit[0]
    org = None
    try:
        req = urllib.request.Request(EDGE + "/v1/soc/whoami",
                                     headers={"authorization": "Bearer " + token, "user-agent": UA})
        with urllib.request.urlopen(req, timeout=6) as r:
            org = json.loads(r.read().decode()).get("org") or None
        with _cache_lock:
            _org_cache[token] = (org, now + TTL_OK)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            with _cache_lock:
                _org_cache[token] = (None, now + TTL_BAD)  # token invalid
    except Exception:
        pass  # edge inaccesibil -> fallback la apelant
    return org


def primary_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1)); ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "0.0.0.0"


def write_event(ev):
    with _lock:
        try:
            if os.path.exists(LOG) and os.path.getsize(LOG) > MAXBYTES:
                os.replace(LOG, LOG + ".1")
        except Exception:
            pass
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/v1/soc/health"):
            self._send(200, {"ok": True, "service": "cyber3-soc", "org": ORG})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/v1/soc/event":
            self._send(404, {"error": "not_found"}); return
        try:
            n = int(self.headers.get("content-length", "0") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > 8192:
            self._send(400, {"error": "bad_length"}); return
        try:
            body = json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            self._send(400, {"error": "bad_json"}); return
        t = str(body.get("type", ""))
        if t not in TYPES:
            self._send(400, {"error": "bad_type"}); return
        auth = self.headers.get("authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        # Org AUTORITAR din token (edge). Fallback doar dacă edge e jos ȘI tokenul nu e în cache:
        # CYBER3_ORG dacă e setat real, altfel "UNRESOLVED" (evenimentul NU se pierde, e reconciliabil).
        org = resolve_org(token) or (ORG if ORG and ORG != "NECONFIGURAT" else "UNRESOLVED")
        # Toate câmpurile sub namespace "c3" (-> data.c3.*) ca să NU se ciocnească cu
        # schema rezervată Wazuh data.* (data.data=keyword, data.os=object). Vezi rule id 100600+.
        ev = {"c3": {
            "v": 1, "app": "cyber3", "org": org, "source": "sensor",
            "device_id": str(body.get("device_id", ""))[:64],
            "os": str(body.get("os", ""))[:64],
            "type": t, "ts": int(time.time() * 1000),
            "ip": self.client_address[0],
            "token": token[:16],
            "data": body.get("data") if isinstance(body.get("data"), dict) else {},
        }}
        write_event(ev)
        self._send(200, {"ok": True})


def udp_responder():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", UDP_PORT))
    while True:
        try:
            data, addr = s.recvfrom(512)
            if data.strip() == DISCOVER:
                reply = json.dumps({"service": "cyber3-soc", "org": ORG,
                                    "http_port": HTTP_PORT, "ip": primary_ip()}).encode()
                s.sendto(reply, addr)
        except Exception:
            time.sleep(0.5)


if __name__ == "__main__":
    threading.Thread(target=udp_responder, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), H).serve_forever()
