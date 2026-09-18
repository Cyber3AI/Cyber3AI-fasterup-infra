# Infrastructura VPN CYBER3 (WireGuard) — vpn.cyber3.ai

- `node/` — nod VPN: `node-setup.sh` (WireGuard wg0 10.3.0.1/24, NAT, unbound no-logs, RAM-only) + `agent.py` (serviciul `cyber3-agent`, port 8080; `/stat`, `/usage`, `/metrics` independent de furnizor).
- `control-plane/` — worker Cloudflare `cyber3-vpn-cp`: alocare nod + failover, abonamente (Google Play + Paddle), plafon gratuit 400 MB/zi, contorizare agregată a conexiunilor (`cstat:<zi>`: țară, platformă, plan, nod — fără IP).
- `vpn-ops/` — worker `cyber3-vpn-ops` = portalul operațional **vpn.cyber3.ai** (colectare la 5 min, istoric 24h/30z/12 luni, timp real, alerte + raport zilnic, comandă și control, manualul administratorului).

Secretele NU sunt în repo (sunt ca secrete pe workeri / în `/etc/cyber3/agent.token` pe noduri).
