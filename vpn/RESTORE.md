# RESTORE — vpn.cyber3.ai (portalul operațional VPN) + nodurile + control-plane

Stare salvată: 19 sep 2026. Secretele NU sunt aici — doar numele lor și de unde se iau.

## 1. Portalul `cyber3-vpn-ops` (vpn.cyber3.ai)
```bash
cd vpn/vpn-ops            # (pe laptop: "CYBER3.AI VPN PREMIUM/vpn-ops")
npx wrangler deploy        # creează/actualizează workerul + domeniul vpn.cyber3.ai + cron */5
```
- KV `OPS` = `d8839c9b97d44a3c8e15804e900dacae` (dacă se pierde: `wrangler kv namespace create cyber3-vpn-ops` și pune noul id în wrangler.toml).
- KV `CP` = `368940c1e4c345db869c87fef410b13a` (KV-ul control-plane-ului — NU se recreează).
- Service bindings: `cyber3-vpn-cp`, `cyber3-billing`, `cyber3-metrics` (trebuie să existe).
- Secrete (`wrangler secret bulk fisier.json`, fișier 0600 șters imediat după):

| Secret | Sursa (laptop, `~/.cyber3-secrets/`) |
|---|---|
| OPS_PASS | `mihai-unified.pass` (parola unică, user `mihai`) |
| AGENT_TOKEN | `vpn1-agent.token` (= `/etc/cyber3/agent.token` pe noduri) |
| HZ_TOKEN | `hetzner.token` |
| CP_ADMIN | `vpn-cp-admin.token` |
| BILLING_ADMIN | `billing-admin.token` |
| RESEND_API_KEY | `resend-api.key` |
| GOOGLE_SA_JSON | `cyber3-play-api.json` (conținutul întreg) |
| METRICS_TOKEN | `metrics-report.token` |

- Starea (opțional — se reface singură din colectare, istoricul se pierde): în backup-ul R2/laptop, folderul `kvdump/` → `wrangler kv key put <cheie> --path ops_<cheie>.json --namespace-id d8839c9b… --remote` (cheile: snap, hist, hourly, daily, clients, play, funnel, billing, tags, registry, drained).
- Verificare: `curl https://vpn.cyber3.ai/api/health` → ok; pagina cere login; butonul „Colectează acum”.

## 2. Agentul de pe noduri (`vpn/node/agent.py`)
```bash
scp agent.py root@IP:/opt/cyber3/agent.py.new
ssh root@IP 'cd /opt/cyber3 && python3 -m py_compile agent.py.new && cp -p agent.py agent.py.bak && mv agent.py.new agent.py && systemctl restart cyber3-agent'
```
Repornirea agentului NU deconectează clienții (tunelurile sunt în kernel). Endpoint-uri: `/stat`, `/usage`, `/metrics[?nolat=1]`. Nod nou: `node-setup.sh` apoi agentul, apoi Registru + „Activează nodul” în portal.

## 3. Control-plane `cyber3-vpn-cp` (`vpn/control-plane/`)
Pe laptop sursa e `CYBER3.APP/vpn-cp/`. `npx wrangler deploy` din acel folder. Contractul cu aplicațiile (Android, Windows, iOS) NU se schimbă: `/connect` {user_id, client_pubkey, node?} → {node, client_ip, dns, server_pubkey, endpoint, allowed_ips, keepalive, tier}; `/nodes` → {nodes:[{name,peers}]}.
Rutare (19 sep): cheia KV `routing` publicată de portal la 5 min; dacă e mai veche de 15 min, control-plane-ul revine automat la logica veche (probe live). Backup sursă înainte de rutare: `src/index.js.bak-prerouting-20260919`.
