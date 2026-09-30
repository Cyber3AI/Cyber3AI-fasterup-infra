// NOC FasterUp/CYBER3 — edge worker (treapta 2 cu aprobare-om pt remedieri sensibile).
// fetch: /v1/noc/report(agent) /v1/noc/state(admin) /v1/noc/commands(agent: actiuni aprobate) /v1/noc/approve|deny(link) /v1/noc/health /v1/noc/run(admin)
// scheduled: probe cloud + alerte Telegram + rezumat AI. Vezi [[noc-design-spec]].

export interface Env {
  NOC_KV: KVNamespace;
  NOC_NODE_TOKEN: string; NOC_ADMIN_TOKEN: string; CCC_PUSH_TOKEN: string; NOC_READ_TOKEN: string;
  NOC_TG_TOKEN: string; NOC_TG_CHAT: string;
  IOC_BUNDLES: R2Bucket;
  LLM: Fetcher;
}
const CORS: Record<string, string> = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "content-type,authorization" };
const json = (o: unknown, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", ...CORS } });
const html = (h: string, s = 200) => new Response(h, { status: s, headers: { "content-type": "text/html;charset=utf-8", ...CORS } });
const bearer = (req: Request) => { const a = req.headers.get("authorization") || ""; return a.startsWith("Bearer ") ? a.slice(7).trim() : ""; };
const STALE_S = 300, APPROVE_TTL = 1800;
const PROBES = [
  { id: "cyber3-edge", url: "https://cyber3-edge.cyber3.workers.dev/", type: "edge", group: "cloud" },
  { id: "cyber3.ai", url: "https://cyber3.ai/", type: "site", group: "cloud" },
  { id: "fasterup.ai", url: "https://fasterup.ai/", type: "site", group: "cloud" },
  { id: "vpn-cp", url: "https://cyber3-vpn-cp.cyber3.workers.dev/", type: "vpn", group: "cloud" },
];

async function loadNodes(env: Env) {
  const list = await env.NOC_KV.list({ prefix: "noc:node:" }); const nodes: any[] = [];
  for (const k of list.keys) { const v = await env.NOC_KV.get(k.name); if (v) nodes.push(JSON.parse(v)); }
  const now = Date.now();
  for (const n of nodes) {
    n.report_age_s = Math.round((now - (n.srv_ts || 0)) / 1000);
    if (n.report_age_s > STALE_S) { n.status = "red"; n.reasons = Array.isArray(n.reasons) ? n.reasons : []; if (!n.reasons.some((r: string) => r.includes("fara raport"))) n.reasons.push(`fara raport ${n.report_age_s}s (nod mort?)`); }
  }
  nodes.sort((a, b) => String(a.node).localeCompare(String(b.node)));
  return nodes;
}
async function listProps(env: Env) {
  const list = await env.NOC_KV.list({ prefix: "noc:prop:" }); const out: any[] = [];
  for (const k of list.keys) { const v = await env.NOC_KV.get(k.name); if (v) out.push(JSON.parse(v)); }
  return out;
}
async function tg(env: Env, text: string) {
  if (!env.NOC_TG_TOKEN || !env.NOC_TG_CHAT) return;
  try { await fetch(`https://api.telegram.org/bot${env.NOC_TG_TOKEN}/sendMessage`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: env.NOC_TG_CHAT, text, parse_mode: "HTML", disable_web_page_preview: true }) }); } catch (_) {}
}
async function probe(p: any) {
  const t0 = Date.now(); let status = "red", reasons: string[] = [], http = 0;
  try { const r = await fetch(p.url, { method: "GET", signal: AbortSignal.timeout(8000) } as any); http = r.status; if (r.status < 500) status = "green"; else { status = "amber"; reasons.push(`HTTP ${r.status}`); } }
  catch (_) { status = "red"; reasons.push("inaccesibil"); }
  return { node: p.id, type: p.type, group: p.group, status, reasons, metrics: { probe: { http, ms: Date.now() - t0 } }, srv_ts: Date.now() };
}
// Self-test unelte gratuite (cyber3-llm /v1/selftest) via Service Binding — nod în NOC + alertă la roșu (scor identic/DMARC/DNSSEC/IOC).
async function selftestNode(env: Env): Promise<any> {
  let status = "red"; const reasons: string[] = [];
  try {
    const r = await env.LLM.fetch("https://llm/v1/selftest", { signal: AbortSignal.timeout(24000) } as any);
    const j: any = await r.json().catch(() => null);
    if (j && j.ok === true) status = "green";
    else if (j && Array.isArray(j.checks)) reasons.push(`${j.passed}/${j.total}: ` + j.checks.filter((c: any) => !c.pass).map((c: any) => c.name).join(", "));
    else reasons.push(`raspuns invalid (HTTP ${r.status})`);
  } catch (_) { reasons.push("selftest inaccesibil"); }
  return { node: "selftest-unelte-free", type: "selftest", group: "cloud", status, reasons, metrics: {}, srv_ts: Date.now() };
}
// Stratul 2 (mecanism armat): confirma ca fiecare senzor inline POATE bloca ACUM (br_netfilter ON + Suricata activ + raport proaspat).
// Prinde exact regresia din 19 iun (br_netfilter OFF -> AR inefectiv). Citeste datele deja raportate de agenti - zero atingere de senzor.
async function socBlockArmedNode(env: Env): Promise<any> {
  let inline: any[] = [];
  try { inline = (await loadNodes(env)).filter((n: any) => n.metrics?.security && ("br_netfilter" in n.metrics.security)); }
  catch (_) { return { node: "soc-blocare-armata", type: "canary", group: "cloud", status: "amber", reasons: ["nu am putut citi senzorii"], metrics: {}, srv_ts: Date.now() }; }
  // BLOCARE efectiva = lant CYBER3_BLOCK pe FORWARD (can_block) SI senzor cu adevarat inline (inline_ok: membri bridge care forwardeaza).
  // chainGap = regresie REALA (lant lipsa / br_netfilter off / suricata jos) -> ROSU (cazul ANRE 24 iul).
  // passive = are lantul dar NU e inline (icisoc107: pe port normal fara mirror, doar broadcast) -> AMBER, nu ROSU (limitare de pozitie, nu regresie).
  const chainGap: string[] = []; const passive: string[] = []; let armed = 0;
  for (const n of inline) {
    const sec = n.metrics.security || {};
    // icisoc110: fara bridge-nf (kernel pve) -> blocarea efectiva e nft bridge in VLAN (ar_method "nft-bridge", verificat de agent).
    const chainOk = (sec.br_netfilter === 1 || sec.ar_method === "nft-bridge") && sec.can_block === 1 && n.metrics.services?.suricata === "active" && (n.report_age_s || 0) <= 300;
    // inline structural (bridge cu >=2 membri + carrier) = armat si cand traficul e ~0 (noapte/weekend, institutii inchise);
    // inline_ok (>20pps) singur dadea fals "pasiv" pe f009 sambata la 4pps. icisoc107 (1 membru) ramane pasiv.
    const inlineOk = sec.inline_ok === 1 || (n.metrics.inline === true && n.metrics.capture?.br0_carrier === true);
    if (chainOk && inlineOk) armed++;
    else if (!chainOk) chainGap.push(n.node);
    else passive.push(n.node);
  }
  let status = "green"; const reasons: string[] = [];
  if (!inline.length) { status = "amber"; reasons.push("niciun senzor raportat"); }
  if (chainGap.length) { status = "red"; reasons.push(`BLOCARE PIERDUTA (lant/br_netfilter/suricata): ${chainGap.join(", ")}`); }
  if (passive.length) { if (status !== "red") status = "amber"; reasons.push(`nu blocheaza — pasiv/orb (nu-i inline): ${passive.join(", ")}`); }
  return { node: "soc-blocare-armata", type: "canary", group: "cloud", status, reasons,
    metrics: { armed, total: inline.length, chain_gap: chainGap, passive }, srv_ts: Date.now() };
}
// Stratul 3 (L2 Shield): canary — cati senzori au L2 Shield ARMAT (ebtables anti-gateway-ARP-spoof, chain CYBER3_L2SHIELD)
// + cate frame-uri ARP-spoof a blocat. COMPLEMENTAR stratului 2 (AR pe IP): acopera unghiul mort L2 (ARP-poison/MITM).
// Citeste metrics.l2shield deja raportat de agenti (present/armed/mode/rules/drops) — zero atingere de senzor.
async function l2ShieldArmedNode(env: Env): Promise<any> {
  let sensors: any[] = [];
  try { sensors = (await loadNodes(env)).filter((n: any) => n.group === "sensors" && n.metrics?.l2shield); }
  catch (_) { return { node: "soc-l2shield-strat3", type: "canary", group: "cloud", status: "amber", reasons: ["nu am putut citi senzorii"], metrics: {}, srv_ts: Date.now() }; }
  const armed: string[] = []; const presentNotArmed: string[] = []; let drops = 0; let drops24 = 0;
  for (const n of sensors) {
    const l2 = n.metrics.l2shield || {};
    if (l2.present !== 1) continue; // nedesfasurat inca (rollout in curs) — nu-l numaram ca lipsa
    drops += Number(l2.drops || 0);
    drops24 += Number(l2.drops_24h || 0); // contor CUMULATIV 24h (imun la resetul pcnt), la fel ca IPS/AR/CyberBot
    if (l2.armed === 1 && (n.report_age_s || 0) <= 300) armed.push(n.node);
    else presentNotArmed.push(n.node);
  }
  let status = "green"; const reasons: string[] = [];
  if (!armed.length && !presentNotArmed.length) { status = "amber"; reasons.push("L2 Shield nedesfasurat inca (0 senzori cu strat 3)"); }
  if (presentNotArmed.length) { status = "amber"; reasons.push(`prezent dar NEarmat: ${presentNotArmed.join(", ")}`); }
  if (drops24 > 0) reasons.push(`${drops24} ARP-spoof blocate la L2 (24h)`);
  return { node: "soc-l2shield-strat3", type: "canary", group: "cloud", status, reasons,
    metrics: { armed: armed.length, armed_nodes: armed, present_not_armed: presentNotArmed, drops, drops_24h: drops24 }, srv_ts: Date.now() };
}
// Rezumatul AI (Claude Haiku) a fost ELIMINAT din NOC (15 iul 2026): nu aducea valoare pentru
// monitorizarea infra și consuma API Claude la FIECARE cron (~3 min). Dashboardul afișează
// rezumatul simplu (X noduri · ok/avertisment/critic) direct din probe, ZERO apeluri LLM.
async function runCron(env: Env) {
  const [probes, stNode, blkNode, l2Node] = await Promise.all([Promise.all(PROBES.map(probe)), selftestNode(env), socBlockArmedNode(env), l2ShieldArmedNode(env)]);
  let r2s = "green"; const r2r: string[] = [];
  try { const o = await env.IOC_BUNDLES.head("downloads/cyber3-latest.apk"); if (!o) { r2s = "amber"; r2r.push("obiect lipsa"); } } catch (_) { r2s = "red"; r2r.push("R2 inaccesibil"); }
  probes.push({ node: "r2", type: "r2", group: "cloud", status: r2s, reasons: r2r, metrics: {}, srv_ts: Date.now() } as any);
  probes.push({ node: "noc", type: "edge", group: "cloud", status: "green", reasons: [], metrics: {}, srv_ts: Date.now() } as any);
  probes.push(stNode as any);
  probes.push(blkNode as any);
  probes.push(l2Node as any);
  for (const p of probes) await env.NOC_KV.put("noc:node:" + p.node, JSON.stringify(p), { expirationTtl: 86400 });
  const nodes = await loadNodes(env);
  for (const n of nodes) {
    const prev = (await env.NOC_KV.get("noc:alert:" + n.node)) || "green";
    if (n.status !== prev) {
      if (n.status === "red" || n.status === "amber") await tg(env, `${n.status === "red" ? "🔴" : "🟡"} <b>NOC: ${n.node}</b> → ${n.status.toUpperCase()}\n${(n.reasons || []).join("; ") || "-"}`);
      else if (n.status === "green" && prev !== "green") await tg(env, `🟢 <b>NOC: ${n.node}</b> → recuperat (OK)`);
      await env.NOC_KV.put("noc:alert:" + n.node, n.status, { expirationTtl: 604800 });
    }
  }
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url); const path = url.pathname; const base = url.origin;
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    if (path === "/v1/noc/health") return json({ ok: true, service: "cyber3-noc" });
    // Rezumat PUBLIC (doar agregat, fără detalii/secrete) — pentru CCC (ccc.cyber3.ai)
    if (path === "/v1/noc/summary") {
      const nodes = await loadNodes(env); const c = (s: string) => nodes.filter(n => n.status === s).length;
      return json({ total: nodes.length, green: c("green"), amber: c("amber"), red: c("red"), ts: Date.now() });
    }

    // L2 SHIELD (strat 3) — agregat PUBLIC (DOAR cifre, fără IP/nume senzori): pt portal + CCC + agregator.
    if (path === "/v1/noc/l2shield") {
      const nodes = await loadNodes(env);
      const sens = nodes.filter((n: any) => n.group === "sensors" && n.metrics?.l2shield?.present === 1);
      let armed = 0, drops = 0, drops24 = 0, drop_mode = 0;
      const detail = !!env.NOC_READ_TOKEN && bearer(req) === env.NOC_READ_TOKEN;  // per-nod DOAR autentificat (portal intern)
      const by_node: Record<string, any> = {};
      for (const n of sens) { const l = n.metrics.l2shield || {}; drops += Number(l.drops || 0); drops24 += Number(l.drops_24h || 0); if (l.armed === 1) armed++; if (l.mode === "drop") drop_mode++;
        if (detail) by_node[n.node] = { armed: l.armed || 0, mode: l.mode || "off", blocks: Number(l.drops_24h || 0), blocks_instant: Number(l.drops || 0), rules: l.rules || 0 }; }
      // blocks = total CUMULATIV pe 24h (ca IPS/AR/CyberBot); blocks_instant = pcnt curent (se reseteaza la re-aplicare)
      const out: any = { sensors_with_l2: sens.length, armed, enforce: drop_mode, blocks: drops24, blocks_instant: drops, ts: Date.now() };
      if (detail) out.by_node = by_node;
      return json(out);
    }

    // CCC KPIs — read PUBLIC agregat (fără secrete) pentru ccc.cyber3.ai
    if (path === "/v1/ccc/summary") {
      const v = await env.NOC_KV.get("ccc:kpis");
      const d: any = v ? JSON.parse(v) : null;
      const fresh = d && (Date.now() - (d.ts || 0) < 1800_000); // <30 min = live
      if (!fresh) return json({ live: false });
      // SECURITATE (defense-in-depth): endpoint PUBLIC — nu expune NICIODATĂ IP-uri,
      // nici dintr-un record vechi rămas în KV. Doar momentele blocărilor.
      const safe = { ...d, recent: Array.isArray(d.recent) ? d.recent.map((x: any) => ({ ts: x?.ts })) : [] };
      return json({ ...safe, live: true });
    }
    // CCC infra — status PUBLIC per-componentă (core+cloud individual; senzori doar AGREGAT
    // ca să nu expunem nume de senzori/clienți). Fără metrici/IP — doar culoarea de sănătate.
    if (path === "/v1/ccc/infra") {
      const nodes = await loadNodes(env);
      const CORE = new Set(["soc-vpn-relay", "relay-2", "wazuh-server", "r2", "misp", "portal", "portal-dr", "noc", "cyber3-edge", "vpn-cp", "pve", "cyber3.ai", "fasterup.ai", "cyber3-vpn-1", "cyber3-vpn-2"]);
      const st: Record<string, string> = {};
      let s_t = 0, s_g = 0, s_a = 0, s_r = 0;
      for (const n of nodes) {
        if (n.group === "sensors") { s_t++; if (n.status === "red") s_r++; else if (n.status === "amber") s_a++; else s_g++; }
        else if (CORE.has(n.node)) st[n.node] = n.status;
      }
      return json({ nodes: st, sensors: { total: s_t, green: s_g, amber: s_a, red: s_r }, ts: Date.now() });
    }

    // CCC MOAT — istoric zilnic CYBER3 DATABASE (DOAR cifre agregate: total/first-party/MISP).
    // PUBLIC dar SIGUR: fără IP-uri, nume de senzori/clienți sau timing exploatabil — doar numere.
    if (path === "/v1/ccc/moat") {
      let hist: any = {}; try { hist = JSON.parse((await env.NOC_KV.get("ccc:moat_hist")) || "{}"); } catch { hist = {}; }
      const rows = Object.keys(hist).sort().map((d) => ({ date: d, ...hist[d] }));
      return json({ latest: rows.length ? rows[rows.length - 1] : null, history: rows, ts: Date.now() });
    }

    // CCC KPIs — push autentificat de la portal (calculează din indexer Wazuh, intern)
    if (path === "/v1/ccc/push" && req.method === "POST") {
      if (bearer(req) !== env.CCC_PUSH_TOKEN) return json({ error: "unauthorized" }, 401);
      let b: any; try { b = await req.json(); } catch { return json({ error: "bad_json" }, 400); }
      const rec = {
        events_24h: Math.max(0, Math.round(Number(b.events_24h) || 0)),
        blocks_24h: Math.max(0, Math.round(Number(b.blocks_24h) || 0)),
        autonomy_pct: Math.min(100, Math.max(0, Math.round(Number(b.autonomy_pct) || 0))),
        sensors: Math.max(0, Math.round(Number(b.sensors) || 0)),
        // MLEO — corelare L3<->L2 (doar CIFRE agregate; sigur public, FĂRĂ MAC/IP). Detaliul = doar în portal (admin).
        mleo: (b.mleo && typeof b.mleo === "object") ? {
          recon: Math.max(0, Math.round(Number(b.mleo.recon) || 0)),
          macs: Math.max(0, Math.round(Number(b.mleo.macs) || 0)),
          candidates: Math.max(0, Math.round(Number(b.mleo.candidates) || 0)),
          match1: Math.max(0, Math.round(Number(b.mleo.match1) || 0)),
          proposals: Math.max(0, Math.round(Number(b.mleo.proposals) || 0)),
        } : {},
        // Defalcare cascadă pe straturi (7-straturi; sigur public — doar numere): IPS/AR/L2 Shield/CyberBot
        layers: (b.layers && typeof b.layers === "object") ? {
          ips: Math.max(0, Math.round(Number(b.layers.ips) || 0)),
          ar_native: Math.max(0, Math.round(Number(b.layers.ar_native) || 0)),
          l2shield: Math.max(0, Math.round(Number(b.layers.l2shield) || 0)),
          cyberbot: Math.max(0, Math.round(Number(b.layers.cyberbot) || 0)),
        } : {},
        // SECURITATE: NU stocăm/expunem IP-uri pe endpoint-ul PUBLIC (/v1/ccc/summary).
        // Un IP + timestamp i-ar spune atacatorului că a fost detectat (își rotește IP-ul)
        // și ar fi corelabil cu clientul atacat. Păstrăm DOAR momentele blocărilor.
        recent: Array.isArray(b.recent) ? b.recent.slice(0, 6).map((x: any) => ({ ts: Number(x?.ts) || Date.now() })) : [],
        ts: Date.now(),
      };
      await env.NOC_KV.put("ccc:kpis", JSON.stringify(rec), { expirationTtl: 7200 });
      // MOAT CYBER3 DATABASE — istoric zilnic (upsert pe zi, păstrează 30z). Doar cifre agregate.
      if (b.moat && typeof b.moat === "object") {
        const day = String(b.moat.date || "").slice(0, 10);
        if (/^\d{4}-\d{2}-\d{2}$/.test(day)) {
          let hist: any = {}; try { hist = JSON.parse((await env.NOC_KV.get("ccc:moat_hist")) || "{}"); } catch { hist = {}; }
          hist[day] = {
            total: Math.max(0, Math.round(Number(b.moat.total) || 0)),
            fp: Math.max(0, Math.round(Number(b.moat.firstparty) || 0)),
            misp: Math.max(0, Math.round(Number(b.moat.misp) || 0)),
            cats: (b.moat.by_category && typeof b.moat.by_category === "object") ? b.moat.by_category : {},
          };
          const ds = Object.keys(hist).sort(); while (ds.length > 30) delete hist[ds.shift() as string];
          await env.NOC_KV.put("ccc:moat_hist", JSON.stringify(hist));
        }
      }
      return json({ ok: true, stored: rec });
    }

    if (path === "/v1/noc/report" && req.method === "POST") {
      if (bearer(req) !== env.NOC_NODE_TOKEN) return json({ error: "unauthorized" }, 401);
      let body: any; try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400); }
      const node = String(body?.node || "").slice(0, 64); if (!node) return json({ error: "no_node" }, 400);
      await env.NOC_KV.put("noc:node:" + node, JSON.stringify({ ...body, node, srv_ts: Date.now() }), { expirationTtl: 86400 });
      // remedieri AUTO efectuate -> alerta
      if (Array.isArray(body?.remediations) && body.remediations.length)
        ctx.waitUntil(tg(env, `🔧 <b>NOC auto-remediere · ${node}</b>\n${body.remediations.map((a: string) => "• " + a).join("\n")}`));
      // actiuni APROBATE executate -> marcheaza done
      if (Array.isArray(body?.executed))
        for (const action of body.executed) {
          const key = `noc:prop:${node}:${action}`; const ex = await env.NOC_KV.get(key);
          if (ex) { await env.NOC_KV.put(key, JSON.stringify({ ...JSON.parse(ex), state: "done", done_ts: Date.now() }), { expirationTtl: 86400 }); }
          ctx.waitUntil(tg(env, `✅ <b>NOC · ${node}</b> — executat (aprobat): ${action}`));
        }
      // PROPUNERI sensibile -> creeaza pending + Telegram cu Aproba/Respinge (o singura data)
      if (Array.isArray(body?.proposals))
        for (const p of body.proposals) {
          const key = `noc:prop:${node}:${p.action}`; const ex = await env.NOC_KV.get(key);
          const cur = ex ? JSON.parse(ex) : null;
          if (!cur || cur.state === "done" || cur.state === "denied") {
            const nonce = crypto.randomUUID().slice(0, 12);
            await env.NOC_KV.put(key, JSON.stringify({ node, action: p.action, label: p.label || p.action, reason: p.reason || "", nonce, state: "pending", ts: Date.now() }), { expirationTtl: 86400 });
            const id = encodeURIComponent(node + ":" + p.action);
            ctx.waitUntil(tg(env, `⏳ <b>NOC — APROBARE necesară · ${node}</b>\n${p.label || p.action}\nmotiv: ${p.reason || "-"}\n\n✅ Aprobă: ${base}/v1/noc/approve?id=${id}&k=${nonce}\n⛔ Respinge: ${base}/v1/noc/deny?id=${id}&k=${nonce}`));
          }
        }
      return json({ ok: true });
    }

    // agentul trage actiunile aprobate pentru el
    if (path === "/v1/noc/commands" && req.method === "GET") {
      if (bearer(req) !== env.NOC_NODE_TOKEN) return json({ error: "unauthorized" }, 401);
      const node = url.searchParams.get("node") || ""; const approved: string[] = [];
      const props = await listProps(env);
      const now = Date.now();
      for (const p of props) if (p.node === node && p.state === "approved" && (now - (p.approved_at || 0)) < APPROVE_TTL * 1000) approved.push(p.action);
      return json({ approved });
    }

    // link Aproba / Respinge (nonce per-propunere, fara token admin)
    if (path === "/v1/noc/approve" || path === "/v1/noc/deny") {
      const id = decodeURIComponent(url.searchParams.get("id") || ""); const k = url.searchParams.get("k") || "";
      const key = "noc:prop:" + id; const ex = await env.NOC_KV.get(key);
      if (!ex) return html("<h2>Propunere inexistentă sau expirată.</h2>", 404);
      const p = JSON.parse(ex);
      if (p.nonce !== k) return html("<h2>Token invalid.</h2>", 403);
      if (path === "/v1/noc/approve") { p.state = "approved"; p.approved_at = Date.now(); await env.NOC_KV.put(key, JSON.stringify(p), { expirationTtl: 86400 }); ctx.waitUntil(tg(env, `👍 <b>NOC · ${p.node}</b> — APROBAT: ${p.label}. Se execută în ≤60s.`)); return html(`<body style="font-family:sans-serif;background:#070b12;color:#dce8ff;text-align:center;padding-top:80px"><h1 style="color:#1fd65f">✅ Aprobat</h1><p>${p.label} pe <b>${p.node}</b> — se execută în ≤60s.</p></body>`); }
      else { p.state = "denied"; p.denied_at = Date.now(); await env.NOC_KV.put(key, JSON.stringify(p), { expirationTtl: 7200 }); ctx.waitUntil(tg(env, `⛔ <b>NOC · ${p.node}</b> — RESPINS: ${p.label}.`)); return html(`<body style="font-family:sans-serif;background:#070b12;color:#dce8ff;text-align:center;padding-top:80px"><h1 style="color:#ff3b3b">⛔ Respins</h1><p>${p.label} pe <b>${p.node}</b> — nu se execută.</p></body>`); }
    }

    if (path === "/v1/noc/state" && req.method === "GET") {
      if (bearer(req) !== env.NOC_ADMIN_TOKEN) return json({ error: "unauthorized" }, 401);
      const nodes = await loadNodes(env); const c = (s: string) => nodes.filter(n => n.status === s).length;
      const props = (await listProps(env)).filter(p => p.state === "pending" || p.state === "approved");
      return json({ summary: { total: nodes.length, green: c("green"), amber: c("amber"), red: c("red"), ts: Date.now() }, ai_summary: null, ai_ts: null, proposals: props, nodes });
    }

    if (path === "/v1/noc/run" && req.method === "GET") {
      if (bearer(req) !== env.NOC_ADMIN_TOKEN) return json({ error: "unauthorized" }, 401);
      await runCron(env); return json({ ok: true, ran: true });
    }
    return json({ error: "not_found" }, 404);
  },
  async scheduled(_e: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> { ctx.waitUntil(runCron(env)); },
};
