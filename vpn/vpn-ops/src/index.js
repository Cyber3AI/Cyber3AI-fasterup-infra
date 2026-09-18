// cyber3-vpn-ops — vpn.cyber3.ai: portalul operațional al infrastructurii VPN (WireGuard).
// Surse: agenții de pe noduri (/stat, /metrics — independenți de furnizor), API Hetzner Cloud,
// KV-ul control-plane-ului cyber3-vpn-cp (citit doar), billing.cyber3.ai (încasări app).
// No-logs: nu se citesc și nu se stochează destinații sau adrese IP ale clienților — doar contoare agregate.
import { PAGE } from "./ui.js";

const HIST_MAX = 288;                // 24h la 5 minute
const POOL = 253;                    // adrese client pe /24 (10.3.0.2–254)
const CAP_PER_2VCPU = 100;           // tuneluri concurente recomandate per 2 vCPU (regula de dimensionare)
const FREE_CAP = 400 * 1024 * 1024;  // 400 MB/zi pe planul gratuit
const ALERT_COOLDOWN = 6 * 3600e3;

const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const ipOf = (url) => (String(url).match(/(\d+\.\d+\.\d+\.\d+)/) || [])[1] || null;
const today = () => new Date().toISOString().slice(0, 10);

function authed(req, env) {
  const h = req.headers.get("authorization") || "";
  if (!h.startsWith("Basic ") || !env.OPS_PASS) return false;
  try { const [u, p] = atob(h.slice(6)).split(":"); return u === "mihai" && p === env.OPS_PASS; } catch { return false; }
}

async function fetchJson(url, opt = {}, ms = 10000) {
  const r = await fetch(url, { ...opt, signal: AbortSignal.timeout(ms) });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

// ---------- colectare noduri (agent WireGuard) + Hetzner ----------
// Nodurile din rotație (KV control-plane) + cele scoase temporar din rotație (rămân monitorizate).
async function fleet(env) {
  const reg = (await env.CP.get("nodes", "json")) || [];
  const drained = (await env.OPS.get("drained", "json")) || {};
  return [...reg, ...Object.values(drained).filter((d) => !reg.find((r) => r.name === d.name)).map((d) => ({ name: d.name, url: d.url, drained: true }))];
}

async function collectNodes(env, prev) {
  const reg = await fleet(env);
  const ips = reg.map((n) => ipOf(n.url));
  const auth = { headers: { authorization: "Bearer " + env.AGENT_TOKEN } };
  const nodes = await Promise.all(reg.map(async (n, i) => {
    const o = { name: n.name, url: n.url, ip: ips[i], ok: false, drained: !!n.drained };
    try {
      const t0 = Date.now();
      o.stat = await fetchJson(n.url + "/stat", auth, 8000);
      o.rtt_cp_ms = Date.now() - t0;
      o.ok = true;
    } catch (e) { o.err = String(e.message || e); }
    if (o.ok) {
      try { o.met = await fetchJson(n.url + "/metrics?targets=" + ips.filter((_, j) => j !== i).join(","), auth, 20000); }
      catch (e) { o.met_err = String(e.message || e); }
    }
    return o;
  }));

  // Hetzner: tip, locație, cost, trafic lunar (doar pentru nodurile găsite acolo)
  let hz = {};
  try {
    const d = await fetchJson("https://api.hetzner.cloud/v1/servers?per_page=50", { headers: { authorization: "Bearer " + env.HZ_TOKEN } }, 12000);
    for (const s of d.servers || []) {
      const ip = s.public_net?.ipv4?.ip; if (!ip) continue;
      const loc = s.location || {}; const t = s.server_type || {};
      const pr = (t.prices || []).find((p) => p.location === loc.name) || {};
      hz[ip] = {
        id: s.id, hname: s.name, status: s.status, type: t.name, cores: t.cores, memory_gb: t.memory, disk_gb: t.disk,
        location: loc.name, city: loc.city, country: loc.country, lat: loc.latitude, lon: loc.longitude,
        price_month: +(pr.price_monthly?.net || 0), price_tb: +(pr.price_per_tb_traffic?.net || 0),
        included_bytes: s.included_traffic || 0, out_bytes: s.outgoing_traffic || 0, in_bytes: s.ingoing_traffic || 0, created: s.created,
      };
    }
  } catch (e) { hz = { _err: String(e.message || e) }; }

  const reg2 = (await env.OPS.get("registry", "json")) || {};
  const pmap = Object.fromEntries((prev?.nodes || []).map((n) => [n.name, n]));
  const dt = prev?.ts ? (Date.now() - prev.ts) / 1000 : 0;
  for (const n of nodes) {
    n.hz = hz[n.ip] || null;
    n.provider = n.hz ? "Hetzner Cloud" : (reg2[n.name]?.provider || "Data center propriu");
    n.country = n.hz?.country || reg2[n.name]?.country || "";
    n.city = n.hz?.city || reg2[n.name]?.location || "";
    const m = n.met, p = pmap[n.name]?.met;
    n.rate = null; n.delta = null;
    if (m && p && dt > 30) {
      const r = (a, b) => (a >= b ? ((a - b) * 8) / dt / 1e6 : null); // Mbps; null dacă s-a resetat contorul
      const d = (a, b) => (a >= b ? a - b : 0);
      n.rate = { rx: r(m.net.rx_bytes, p.net.rx_bytes), tx: r(m.net.tx_bytes, p.net.tx_bytes), wg_rx: r(m.wg.rx_bytes, p.wg.rx_bytes), wg_tx: r(m.wg.tx_bytes, p.wg.tx_bytes) };
      // trafic clienți în interval (octeți prin tunel, ambele sensuri) — baza graficelor de consum
      n.delta = { wg: d(m.wg.rx_bytes, p.wg.rx_bytes) + d(m.wg.tx_bytes, p.wg.tx_bytes), net: d(m.net.rx_bytes, p.net.rx_bytes) + d(m.net.tx_bytes, p.net.tx_bytes) };
    }
    const cores = m?.cpu?.cores || n.hz?.cores || 2;
    n.capacity = Math.round((cores / 2) * CAP_PER_2VCPU);
  }
  return { nodes, hz_err: hz._err || null };
}

// ---------- clienți (KV control-plane, citit doar) ----------
async function listAll(kv, prefix, limit = 2000) {
  const out = []; let cursor;
  do {
    const r = await kv.list({ prefix, cursor, limit: 1000 });
    out.push(...r.keys.map((k) => k.name)); cursor = r.list_complete ? null : r.cursor;
  } while (cursor && out.length < limit);
  return out;
}
const maskEmail = (e) => { const [u, d] = String(e).split("@"); return (u || "").slice(0, 2) + "•••@" + (d || ""); };

async function collectClients(env) {
  const tags = (await env.OPS.get("tags", "json")) || {};
  const now = Date.now(), day = today();
  const [emails, users, usages, peers, tunnels] = await Promise.all(["email:", "user:", "usage:", "peer:", "tunnels:"].map((p) => listAll(env.CP, p)));
  const get = (k) => env.CP.get(k, "json");
  const subs = [];
  for (const k of emails) {
    const v = (await get(k)) || {}; const email = k.slice(6);
    const t = (await get("tunnels:" + email)) || [];
    subs.push({ id: "email:" + maskEmail(email), key: k, source: "Paddle / web", tier: v.tier || "—", status: v.status || "—", until: v.premium_until || 0,
      active: (v.premium_until || 0) > now, devices: (v.devices || []).length, tunnels: t.length, tag: tags[k] || "" });
  }
  // user:<uid> = Google Play (source:"play") sau înregistrări vechi/test. Un abonament Play pe mai multe
  // dispozitive are ACELAȘI purchase token → se numără o singură dată (cheia = sub_id).
  const playSeen = {};
  for (const k of users) {
    const v = (await get(k)) || {}; const sid = String(v.sub_id || ""); const uid = k.slice(5);
    const isTest = /^(test|e2e|sub_test)/i.test(uid) || /^sub_test/i.test(sid) || (!sid && !v.status);
    const src = v.source === "play" ? "Google Play" : (/^\d+$/.test(sid) ? "Lemon (test, retras)" : (isTest ? "test / admin" : "manual"));
    const tkey = v.source === "play" ? "play:" + sid.slice(-24) : k;
    if (playSeen[tkey]) {
      // același abonament pe alt dispozitiv: păstrează cea mai nouă expirare
      const r = playSeen[tkey]; r.devices++;
      if ((v.premium_until || 0) > r.until) { r.until = v.premium_until; r.active = r.until > now; r.status = v.status || r.status; }
      continue;
    }
    const row = { id: v.source === "play" ? "play:" + sid.slice(0, 10) + "…" : "uid:" + uid.slice(0, 8) + "…", key: tkey, source: src, token: v.source === "play" ? sid : null,
      tier: v.tier || "—", status: v.status || (v.premium_until > now ? "active" : "—"), until: v.premium_until || 0, active: (v.premium_until || 0) > now,
      devices: 1, tunnels: 0, tag: tags[tkey] || (isTest || src.startsWith("Lemon") ? "test" : "") };
    playSeen[tkey] = row; subs.push(row);
  }
  // free: consum pe zi (fără nicio destinație — doar volum, pentru plafonul de 400 MB)
  const free = { today_users: 0, today_capped: 0, today_bytes: 0, by_day: {}, top: [] };
  for (const k of usages) {
    const v = await get(k); if (!v || !v.day) continue;
    free.by_day[v.day] = (free.by_day[v.day] || 0) + 1;
    if (v.day === day) { free.today_users++; free.today_bytes += v.bytes || 0; if (v.capped) free.today_capped++; free.top.push({ uid: k.slice(6, 14) + "…", bytes: v.bytes || 0, capped: !!v.capped }); }
  }
  free.top.sort((a, b) => b.bytes - a.bytes); free.top = free.top.slice(0, 15);
  // conexiuni agregate pe zi (țară, platformă desktop/mobil, plan, nod, rută țară→nod) — scrise de control-plane la /connect
  const conn = { days: {}, sum: { total: 0, country: {}, platform: {}, tier: {}, node: {}, route: {}, mode: {} } };
  for (const k of (await listAll(env.CP, "cstat:")).sort().slice(-60)) {
    const v = await get(k); if (!v) continue; const dday = k.slice(6); conn.days[dday] = v;
    if (Date.now() - Date.parse(dday) <= 30 * 864e5) {
      conn.sum.total += v.total || 0;
      for (const f of ["country", "platform", "tier", "node", "route", "mode"]) for (const [kk, n] of Object.entries(v[f] || {})) conn.sum[f][kk] = (conn.sum[f][kk] || 0) + n;
    }
  }
  const per_node = {}; let stale = 0;
  for (const k of peers) { const v = await get(k); if (!v) continue; per_node[v.name || ipOf(v.node) || "?"] = (per_node[v.name || ipOf(v.node) || "?"] || 0) + 1; if (now - (v.ts || 0) > 30 * 864e5) stale++; }
  const act = subs.filter((s) => s.active);
  return {
    ts: now, subs, free, conn, peers: { total: peers.length, per_node, stale_30d: stale },
    counts: { paid_active: act.length, paid_real: act.filter((s) => s.tag !== "operator" && s.tag !== "test").length, tunnels_accounts: tunnels.length,
      by_tier: act.reduce((a, s) => ((a[s.tier] = (a[s.tier] || 0) + 1), a), {}), by_source: act.reduce((a, s) => ((a[s.source] = (a[s.source] || 0) + 1), a), {}) },
  };
}

// ---------- Google Play: re-verificare live a fiecărui abonament (Play Developer API, subscriptionsv2) ----------
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function googleToken(env) {
  const cached = await env.OPS.get("gtoken", "json");
  if (cached && cached.exp > Date.now() + 60e3) return cached.token;
  const sa = JSON.parse(env.GOOGLE_SA_JSON);
  const now = Math.floor(Date.now() / 1000);
  const enc = (o) => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const unsigned = enc({ alg: "RS256", typ: "JWT" }) + "." + enc({ iss: sa.client_email, scope: "https://www.googleapis.com/auth/androidpublisher", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 });
  const pem = sa.private_key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const key = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + unsigned + "." + b64url(sig) });
  const j = await r.json(); if (!j.access_token) throw new Error("google token: " + (j.error || r.status));
  await env.OPS.put("gtoken", JSON.stringify({ token: j.access_token, exp: Date.now() + (j.expires_in - 120) * 1000 }), { expirationTtl: 3600 });
  return j.access_token;
}
async function collectPlay(env, clients) {
  const rows = (clients?.subs || []).filter((s) => s.token);
  if (!rows.length || !env.GOOGLE_SA_JSON) return { ts: Date.now(), subs: [], note: rows.length ? "GOOGLE_SA_JSON lipsă" : "niciun abonament Play înregistrat" };
  const tok = await googleToken(env); const out = [];
  for (const s of rows) {
    try {
      const d = await fetchJson(`https://androidpublisher.googleapis.com/androidpublisher/v3/applications/ai.cyber3.app/purchases/subscriptionsv2/tokens/${encodeURIComponent(s.token)}`, { headers: { authorization: "Bearer " + tok } }, 12000);
      const li = (d.lineItems || [])[0] || {};
      out.push({ key: s.key, id: s.id, tag: s.tag, state: d.subscriptionState, product: li.productId, base_plan: li.offerDetails?.basePlanId, offer: li.offerDetails?.offerId || null,
        expiry: li.expiryTime ? Date.parse(li.expiryTime) : 0, auto_renew: !!li.autoRenewingPlan?.autoRenewEnabled, region: d.regionCode, start: d.startTime ? Date.parse(d.startTime) : 0,
        test: !!d.testPurchase, ack: d.acknowledgementState, order: d.latestOrderId || null });
    } catch (e) { out.push({ key: s.key, id: s.id, tag: s.tag, err: String(e.message || e) }); }
  }
  return { ts: Date.now(), subs: out };
}

// ---------- pâlnia aplicației (telemetrie proprie cyber3-metrics) ----------
async function collectFunnel(env) {
  try {
    const r = await env.METRICS.fetch("https://metrics.internal/report?days=14&token=" + encodeURIComponent(env.METRICS_TOKEN));
    if (!r.ok) return { err: "HTTP " + r.status };
    const d = await r.json();
    return { ts: Date.now(), days: d.days, funnel: d.funnel || [], free_funnel: d.free_funnel || [], by_vc: d.app_open_by_vc || null };
  } catch (e) { return { err: String(e.message || e) }; }
}

async function collectBilling(env) {
  try {
    const r = await env.BILLING.fetch("https://billing.internal/admin/dash", { headers: { authorization: "Bearer " + env.BILLING_ADMIN } });
    if (!r.ok) return { err: "HTTP " + r.status };
    const d = await r.json();
    const app = (d.categories || []).find((c) => c.key === "app") || {};
    return { ts: Date.now(), mor: d.mor || null, app: { paid: app.paid || {}, refunded: app.refunded || {}, count: app.count || 0, channel: app.channel || {} }, catalog: d.catalog?.app || [] };
  } catch (e) { return { err: String(e.message || e) }; }
}

// ---------- alerte ----------
function evaluate(snap, clients) {
  const a = [];
  const add = (sev, key, node, msg) => a.push({ sev, key, node, msg });
  for (const n of snap.nodes) {
    if (!n.ok) { add(n.drained ? "WARN" : "CRIT", "down:" + n.name, n.name, "Nod inaccesibil (" + (n.err || "fără răspuns") + ")" + (n.drained ? " — e scos din rotație" : " — clienții sunt mutați automat pe celelalte noduri")); continue; }
    if (n.drained) add("WARN", "drained:" + n.name, n.name, "Scos din rotație: nu primește tuneluri noi (cele existente continuă). Readu-l din tab-ul Noduri.");
    const m = n.met; if (!m) { add("WARN", "nometrics:" + n.name, n.name, "Agentul nu întoarce /metrics"); continue; }
    if (m.cpu.util_pct > 95) add("CRIT", "cpu:" + n.name, n.name, `CPU ${m.cpu.util_pct}%`); else if (m.cpu.util_pct > 85) add("WARN", "cpu:" + n.name, n.name, `CPU ${m.cpu.util_pct}%`);
    const memPct = 100 * (1 - m.mem.avail_mb / m.mem.total_mb); if (memPct > 90) add("WARN", "mem:" + n.name, n.name, `RAM ${memPct.toFixed(0)}%`);
    if (m.disk.free_gb / m.disk.total_gb < 0.1) add("WARN", "disk:" + n.name, n.name, `Disc liber ${m.disk.free_gb} GB`);
    const pool = m.wg.peers / POOL; if (pool > 0.9) add("CRIT", "pool:" + n.name, n.name, `Pool WireGuard ${m.wg.peers}/${POOL}`); else if (pool > 0.7) add("WARN", "pool:" + n.name, n.name, `Pool WireGuard ${m.wg.peers}/${POOL}`);
    if (m.wg.active_3m > n.capacity * 0.8) add("WARN", "cap:" + n.name, n.name, `${m.wg.active_3m} tuneluri active / capacitate ${n.capacity}`);
    if (m.unbound !== "active") add("CRIT", "dns:" + n.name, n.name, "Resolverul DNS (unbound) nu rulează — clienții rămân fără DNS în tunel");
    if (!m.ioc.blocklist_lines) add("WARN", "ioc:" + n.name, n.name, "Lista de domenii periculoase e goală — filtrarea IOC pe nod nu are date");
    if (n.hz && n.hz.included_bytes) {
      const d = new Date(), dim = new Date(d.getUTCFullYear(), d.getUTCMonth() + 1, 0).getDate();
      const proj = (n.hz.out_bytes / Math.max(1, d.getUTCDate())) * dim;
      if (proj > n.hz.included_bytes * 0.9) add("WARN", "traffic:" + n.name, n.name, `Trafic proiectat ${(proj / 1e12).toFixed(2)} TB > 90% din ${(n.hz.included_bytes / 1e12).toFixed(2)} TB incluși`);
    }
    if (n.rtt_cp_ms > 3000) add("WARN", "rtt:" + n.name, n.name, `Control-plane → nod ${n.rtt_cp_ms} ms`);
  }
  if (snap.hz_err) add("WARN", "hz", "", "API Hetzner indisponibil: " + snap.hz_err);
  return a;
}

async function notify(env, alerts) {
  if (!env.RESEND_API_KEY) return;
  const st = (await env.OPS.get("alertstate", "json")) || {};
  const now = Date.now(); const fresh = alerts.filter((x) => x.sev === "CRIT" && (!st[x.key] || now - st[x.key] > ALERT_COOLDOWN));
  if (!fresh.length) return;
  const html = "<h3>CYBER3 VPN — alerte critice</h3><ul>" + fresh.map((x) => `<li><b>${x.node || "flotă"}</b>: ${x.msg}</li>`).join("") + "</ul><p>https://vpn.cyber3.ai</p>";
  const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { authorization: "Bearer " + env.RESEND_API_KEY, "content-type": "application/json" },
    body: JSON.stringify({ from: env.ALERT_FROM, to: [env.ALERT_TO], subject: `[VPN CRIT] ${fresh.length} alertă(e) — ${fresh.map((x) => x.node).join(", ")}`, html }) });
  if (r.ok) { for (const x of fresh) st[x.key] = now; await env.OPS.put("alertstate", JSON.stringify(st)); }
}

// ---------- ciclu complet ----------
async function collect(env, { force = false } = {}) {
  const prev = await env.OPS.get("snap", "json");
  const { nodes, hz_err } = await collectNodes(env, prev);
  const snap = { ts: Date.now(), nodes, hz_err };
  const minute = new Date().getUTCMinutes();
  let clients = await env.OPS.get("clients", "json");
  if (force || !clients || minute % 15 < 5) { clients = await collectClients(env); await env.OPS.put("clients", JSON.stringify(clients)); }
  let billing = await env.OPS.get("billing", "json");
  if (force || !billing || minute % 30 < 5) {
    billing = await collectBilling(env); await env.OPS.put("billing", JSON.stringify(billing));
    const play = await collectPlay(env, clients).catch((e) => ({ ts: Date.now(), subs: [], err: String(e.message || e) }));
    await env.OPS.put("play", JSON.stringify(play));
    await env.OPS.put("funnel", JSON.stringify(await collectFunnel(env)));
  }
  snap.alerts = evaluate(snap, clients);
  await env.OPS.put("snap", JSON.stringify(snap));
  // istoric compact 24h
  const hist = (await env.OPS.get("hist", "json")) || [];
  hist.push({ t: snap.ts, n: Object.fromEntries(nodes.map((n) => [n.name, n.ok ? {
    c: n.met?.cpu.util_pct ?? null, m: n.met ? Math.round(100 * (1 - n.met.mem.avail_mb / n.met.mem.total_mb)) : null,
    rx: n.rate?.rx ?? null, tx: n.rate?.tx ?? null, wr: n.rate?.wg_rx ?? null, wt: n.rate?.wg_tx ?? null,
    p: n.met?.wg.peers ?? n.stat?.peers ?? null, a: n.met?.wg.active_3m ?? null, r: n.rtt_cp_ms ?? null, b: n.delta?.wg ?? null,
    l: n.met ? Object.fromEntries(Object.entries(n.met.lat).map(([k, v]) => [k, v.ms])) : null,
  } : { down: 1 }])) });
  while (hist.length > HIST_MAX) hist.shift();
  await env.OPS.put("hist", JSON.stringify(hist));
  await rollup(env, snap, clients);
  await notify(env, snap.alerts).catch(() => {});
  await dailyReport(env, snap, clients).catch(() => {});
  return snap;
}

// ---------- agregări pe oră (30 zile) și pe zi (12 luni) — pentru grafice pe perioade ----------
async function rollup(env, snap, clients) {
  const up = snap.nodes.filter((n) => n.ok);
  const s = {
    act: up.reduce((a, n) => a + (n.met?.wg.active_3m || 0), 0),
    peers: up.reduce((a, n) => a + (n.met?.wg.peers ?? n.stat?.peers ?? 0), 0),
    rx: up.reduce((a, n) => a + (n.rate?.wg_rx || 0), 0), tx: up.reduce((a, n) => a + (n.rate?.wg_tx || 0), 0),
    bytes: up.reduce((a, n) => a + (n.delta?.wg || 0), 0),
    cpu: up.length ? up.reduce((a, n) => a + (n.met?.cpu.util_pct || 0), 0) / up.length : 0,
    up: up.length, total: snap.nodes.length,
    free: clients?.free?.today_users || 0, paid: clients?.counts?.paid_active || 0, real: clients?.counts?.paid_real || 0,
  };
  const per = Object.fromEntries(up.map((n) => [n.name, { a: n.met?.wg.active_3m || 0, b: n.delta?.wg || 0 }]));
  const merge = (arr, key, max) => {
    let b = arr[arr.length - 1];
    if (!b || b.k !== key) { b = { k: key, t: snap.ts, n: 0, act_max: 0, act_sum: 0, peers_max: 0, rx_sum: 0, tx_sum: 0, rx_max: 0, tx_max: 0, bytes: 0, cpu_sum: 0, up_min: 99, free_max: 0, paid_max: 0, real_max: 0, nodes: {} }; arr.push(b); }
    b.n++; b.act_max = Math.max(b.act_max, s.act); b.act_sum += s.act; b.peers_max = Math.max(b.peers_max, s.peers);
    b.rx_sum += s.rx; b.tx_sum += s.tx; b.rx_max = Math.max(b.rx_max, s.rx); b.tx_max = Math.max(b.tx_max, s.tx);
    b.bytes += s.bytes; b.cpu_sum += s.cpu; b.up_min = Math.min(b.up_min, s.up); b.total = s.total;
    b.free_max = Math.max(b.free_max, s.free); b.paid_max = Math.max(b.paid_max, s.paid); b.real_max = Math.max(b.real_max, s.real);
    for (const [k, v] of Object.entries(per)) { const x = b.nodes[k] || (b.nodes[k] = { a_max: 0, b: 0 }); x.a_max = Math.max(x.a_max, v.a); x.b += v.b; }
    while (arr.length > max) arr.shift();
  };
  const d = new Date(snap.ts);
  const hourly = (await env.OPS.get("hourly", "json")) || []; merge(hourly, d.toISOString().slice(0, 13), 720); await env.OPS.put("hourly", JSON.stringify(hourly));
  const daily = (await env.OPS.get("daily", "json")) || []; merge(daily, d.toISOString().slice(0, 10), 400); await env.OPS.put("daily", JSON.stringify(daily));
}

// ---------- raport zilnic pentru administrator (08:00–09:00 ora României) ----------
async function dailyReport(env, snap, clients) {
  const d = new Date(snap.ts); if (d.getUTCHours() !== 6 || !env.RESEND_API_KEY) return;
  const key = "report:" + d.toISOString().slice(0, 10); if (await env.OPS.get(key)) return;
  const daily = (await env.OPS.get("daily", "json")) || []; const y = daily[daily.length - 2] || daily[daily.length - 1] || {};
  const up = snap.nodes.filter((n) => n.ok).length, al = snap.alerts || [];
  const out = snap.nodes.reduce((a, n) => a + (n.hz?.out_bytes || 0), 0), cost = snap.nodes.reduce((a, n) => a + (n.hz?.price_month || 0), 0);
  const gb = (b) => (b / 1e9).toFixed(2) + " GB";
  const html = `<h2>CYBER3 VPN — raport zilnic ${d.toISOString().slice(0, 10)}</h2>
<p><b>${al.length ? "⚠️ " + al.length + " problemă(e) de verificat" : "✅ Totul funcționează"}</b></p>
<ul><li>Noduri online: <b>${up} / ${snap.nodes.length}</b></li>
<li>Ieri: vârf tuneluri active <b>${y.act_max || 0}</b>, trafic clienți <b>${gb(y.bytes || 0)}</b>, CPU mediu ${y.n ? (y.cpu_sum / y.n).toFixed(1) : 0}%</li>
<li>Clienți plătitori reali: <b>${clients?.counts?.paid_real ?? "—"}</b> · abonamente active (incl. operator/test): ${clients?.counts?.paid_active ?? "—"} · VPN gratuit ieri: ${y.free_max || 0} utilizatori</li>
<li>Trafic ieșire luna aceasta: ${gb(out)} · cost servere: €${cost.toFixed(2)}/lună</li></ul>
${al.length ? "<h3>De verificat</h3><ul>" + al.map((a) => `<li><b>${a.sev}</b> ${a.node || "flotă"} — ${a.msg}</li>`).join("") + "</ul>" : ""}
<p>Detalii și proceduri: <a href="https://vpn.cyber3.ai">vpn.cyber3.ai</a> (tab Manual pentru ce faci la fiecare situație).</p>`;
  const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { authorization: "Bearer " + env.RESEND_API_KEY, "content-type": "application/json" },
    body: JSON.stringify({ from: env.ALERT_FROM, to: [env.ALERT_TO], subject: `[VPN] Raport zilnic — ${up}/${snap.nodes.length} noduri · ${al.length ? al.length + " de verificat" : "totul OK"}`, html }) });
  if (r.ok) await env.OPS.put(key, "1", { expirationTtl: 3 * 86400 });
}

// ---------- timp real: citire directă a agenților (mod rapid, fără ping) ----------
async function live(env) {
  const reg = await fleet(env);
  const auth = { headers: { authorization: "Bearer " + env.AGENT_TOKEN } };
  const nodes = await Promise.all(reg.map(async (n) => {
    try {
      const m = await fetchJson(n.url + "/metrics?nolat=1", auth, 6000);
      return { name: n.name, ok: true, drained: !!n.drained, act: m.wg.active_3m, peers: m.wg.peers, cpu: m.cpu.util_pct, wg_rx: m.wg.rx_bytes, wg_tx: m.wg.tx_bytes, net_rx: m.net.rx_bytes, net_tx: m.net.tx_bytes };
    } catch (e) { return { name: n.name, ok: false }; }
  }));
  return { t: Date.now(), nodes };
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url); const p = url.pathname;
    if (p === "/api/health") return json({ ok: true, service: "cyber3-vpn-ops" });
    if (!authed(req, env)) return new Response("Autentificare necesară", { status: 401, headers: { "www-authenticate": 'Basic realm="CYBER3 VPN Ops", charset="UTF-8"' } });
    if (p === "/" || p === "/index.html") return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex" } });
    if (p === "/api/snapshot") {
      const [snap, clients, billing, registry, tags, play, funnel, drained] = await Promise.all(["snap", "clients", "billing", "registry", "tags", "play", "funnel", "drained"].map((k) => env.OPS.get(k, "json")));
      // tokenurile de achiziție Play rămân pe server (nu ajung în browser)
      const safeClients = clients ? { ...clients, subs: (clients.subs || []).map(({ token, ...r }) => r) } : null;
      return json({ snap, clients: safeClients, billing, play, funnel, registry: registry || {}, tags: tags || {}, drained: drained || {}, now: Date.now() });
    }
    if (p === "/api/history") return json((await env.OPS.get("hist", "json")) || []);
    if (p === "/api/series") {
      const per = url.searchParams.get("period") || "24h";
      if (per === "24h") return json({ period: per, res: "5min", points: (await env.OPS.get("hist", "json")) || [] });
      const src = per === "12m" ? "daily" : "hourly";
      let arr = (await env.OPS.get(src, "json")) || [];
      if (per === "7d") arr = arr.slice(-168);
      return json({ period: per, res: src === "daily" ? "zi" : "oră", points: arr });
    }
    if (p === "/api/live") return json(await live(env));
    if ((p === "/api/cp/drain" || p === "/api/cp/activate") && req.method === "POST") {
      // Comandă și control: scoate un nod din rotația de alocare (tunelurile existente rămân) sau îl readuce.
      const b = await req.json().catch(() => ({}));
      const nodes = (await env.CP.get("nodes", "json")) || [];
      const drained = (await env.OPS.get("drained", "json")) || {};
      if (p === "/api/cp/drain") {
        const n = nodes.find((x) => x.name === b.name); if (!n) return json({ error: "nod necunoscut" }, 404);
        if (nodes.length <= 1) return json({ error: "nu scot ultimul nod din rotație" }, 409);
        drained[n.name] = { ...n, ts: Date.now() };
        await env.CP.put("nodes", JSON.stringify(nodes.filter((x) => x.name !== b.name)));
      } else {
        const n = drained[b.name]; if (!n) return json({ error: "nodul nu e în lista celor scoase" }, 404);
        if (!nodes.find((x) => x.name === n.name)) nodes.push({ name: n.name, url: n.url });
        delete drained[b.name]; await env.CP.put("nodes", JSON.stringify(nodes));
      }
      await env.OPS.put("drained", JSON.stringify(drained));
      return json({ ok: true, drained });
    }
    if (p === "/api/collect" && req.method === "POST") { await collect(env, { force: true }); return json({ ok: true }); }
    if (p === "/api/registry" && req.method === "POST") {
      const b = await req.json().catch(() => ({})); if (!b.name) return json({ error: "name" }, 400);
      const reg = (await env.OPS.get("registry", "json")) || {};
      reg[b.name] = { provider: b.provider || "", location: b.location || "", country: b.country || "", ip: b.ip || "", port_mbps: +b.port_mbps || null, status: b.status || "planificat", brand: b.brand || "CYBER3", notes: b.notes || "", ts: Date.now() };
      await env.OPS.put("registry", JSON.stringify(reg)); return json({ ok: true, registry: reg });
    }
    if (p === "/api/registry" && req.method === "DELETE") {
      const reg = (await env.OPS.get("registry", "json")) || {}; delete reg[url.searchParams.get("name")];
      await env.OPS.put("registry", JSON.stringify(reg)); return json({ ok: true, registry: reg });
    }
    if (p === "/api/tag" && req.method === "POST") {
      const b = await req.json().catch(() => ({})); const tags = (await env.OPS.get("tags", "json")) || {};
      if (b.tag) tags[b.key] = b.tag; else delete tags[b.key];
      await env.OPS.put("tags", JSON.stringify(tags)); return json({ ok: true });
    }
    if (p === "/api/cp/register-node" && req.method === "POST") {
      // Activează un nod pentru clienți (intră în rotația /connect a control-plane-ului).
      const b = await req.json().catch(() => ({}));
      if (!/^[a-z0-9-]{3,32}$/.test(b.name || "") || !/^https?:\/\/[\w.-]+(:\d+)?$/.test(b.url || "")) return json({ error: "nume sau URL invalid" }, 400);
      const r = await env.VPNCP.fetch("https://cp.internal/admin/register-node", { method: "POST", headers: { authorization: "Bearer " + env.CP_ADMIN, "content-type": "application/json" }, body: JSON.stringify({ name: b.name, url: b.url }) });
      return json({ ok: r.ok, status: r.status, body: await r.text() }, r.ok ? 200 : 502);
    }
    return json({ error: "not found" }, 404);
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(collect(env)); },
};
