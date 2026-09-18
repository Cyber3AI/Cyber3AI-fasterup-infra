// CYBER3.AI VPN — control plane (Pas 3+4+5). Worker Cloudflare.
// Storage = KV. Multi-nod: registru noduri in KV ("nodes"), selectie dupa incarcare, failover.
// Worker -> agent nod via hostname nip.io (Workers nu pot fetch IP brut) + firewall CF + bearer.
//
// IDENTITATE (Pas 5, passwordless email): sursa de adevar a abonamentului = `email:<email>`
// (scrisa de webhook-ul de plată Paddle din attr.user_email). Un dispozitiv (user_id = UUID local)
// se LEAGA de un abonament prin `bind:<uid>` = email, fie automat (dispozitivul care plateste,
// din custom_data.user_id), fie prin restore (OTP pe email). Astfel reinstalarea / telefonul nou /
// 5 dispozitive functioneaza: orice device dovedeste emailul (cod) -> se leaga -> are premium.
// CORS deschis pe răspunsuri (doar antet — endpoint-urile sensibile rămân protejate cu bearer;
// necesar ca pagina publică /status de pe cyber3.ai să poată verifica /health și /nodes din browser).
const json = (o, s = 200) =>
  new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "access-control-allow-origin": "*" } });
const now = () => Date.now();
const normEmail = (e) => String(e || "").trim().toLowerCase();
// UNLIMITED DEVICES: inregistrarea dispozitivelor (bind) e nelimitata. Fair-use = plafon pe
// tuneluri ACTIVE simultan per abonament (registru `tunnels:<email>`, prune stale > STALE_MS).
const MAX_TUNNELS = 10;                 // tuneluri active simultan per abonament (anti account-sharing)
const TUNNEL_STALE_MS = 24 * 3600 * 1000;   // un tunel fara /disconnect e considerat inactiv dupa 24h
// FREE plafonat: mecanica dovedita de piata (VPN gratis cu plafon -> upgrade nelimitat).
const FREE_CAP_BYTES = 400 * 1024 * 1024;   // 400 MB / zi (decizie operator 24 aug 2026)
const todayUTC = () => new Date(now()).toISOString().slice(0, 10);          // "YYYY-MM-DD"
const dayResetAt = (day) => Date.parse(day + "T00:00:00Z") + 86400000;      // urmatoarea miezul-noptii UTC

// agentUrl: ex. "http://<ip>.nip.io:8080"
async function agentAt(env, base, method, path, body, timeoutMs = 6000) {
  const r = await fetch(base + path, {
    method,
    headers: { authorization: "Bearer " + env.AGENT_TOKEN, "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const txt = await r.text();
  if (!r.ok) throw new Error("agent " + r.status + ": " + txt);
  return JSON.parse(txt);
}

async function getNodes(env) {
  return (await env.VPN.get("nodes", "json")) || [];
}

// HMAC-SHA256 hex (pt verificarea semnăturii webhook-ului de plată Paddle)
async function hmacHex(secret, body) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// entitlement-ul efectiv al unui dispozitiv: rezolva prin email (bind) daca exista,
// altfel cade pe inregistrarea legacy `user:<uid>` (compat cu testele/cumparatorii vechi).
async function entitlement(env, uid) {
  const email = await env.VPN.get("bind:" + uid);   // string sau null
  if (email) return await env.VPN.get("email:" + email, "json");
  return await env.VPN.get("user:" + uid, "json");
}
const isActive = (e) => !!(e && e.premium_until && e.premium_until > now());

// trimite email prin Resend (https://resend.com). Necesita secret RESEND_API_KEY + var RESEND_FROM.
async function sendEmail(env, to, subject, html) {
  if (!env.RESEND_API_KEY) throw new Error("email not configured");
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { authorization: "Bearer " + env.RESEND_API_KEY, "content-type": "application/json" },
    body: JSON.stringify({ from: env.RESEND_FROM || "CYBER3 <noreply@cyber3.ai>", to: [to], subject, html }),
    signal: AbortSignal.timeout(10000),
  });
  if (!r.ok) throw new Error("resend " + r.status + ": " + (await r.text()).slice(0, 200));
}

// rezolvă entitlement-ul pt un email: KV întâi, apoi Paddle live (și cachează în KV la hit).
// Asigură că un client care a plătit poate restaura abonamentul chiar dacă webhook-ul n-a scris încă KV.
async function resolveEmail(env, email) {
  let ent = await env.VPN.get("email:" + email, "json");
  if (isActive(ent)) return ent;
  const ls = await paddleLookupEmail(env, email);
  if (ls) {
    const devices = Array.isArray(ent && ent.devices) ? ent.devices : [];
    ent = { premium_until: ls.premium_until, tier: ls.tier, status: ls.status, sub_id: ls.sub_id, devices };
    await env.VPN.put("email:" + email, JSON.stringify(ent));
  }
  return ent;
}

// ---- Paddle (Merchant of Record) — billing web principal ----
const paddleBase = (env) => (env.PADDLE_ENV === "live" ? "https://api.paddle.com" : "https://sandbox-api.paddle.com");
// verifică semnătura webhook Paddle: header "Paddle-Signature: ts=..;h1=.." => hmac(secret, ts+":"+raw)
async function paddleVerify(env, raw, sigHeader) {
  if (!env.PADDLE_WEBHOOK_SECRET || !sigHeader) return false;
  const parts = Object.fromEntries(sigHeader.split(";").map((kv) => kv.split("=")));
  if (!parts.ts || !parts.h1) return false;
  const expect = await hmacHex(env.PADDLE_WEBHOOK_SECRET, parts.ts + ":" + raw);
  return expect === parts.h1;
}
async function paddleGet(env, path) {
  try {
    const r = await fetch(paddleBase(env) + path, {
      headers: { authorization: "Bearer " + env.PADDLE_API_KEY }, signal: AbortSignal.timeout(10000) });
    return r.ok ? await r.json() : null;
  } catch { return null; }
}
async function paddleCustomerEmail(env, customerId) {
  if (!customerId) return "";
  const d = await paddleGet(env, "/customers/" + customerId);
  return normEmail(d && d.data && d.data.email);
}
const paddleTier = (env, priceId) =>
  (priceId === env.PADDLE_PRICE_MAXIMUS_MONTHLY || priceId === env.PADDLE_PRICE_MAXIMUS_ANNUAL) ? "maximus" : "faster";
// restore: caută abonament activ în Paddle după email (customer -> subscriptions)
async function paddleLookupEmail(env, email) {
  if (!env.PADDLE_API_KEY) return null;
  const c = await paddleGet(env, "/customers?email=" + encodeURIComponent(email));
  const cust = c && c.data && c.data[0];
  if (!cust) return null;
  const s = await paddleGet(env, "/subscriptions?customer_id=" + cust.id + "&status=active,trialing,past_due,canceled");
  let best = null;
  for (const sub of ((s && s.data) || [])) {
    const endIso = (sub.current_billing_period && sub.current_billing_period.ends_at) || sub.next_billed_at;
    const until = endIso ? Date.parse(endIso) : 0;
    if (!(["active", "trialing", "past_due", "canceled"].includes(sub.status) && until > now())) continue;
    const pid = sub.items && sub.items[0] && sub.items[0].price && sub.items[0].price.id;
    if (!best || until > best.premium_until) best = { premium_until: until, tier: paddleTier(env, pid), status: sub.status, sub_id: sub.id };
  }
  return best;
}

// health-check toate nodurile in paralel; intoarce doar cele vii cu metrici
async function healthyNodes(env) {
  const nodes = await getNodes(env);
  const checks = await Promise.all(
    nodes.map(async (n) => {
      try {
        const s = await agentAt(env, n.url, "GET", "/stat", null, 4000);
        return { ...n, ok: true, peers: s.peers, load1: s.load1, server_pubkey: s.pubkey, endpoint: s.endpoint };
      } catch {
        return { ...n, ok: false };
      }
    })
  );
  return checks.filter((c) => c.ok);
}

// ---- Google Play Developer API: verificare abonament (Play Billing, doar build-ul `play`) ----
// Autentificare cu service account (JWT RS256 -> OAuth token, cache in KV ~1h).
function b64url(buf) {
  const bytes = new Uint8Array(buf);
  let s = ""; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function pemToDer(pem) {
  const b64 = String(pem).replace(/-----BEGIN [^-]+-----/, "").replace(/-----END [^-]+-----/, "").replace(/\s+/g, "");
  const bin = atob(b64); const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
async function googleAccessToken(env) {
  const cached = await env.VPN.get("google:token", "json");
  if (cached && cached.exp > now() + 60000) return cached.token;
  const sa = JSON.parse(env.GOOGLE_SA_JSON);
  const iat = Math.floor(now() / 1000), exp = iat + 3600;
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const claim = b64url(new TextEncoder().encode(JSON.stringify({
    iss: sa.client_email, scope: "https://www.googleapis.com/auth/androidpublisher",
    aud: "https://oauth2.googleapis.com/token", iat, exp,
  })));
  const signingInput = header + "." + claim;
  const key = await crypto.subtle.importKey(
    "pkcs8", pemToDer(sa.private_key), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signingInput));
  const jwt = signingInput + "." + b64url(sig);
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + encodeURIComponent(jwt),
    signal: AbortSignal.timeout(10000),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error("google token: " + JSON.stringify(j).slice(0, 160));
  await env.VPN.put("google:token", JSON.stringify({ token: j.access_token, exp: now() + (j.expires_in - 120) * 1000 }), { expirationTtl: 3600 });
  return j.access_token;
}
async function verifyPlaySub(env, pkg, token) {
  const at = await googleAccessToken(env);
  const r = await fetch(
    `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${pkg}/purchases/subscriptionsv2/tokens/${encodeURIComponent(token)}`,
    { headers: { authorization: "Bearer " + at }, signal: AbortSignal.timeout(10000) }
  );
  const j = await r.json();
  if (!r.ok) throw new Error("play api " + r.status + ": " + JSON.stringify(j).slice(0, 160));
  return j;
}

// CRON (la 5 min): masoara consumul FREE per-user din /usage al nodurilor si aplica plafonul.
// Premium = neatins (nu are fpk). Delta cumulativ pe control-plane (RAM-only: transfer reset la re-add).
async function meterFree(env) {
  const nodes = await getNodes(env);
  const day = todayUTC();
  for (const n of nodes) {
    let transfer;
    try { transfer = (await agentAt(env, n.url, "GET", "/usage", null, 5000)).transfer || {}; }
    catch { continue; }                       // nod jos -> il sarim
    for (const pubkey of Object.keys(transfer)) {
      const uid = await env.VPN.get("fpk:" + pubkey);
      if (!uid) continue;                     // nu e free (premium/necunoscut) -> ignorat
      const t = transfer[pubkey];
      const total = (t.rx || 0) + (t.tx || 0);
      let u = await env.VPN.get("usage:" + uid, "json");
      if (!u || u.day !== day) u = { day, bytes: 0, capped: false, last: {} };
      const prev = u.last[pubkey] || 0;
      u.bytes += total >= prev ? total - prev : total;   // delta; total<prev => re-add/reboot
      u.last[pubkey] = total;
      if (u.bytes >= FREE_CAP_BYTES && !u.capped) {       // plafon atins -> deconectare
        u.capped = true;
        try { await agentAt(env, n.url, "DELETE", "/peer", { pubkey }); } catch {}
        await env.VPN.delete("fpk:" + pubkey);
        await env.VPN.delete("peer:" + uid);
      }
      await env.VPN.put("usage:" + uid, JSON.stringify(u));
    }
  }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;
    try {
      if (p === "/health") return json({ ok: true, service: "cyber3-vpn-cp" });

      // ---- stare abonament (app întreabă după plată / la pornire) ----
      if (p === "/me" && req.method === "GET") {
        const uid = url.searchParams.get("user_id");
        if (!uid) return json({ error: "missing user_id" }, 400);
        const e = await entitlement(env, uid);
        const email = await env.VPN.get("bind:" + uid);
        const premium = isActive(e);
        let usage = null;
        if (!premium) {
          const day = todayUTC();
          let u = await env.VPN.get("usage:" + uid, "json");
          if (!u || u.day !== day) u = { day, bytes: 0, capped: false };
          usage = { used: u.bytes, cap: FREE_CAP_BYTES, capped: !!(u.capped || u.bytes >= FREE_CAP_BYTES), reset_at: dayResetAt(day) };
        }
        return json({ premium, tier: e?.tier || (premium ? null : "free"), until: e?.premium_until || null, linked: !!email, usage });
      }

      // ---- checkout: app cere link de plată (cu user_id în custom data) ----
      if (p === "/billing/checkout" && req.method === "GET") {
        const tier = (url.searchParams.get("tier") || "").toLowerCase();      // faster|maximus
        const period = (url.searchParams.get("period") || "monthly").toLowerCase(); // monthly|annual
        const uid = url.searchParams.get("user_id");
        if (!uid || !tier) return json({ error: "missing tier/user_id" }, 400);
        const cbase = env.PADDLE_CHECKOUT_URL || "https://cyber3.ai/checkout";
        return json({ url: `${cbase}?tier=${encodeURIComponent(tier)}&period=${encodeURIComponent(period)}&uid=${encodeURIComponent(uid)}` });
      }

      // ---- Play Billing: app trimite purchase_token dupa plata; verificam cu Google si acordam premium ----
      // Doar pentru build-ul `play` (Play Store). Restul distributiei ramane pe Paddle (/billing/checkout).
      if (p === "/billing/play/verify" && req.method === "POST") {
        const b = await req.json().catch(() => null);
        const uid = b?.user_id, token = b?.purchase_token, pid = b?.product_id;
        if (!uid || !token) return json({ error: "missing user_id/purchase_token" }, 400);
        if (!env.GOOGLE_SA_JSON) return json({ error: "play_verify_not_configured" }, 503);
        const pkg = env.ANDROID_PACKAGE || "ai.cyber3.app";
        let sub;
        try { sub = await verifyPlaySub(env, pkg, token); }
        catch (e) { return json({ error: "verify_failed", detail: String(e).slice(0, 160) }, 502); }
        const activeStates = ["SUBSCRIPTION_STATE_ACTIVE", "SUBSCRIPTION_STATE_IN_GRACE_PERIOD"];
        const li = (sub.lineItems || [])[0] || {};
        const until = li.expiryTime ? Date.parse(li.expiryTime) : 0;
        const prod = li.productId || pid || "";
        const tier = /maximus/i.test(prod) ? "maximus" : "faster";
        const grant = activeStates.includes(sub.subscriptionState) && until > now();
        // Play e legat de contul Google (nu de email) -> stocam entitlement pe uid: fallback user:<uid>
        await env.VPN.put("user:" + uid, JSON.stringify({
          premium_until: grant ? until : 0, tier, status: sub.subscriptionState, sub_id: token, source: "play",
        }));
        return json({ premium: grant, tier, until: grant ? until : 0, state: sub.subscriptionState });
      }

      // ---- auth passwordless: cere cod OTP pe email (pt restore / alt dispozitiv) ----
      if (p === "/auth/request-code" && req.method === "POST") {
        const { email: rawEmail } = await req.json().catch(() => ({}));
        const email = normEmail(rawEmail);
        if (!email || !email.includes("@")) return json({ error: "bad email" }, 400);
        // restore are sens doar pt un email cu abonament activ -> evita spam catre adrese arbitrare
        const ent = await resolveEmail(env, email);
        if (!isActive(ent)) return json({ ok: true, sent: false, note: "no active subscription for this email" });
        // rate-limit: max 1 cod / 60s
        const prev = await env.VPN.get("otp:" + email, "json");
        if (prev && prev.ts && now() - prev.ts < 60000) return json({ ok: true, sent: true, note: "code already sent" });
        const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
        await env.VPN.put("otp:" + email, JSON.stringify({ code, ts: now(), attempts: 0 }), { expirationTtl: 600 });
        await sendEmail(env, email, "Codul tău CYBER3",
          `<p>Codul tău de verificare CYBER3 este:</p>
           <p style="font-size:28px;font-weight:bold;letter-spacing:4px">${code}</p>
           <p>Expiră în 10 minute. Dacă nu ai cerut tu acest cod, ignoră acest email.</p>`);
        return json({ ok: true, sent: true });
      }

      // ---- auth passwordless: verifică codul -> leagă dispozitivul de abonament ----
      if (p === "/auth/verify" && req.method === "POST") {
        const { email: rawEmail, code, user_id: uid } = await req.json().catch(() => ({}));
        const email = normEmail(rawEmail);
        if (!email || !code || !uid) return json({ error: "missing email/code/user_id" }, 400);
        const rec = await env.VPN.get("otp:" + email, "json");
        if (!rec) return json({ error: "code expired" }, 400);
        if ((rec.attempts || 0) >= 5) { await env.VPN.delete("otp:" + email); return json({ error: "too many attempts" }, 429); }
        if (String(code).trim() !== rec.code) {
          await env.VPN.put("otp:" + email, JSON.stringify({ ...rec, attempts: (rec.attempts || 0) + 1 }), { expirationTtl: 600 });
          return json({ error: "wrong code" }, 401);
        }
        const ent = await resolveEmail(env, email);
        if (!isActive(ent)) return json({ error: "no active subscription" }, 403);
        // UNLIMITED DEVICES: inregistrare nelimitata (plafonul e pe tuneluri active, la /connect)
        const devices = Array.isArray(ent.devices) ? ent.devices : [];
        if (!devices.includes(uid)) {
          devices.push(uid);
          await env.VPN.put("email:" + email, JSON.stringify({ ...ent, devices }));
        }
        await env.VPN.put("bind:" + uid, email);
        await env.VPN.delete("otp:" + email);
        return json({ ok: true, premium: true, tier: ent.tier, until: ent.premium_until });
      }

      // ---- webhook Paddle (Merchant of Record): setează premium în KV (keyed pe email) ----
      if (p === "/billing/paddle-webhook" && req.method === "POST") {
        const raw = await req.text();
        if (!(await paddleVerify(env, raw, req.headers.get("Paddle-Signature"))))
          return json({ error: "bad signature" }, 401);
        let body; try { body = JSON.parse(raw); } catch { return json({ error: "bad json" }, 400); }
        const evt = (body && body.event_type) || "";
        if (!evt.startsWith("subscription.")) return json({ ok: true, note: "ignored " + evt });
        const d = body.data || {};
        const cd = d.custom_data || {};
        const uid = cd.user_id || null;
        const pid = d.items && d.items[0] && d.items[0].price && d.items[0].price.id;
        // GARDĂ cont-partajat: procesăm DOAR abonamentele VPN app (Faster/Maximus).
        // Abonamentele LLM (Entry/Pro/Scale) merg la cyber3-billing → aici le ignorăm.
        const vpnPrices = [env.PADDLE_PRICE_FASTER_MONTHLY, env.PADDLE_PRICE_FASTER_ANNUAL, env.PADDLE_PRICE_MAXIMUS_MONTHLY, env.PADDLE_PRICE_MAXIMUS_ANNUAL];
        if (!vpnPrices.includes(pid) && cd.tier !== "faster" && cd.tier !== "maximus")
          return json({ ok: true, note: "not a VPN product (ignored)" });
        const tier = (cd.tier === "maximus" || paddleTier(env, pid) === "maximus") ? "maximus" : "faster";
        const endIso = (d.current_billing_period && d.current_billing_period.ends_at) || d.next_billed_at;
        const until = endIso ? Date.parse(endIso) : 0;
        // active/trialing/past_due => premium cât timp ends_at e în viitor; canceled cu ends_at viitor => acces până la final
        const grant = ["active", "trialing", "past_due"].includes(d.status)
          ? until > now()
          : (d.status === "canceled" && until > now());
        const email = normEmail(cd.email) || await paddleCustomerEmail(env, d.customer_id);
        if (email) {
          const prev = (await env.VPN.get("email:" + email, "json")) || {};
          const devices = Array.isArray(prev.devices) ? prev.devices : [];
          if (uid && !devices.includes(uid)) devices.push(uid);
          await env.VPN.put("email:" + email, JSON.stringify({
            premium_until: grant ? until : 0, tier, status: d.status, sub_id: d.id || null, devices }));
          if (uid) await env.VPN.put("bind:" + uid, email);
        } else if (uid) {
          await env.VPN.put("user:" + uid, JSON.stringify({
            premium_until: grant ? until : 0, tier, status: d.status, sub_id: d.id || null }));
        }
        return json({ ok: true });
      }

      // ---- admin ----
      if (p.startsWith("/admin/")) {
        if (req.headers.get("authorization") !== "Bearer " + env.ADMIN_TOKEN)
          return json({ error: "unauthorized" }, 401);

        if (p === "/admin/set-premium" && req.method === "POST") {
          const { user_id, days } = await req.json();
          if (!user_id) return json({ error: "missing user_id" }, 400);
          const until = now() + (days || 30) * 86400000;
          await env.VPN.put("user:" + user_id, JSON.stringify({ premium_until: until }));
          return json({ user_id, premium_until: until });
        }
        if (p === "/admin/register-node" && req.method === "POST") {
          const { name, url: nurl } = await req.json();
          if (!name || !nurl) return json({ error: "missing name/url" }, 400);
          const nodes = await getNodes(env);
          const others = nodes.filter((n) => n.name !== name);
          others.push({ name, url: nurl });
          await env.VPN.put("nodes", JSON.stringify(others));
          return json({ nodes: others });
        }
        if (p === "/admin/nodes" && req.method === "GET") return json({ nodes: await healthyNodes(env) });
        return json({ error: "not found" }, 404);
      }

      // ---- nodurile disponibile (public, pentru globul din app): doar nume + incarcare ----
      if (p === "/nodes" && req.method === "GET") {
        return json({ nodes: (await healthyNodes(env)).map((n) => ({ name: n.name, peers: n.peers })) });
      }

      // ---- connect: selectie nod sanatos + cel mai gol (sau nodul ALES de user pe glob) ----
      if (p === "/connect" && req.method === "POST") {
        const { user_id, client_pubkey, node } = await req.json();
        if (!user_id || !client_pubkey) return json({ error: "missing user_id/client_pubkey" }, 400);
        // OPEN_TEST=1 -> sare peste verificare (DOAR pentru test pe telefon; se oprește după).
        // Premium = nelimitat. NU premium = FREE plafonat (400 MB/zi): sub plafon -> tunel;
        // peste plafon -> 402 (app arata upsell). Reset zilnic UTC. Calea premium NEATINSA.
        let freeTier = false;
        if (env.OPEN_TEST !== "1") {
          const e = await entitlement(env, user_id);
          if (!isActive(e)) {
            freeTier = true;
            const day = todayUTC();
            let u = await env.VPN.get("usage:" + user_id, "json");
            if (!u || u.day !== day) u = { day, bytes: 0, capped: false, last: {} };
            if (u.capped || u.bytes >= FREE_CAP_BYTES) {
              return json({ error: "cap_reached", tier: "free", used: u.bytes, cap: FREE_CAP_BYTES, reset_at: dayResetAt(day) }, 402);
            }
            await env.VPN.put("usage:" + user_id, JSON.stringify(u));
          }
        }

        // fair-use: max MAX_TUNNELS tuneluri ACTIVE simultan per abonament (dispozitive nelimitate).
        // registru `tunnels:<email>` = [{uid, ts}]; prune stale + acelasi uid (reconectare permisa).
        const tEmail = await env.VPN.get("bind:" + user_id);
        let tKey = null, tActive = null;
        if (tEmail) {
          tKey = "tunnels:" + tEmail;
          const cutoff = now() - TUNNEL_STALE_MS;
          tActive = ((await env.VPN.get(tKey, "json")) || [])
            .filter((t) => t && t.ts > cutoff && t.uid !== user_id);
          if (tActive.length >= MAX_TUNNELS) return json({ error: "tunnel_limit", limit: MAX_TUNNELS }, 409);
        }

        const healthy = await healthyNodes(env);
        if (!healthy.length) return json({ error: "no healthy node" }, 503);
        // asignare: cel mai putin incarcat (peers, apoi load1)
        healthy.sort((a, b) => a.peers - b.peers || a.load1 - b.load1);
        // nod preferat ales de user pe glob; fallback automat daca nu (mai) e sanatos
        const pick = (typeof node === "string" && healthy.find((n) => n.name === node)) || healthy[0];

        const a = await agentAt(env, pick.url, "POST", "/peer", { pubkey: client_pubkey });
        await env.VPN.put(
          "peer:" + user_id,
          JSON.stringify({ pubkey: client_pubkey, ip: a.client_ip, node: pick.url, name: pick.name, ts: now() })
        );
        // FREE: index invers pubkey->uid ca cronul sa masoare consumul si sa aplice plafonul.
        if (freeTier) await env.VPN.put("fpk:" + client_pubkey, user_id);
        if (tKey) {
          tActive.push({ uid: user_id, ts: now() });
          await env.VPN.put(tKey, JSON.stringify(tActive));
        }
        // Statistică AGREGATĂ pe zi pentru vpn.cyber3.ai (no-logs: fără IP, fără identitate — doar contoare):
        // țara cererii (Cloudflare), platforma aplicației, planul, nodul ales și ruta țară→nod.
        try {
          const ua = req.headers.get("user-agent") || "";
          const plat = /android|dalvik|okhttp/i.test(ua) ? "android" : /java|windows|jdk|ktor/i.test(ua) ? "windows" : /iphone|ipad|ios|cfnetwork|darwin/i.test(ua) ? "ios" : "altele";
          const cc = (req.cf && req.cf.country) || "??";
          const ck = "cstat:" + todayUTC();
          const c = (await env.VPN.get(ck, "json")) || { total: 0, country: {}, platform: {}, tier: {}, node: {}, route: {}, mode: {} };
          const inc = (o, k) => { o[k] = (o[k] || 0) + 1; };
          c.total++; inc(c.country, cc); inc(c.platform, plat); inc(c.tier, freeTier ? "free" : "premium");
          inc(c.node, pick.name); inc(c.route, cc + ">" + pick.name); inc(c.mode, typeof node === "string" && pick.name === node ? "ales" : "auto");
          await env.VPN.put(ck, JSON.stringify(c), { expirationTtl: 400 * 86400 });
        } catch (_) {}
        return json({
          node: pick.name,
          client_ip: a.client_ip,
          dns: a.dns,
          server_pubkey: a.server_pubkey,
          endpoint: a.endpoint,
          allowed_ips: "0.0.0.0/0, ::/0",
          keepalive: 25,
          tier: freeTier ? "free" : "premium",   // clientul distinge tunel free (NU marca premium) de premium
        });
      }

      // ---- disconnect: foloseste nodul stocat ----
      if (p === "/disconnect" && req.method === "POST") {
        const { user_id, client_pubkey } = await req.json();
        const rec = user_id ? await env.VPN.get("peer:" + user_id, "json") : null;
        const pub = client_pubkey || (rec && rec.pubkey);
        if (!pub) return json({ error: "missing client_pubkey" }, 400);
        if (rec && rec.node) {
          try { await agentAt(env, rec.node, "DELETE", "/peer", { pubkey: pub }); } catch {}
        } else {
          // necunoscut: incearca pe toate nodurile
          for (const n of await getNodes(env)) {
            try { await agentAt(env, n.url, "DELETE", "/peer", { pubkey: pub }); } catch {}
          }
        }
        if (user_id) {
          await env.VPN.delete("peer:" + user_id);
          if (pub) await env.VPN.delete("fpk:" + pub);   // FREE: scoate indexul de masurare
          // scoate uid-ul din registrul de tuneluri active al abonamentului
          const dEmail = await env.VPN.get("bind:" + user_id);
          if (dEmail) {
            const dKey = "tunnels:" + dEmail;
            const left = ((await env.VPN.get(dKey, "json")) || []).filter((t) => t && t.uid !== user_id);
            await env.VPN.put(dKey, JSON.stringify(left));
          }
        }
        return json({ disconnected: true });
      }

      return json({ error: "not found" }, 404);
    } catch (e) {
      return json({ error: String(e && e.message ? e.message : e) }, 500);
    }
  },

  // CRON trigger (vezi wrangler.toml [triggers] crons) -> masurare + plafonare FREE.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(meterFree(env));
  },
};
