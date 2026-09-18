// Injectează bara sticky de instalare Google Play pe toate paginile HTML (mobile-first).
const PLAY = "https://play.google.com/store/apps/details?id=ai.cyber3.app&referrer=utm_source%3Dfasterup%26utm_medium%3Dstickybar%26utm_campaign%3Dapp-install";
const BAR = `<style>#c3bar{position:fixed;left:0;right:0;bottom:0;z-index:2147483000;background:linear-gradient(180deg,#0a1f3a,#071a30);border-top:2px solid #D4AF37;box-shadow:0 -6px 24px rgba(0,0,0,.45);display:flex;align-items:center;gap:10px;padding:9px 12px;padding-bottom:calc(9px + env(safe-area-inset-bottom));font-family:system-ui,Segoe UI,Arial,sans-serif}
#c3bar .t{flex:1;color:#eaf1ff;font-size:13px;line-height:1.25;font-weight:600}#c3bar .t b{color:#D4AF37}
#c3bar a.i{background:#D4AF37;color:#1a1400;font-weight:800;font-size:13px;padding:11px 16px;border-radius:9px;text-decoration:none;white-space:nowrap;flex-shrink:0}
#c3bar .x{background:transparent;border:0;color:#9fb3d1;font-size:22px;line-height:1;padding:4px 8px;cursor:pointer;flex-shrink:0}
@media(max-width:520px){#c3bar{gap:8px;padding:8px 10px;padding-bottom:calc(8px + env(safe-area-inset-bottom))}#c3bar .t{font-size:11.5px}#c3bar a.i{padding:11px 14px;font-size:12.5px}}</style>
<div id="c3bar"><svg viewBox="0 0 24 24" width="30" height="30" style="flex-shrink:0" aria-hidden="true"><path d="M12 2.1 L20.6 5 V11 C20.6 16.6 16.8 20.5 12 21.9 C7.2 20.5 3.4 16.6 3.4 11 V5 Z" fill="rgba(212,175,55,.16)" stroke="#D4AF37" stroke-width="1.3"/><g fill="none" stroke="#f2d778" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5.2 V18.2"/><path d="M12 5.7 h2.2 a2 2 0 0 1 0 3.9 H12"/><path d="M8 11 L16 15.6"/><path d="M16 11 L8 15.6"/></g></svg><div class="t"><b>Protejează-ți telefonul</b> — <span style="color:#FF0000;font-weight:800">CYBER3</span>, gratuit pe Google Play</div><a class="i" href="${PLAY}">Instalează</a><button class="x" aria-label="Închide" onclick="c3barClose()">×</button></div>
<script>function c3barClose(){var b=document.getElementById('c3bar');if(b)b.remove();document.body.style.paddingBottom='';try{localStorage.setItem('c3bar_x','1')}catch(e){}}
(function(){try{if(localStorage.getItem('c3bar_x')){var b=document.getElementById('c3bar');if(b)b.remove();return}}catch(e){}document.body.style.paddingBottom='68px'})();</script>`;
// Redirect de limbă (server-side): pe rădăcină, deschide în limba potrivită.
// Prioritate: cookie (alegere explicită a userului) > GEO România/Moldova → română > limba browserului > EN.
// v3 (16 sep 2026): fasterup.ai = piața de administrație publică din România → TOȚI vizitatorii
// din RO/MD văd site-ul în ROMÂNĂ, chiar dacă browserul e setat pe engleză. Restul lumii = limba browserului.
const LANG_PATHS = new Set(["/", "/ro/", "/es/", "/it/", "/de/", "/fr/", "/ru/", "/zh/", "/en/"]);
// Toate limbile suportate → cale (en = rădăcina, servită direct fără redirect).
const LANG_MAP = { en: "/", ro: "/ro/", es: "/es/", it: "/it/", de: "/de/", fr: "/fr/", ru: "/ru/", zh: "/zh/" };

function langRedirect(request, url) {
  const p = url.pathname;
  if (p !== "/" && p !== "/index.html") return null;            // DOAR rădăcina; nu atinge /ro/, /es/ etc.
  // 1) alegerea explicită a userului (cookie fulang) — întâietate absolută (butoanele de limbă funcționează)
  const m = /(?:^|;\s*)fulang=([^;]*)/.exec(request.headers.get("cookie") || "");
  if (m) {
    const val = decodeURIComponent(m[1] || "");
    return (LANG_PATHS.has(val) && val !== "/" && val !== "/index.html") ? url.origin + val : null;
  }
  // 2) GEO România/Moldova → ROMÂNĂ pentru TOȚI (indiferent de limba browserului) — piața admin publică RO
  const country = (request.cf && request.cf.country) || request.headers.get("cf-ipcountry") || "";
  if (country === "RO" || country === "MD") return url.origin + "/ro/";
  // 3) restul lumii: limba browserului (Accept-Language) — prima limbă suportată câștigă
  const al = (request.headers.get("accept-language") || "").toLowerCase();
  for (const part of al.split(",")) {
    const lang = part.split(";")[0].trim().slice(0, 2);
    if (lang in LANG_MAP) {
      const t = LANG_MAP[lang];
      return t === "/" ? null : url.origin + t;                 // en → rădăcină (fără redirect)
    }
  }
  return null;                                                   // altfel rădăcina (EN)
}

export async function onRequest(context) {
  const url = new URL(context.request.url);
  const target = langRedirect(context.request, url);
  if (target) return Response.redirect(target, 302);
  const res = await context.next();
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("text/html")) return res;
  return new HTMLRewriter().on("body", { element(el) { el.append(BAR, { html: true }); } }).transform(res);
}
