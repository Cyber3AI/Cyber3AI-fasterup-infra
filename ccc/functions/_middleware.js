// Gate server-side pt CCC — Basic Auth. Fără parolă → 401 (fail closed).
export async function onRequest(context) {
  const { request, env, next } = context;
  const USER = env.CCC_USER || "mihai";
  const PASS = env.CCC_PASS || "";
  const need = () => new Response("CYBER3 CCC — autentificare necesară", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="CYBER3 Command & Control", charset="UTF-8"' },
  });
  if (!PASS) return need();                       // fail closed dacă secretul nu-i setat
  const hdr = request.headers.get("Authorization") || "";
  if (!hdr.startsWith("Basic ")) return need();
  let dec = "";
  try { dec = atob(hdr.slice(6)); } catch (_) { return need(); }
  const i = dec.indexOf(":");
  const u = dec.slice(0, i), p = dec.slice(i + 1);
  if (u === USER && p === PASS) return await next(); // OK → servește pagina
  return need();
}
