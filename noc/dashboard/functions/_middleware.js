// Gate server-side pt NOC — Basic Auth. Fără parolă → 401 (fail closed).
export async function onRequest(context) {
  const { request, env, next } = context;
  const USER = env.NOC_USER || "mihai";
  const PASS = env.NOC_PASS || "";
  const need = () => new Response("CYBER3 NOC — autentificare necesară", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="CYBER3 NOC", charset="UTF-8"' },
  });
  if (!PASS) return need();
  const hdr = request.headers.get("Authorization") || "";
  if (!hdr.startsWith("Basic ")) return need();
  let dec = "";
  try { dec = atob(hdr.slice(6)); } catch (_) { return need(); }
  const i = dec.indexOf(":");
  if (dec.slice(0, i) === USER && dec.slice(i + 1) === PASS) return await next();
  return need();
}
