// Interfața vpn.cyber3.ai — portal pentru un administrator care preia exploatarea fără să cunoască istoria sistemului.
// Fiecare tab: „Ce vezi aici” + „Ce faci”. JS-ul de mai jos NU folosește template literals și nici secvența dolar-acoladă.
export const PAGE = String.raw`<!doctype html>
<html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>CYBER3 VPN Operations</title>
<style>
:root{--bg:#070d1a;--p1:#0e1726;--p2:#0b1321;--p3:#101c31;--line:#1d2a44;--ink:#e8eefb;--mut:#9aa8c4;--dim:#63739a;
--gold:#D4AF37;--red:#e11d2e;--ok:#22d38a;--warn:#fbbf24;--crit:#ff4d5e;--blue:#4f8cff;--cyan:#22d3ee;
--mono:ui-monospace,"Cascadia Mono",Consolas,"SF Mono",monospace;--sans:"Segoe UI",system-ui,-apple-system,Arial,sans-serif}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:radial-gradient(1200px 500px at 85% -10%,rgba(212,175,55,.06),transparent 60%),var(--bg);color:var(--ink);font:14px/1.55 var(--sans)}
a{color:var(--gold)}code{font:12.5px var(--mono);background:var(--p3);padding:1px 5px;border-radius:5px;color:#dfe7f7}
header{position:sticky;top:0;z-index:30;background:rgba(7,13,26,.94);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.hd{max-width:1440px;margin:0 auto;padding:10px 20px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:800}
.brand .x{width:28px;height:28px;border-radius:50%;border:2px solid var(--red);display:grid;place-items:center;color:var(--red);font-weight:900;animation:pl 3s ease-in-out infinite}
@keyframes pl{50%{box-shadow:0 0 0 5px rgba(225,29,46,.12)}}
.brand b{color:var(--red)}.brand small{display:block;color:var(--mut);font-weight:600;font-size:10.5px;letter-spacing:.18em}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{font:600 11px var(--mono);padding:4px 10px;border-radius:20px;border:1px solid var(--line);color:var(--mut)}
.chip.on{border-color:rgba(34,211,138,.5);color:var(--ok)}.chip.plan{border-color:rgba(212,175,55,.45);color:var(--gold)}
.upd{margin-left:auto;font:12px var(--mono);color:var(--mut);display:flex;gap:10px;align-items:center}
button{font:600 12.5px var(--sans);background:var(--p1);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:7px 12px;cursor:pointer}
button:hover{border-color:var(--gold)}button:focus-visible,a:focus-visible,select:focus-visible,input:focus-visible{outline:2px solid var(--gold);outline-offset:2px}
button.pri{background:var(--gold);color:#1a1400;border-color:var(--gold)}button.dang{border-color:rgba(255,77,94,.5);color:#ffb3bb}button.sm{padding:4px 9px;font-size:11.5px}
.tabs{max-width:1440px;margin:0 auto;padding:0 20px 10px;display:flex;gap:4px;overflow-x:auto;scrollbar-width:none}
.tabs a{flex:0 0 auto;text-decoration:none;color:var(--mut);font-size:13px;font-weight:600;padding:7px 12px;border-radius:9px;border:1px solid transparent}
.tabs a:hover{color:var(--ink);background:var(--p1)}.tabs a.on{color:#1a1400;background:var(--gold)}
.tabs a .b{display:inline-block;min-width:17px;padding:0 5px;margin-left:5px;border-radius:9px;font:700 10.5px var(--mono);background:var(--crit);color:#fff;text-align:center}
main{max-width:1440px;margin:0 auto;padding:18px 20px 60px}
.tab{display:none}.tab.on{display:block}
h2{font-size:21px;margin:0 0 6px;letter-spacing:-.01em}
h3{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--mut);margin:22px 0 10px;font-family:var(--mono);font-weight:700}
.help{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:6px 0 18px}
.help div{background:var(--p3);border:1px solid var(--line);border-radius:12px;padding:11px 14px;font-size:13.2px;color:#c9d4ea}
.help div>b:first-child{display:block;font:700 11px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--gold);margin-bottom:4px}.help b{color:#eef3fc}
.cc{display:inline-block;font:700 10px var(--mono);padding:1px 5px;border-radius:5px;border:1px solid var(--line);color:var(--mut);margin-right:4px;letter-spacing:.04em;vertical-align:1px}
.help ul{margin:0;padding-left:18px}.help li{margin:2px 0}
.grid{display:grid;gap:12px}.k6{grid-template-columns:repeat(6,1fr)}.k5{grid-template-columns:repeat(5,1fr)}.k4{grid-template-columns:repeat(4,1fr)}.k3{grid-template-columns:repeat(3,1fr)}.k2{grid-template-columns:repeat(2,1fr)}
.card{background:linear-gradient(180deg,var(--p1),var(--p2));border:1px solid var(--line);border-radius:14px;padding:14px 16px;min-width:0}
.card>h3:first-child{margin-top:0}
.kpi .v{font:800 26px var(--mono);letter-spacing:-.02em;font-variant-numeric:tabular-nums;line-height:1.15}
.kpi .l{font-size:12.5px;color:#c9d4ea;margin-top:4px;font-weight:600}.kpi .s{font:11px var(--mono);color:var(--dim);margin-top:4px}
.ok{color:var(--ok)}.warn{color:var(--warn)}.crit{color:var(--crit)}.gold{color:var(--gold)}.dim{color:var(--dim)}.mut{color:var(--mut)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:1px}
.d-ok{background:var(--ok);box-shadow:0 0 8px var(--ok)}.d-warn{background:var(--warn)}.d-crit{background:var(--crit);box-shadow:0 0 8px var(--crit)}.d-plan{background:var(--gold)}.d-off{background:var(--dim)}
.banner{border-radius:16px;padding:18px 20px;display:flex;gap:16px;align-items:flex-start;margin-bottom:16px;border:1px solid}
.banner .ic{font-size:30px;line-height:1}.banner h2{margin:0 0 4px}.banner p{margin:0;color:#d6deef}
.banner.g{background:linear-gradient(135deg,rgba(34,211,138,.12),rgba(34,211,138,.03));border-color:rgba(34,211,138,.4)}
.banner.y{background:linear-gradient(135deg,rgba(251,191,36,.12),rgba(251,191,36,.03));border-color:rgba(251,191,36,.45)}
.banner.r{background:linear-gradient(135deg,rgba(255,77,94,.15),rgba(255,77,94,.03));border-color:rgba(255,77,94,.5)}
.live .v{font-size:32px}.live .pulse{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--ok);margin-right:6px;animation:pp 1.6s infinite}
@keyframes pp{50%{opacity:.25}}
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
table{border-collapse:collapse;width:100%;font-size:12.8px}
th{text-align:left;font:600 10.5px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--dim);padding:9px 10px;border-bottom:1px solid var(--line);background:var(--p2);white-space:nowrap}
td{padding:9px 10px;border-bottom:1px solid rgba(29,42,68,.7);vertical-align:middle;white-space:nowrap}
tr:last-child td{border-bottom:0}td.num{font-family:var(--mono);font-variant-numeric:tabular-nums;text-align:right}td.wrap{white-space:normal;min-width:240px}
.bar{height:6px;border-radius:4px;background:rgba(154,168,196,.15);overflow:hidden;min-width:70px}.bar i{display:block;height:100%;border-radius:4px}
.tag{font:600 10px var(--mono);padding:2px 7px;border-radius:12px;border:1px solid currentColor;letter-spacing:.06em}
.note{font-size:13px;color:#cdd7ec;border-left:3px solid var(--gold);padding:8px 12px;margin:8px 0;background:rgba(212,175,55,.05);border-radius:0 10px 10px 0}
.note.w{border-color:var(--warn);background:rgba(251,191,36,.06)}.note.c{border-color:var(--crit);background:rgba(255,77,94,.07)}
.map{position:relative;height:260px;border-radius:12px;overflow:hidden;border:1px solid var(--line);
background:linear-gradient(rgba(29,42,68,.35) 1px,transparent 1px) 0 0/100% 12.5%,linear-gradient(90deg,rgba(29,42,68,.35) 1px,transparent 1px) 0 0/8.33% 100%,var(--p2)}
.pin{position:absolute;transform:translate(-50%,-50%);font:600 11px var(--mono);white-space:nowrap;text-align:center}
.pin i{display:block;width:12px;height:12px;border-radius:50%;margin:0 auto 3px;border:2px solid var(--bg)}
.pin span{background:rgba(7,13,26,.85);padding:1px 6px;border-radius:6px;border:1px solid var(--line)}
.heat td{text-align:center;font-family:var(--mono)}
.chart{position:relative;width:100%;min-height:200px}.chart svg{display:block;width:100%}
.tip{position:absolute;pointer-events:none;background:rgba(7,13,26,.96);border:1px solid var(--line);border-radius:8px;padding:7px 9px;font:11.5px var(--mono);white-space:nowrap;z-index:5;display:none}
.lg{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:6px;font:11.5px var(--mono);color:var(--mut)}.lg i{display:inline-block;width:10px;height:3px;border-radius:2px;margin-right:6px;vertical-align:3px}
.empty{padding:40px 10px;text-align:center;color:var(--dim);font-size:13px}
.per{display:flex;gap:4px;flex-wrap:wrap;margin:0 0 14px}.per button.on{background:var(--gold);color:#1a1400;border-color:var(--gold)}
.frm{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:8px;align-items:end}
.frm label{font-size:11.5px;color:var(--mut);display:flex;flex-direction:column;gap:4px}
input,select{background:var(--p2);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:7px 9px;font:13px var(--sans);min-width:0}
.steps{display:flex;flex-direction:column;gap:8px}
.st{display:grid;grid-template-columns:28px 1fr;gap:10px;align-items:start;font-size:13.2px}.st b{font:800 12px var(--mono);color:#1a1400;background:var(--gold);border-radius:50%;width:22px;height:22px;display:grid;place-items:center}
.fun{display:grid;grid-template-columns:200px 1fr 60px;gap:10px;align-items:center;font-size:12.5px;margin:5px 0}.fun .bar{height:10px}
.lay{display:grid;grid-template-columns:170px 1fr 150px;gap:12px;align-items:center;padding:11px 0;border-bottom:1px solid rgba(29,42,68,.7)}
.lay:last-child{border-bottom:0}.lay b{font-size:13.5px}
.arch{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;align-items:stretch}
.box{border:1px solid var(--line);border-radius:12px;padding:12px;background:var(--p3);font-size:12.8px}
.box b{display:block;font-size:13.5px;margin-bottom:4px}.box .w{font:11px var(--mono);color:var(--gold);letter-spacing:.1em;text-transform:uppercase;margin-bottom:6px}
.gl{display:grid;grid-template-columns:190px 1fr;gap:6px 14px;font-size:13.2px}.gl dt{font-weight:700;color:var(--gold)}.gl dd{margin:0;color:#cdd7ec}
details.proc{border:1px solid var(--line);border-radius:12px;background:var(--p2);margin:8px 0}
details.proc summary{cursor:pointer;padding:11px 14px;font-weight:700;list-style:none}details.proc summary::before{content:"▸ ";color:var(--gold)}details.proc[open] summary::before{content:"▾ "}
details.proc .in{padding:0 16px 12px;font-size:13.2px;color:#cdd7ec}details.proc ol{margin:6px 0;padding-left:20px}details.proc li{margin:3px 0}
@media(max-width:1100px){.k6,.k5{grid-template-columns:repeat(3,1fr)}.k4{grid-template-columns:repeat(2,1fr)}.frm{grid-template-columns:repeat(2,1fr)}.arch{grid-template-columns:1fr 1fr}.help{grid-template-columns:1fr}}
@media(max-width:700px){.k6,.k5,.k4,.k3,.k2{grid-template-columns:1fr 1fr}.lay,.gl{grid-template-columns:1fr}.fun{grid-template-columns:120px 1fr 50px}.arch{grid-template-columns:1fr}}
@media(prefers-reduced-motion:reduce){.brand .x,.live .pulse{animation:none}}
</style></head><body>
<header><div class="hd">
  <div class="brand"><div class="x">✚</div><div><b>CYBER3</b> · VPN OPERATIONS<small>COMANDĂ · CONTROL · EXPLOATARE — INFRASTRUCTURĂ WIREGUARD</small></div></div>
  <div class="chips"><span class="chip on">● CYBER3 VPN · LIVE</span><span class="chip plan">◆ VPNzone.NET · pregătit</span></div>
  <div class="upd"><span id="upd">—</span><button id="refresh" title="Rulează acum o colectare completă (durează ~15 s)">Colectează acum</button></div>
</div>
<nav class="tabs" id="tabs">
  <a href="#acum">Acum</a><a href="#grafice">Grafice</a><a href="#noduri">Noduri</a><a href="#conexiuni">Conexiuni</a><a href="#clienti">Clienți & vânzări</a>
  <a href="#latenta">Latență</a><a href="#resurse">Resurse & costuri</a><a href="#alerte">Alerte</a><a href="#exploatare">Exploatare</a>
  <a href="#scalare">Scalare</a><a href="#oferte">Produse & oferte</a><a href="#internet">Internet · VPNzone</a><a href="#manual">📘 Manual</a>
</nav></header>
<main>

<section class="tab" id="t-acum">
  <div id="banner"></div>
  <div class="grid k4" id="livek"></div>
  <div class="grid k2" style="margin-top:12px"><div class="card"><h3>Clienți conectați — ultimele minute (live)</h3><div class="chart" id="lc1"></div></div>
  <div class="card"><h3>Bandă prin tunel — live (Mbps)</h3><div class="chart" id="lc2"></div></div></div>
  <div class="grid k6" id="kpis" style="margin-top:12px"></div>
  <h3>Harta flotei</h3><div class="map" id="map"></div>
  <div class="help" style="margin-top:14px"><div><b>Ce vezi aici</b>Starea întregii infrastructuri VPN într-un singur ecran: bannerul de sus îți spune dacă totul e în regulă. Cifrele „live” se actualizează la 10 secunde direct din noduri; restul la 5 minute.</div>
  <div><b>Ce faci</b><ul><li>Verde → nimic de făcut.</li><li>Galben/roșu → deschide tab-ul <b>Alerte</b>; fiecare alertă are procedura ei în <b>Manual</b>.</li><li>Primești zilnic la 09:00 un raport pe email cu același rezumat.</li></ul></div></div>
</section>

<section class="tab" id="t-grafice">
  <h2>Grafice pe perioade</h2>
  <div class="help"><div><b>Ce vezi aici</b>Evoluția încărcării: clienți conectați (tuneluri active), bandă, trafic consumat, procesor, clienți pe planuri și disponibilitatea nodurilor. Treci cu mouse-ul peste grafic pentru valori exacte.</div>
  <div><b>Cum citești</b><ul><li><b>Live</b> = ultimele minute, din noduri, la 10 s (cât stă pagina deschisă).</li><li><b>24h</b> = puncte la 5 min. <b>7 / 30 zile</b> = pe oră (vârf/medie). <b>12 luni</b> = pe zi.</li><li>Istoricul lung se construiește de acum înainte (portalul e nou).</li></ul></div></div>
  <div class="per" id="per"></div>
  <div class="grid k2">
    <div class="card"><h3>Clienți conectați (tuneluri active) — pe noduri</h3><div class="chart" id="g1"></div></div>
    <div class="card"><h3>Bandă prin tunel (Mbps)</h3><div class="chart" id="g2"></div></div>
    <div class="card"><h3>Trafic consumat de clienți</h3><div class="chart" id="g3"></div></div>
    <div class="card"><h3>Procesor (CPU %)</h3><div class="chart" id="g4"></div></div>
    <div class="card"><h3>Clienți pe planuri</h3><div class="chart" id="g5"></div></div>
    <div class="card"><h3>Disponibilitate — noduri online</h3><div class="chart" id="g6"></div></div>
  </div>
</section>

<section class="tab" id="t-noduri">
  <h2>Noduri & încărcare</h2>
  <div class="help"><div><b>Ce vezi aici</b>Fiecare server VPN (nod): unde e, cine îl găzduiește, câți clienți are conectați acum, cât din capacitate folosește, procesor, memorie și bandă. <b>Tuneluri active</b> = clienți cu trafic în ultimele 3 minute. <b>Peer-i</b> = chei de clienți înregistrate pe nod (maximum 253).</div>
  <div><b>Comenzi</b><ul><li><b>Scoate din rotație</b>: nodul nu mai primește clienți noi, cei conectați rămân. Folosește-l înainte de mentenanță.</li><li><b>Readu în rotație</b>: nodul primește din nou clienți.</li><li>Nodul se scoate singur din alocare dacă pică (failover automat) — nu trebuie să intervii.</li></ul></div></div>
  <div class="tw"><table id="tnodes"></table></div>
</section>

<section class="tab" id="t-conexiuni">
  <h2>Conexiuni — de unde și de pe ce aplicație</h2>
  <div class="help"><div><b>Ce vezi aici</b>Fiecare conectare la VPN, numărată pe țara din care vine clientul, pe aplicație (<b>Android</b> = mobil, <b>Windows</b> = desktop), pe plan și pe nodul primit. Ultimele 30 de zile. Nu se păstrează nicio adresă IP și nicio identitate — doar contoare.</div>
  <div><b>La ce folosește</b><ul><li>Unde cresc clienții → unde deschidem noduri noi.</li><li><b>Rute lungi</b> (ex. client din România trimis în SUA) = latență mare; vezi recomandarea din <b>Scalare</b>.</li><li>Raportul desktop/mobil arată pe ce aplicație merită investit.</li></ul></div></div>
  <div class="grid k4" id="connk"></div>
  <div class="grid k2" style="margin-top:12px"><div class="card"><h3>Țări (30 zile)</h3><div class="tw"><table id="tcountry"></table></div></div>
  <div class="card"><h3>Conexiuni pe zi — pe aplicație</h3><div class="chart" id="gconn"></div><h3>Rute țară client → nod</h3><div class="tw"><table id="troute"></table></div></div></div>
</section>

<section class="tab" id="t-clienti">
  <h2>Clienți & vânzări</h2>
  <div class="help"><div><b>Ce vezi aici</b>Abonații plătitori (Google Play + web), utilizatorii VPN-ului gratuit și pâlnia de conversie a aplicației, de la deschidere până la plată. Google Play e canalul principal (acolo duc campaniile); fiecare abonament Play e re-verificat direct la Google la 30 de minute.</div>
  <div><b>Ce faci</b><ul><li>Marchează conturile tale sau de test cu „operator” / „test” — astfel „plătitori reali” rămâne exact.</li><li>Pâlnia arată unde se pierd utilizatorii (ex. mulți ating plafonul gratuit, puțini plătesc).</li></ul></div></div>
  <div class="grid k6" id="ckpis"></div>
  <h3>Google Play — abonamente verificate live la Google</h3><div class="tw"><table id="tplay"></table></div>
  <h3>Toate abonamentele (o achiziție = un rând, chiar dacă e pe mai multe dispozitive)</h3><div class="tw"><table id="tsubs"></table></div>
  <div class="grid k2" style="margin-top:12px"><div class="card"><h3>VPN gratuit azi — consum vs plafon 400 MB</h3><div id="free"></div></div>
  <div class="card"><h3>Pâlnia aplicației — 14 zile</h3><div id="funnel"></div></div></div>
</section>

<section class="tab" id="t-latenta">
  <h2>Latență</h2>
  <div class="help"><div><b>Ce vezi aici</b>Cât de repede răspunde fiecare nod: spre marile resolvere de Internet (1.1.1.1 Cloudflare, 8.8.8.8 Google, 9.9.9.9 Quad9), spre celelalte noduri și timpul în care control-plane-ul primește răspuns de la agent. Măsurat la 5 minute, de pe fiecare nod.</div>
  <div><b>Praguri</b><ul><li>Verde sub 40 ms, galben 40–100 ms, roșu peste 100 ms sau fără răspuns.</li><li>Pierderi de pachete (%) apar lângă valoare — dacă persistă pe un nod, verifică rețeaua furnizorului.</li></ul></div></div>
  <div class="grid k2"><div class="card"><h3>Nod → Internet (ms)</h3><div class="tw"><table id="tlat"></table></div></div>
  <div class="card"><h3>Nod ↔ nod (ms)</h3><div class="tw"><table class="heat" id="tmesh"></table></div></div></div>
</section>

<section class="tab" id="t-resurse">
  <h2>Resurse & costuri</h2>
  <div class="help"><div><b>Ce vezi aici</b>Traficul de ieșire consumat luna aceasta față de cel inclus în planul fiecărui server, proiecția la final de lună și costul. Peste traficul inclus, furnizorul taxează pe TB — atenție la SUA și Singapore, unde traficul inclus e mic.</div>
  <div><b>Ce faci</b><ul><li>Proiecție peste 90% → alertă; mută volumul pe noduri cu trafic inclus mare sau adaugă un nod în aceeași regiune.</li><li>Costul pe TB peste inclus e colorat galben unde e scump.</li></ul></div></div>
  <div class="grid k4" id="rkpis"></div><div class="tw" style="margin-top:12px"><table id="tres"></table></div>
</section>

<section class="tab" id="t-alerte">
  <h2>Alerte</h2>
  <div class="help"><div><b>Ce vezi aici</b>Problemele detectate la ultima colectare. <b>CRIT</b> = afectează clienții acum (ți se trimite și email, o dată la 6 ore pe aceeași problemă). <b>WARN</b> = de urmărit / de planificat.</div>
  <div><b>Ce faci</b>Deschide <b>Manual → Proceduri</b>: fiecare tip de alertă are pașii de rezolvare, scriși pentru cineva care nu a construit sistemul.</div></div>
  <div id="alerts"></div><h3>Regulile după care se generează alertele</h3><div class="tw"><table id="trules"></table></div>
</section>

<section class="tab" id="t-exploatare">
  <h2>Exploatare & automatizare</h2>
  <div class="help"><div><b>Ce vezi aici</b>Automatizările care țin infrastructura în viață fără intervenție umană, registrul nodurilor în pregătire și comenzile de adăugare a unui nod nou.</div>
  <div><b>Ce faci</b><ul><li>Automatizările cu „atenție” au explicația alături.</li><li>Nod nou: urmezi cei 6 pași, apoi îl activezi din formularul de jos. Acțiunile de aici modifică producția și cer confirmare.</li></ul></div></div>
  <div class="grid k2"><div class="card"><h3>Automatizări</h3><div class="tw"><table id="tauto"></table></div></div>
  <div class="card"><h3>Procedura: nod nou (Hetzner sau data center propriu)</h3><div class="steps" id="runbook"></div></div></div>
  <div class="card" style="margin-top:12px"><h3>Registrul flotei — noduri planificate / în pregătire</h3><div class="tw"><table id="treg"></table></div>
  <h3>Adaugă în registru</h3>
  <div class="frm"><label>Nume<input id="rg_name" placeholder="vpn-dc1"></label><label>Furnizor<input id="rg_prov" placeholder="Data center propriu"></label>
  <label>Locație<input id="rg_loc" placeholder="București"></label><label>Țară (2 litere)<input id="rg_cc" placeholder="RO" maxlength="2"></label>
  <label>Port (Mbps)<input id="rg_port" placeholder="10000"></label><label>Brand<select id="rg_brand"><option>CYBER3</option><option>VPNzone.NET</option><option>CYBER3 + VPNzone.NET</option></select></label>
  <label>IP public<input id="rg_ip" placeholder="—"></label><label>Stare<select id="rg_st"><option>planificat</option><option>în instalare</option><option>test</option></select></label>
  <label style="grid-column:span 3">Note<input id="rg_notes" placeholder="metal, placă de rețea, uplink…"></label><button class="pri" id="rg_add">Salvează în registru</button></div></div>
  <div class="card" style="margin-top:12px"><h3>Activează un nod în control-plane (primește clienți)</h3>
  <p class="mut" style="margin:0 0 10px">Doar după ce nodul are WireGuard + agentul instalate (pașii de mai sus). De aici încolo control-plane-ul îl verifică la fiecare conectare și îl ocolește automat dacă pică.</p>
  <div class="frm"><label>Nume nod<input id="cp_name" placeholder="vpn-dc1"></label><label style="grid-column:span 3">Adresa agentului<input id="cp_url" placeholder="http://IP.nip.io:8080"></label><button class="pri" id="cp_add">Activează nodul</button><span id="cp_msg" class="mut"></span></div></div>
</section>

<section class="tab" id="t-scalare">
  <h2>Scalare & capacitate</h2>
  <div class="help"><div><b>Ce vezi aici</b>Cât din capacitatea flotei e folosită, pe regiuni, și unde trebuie adăugat următorul nod. WireGuard ține fiecare client pe un nod, deci creștem <b>adăugând noduri</b> (scalare orizontală) — control-plane-ul le folosește automat.</div>
  <div><b>Regula de dimensionare</b><ul><li>~100 de clienți conectați simultan la fiecare 2 procesoare virtuale.</li><li>Maximum 253 de chei de client pe nod (o rețea /24).</li><li>Peste 70% utilizare într-o regiune → adaugă un nod acolo.</li></ul></div></div>
  <div class="grid k4" id="skpis"></div><div class="grid k2" style="margin-top:12px"><div class="card"><h3>Pe regiuni</h3><div class="tw"><table id="tregion"></table></div></div>
  <div class="card"><h3>Recomandări</h3><div id="recs"></div></div></div>
</section>

<section class="tab" id="t-oferte">
  <h2>Produse & oferte</h2>
  <div class="help"><div><b>Ce vezi aici</b>Ce vând aplicațiile pe această infrastructură — exact cum apare în aplicație (Android din Google Play și Windows) — și planul VPNzone.NET, care va rula pe aceeași flotă.</div>
  <div><b>De reținut</b>Planul gratuit are 400 MB/zi prin serverele noastre; la plafon aplicația oferă trecerea la VPN Nelimitat. Planurile plătite nu au limită de trafic (fair-use: maximum 10 tuneluri simultane pe cont).</div></div>
  <div class="tw"><table id="toffers"></table></div>
  <div class="note w">Onest față de ce livrează infrastructura azi: (1) „filtrare de domenii malițioase” în tunel — lista de domenii de pe noduri e goală, sursa nu există încă; (2) „Scam Shield Pro” și „Ștergere date (GDPR)” din Protecție maximă sunt etichete în aplicație, fără implementare în spate.</div>
</section>

<section class="tab" id="t-internet">
  <h2>Infrastructură Internet · VPNzone.NET</h2>
  <div class="help"><div><b>Ce vezi aici</b>Exploatarea unificată a infrastructurii de servere și de Internet, independent de furnizor. Aceeași flotă WireGuard și același control-plane servesc CYBER3 azi și VPNzone.NET mâine; aplicația nu știe ce e sub fiecare steag.</div>
  <div><b>Direcția</b>De la servere închiriate (azi) spre metal propriu în data center, spațiu IP propriu, ASN, tranzit multiplu și peering la marile puncte de schimb — Internet nelimitat la cost minim.</div></div>
  <div class="card" id="layers"></div><div class="grid k3" style="margin-top:12px" id="brands"></div>
</section>

<section class="tab" id="t-manual">
  <h2>📘 Manualul administratorului</h2>
  <p class="mut" style="max-width:110ch">Scris pentru cine preia exploatarea fără să fi construit sistemul. Începe cu „Cum funcționează”, apoi „Rutina”. Când apare o alertă, deschide procedura ei.</p>
  <h3>Cum funcționează — pe scurt</h3>
  <div class="arch">
    <div class="box"><div class="w">1 · Clientul</div><b>Aplicația CYBER3</b>Android (Google Play) sau Windows. Apasă „Conectează”; aplicația își generează o cheie WireGuard pe dispozitiv (cheia privată nu pleacă niciodată de pe telefon/PC).</div>
    <div class="box"><div class="w">2 · Creierul</div><b>Control-plane-ul</b><code>cyber3-vpn-cp</code> pe Cloudflare. Verifică abonamentul (sau plafonul gratuit), alege un nod sănătos și înregistrează cheia clientului pe el.</div>
    <div class="box"><div class="w">3 · Serverul</div><b>Nodul VPN</b>Server Ubuntu cu WireGuard. Agentul de pe nod (<code>cyber3-agent</code>) primește comenzile control-plane-ului. Traficul clientului iese spre Internet de aici.</div>
    <div class="box"><div class="w">4 · Supravegherea</div><b>Acest portal</b><code>vpn.cyber3.ai</code> citește la 5 minute nodurile, furnizorul (Hetzner), abonamentele (Google Play, web) și trimite alerte + raport zilnic.</div>
  </div>
  <h3>Rutina administratorului</h3>
  <div class="grid k3"><div class="card"><b class="gold">Zilnic (5 minute)</b><ul><li>Citește raportul de pe email (09:00).</li><li>Deschide tab-ul <b>Acum</b>: bannerul trebuie să fie verde.</li><li>Orice CRIT → procedura din Manual, în aceeași zi.</li></ul></div>
  <div class="card"><b class="gold">Săptămânal (20 minute)</b><ul><li><b>Grafice</b> 7 zile: crește numărul de clienți? Există vârfuri de CPU?</li><li><b>Resurse & costuri</b>: proiecția de trafic pe fiecare nod.</li><li><b>Scalare</b>: recomandări noi?</li><li><b>Clienți</b>: abonamente noi, pâlnia.</li></ul></div>
  <div class="card"><b class="gold">Lunar</b><ul><li>Verifică factura furnizorului față de costul din portal.</li><li>Actualizează sistemul pe noduri (unul câte unul, cu „Scoate din rotație” înainte).</li><li>Decide nodurile noi pe baza tab-ului <b>Conexiuni</b> (de unde vin clienții).</li></ul></div></div>
  <h3>Glosar</h3>
  <dl class="gl">
    <dt>WireGuard</dt><dd>Protocolul VPN folosit pe toată infrastructura: rapid, modern, criptare puternică. Fiecare client are o pereche de chei.</dd>
    <dt>Nod</dt><dd>Un server VPN prin care iese traficul clienților. Azi: servere Hetzner Cloud în Germania, Finlanda, SUA, Singapore; în curând și în data center propriu.</dd>
    <dt>Peer</dt><dd>Cheia unui client înregistrată pe un nod. Un peer nu înseamnă că clientul e conectat acum.</dd>
    <dt>Tunel activ</dt><dd>Un client cu trafic în ultimele 3 minute (ultimul „handshake” WireGuard). Aceasta e cifra „clienți conectați”.</dd>
    <dt>Pool</dt><dd>Adresele interne pe care un nod le poate da clienților: 253 (rețeaua 10.3.0.0/24).</dd>
    <dt>Control-plane</dt><dd>Programul central (pe Cloudflare) care decide pe ce nod merge fiecare client și verifică abonamentele.</dd>
    <dt>Agent</dt><dd>Programul mic de pe fiecare nod care execută comenzile control-plane-ului și raportează starea nodului.</dd>
    <dt>Rotație</dt><dd>Lista nodurilor care primesc clienți noi. Un nod scos din rotație păstrează clienții conectați, dar nu primește alții.</dd>
    <dt>Failover</dt><dd>Dacă un nod pică, control-plane-ul îl ocolește automat la conectările noi.</dd>
    <dt>RAM-only / no-logs</dt><dd>Cheile clienților trăiesc doar în memorie și dispar la repornire; nu se înregistrează ce site-uri vizitează clienții și nici adresele lor.</dd>
    <dt>Plafon gratuit</dt><dd>400 MB pe zi pe planul gratuit; peste, aplicația cere trecerea la un plan plătit. Se resetează la miezul nopții (UTC).</dd>
    <dt>Fair-use</dt><dd>Planurile plătite sunt nelimitate; singura limită: maximum 10 tuneluri simultane pe același abonament (anti-partajare).</dd>
    <dt>Trafic inclus</dt><dd>Cât trafic de ieșire intră în prețul lunar al serverului; peste, furnizorul taxează pe TB.</dd>
    <dt>IOC</dt><dd>Indicatori de amenințare (domenii periculoase) pe care nodul ar trebui să-i blocheze la nivel DNS.</dd>
  </dl>
  <h3>Proceduri — ce faci când…</h3>
  <details class="proc"><summary>Un nod e DOWN (alertă CRIT „Nod inaccesibil”)</summary><div class="in">Clienții noi sunt deja trimiși automat pe celelalte noduri; cei conectați la nodul căzut se reconectează singuri pe altul.<ol>
  <li>În consola Hetzner: serverul e „running”? Dacă nu → Power on.</li><li>Conectează-te: <code>ssh root@IP_NOD</code>.</li>
  <li>Verifică serviciile: <code>systemctl status cyber3-agent wg-quick@wg0 unbound</code>.</li><li>Repornește ce e oprit: <code>systemctl restart cyber3-agent</code> (nu deconectează clienții).</li>
  <li>Apasă „Colectează acum” în portal: nodul trebuie să apară UP.</li><li>Dacă nu revine în 30 de minute: <b>Scoate din rotație</b> și investighează (rețea furnizor, disc, memorie).</li></ol></div></details>
  <details class="proc"><summary>Resolverul DNS (unbound) e oprit — CRIT</summary><div class="in">Clienții au Internet, dar fără DNS nu se încarcă site-urile.<ol><li><code>ssh root@IP_NOD</code></li><li><code>systemctl restart unbound && systemctl status unbound</code></li><li>Test: <code>dig @10.3.0.1 google.com +short</code> trebuie să întoarcă adrese.</li><li>Dacă nu pornește: <code>journalctl -u unbound -n 50</code> și scoate nodul din rotație până e reparat.</li></ol></div></details>
  <details class="proc"><summary>Procesor sau clienți peste capacitate (WARN)</summary><div class="in"><ol><li>Uită-te în <b>Grafice</b>: e un vârf scurt sau o creștere constantă?</li><li>Creștere constantă → adaugă un nod în aceeași regiune (procedura din <b>Exploatare</b>).</li><li>Până atunci, dacă nodul e sufocat: <b>Scoate din rotație</b> temporar ca să nu mai primească clienți noi.</li></ol></div></details>
  <details class="proc"><summary>Pool WireGuard aproape plin</summary><div class="in">Multe chei de clienți înregistrate, chiar dacă nu sunt conectați.<ol><li>Planifică o repornire a nodului în afara orelor de vârf: <b>Scoate din rotație</b> → așteaptă să scadă tunelurile active → <code>reboot</code> (RAM-only: cheile vechi dispar, clienții se reînregistrează singuri la reconectare) → <b>Readu în rotație</b>.</li><li>Dacă se umple repede → adaugă nod.</li></ol></div></details>
  <details class="proc"><summary>Trafic proiectat peste cel inclus (cost)</summary><div class="in"><ol><li>Vezi în <b>Resurse & costuri</b> ce nod și cât costă depășirea.</li><li>Opțiuni: scoate din rotație nodul scump dacă există alternativă apropiată; adaugă un nod cu trafic inclus mare în aceeași regiune; pe termen lung — metal propriu (tab <b>Internet</b>).</li></ol></div></details>
  <details class="proc"><summary>Un client spune că nu se poate conecta</summary><div class="in"><ol><li>Nodurile sunt UP? (tab <b>Acum</b>).</li><li>Plan gratuit: a atins plafonul de 400 MB? (tab <b>Clienți</b>, VPN gratuit) — e normal până la miezul nopții UTC.</li><li>Plan plătit: abonamentul e activ? Pentru Google Play vezi starea verificată la Google.</li><li>Are deja 10 tuneluri deschise pe același abonament? (limita fair-use) — să închidă VPN-ul pe dispozitivele nefolosite.</li><li>Altfel: reinstalare aplicație + „Am deja un abonament” (restaurare pe email).</li></ol></div></details>
  <details class="proc"><summary>Adaug un nod nou (Hetzner sau data center propriu)</summary><div class="in">Urmează cei 6 pași din tab-ul <b>Exploatare</b>. Pe metal propriu: placă de rețea de calitate (Intel E810/X710 sau Mellanox), Ubuntu, IP public, UDP 51820 deschis. După activare verifică în portal: UP, latență, primii clienți.</div></details>
  <details class="proc"><summary>Mentenanță planificată pe un nod</summary><div class="in"><ol><li><b>Scoate din rotație</b> (tab Noduri).</li><li>Așteaptă ca „tuneluri active” să scadă (clienții se deconectează natural; cei rămași se reconectează pe alt nod după repornire).</li><li>Fă actualizarea: <code>apt update && apt upgrade -y && reboot</code>.</li><li>Verifică UP în portal → <b>Readu în rotație</b>.</li></ol></div></details>
  <details class="proc"><summary>Lista IOC goală pe noduri (WARN permanent — cunoscut)</summary><div class="in">Nodurile au mecanismul de sincronizare (orar), dar sursa de domenii (<code>/v1/domains</code> pe edge-ul CYBER3) nu e construită. Nu afectează funcționarea VPN-ului. E un task de dezvoltare, nu de exploatare.</div></details>
  <h3>Unde rulează fiecare componentă</h3>
  <div class="tw"><table><tr><th>Componentă</th><th>Unde</th><th>Cod sursă</th></tr>
  <tr><td>Control-plane</td><td>Cloudflare Workers <code>cyber3-vpn-cp</code> + KV</td><td class="mut">CYBER3.APP/vpn-cp/</td></tr>
  <tr><td>Portalul acesta</td><td>Cloudflare Workers <code>cyber3-vpn-ops</code> → vpn.cyber3.ai</td><td class="mut">CYBER3.AI VPN PREMIUM/vpn-ops/</td></tr>
  <tr><td>Noduri VPN</td><td>Hetzner Cloud (6), în curând data center propriu</td><td class="mut">CYBER3.AI VPN PREMIUM/node-setup.sh + agent.py</td></tr>
  <tr><td>Abonamente</td><td>Google Play (principal) + Paddle (web)</td><td class="mut">verificare în control-plane</td></tr>
  <tr><td>Alerte / raport</td><td>Email prin Resend → mihai@rol.ro</td><td class="mut">vpn-ops</td></tr></table></div>
  <h3>Securitate</h3>
  <div class="note w">SSH pe noduri e deschis spre Internet (doar cu cheie, fără parolă). Nodul din Singapore are peste 1.100 de încercări de conectare respinse de la scanere. Recomandare: în firewall-ul Hetzner <code>cyber3-vpn-fw</code>, permite portul 22 doar din rețeaua de administrare.</div>
</section>
<p class="dim" style="font:11px var(--mono);text-align:center">CYBER3 · ROL PORTAL SERVICES SRL · portal intern · WireGuard · no-logs</p>
</main>
<script>
var D=null,H=[],LIVE=[],PER="24h",SER=null;
var NAMES_RO=(function(){try{return new Intl.DisplayNames(["ro"],{type:"region"})}catch(e){return null}})();
function $(id){return document.getElementById(id)}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]})}
function fb(b){if(b==null)return "—";var u=["B","KB","MB","GB","TB"],i=0;b=+b;while(b>=1000&&i<4){b/=1000;i++}return (i?b.toFixed(b<10?2:1):b)+" "+u[i]}
function fm(v){return v==null?"—":(v<10?v.toFixed(2):v.toFixed(1))}
function eur(v){return v==null?"—":"€"+(+v).toFixed(2)}
function pct(v){return v==null||isNaN(v)?"—":Math.round(v)+"%"}
function col(v,w,c){return v==null?"var(--dim)":(v>=c?"var(--crit)":(v>=w?"var(--warn)":"var(--ok)"))}
function bar(v,w,c){v=Math.max(0,Math.min(100,v||0));return '<div class="bar"><i style="width:'+v+'%;background:'+col(v,w||70,c||90)+'"></i></div>'}
function flag(cc){return '<span class="cc">'+(cc&&cc.length===2&&cc!=="??"?esc(cc.toUpperCase()):"—")+'</span>'}
function cname(cc){if(!cc||cc==="??")return "necunoscut";try{return NAMES_RO?NAMES_RO.of(cc):cc}catch(e){return cc}}
function ago(t){if(!t)return "—";var s=(Date.now()-t)/1000;return s<90?Math.round(s)+" s":(s<5400?Math.round(s/60)+" min":(s<172800?Math.round(s/3600)+" h":Math.round(s/86400)+" zile"))}
function dt(t){return t?new Date(t).toLocaleString("ro-RO",{dateStyle:"short",timeStyle:"short"}):"—"}
function kpi(v,l,s,cls){return '<div class="card kpi"><div class="v '+(cls||"")+'">'+v+'</div><div class="l">'+l+'</div>'+(s?'<div class="s">'+s+'</div>':"")+'</div>'}
var PAL=["#4f8cff","#22d38a","#fbbf24","#a78bfa","#22d3ee","#fb7185","#f97316","#84cc16","#e879f9","#2dd4bf","#f43f5e","#60a5fa"];
function pcol(i){return i<PAL.length?PAL[i]:"hsl("+((i*67)%360)+",70%,62%)"}

// ---------- grafice SVG (linii / arii stivuite / bare) cu tooltip ----------
function tfmt(t,span){var d=new Date(t);if(span<=2*864e5)return d.toLocaleTimeString("ro-RO",{hour:"2-digit",minute:"2-digit"});if(span<=90*864e5)return d.toLocaleDateString("ro-RO",{day:"2-digit",month:"2-digit"})+(span<=10*864e5?" "+d.getHours()+"h":"");return d.toLocaleDateString("ro-RO",{month:"short",year:"2-digit"})}
function nice(m){if(m<=0)return 1;var p=Math.pow(10,Math.floor(Math.log10(m))),f=m/p;return (f<=1?1:f<=2?2:f<=5?5:10)*p}
function chart(el,ts,series,o){o=o||{};
 if(!el)return;if(!ts.length||!series.length){el.innerHTML='<div class="empty">'+(o.empty||"Încă nu sunt date pentru perioada aleasă — istoricul se construiește automat la fiecare 5 minute.")+'</div>';return}
 var W=Math.max(320,el.clientWidth||700),Hh=o.h||210,L=48,R=10,T=10,B=26,iw=W-L-R,ih=Hh-T-B,n=ts.length;
 var t0=ts[0],t1=ts[n-1],span=Math.max(1,t1-t0);
 var X=function(i){return n<2?L+iw/2:L+(ts[i]-t0)/span*iw};
 var tot=ts.map(function(_,i){var s=0;series.forEach(function(se){var v=se.v[i];if(v!=null)s+=o.stack?v:0});return s});
 var mx=0;series.forEach(function(se){se.v.forEach(function(v){if(v!=null&&v>mx)mx=v})});if(o.stack)mx=Math.max.apply(null,tot.concat([0]));mx=nice(mx*1.08);
 var Y=function(v){return T+ih-(v/mx)*ih};
 var g="";for(var k=0;k<=4;k++){var yv=mx*k/4,y=Y(yv);g+='<line x1="'+L+'" x2="'+(W-R)+'" y1="'+y+'" y2="'+y+'" stroke="#1d2a44"/><text x="'+(L-6)+'" y="'+(y+4)+'" text-anchor="end" fill="#63739a" font-size="10.5" font-family="monospace">'+(o.yf?o.yf(yv):Math.round(yv*100)/100)+'</text>'}
 var xt="";for(var k2=0;k2<5;k2++){var tt=t0+span*k2/4,xx=L+iw*k2/4;xt+='<text x="'+xx+'" y="'+(Hh-6)+'" text-anchor="'+(k2===0?"start":k2===4?"end":"middle")+'" fill="#63739a" font-size="10.5" font-family="monospace">'+tfmt(tt,span)+'</text>'}
 var body="",base=ts.map(function(){return 0});
 if(o.bars){var bw=Math.max(1.5,iw/n*0.7);series.forEach(function(se,si){se.v.forEach(function(v,i){if(v==null)return;var y0=Y(base[i]+v),hh=Y(base[i])-y0;body+='<rect x="'+(X(i)-bw/2)+'" y="'+y0+'" width="'+bw+'" height="'+Math.max(0,hh)+'" fill="'+se.c+'" opacity=".85"/>';if(o.stack)base[i]+=v})})}
 else series.forEach(function(se){var pts=[],lo=[];se.v.forEach(function(v,i){if(v==null)return;var b0=o.stack?base[i]:0;pts.push([X(i),Y(b0+v)]);lo.push([X(i),Y(b0)]);if(o.stack)base[i]+=v});if(!pts.length)return;
  var d=pts.map(function(p,i){return (i?"L":"M")+p[0].toFixed(1)+","+p[1].toFixed(1)}).join("");
  if(o.stack||o.area){var a=d+lo.slice().reverse().map(function(p){return "L"+p[0].toFixed(1)+","+p[1].toFixed(1)}).join("")+"Z";body+='<path d="'+a+'" fill="'+se.c+'" opacity="'+(o.stack?.45:.14)+'"/>'}
  body+='<path d="'+d+'" fill="none" stroke="'+se.c+'" stroke-width="1.8"/>'});
 el.innerHTML='<svg viewBox="0 0 '+W+' '+Hh+'" height="'+Hh+'">'+g+xt+body+'<line class="cur" x1="0" x2="0" y1="'+T+'" y2="'+(T+ih)+'" stroke="#D4AF37" stroke-dasharray="3 3" style="display:none"/><rect x="'+L+'" y="'+T+'" width="'+iw+'" height="'+ih+'" fill="transparent"/></svg><div class="tip"></div>'
  +'<div class="lg">'+series.map(function(se){var last=null;for(var i=se.v.length-1;i>=0;i--)if(se.v[i]!=null){last=se.v[i];break}return '<span><i style="background:'+se.c+'"></i>'+esc(se.n)+(last!=null?": "+(o.yf?o.yf(last):Math.round(last*100)/100):"")+'</span>'}).join("")+'</div>';
 var svg=el.querySelector("svg"),tip=el.querySelector(".tip"),cur=el.querySelector(".cur");
 svg.addEventListener("mousemove",function(ev){var r=svg.getBoundingClientRect(),x=(ev.clientX-r.left)*W/r.width;var bi=0,bd=1e9;for(var i=0;i<n;i++){var dd=Math.abs(X(i)-x);if(dd<bd){bd=dd;bi=i}}
  cur.setAttribute("x1",X(bi));cur.setAttribute("x2",X(bi));cur.style.display="";
  var h='<div class="gold">'+new Date(ts[bi]).toLocaleString("ro-RO",{dateStyle:"short",timeStyle:"short"})+'</div>'+series.map(function(se){var v=se.v[bi];return '<div><span style="color:'+se.c+'">■</span> '+esc(se.n)+': '+(v==null?"—":(o.yf?o.yf(v):Math.round(v*100)/100))+'</div>'}).join("");
  if(o.stack)h+='<div class="mut">total: '+(o.yf?o.yf(tot[bi]):Math.round(tot[bi]*100)/100)+'</div>';
  tip.innerHTML=h;tip.style.display="block";var px=(X(bi)/W)*r.width;tip.style.left=Math.min(px+12,r.width-tip.offsetWidth-4)+"px";tip.style.top="8px"});
 svg.addEventListener("mouseleave",function(){tip.style.display="none";cur.style.display="none"});
}

// ---------- taburi ----------
function showTab(){var h=(location.hash||"#acum").slice(1);if(!$("t-"+h))h="acum";
 Array.prototype.forEach.call(document.querySelectorAll(".tab"),function(s){s.classList.toggle("on",s.id==="t-"+h)});
 Array.prototype.forEach.call(document.querySelectorAll("#tabs a"),function(a){a.classList.toggle("on",a.getAttribute("href")==="#"+h)});
 if(h==="grafice")loadSeries();if(D)render();window.scrollTo(0,0)}
window.addEventListener("hashchange",showTab);

function nodes(){return (D&&D.snap&&D.snap.nodes)||[]}
function render(){
 var s=D.snap||{nodes:[]},N=s.nodes||[],C=D.clients||{},B=D.billing||{},P=D.play||{},F=D.funnel||{},R=D.registry||{},cc=C.counts||{},fr=C.free||{};
 $("upd").textContent="date complete: acum "+ago(s.ts);
 var up=N.filter(function(n){return n.ok}),act=0,peers=0,cap=0,cost=0,out=0,incl=0,over=0,now=new Date(),dim=new Date(now.getUTCFullYear(),now.getUTCMonth()+1,0).getDate();
 N.forEach(function(n){var m=n.met;if(m){act+=m.wg.active_3m;peers+=m.wg.peers}else if(n.stat)peers+=n.stat.peers;cap+=n.capacity||0;
  if(n.hz){cost+=n.hz.price_month;out+=n.hz.out_bytes;incl+=n.hz.included_bytes;var pr=n.hz.out_bytes/Math.max(1,now.getUTCDate())*dim;n._proj=pr;n._over=Math.max(0,(pr-n.hz.included_bytes)/1e12*n.hz.price_tb);over+=n._over}});
 var al=s.alerts||[],cr=al.filter(function(a){return a.sev==="CRIT"}),wa=al.filter(function(a){return a.sev!=="CRIT"});
 var ta=document.querySelector('#tabs a[href="#alerte"]');ta.innerHTML="Alerte"+(al.length?'<span class="b" style="background:'+(cr.length?"var(--crit)":"var(--warn)")+';color:'+(cr.length?"#fff":"#1a1400")+'">'+al.length+'</span>':"");

 // ACUM
 var bn;if(cr.length)bn='<div class="banner r"><div class="ic">⛔</div><div><h2>Atenție: '+cr.length+' problemă(e) critică(e)</h2><p>'+cr.map(function(a){return "<b>"+esc(a.node||"flotă")+"</b>: "+esc(a.msg)}).join("<br>")+'</p><p style="margin-top:6px">→ Deschide <a href="#manual">Manual → Proceduri</a> pentru pașii de rezolvare.</p></div></div>';
 else if(wa.length)bn='<div class="banner y"><div class="ic">⚠️</div><div><h2>Funcționează — cu '+wa.length+' observație(i)</h2><p>Clienții nu sunt afectați. Detalii și ce faci: <a href="#alerte">tab-ul Alerte</a>.</p></div></div>';
 else bn='<div class="banner g"><div class="ic">✅</div><div><h2>Totul funcționează</h2><p>Toate cele '+N.length+' noduri răspund, nicio problemă detectată. Nu e nimic de făcut.</p></div></div>';
 $("banner").innerHTML=bn;
 $("kpis").innerHTML=kpi(up.length+" / "+N.length,"noduri online",Object.keys(R).length?Object.keys(R).length+" în pregătire":"",up.length===N.length?"ok":"crit")
  +kpi(peers,"clienți înregistrați pe noduri","chei WireGuard (peer-i)")
  +kpi(cc.paid_real!=null?cc.paid_real:"—","clienți plătitori reali",(cc.paid_active||0)+" abonamente active incl. operator/test",cc.paid_real?"ok":"")
  +kpi(fr.today_users!=null?fr.today_users:"—","VPN gratuit azi",(fr.today_capped||0)+" au atins plafonul")
  +kpi(fb(out),"trafic luna aceasta","din "+fb(incl)+" incluși")
  +kpi(eur(cost),"cost servere / lună",over>0?"+ "+eur(over)+" depășire proiectată":"fără depășiri proiectate",over>0?"warn":"");
 var pins=N.filter(function(n){return n.hz&&n.hz.lat!=null}).map(function(n){var x=(n.hz.lon+180)/360*100,y=(90-n.hz.lat)/180*100,c=n.ok?(n.drained?"var(--warn)":"var(--ok)"):"var(--crit)";
  return '<div class="pin" style="left:'+x+'%;top:'+y+'%"><i style="background:'+c+'"></i><span>'+flag(n.country)+" "+esc(n.name)+" · "+(n.met?n.met.wg.active_3m:"–")+'</span></div>'}).join("");
 $("map").innerHTML=pins+'<div style="position:absolute;left:12px;bottom:8px;font:11px var(--mono);color:var(--dim)">'+up.length+' noduri online · '+new Set(N.map(function(n){return n.country})).size+' țări · cifra de lângă nod = clienți conectați acum'+(Object.keys(R).length?' · + '+Object.keys(R).length+' în pregătire':'')+'</div>';
 renderLive();

 // NODURI
 var th='<tr><th>Nod</th><th>Unde · furnizor</th><th>Stare</th><th>Comenzi</th><th>Clienți conectați</th><th>Chei / pool</th><th>Încărcare vs capacitate</th><th>CPU</th><th>RAM</th><th>Bandă ↓ / ↑ (Mbps)</th><th>Pornit de</th></tr>';
 $("tnodes").innerHTML=th+N.map(function(n){var m=n.met,h=n.hz||{},memp=m?100*(1-m.mem.avail_mb/m.mem.total_mb):null,capp=m?100*m.wg.active_3m/(n.capacity||100):null,poolp=m?100*m.wg.peers/253:null;
  var st=!n.ok?'<span class="dot d-crit"></span><b class="crit">DOWN</b>':(n.drained?'<span class="dot d-warn"></span><b class="warn">scos din rotație</b>':'<span class="dot d-ok"></span>UP · în rotație');
  var cmd=n.drained?'<button class="sm" onclick="cmdNode(\'activate\',\''+esc(n.name)+'\')">Readu în rotație</button>':'<button class="sm dang" onclick="cmdNode(\'drain\',\''+esc(n.name)+'\')">Scoate din rotație</button>';
  return '<tr><td><b>'+esc(n.name)+'</b><div class="dim" style="font:11px var(--mono)">'+esc(n.ip)+(h.type?" · "+h.type+" · "+h.cores+" vCPU / "+h.memory_gb+" GB":"")+'</div></td>'
  +'<td>'+flag(n.country)+" "+esc(n.city||"")+'<div class="dim" style="font-size:11px">'+esc(n.provider)+'</div></td><td>'+st+'</td><td>'+cmd+'</td>'
  +'<td class="num"><b style="font-size:15px">'+(m?m.wg.active_3m:"—")+'</b><div class="dim" style="font-size:11px">ultimele 15 min: '+(m?m.wg.active_15m:"—")+'</div></td>'
  +'<td class="num">'+(m?m.wg.peers:(n.stat?n.stat.peers:"—"))+' / 253'+(poolp!=null?bar(poolp,70,90):"")+'</td>'
  +'<td>'+(capp!=null?pct(capp)+" din "+n.capacity+bar(capp,70,90):"—")+'</td>'
  +'<td class="num">'+(m?pct(m.cpu.util_pct):"—")+'</td><td class="num">'+pct(memp)+'</td>'
  +'<td class="num">'+(n.rate?fm(n.rate.wg_rx)+" / "+fm(n.rate.wg_tx):"—")+'</td>'
  +'<td class="num">'+(m?Math.round(m.uptime_s/86400)+" zile":"—")+'</td></tr>'}).join("");

 // CONEXIUNI
 var cn=C.conn||{sum:{country:{},platform:{},tier:{},route:{},mode:{}},days:{}},cs=cn.sum||{};
 var pl=cs.platform||{},totc=cs.total||0,pm=function(k){return pl[k]||0};
 $("connk").innerHTML=kpi(totc,"conexiuni în 30 de zile","numărate la fiecare conectare")
  +kpi(pm("android"),"📱 de pe mobil (Android)",totc?pct(100*pm("android")/totc):"")
  +kpi(pm("windows"),"🖥️ de pe desktop (Windows)",totc?pct(100*pm("windows")/totc):"")
  +kpi(Object.keys(cs.country||{}).length,"țări de unde se conectează",(cs.mode&&cs.mode.ales?cs.mode.ales:0)+" cu server ales manual");
 var ctry=Object.keys(cs.country||{}).map(function(k){return [k,cs.country[k]]}).sort(function(a,b){return b[1]-a[1]});
 $("tcountry").innerHTML='<tr><th>Țară</th><th>Conexiuni</th><th>Pondere</th></tr>'+(ctry.length?ctry.slice(0,40).map(function(c){var p=100*c[1]/Math.max(1,totc);return '<tr><td>'+flag(c[0])+" "+esc(cname(c[0]))+'</td><td class="num">'+c[1]+'</td><td>'+pct(p)+bar(p,101,101)+'</td></tr>'}).join(""):'<tr><td colspan="3" class="dim" style="white-space:normal">Nicio conexiune înregistrată încă. Contorizarea a pornit pe 18 sep 2026 — cifrele apar la primele conectări din aplicații.</td></tr>');
 var days=Object.keys(cn.days||{}).sort().slice(-30);
 chart($("gconn"),days.map(function(d){return Date.parse(d)}),[["android","📱 Android","#22d38a"],["windows","🖥️ Windows","#4f8cff"],["ios","iOS","#a78bfa"],["altele","altele","#63739a"]].map(function(x){return {n:x[1],c:x[2],v:days.map(function(d){return ((cn.days[d]||{}).platform||{})[x[0]]||0})}}).filter(function(se){return se.v.some(function(v){return v})}),{bars:true,stack:true,empty:"Conexiunile pe zile apar după primele conectări din aplicații (contorizare pornită 18 sep 2026)."});
 var nc={};N.forEach(function(n){nc[n.name]=n.country});
 var rts=Object.keys(cs.route||{}).map(function(k){var p=k.split(">");return [p[0],p[1],cs.route[k]]}).sort(function(a,b){return b[2]-a[2]});
 $("troute").innerHTML='<tr><th>Client din</th><th>Nod primit</th><th>Conexiuni</th><th></th></tr>'+(rts.length?rts.slice(0,25).map(function(r){var far=nc[r[1]]&&r[0]!=="??"&&continent(r[0])!==continent(nc[r[1]]);return '<tr><td>'+flag(r[0])+" "+esc(cname(r[0]))+'</td><td>'+flag(nc[r[1]])+" "+esc(r[1])+'</td><td class="num">'+r[2]+'</td><td>'+(far?'<span class="tag warn">rută lungă</span>':'<span class="tag ok">local</span>')+'</td></tr>'}).join(""):'<tr><td colspan="4" class="dim">—</td></tr>');

 // CLIENȚI
 var subs=C.subs||[],bs=cc.by_source||{};
 $("ckpis").innerHTML=kpi(cc.paid_real!=null?cc.paid_real:"—","plătitori reali","fără conturile operator/test",cc.paid_real?"ok":"")
  +kpi(cc.paid_active||0,"abonamente active","Google Play "+(bs["Google Play"]||0)+" · web "+(bs["Paddle / web"]||0))
  +kpi(Object.keys(cc.by_tier||{}).map(function(k){return (k==="maximus"?"Maximă ":k==="faster"?"Nelimitat ":k+" ")+cc.by_tier[k]}).join(" · ")||"—","pe plan","")
  +kpi(fr.today_users||0,"VPN gratuit azi",(fr.today_capped||0)+" la plafon · "+fb(fr.today_bytes))
  +kpi((C.peers||{}).total||0,"alocări în control-plane",((C.peers||{}).stale_30d||0)+" mai vechi de 30 zile")
  +kpi(B.app?(Object.keys(B.app.paid||{}).map(function(k){return (B.app.paid[k]/100).toFixed(2)+" "+k}).join(" · ")||"0"):"—","încasat web (billing)","Google Play se încasează separat, prin Google");
 var ps=(P.subs||[]);
 $("tplay").innerHTML='<tr><th>Abonament</th><th>Stare la Google</th><th>Produs</th><th>Plan</th><th>Ofertă</th><th>Expiră</th><th>Reînnoire</th><th>Țară</th><th>Test</th><th>Cine e</th></tr>'+(ps.length?ps.map(function(p){
  if(p.err)return '<tr><td>'+esc(p.id)+'</td><td colspan="9" class="warn">'+esc(p.err)+'</td></tr>';
  var st=(p.state||"").replace("SUBSCRIPTION_STATE_","");return '<tr><td>'+esc(p.id)+'</td><td><span class="dot '+(st==="ACTIVE"?"d-ok":(st==="IN_GRACE_PERIOD"?"d-warn":"d-crit"))+'"></span>'+esc(st)+'</td><td>'+esc(p.product||"—")+'</td><td>'+esc(p.base_plan||"—")+'</td><td>'+esc(p.offer||"—")+'</td><td>'+dt(p.expiry)+'</td><td>'+(p.auto_renew?"da":"nu")+'</td><td>'+flag(p.region)+" "+esc(p.region||"—")+'</td><td>'+(p.test?"da":"nu")+'</td><td>'+tagsel(p.key,p.tag)+'</td></tr>'}).join(""):'<tr><td colspan="10" class="dim">'+esc(P.note||P.err||"încă nicio verificare")+'</td></tr>');
 $("tsubs").innerHTML='<tr><th>Abonament</th><th>Sursă</th><th>Plan</th><th>Stare</th><th>Valabil până</th><th>Dispozitive</th><th>Cine e</th></tr>'+subs.slice().sort(function(a,b){return (b.active-a.active)||(b.until-a.until)}).map(function(r){
  return '<tr><td>'+esc(r.id)+'</td><td>'+esc(r.source)+'</td><td>'+(r.tier==="maximus"?"Protecție maximă":(r.tier==="faster"?"VPN Nelimitat":esc(r.tier)))+'</td><td><span class="dot '+(r.active?"d-ok":"d-off")+'"></span>'+(r.active?"activ":"expirat")+'</td><td>'+dt(r.until)+'</td><td class="num">'+r.devices+'</td><td>'+tagsel(r.key,r.tag)+'</td></tr>'}).join("");
 $("free").innerHTML=(fr.top||[]).length?(fr.top||[]).map(function(t){var p=100*t.bytes/(400*1048576);return '<div class="fun" style="grid-template-columns:110px 1fr 90px"><span class="dim" style="font:11px var(--mono)">'+esc(t.uid)+'</span>'+bar(p,80,100)+'<span class="num" style="font:11px var(--mono)">'+fb(t.bytes)+(t.capped?' <span class=warn>plafon</span>':"")+'</span></div>'}).join("")
  +'<div class="dim" style="font-size:12px;margin-top:8px">Utilizatori pe zile: '+Object.keys(fr.by_day||{}).sort().slice(-7).map(function(d){return d.slice(5)+": "+fr.by_day[d]}).join(" · ")+'</div>':'<div class="dim">Niciun utilizator al VPN-ului gratuit azi.</div>';
 function funn(list,lab){var mx=Math.max.apply(null,list.map(function(x){return x.users||0}).concat([1]));return list.map(function(x){return '<div class="fun"><span>'+esc(lab[x.step]||x.step)+'</span><div class="bar"><i style="width:'+(100*(x.users||0)/mx)+'%;background:var(--gold)"></i></div><span class="num" style="font:12px var(--mono)">'+(x.users||0)+'</span></div>'}).join("")}
 var LB={app_open:"au deschis aplicația",hero_reached:"au văzut ecranul principal",hero_used:"au folosit o verificare",value_moment:"au primit valoare",paywall_shown:"au văzut oferta plătită",checkout_started:"au început plata",purchase_success:"au plătit",free_vpn_card_shown:"au văzut VPN gratuit",free_vpn_tap:"au apăsat VPN gratuit",free_vpn_activated:"au activat VPN gratuit",cap_reached:"au atins plafonul 400 MB",cap_notif_shown:"notificare plafon afișată",cap_notif_tap:"au apăsat notificarea",cap_upsell_shown:"au văzut oferta Nelimitat",cap_upsell_tap:"au apăsat oferta Nelimitat"};
 $("funnel").innerHTML=F.err?'<div class="warn">'+esc(F.err)+'</div>':('<div class="mut" style="font-size:12px;margin-bottom:6px">Pâlnia principală (utilizatori unici)</div>'+funn(F.funnel||[],LB)+'<div class="mut" style="font-size:12px;margin:12px 0 6px">Pâlnia VPN gratuit → plată</div>'+funn(F.free_funnel||[],LB));

 // LATENȚĂ
 var anc=["1.1.1.1","8.8.8.8","9.9.9.9"];
 $("tlat").innerHTML='<tr><th>Nod</th><th>Control-plane → agent</th>'+anc.map(function(a){return "<th>"+a+"</th>"}).join("")+'</tr>'+N.map(function(n){var l=n.met?n.met.lat:{};
  return '<tr><td>'+flag(n.country)+" "+esc(n.name)+'</td><td class="num">'+(n.rtt_cp_ms!=null?n.rtt_cp_ms+" ms":"—")+'</td>'+anc.map(function(a){var v=l[a];return '<td class="num" style="color:'+(v&&v.ms!=null?col(v.ms,40,100):"var(--crit)")+'">'+(v&&v.ms!=null?v.ms.toFixed(1):"✕")+(v&&v.loss?' <span class=warn>'+v.loss+'%</span>':"")+'</td>'}).join("")+'</tr>'}).join("");
 $("tmesh").innerHTML='<tr><th></th>'+N.map(function(n){return "<th>"+esc(n.name.replace("vpn-",""))+"</th>"}).join("")+'</tr>'+N.map(function(a){return '<tr><th>'+esc(a.name.replace("vpn-",""))+'</th>'+N.map(function(b){
  if(a===b)return '<td class="dim">·</td>';var v=a.met&&a.met.lat[b.ip];var ms=v&&v.ms;var bg=ms==null?"rgba(255,77,94,.25)":(ms<30?"rgba(34,211,138,.18)":(ms<120?"rgba(251,191,36,.16)":"rgba(255,77,94,.16)"));
  return '<td style="background:'+bg+'">'+(ms==null?"✕":Math.round(ms))+'</td>'}).join("")+'</tr>'}).join("");

 // RESURSE
 var bwNow=0;N.forEach(function(n){if(n.rate)bwNow+=(n.rate.wg_tx||0)+(n.rate.wg_rx||0)});
 $("rkpis").innerHTML=kpi(fb(out),"trafic ieșire luna aceasta","proiecție: "+fb(N.reduce(function(a,n){return a+(n._proj||0)},0)))+kpi(fm(bwNow)+" Mbps","bandă clienți acum (↓+↑)","")+kpi(eur(cost),"cost servere / lună","furnizor, fără TVA")+kpi(eur(over),"depășire proiectată","la final de lună",over>0?"warn":"ok");
 $("tres").innerHTML='<tr><th>Nod</th><th>Plan</th><th>€ / lună</th><th>Ieșire (lună)</th><th>Inclus</th><th>Consumat</th><th>Proiecție</th><th>€ / TB peste</th><th>Depășire proiectată</th><th>Disc liber</th></tr>'+N.map(function(n){var h=n.hz;
  if(!h)return '<tr><td>'+esc(n.name)+'</td><td colspan="9" class="dim">'+esc(n.provider)+' — costul se introduce manual (în afara API-ului Hetzner)</td></tr>';
  var u=100*h.out_bytes/(h.included_bytes||1),pj=100*(n._proj||0)/(h.included_bytes||1);
  return '<tr><td>'+flag(n.country)+" "+esc(n.name)+'</td><td>'+esc(h.type)+'</td><td class="num">'+eur(h.price_month)+'</td><td class="num">'+fb(h.out_bytes)+'</td><td class="num">'+fb(h.included_bytes)+'</td><td>'+pct(u)+bar(u,70,90)+'</td><td>'+pct(pj)+bar(pj,70,90)+'</td><td class="num '+(h.price_tb>2?"warn":"")+'">'+eur(h.price_tb)+'</td><td class="num '+(n._over>0?"warn":"")+'">'+eur(n._over)+'</td><td class="num">'+(n.met?n.met.disk.free_gb+" / "+n.met.disk.total_gb+" GB":"—")+'</td></tr>'}).join("");

 // ALERTE
 $("alerts").innerHTML=al.length?al.map(function(a){return '<div class="note '+(a.sev==="CRIT"?"c":"w")+'"><b class="'+(a.sev==="CRIT"?"crit":"warn")+'">'+a.sev+'</b> · <b>'+esc(a.node||"flotă")+'</b> — '+esc(a.msg)+'</div>'}).join(""):'<div class="note">Nicio alertă activă. Totul e în regulă.</div>';
 var rules=[["Nod inaccesibil","CRIT","clienții noi sunt trimiși automat pe celelalte noduri"],["Resolver DNS (unbound) oprit","CRIT","clienții rămân fără DNS în tunel"],["Pool WireGuard > 90% / > 70%","CRIT / WARN","maximum 253 de chei pe nod"],["CPU > 95% / > 85%","CRIT / WARN","procesorul nodului"],["Clienți conectați > 80% din capacitate","WARN","~100 la 2 vCPU"],["Trafic proiectat > 90% din inclus","WARN","cost pe TB peste"],["RAM > 90% / disc liber < 10%","WARN",""],["Lista IOC goală","WARN","cunoscut — task de dezvoltare"],["Control-plane → nod > 3 s","WARN","conectare lentă"],["Nod scos din rotație","WARN","reamintire: readu-l după mentenanță"]];
 $("trules").innerHTML='<tr><th>Regulă</th><th>Severitate</th><th>Observație</th></tr>'+rules.map(function(r){return '<tr><td>'+r[0]+'</td><td>'+r[1]+'</td><td class="mut">'+r[2]+'</td></tr>'}).join("");

 // EXPLOATARE
 var ioc=N.filter(function(n){return n.met}).map(function(n){return n.met.ioc.blocklist_lines||0});
 var autos=[["Colectare portal (noduri, furnizor, clienți)","la 5 min",s.ts&&Date.now()-s.ts<900e3?"ok":"crit","ultima: acum "+ago(s.ts)],
  ["Alegerea nodului + failover","la fiecare conectare",up.length?"ok":"crit","control-plane-ul alege nodul viu cel mai gol și ocolește nodurile căzute"],
  ["Plafon VPN gratuit 400 MB/zi","la 5 min","ok","contorizează consumul și deconectează la plafon; reset zilnic"],
  ["Chei RAM-only + jurnal volatil pe noduri","permanent","ok","nimic despre clienți pe disc"],
  ["Sincronizare listă IOC pe noduri","orar",ioc.length&&Math.max.apply(null,ioc)>0?"ok":"warn",ioc.length&&Math.max.apply(null,ioc)>0?"listă populată":"rulează, dar sursa de domenii lipsește → listă goală"],
  ["Re-verificare abonamente Google Play","la 30 min",P.subs&&P.subs.length?"ok":"warn",P.ts?"ultima: acum "+ago(P.ts):"—"],
  ["Contorizare conexiuni (țară, platformă)","la fiecare conectare","ok","agregat pe zi, fără IP"],
  ["Alerte CRIT pe email","la eveniment","ok","o dată la 6 h / problemă"],["Raport zilnic pe email","09:00","ok","rezumatul zilei pentru administrator"]];
 $("tauto").innerHTML='<tr><th>Automatizare</th><th>Cadență</th><th>Stare</th><th>Detaliu</th></tr>'+autos.map(function(a){return '<tr><td>'+a[0]+'</td><td class="mut">'+a[1]+'</td><td><span class="dot d-'+a[2]+'"></span>'+(a[2]==="ok"?"ok":(a[2]==="warn"?"atenție":"eroare"))+'</td><td class="mut wrap">'+esc(a[3])+'</td></tr>'}).join("");
 var rb=["Server Ubuntu 24.04 — Hetzner (<code>hcloud</code>) sau metal propriu; IP public; UDP 51820 deschis","Rulează <code>node-setup.sh</code>: WireGuard, rutare, NAT, DNS unbound no-logs, RAM-only","Instalează agentul <code>/opt/cyber3/agent.py</code> (serviciul <code>cyber3-agent</code>, port 8080, tokenul comun)","Firewall: portul 8080 doar pentru Cloudflare; SSH doar cu cheie (ideal doar din rețeaua de administrare)","Trece nodul în <b>Registru</b> (mai jos) — apare pe hartă „în pregătire”","Activează-l în control-plane (formularul de jos) → verifică în Noduri: UP, latență, primii clienți"];
 $("runbook").innerHTML=rb.map(function(t,i){return '<div class="st"><b>'+(i+1)+'</b><span>'+t+'</span></div>'}).join("");
 var rk=Object.keys(R);
 $("treg").innerHTML='<tr><th>Nume</th><th>Furnizor</th><th>Locație</th><th>Brand</th><th>Port</th><th>Stare</th><th>Note</th><th></th></tr>'+(rk.length?rk.map(function(k){var r=R[k];return '<tr><td><b>'+esc(k)+'</b></td><td>'+esc(r.provider)+'</td><td>'+flag(r.country)+" "+esc(r.location)+'</td><td>'+esc(r.brand)+'</td><td class="num">'+(r.port_mbps?r.port_mbps+" Mbps":"—")+'</td><td><span class="dot d-plan"></span>'+esc(r.status)+'</td><td class="mut wrap">'+esc(r.notes)+'</td><td><button class="sm" onclick="delReg(\''+esc(k)+'\')">Șterge</button></td></tr>'}).join(""):'<tr><td colspan="8" class="dim">Registru gol.</td></tr>');

 // SCALARE
 var regions={};N.forEach(function(n){var r=n.country||"?";regions[r]=regions[r]||{n:0,act:0,cap:0,peers:0};regions[r].n++;regions[r].cap+=n.capacity||0;if(n.met){regions[r].act+=n.met.wg.active_3m;regions[r].peers+=n.met.wg.peers}});
 var util=cap?100*act/cap:0,poolU=N.length?100*peers/(253*N.length):0;
 $("skpis").innerHTML=kpi(pct(util),"capacitate folosită",act+" conectați / "+cap+" posibili",util>70?"warn":"ok")+kpi(pct(poolU),"pool WireGuard folosit",peers+" / "+(253*N.length)+" chei")+kpi(eur(cost/Math.max(1,cap)),"cost / client conectat / lună","la capacitate plină")+kpi(rk.length,"noduri în pregătire","registrul flotei",rk.length?"gold":"");
 $("tregion").innerHTML='<tr><th>Țară</th><th>Noduri</th><th>Conectați / capacitate</th><th>Utilizare</th></tr>'+Object.keys(regions).map(function(k){var r=regions[k],u=r.cap?100*r.act/r.cap:0;return '<tr><td>'+flag(k)+" "+esc(cname(k))+'</td><td class="num">'+r.n+'</td><td class="num">'+r.act+" / "+r.cap+'</td><td>'+pct(u)+bar(u,70,90)+'</td></tr>'}).join("");
 var recs=[];
 recs.push('<b>Prioritar pentru creștere:</b> control-plane-ul alege azi nodul „cel mai gol” din toată lumea, fără să țină cont de unde e clientul — un client din România poate primi un nod din SUA (latență mare). Pentru multe noduri: alegere după regiunea clientului (țara vine deja de la Cloudflare) și stare citită din cache în loc de interogarea tuturor nodurilor la fiecare conectare. Modificare de făcut în control-plane, cu aprobarea ta.');
 Object.keys(regions).forEach(function(k){var r=regions[k];if(r.cap&&r.act/r.cap>0.7)recs.push("Adaugă un nod în "+flag(k)+" "+esc(cname(k))+": "+Math.round(100*r.act/r.cap)+"% din capacitate.")});
 N.forEach(function(n){if(n.hz&&n._over>0)recs.push(esc(n.name)+": trafic peste inclus proiectat ("+eur(n._over)+"/lună).");if(n.met&&n.met.wg.peers>=180)recs.push(esc(n.name)+": pool aproape plin ("+n.met.wg.peers+"/253).")});
 N.forEach(function(n){if(n.hz&&n.hz.included_bytes<2e12)recs.push(esc(n.name)+" ("+esc(n.city)+"): doar "+fb(n.hz.included_bytes)+" trafic inclus, "+eur(n.hz.price_tb)+"/TB peste — primul loc cu risc de cost la creștere.")});
 if(rk.length)recs.push(rk.length+" nod(uri) în pregătire — după instalare, activează-le în Exploatare.");
 $("recs").innerHTML=recs.map(function(r,i){return '<div class="note'+(i===0?" w":"")+'">'+r+'</div>'}).join("");

 // OFERTE
 var of=[["Standard","GRATUIT pentru totdeauna","Filtru DNS local: blochează reclame, trackere și domenii malițioase în toate aplicațiile (fără server)","Android","nu folosește serverele VPN"],
  ["VPN gratuit","GRATUIT · 400 MB/zi","Tunel WireGuard complet prin serverele CYBER3; plafon zilnic 400 MB, reset la miezul nopții UTC; la plafon → ofertă Nelimitat","Android + Windows","nod ales automat"],
  ["VPN Nelimitat","€3,33/lună · €33,3/an · 7 zile gratuit (Google Play)","Trafic nelimitat, IP ascuns, dispozitive nelimitate (max 10 tuneluri simultan), alegerea serverului, kill switch (Android), split tunneling, test de viteză, restaurare pe email","Android + Windows","toate nodurile"],
  ["Protecție maximă","€8,88/lună · €88,8/an","Tot din VPN Nelimitat + servere de viteză supremă; în aplicație mai apar Scam Shield Pro, Ștergere date (GDPR), monitorizare breșe","Android","toate nodurile"],
  ["VPNzone.NET (pregătit)","$3/lună · nelimitat fair-use","„Internet nelimitat și neîngrădit” — aplicație doar VPN, global-first","în dezvoltare","aceeași flotă"]];
 $("toffers").innerHTML='<tr><th>Plan</th><th>Preț</th><th>Ce include</th><th>Platforme</th><th>Infrastructură</th></tr>'+of.map(function(o){return '<tr><td><b>'+o[0]+'</b></td><td class="gold">'+o[1]+'</td><td class="wrap">'+o[2]+'</td><td>'+o[3]+'</td><td class="mut">'+o[4]+'</td></tr>'}).join("");

 // INTERNET
 var countries=new Set(N.map(function(n){return n.country})).size;
 var lay=[["Servere","LIVE",N.length+" servere Hetzner Cloud · "+countries+" țări · 3 continente","+ 2 noduri în data center propriu (săptămâna viitoare) → metal la marile puncte de schimb (IX), colocare, VPS pentru coada lungă"],
  ["Protocol","LIVE","WireGuard, chei RAM-only, no-logs","identic pe toate nivelurile — un singur mod de exploatare"],
  ["Control-plane","LIVE","alocare, failover, plafon gratuit, abonamente","independent de furnizor și de brand — servește și VPNzone.NET"],
  ["Spațiu IP","azi: adrese furnizor","adrese Hetzner (percepute ca „hosting”)","bloc /24 propriu, curat + geolocalizare (locații virtuale)"],
  ["ASN / rutare","planificat","—","număr de sistem autonom propriu, BGP, RPKI"],
  ["Tranzit","azi: Hetzner","conectivitatea furnizorului","≥ 2 furnizori de tranzit, conectare redundantă"],
  ["Peering / IX","planificat","—","DE-CIX, AMS-IX, LINX, UAE-IX — trafic spre Google/Netflix/CDN aproape gratuit"]];
 $("layers").innerHTML='<h3 style="margin-top:0">Straturile infrastructurii — azi și următorul pas</h3>'+lay.map(function(l){return '<div class="lay"><b>'+l[0]+'</b><div><div>'+l[2]+'</div><div class="mut" style="font-size:12.5px">→ '+l[3]+'</div></div><span class="tag '+(l[1]==="LIVE"?"ok":"gold")+'">'+l[1]+'</span></div>'}).join("");
 $("brands").innerHTML=kpi("CYBER3 VPN","LIVE · Android (Google Play) + Windows","Standard · VPN gratuit · Nelimitat · Protecție maximă","ok")
  +kpi("VPNzone.NET","pregătit · vpnzone.net","„Internet nelimitat” $3 — aplicație doar VPN","gold")+kpi(N.length+" + "+rk.length,"noduri comune ambelor branduri","live + în pregătire");
}
function continent(cc){var EU="RO,DE,FI,FR,IT,ES,NL,BE,AT,PL,CZ,HU,BG,GR,PT,SE,NO,DK,IE,GB,CH,SK,SI,HR,RS,MD,UA,LT,LV,EE,LU,CY,MT,IS,AL,MK,BA,ME,BY";var NA="US,CA,MX";var AS="SG,JP,KR,CN,IN,ID,MY,TH,VN,PH,HK,TW,AE,SA,QA,OM,IL,TR,PK,BD";
 return EU.indexOf(cc)>=0?"EU":NA.indexOf(cc)>=0?"NA":AS.indexOf(cc)>=0?"AS":"X"}
function tagsel(key,tag){return '<select onchange="setTag(\''+esc(key)+'\',this.value)" style="padding:3px 6px;font-size:11.5px"><option value=""'+(tag?"":" selected")+'>client</option><option value="operator"'+(tag==="operator"?" selected":"")+'>operator</option><option value="test"'+(tag==="test"?" selected":"")+'>test</option></select>'}

// ---------- timp real ----------
function renderLive(){var L=LIVE;if(!$("livek"))return;var last=L[L.length-1],prev=L[L.length-2];
 var act=0,ok=0,tot=0,cpu=0,rx=null,tx=null;if(last){last.nodes.forEach(function(n){tot++;if(n.ok){ok++;act+=n.act;cpu+=n.cpu}})}
 if(last&&prev){var dt=(last.t-prev.t)/1000;rx=0;tx=0;last.nodes.forEach(function(n){var p=prev.nodes.filter(function(x){return x.name===n.name})[0];if(n.ok&&p&&p.ok&&n.wg_rx>=p.wg_rx){rx+=(n.wg_rx-p.wg_rx)*8/dt/1e6;tx+=(n.wg_tx-p.wg_tx)*8/dt/1e6}})}
 $("livek").innerHTML='<div class="card kpi live"><div class="v"><span class="pulse"></span>'+(last?act:"—")+'</div><div class="l">clienți conectați acum</div><div class="s">actualizat la 10 s</div></div>'
  +'<div class="card kpi live"><div class="v">'+(rx==null?"—":fm(rx))+' <span class="dim" style="font-size:15px">/ '+(tx==null?"—":fm(tx))+'</span></div><div class="l">bandă clienți acum ↓ / ↑ (Mbps)</div></div>'
  +'<div class="card kpi live"><div class="v '+(last&&ok<tot?"crit":"ok")+'">'+(last?ok+" / "+tot:"—")+'</div><div class="l">noduri care răspund acum</div></div>'
  +'<div class="card kpi live"><div class="v">'+(last&&ok?pct(cpu/ok):"—")+'</div><div class="l">procesor mediu flotă</div></div>';
 var ts=L.map(function(x){return x.t}),names=(last?last.nodes:[]).map(function(n){return n.name});
 chart($("lc1"),ts,names.map(function(nm,i){return {n:nm,c:pcol(i),v:L.map(function(x){var n=x.nodes.filter(function(y){return y.name===nm})[0];return n&&n.ok?n.act:null})}}),{stack:true,h:170,empty:"Se adună primele puncte live…"});
 var r1=[],r2=[];for(var i=1;i<L.length;i++){var d=(L[i].t-L[i-1].t)/1000,a=0,b=0;L[i].nodes.forEach(function(n){var p=L[i-1].nodes.filter(function(x){return x.name===n.name})[0];if(n.ok&&p&&p.ok&&n.wg_rx>=p.wg_rx){a+=(n.wg_rx-p.wg_rx)*8/d/1e6;b+=(n.wg_tx-p.wg_tx)*8/d/1e6}});r1.push(a);r2.push(b)}
 chart($("lc2"),ts.slice(1),[{n:"↓ de la clienți",c:"#22d38a",v:r1},{n:"↑ spre clienți",c:"#4f8cff",v:r2}],{area:true,h:170,yf:function(v){return fm(v)},empty:"Se adună primele puncte live…"})}
function pollLive(){fetch("/api/live",{credentials:"include"}).then(function(r){return r.json()}).then(function(d){LIVE.push(d);while(LIVE.length>90)LIVE.shift();var h=(location.hash||"#acum").slice(1);if(h==="acum"||h==="")renderLive();if(h==="grafice"&&PER==="live")drawSeries()}).catch(function(){})}

// ---------- grafice pe perioade ----------
var PERS=[["live","Live"],["24h","24 ore"],["7d","7 zile"],["30d","30 zile"],["12m","12 luni"]];
function perButtons(){$("per").innerHTML=PERS.map(function(p){return '<button class="'+(PER===p[0]?"on":"")+'" onclick="setPer(\''+p[0]+'\')">'+p[1]+'</button>'}).join("")}
function setPer(p){PER=p;perButtons();loadSeries()}
function loadSeries(){perButtons();if(PER==="live"){drawSeries();return}
 var src=PER==="24h"?"24h":PER;Promise.all([fetch("/api/series?period="+src,{credentials:"include"}).then(function(r){return r.json()}),PER==="24h"?fetch("/api/series?period=7d",{credentials:"include"}).then(function(r){return r.json()}):Promise.resolve(null)]).then(function(r){SER=r[0];SER.aux=r[1];drawSeries()})}
function drawSeries(){var names=nodes().map(function(n){return n.name});
 var gb=function(v){return fb(v)};
 if(PER==="live"){var L=LIVE,ts=L.map(function(x){return x.t});
  chart($("g1"),ts,names.map(function(nm,i){return {n:nm,c:pcol(i),v:L.map(function(x){var n=x.nodes.filter(function(y){return y.name===nm})[0];return n&&n.ok?n.act:null})}}),{stack:true,empty:"Graficul live se completează la 10 s cât pagina e deschisă."});
  var r1=[],r2=[],u=[];for(var i=1;i<L.length;i++){var d=(L[i].t-L[i-1].t)/1000,a=0,b=0;L[i].nodes.forEach(function(n){var p=L[i-1].nodes.filter(function(x){return x.name===n.name})[0];if(n.ok&&p&&p.ok&&n.wg_rx>=p.wg_rx){a+=(n.wg_rx-p.wg_rx)*8/d/1e6;b+=(n.wg_tx-p.wg_tx)*8/d/1e6}});r1.push(a);r2.push(b);u.push((a+b)/8*d*1e6)}
  chart($("g2"),ts.slice(1),[{n:"↓ de la clienți",c:"#22d38a",v:r1},{n:"↑ spre clienți",c:"#4f8cff",v:r2}],{area:true,yf:function(v){return fm(v)}});
  chart($("g3"),ts.slice(1),[{n:"trafic în interval",c:"#D4AF37",v:u}],{bars:true,yf:gb});
  chart($("g4"),ts,names.map(function(nm,i){return {n:nm,c:pcol(i),v:L.map(function(x){var n=x.nodes.filter(function(y){return y.name===nm})[0];return n&&n.ok?n.cpu:null})}}),{yf:function(v){return Math.round(v)+"%"}});
  chart($("g5"),[],[],{empty:"Clienții pe planuri se văd pe 24h / 7 / 30 zile / 12 luni."});
  chart($("g6"),ts,[{n:"noduri online",c:"#22d38a",v:L.map(function(x){return x.nodes.filter(function(n){return n.ok}).length})},{n:"total",c:"#63739a",v:L.map(function(x){return x.nodes.length})}],{});return}
 if(!SER)return;var P=SER.points||[];
 if(PER==="24h"){var ts=P.map(function(x){return x.t});
  chart($("g1"),ts,names.map(function(nm,i){return {n:nm,c:pcol(i),v:P.map(function(x){var n=x.n[nm];return n&&!n.down?n.a:null})}}),{stack:true});
  chart($("g2"),ts,[{n:"↓ de la clienți",c:"#22d38a",v:P.map(function(x){var s=0;names.forEach(function(nm){var n=x.n[nm];if(n&&!n.down&&n.wr!=null)s+=n.wr});return s})},{n:"↑ spre clienți",c:"#4f8cff",v:P.map(function(x){var s=0;names.forEach(function(nm){var n=x.n[nm];if(n&&!n.down&&n.wt!=null)s+=n.wt});return s})}],{area:true,yf:function(v){return fm(v)}});
  chart($("g3"),ts,names.map(function(nm,i){return {n:nm,c:pcol(i),v:P.map(function(x){var n=x.n[nm];return n&&!n.down?n.b:null})}}),{bars:true,stack:true,yf:gb});
  chart($("g4"),ts,names.map(function(nm,i){return {n:nm,c:pcol(i),v:P.map(function(x){var n=x.n[nm];return n&&!n.down?n.c:null})}}),{yf:function(v){return Math.round(v)+"%"}});
  var A=(SER.aux&&SER.aux.points||[]).slice(-24);
  chart($("g5"),A.map(function(x){return x.t}),[{n:"VPN gratuit (utilizatori/zi)",c:"#22d3ee",v:A.map(function(x){return x.free_max})},{n:"abonamente active",c:"#D4AF37",v:A.map(function(x){return x.paid_max})},{n:"plătitori reali",c:"#22d38a",v:A.map(function(x){return x.real_max})}],{});
  chart($("g6"),ts,[{n:"noduri online",c:"#22d38a",v:P.map(function(x){return Object.keys(x.n).filter(function(k){return !x.n[k].down}).length})},{n:"total",c:"#63739a",v:P.map(function(x){return Object.keys(x.n).length})}],{});return}
 var ts2=P.map(function(x){return x.t}),unit=SER.res;
 chart($("g1"),ts2,names.map(function(nm,i){return {n:nm+" (vârf/"+unit+")",c:pcol(i),v:P.map(function(x){var n=x.nodes&&x.nodes[nm];return n?n.a_max:null})}}),{stack:true});
 chart($("g2"),ts2,[{n:"↓ medie",c:"#22d38a",v:P.map(function(x){return x.n?x.rx_sum/x.n:null})},{n:"↑ medie",c:"#4f8cff",v:P.map(function(x){return x.n?x.tx_sum/x.n:null})},{n:"↑ vârf",c:"#a78bfa",v:P.map(function(x){return x.tx_max})}],{area:true,yf:function(v){return fm(v)}});
 chart($("g3"),ts2,names.map(function(nm,i){return {n:nm,c:pcol(i),v:P.map(function(x){var n=x.nodes&&x.nodes[nm];return n?n.b:null})}}),{bars:true,stack:true,yf:gb});
 chart($("g4"),ts2,[{n:"CPU mediu flotă",c:"#fbbf24",v:P.map(function(x){return x.n?x.cpu_sum/x.n:null})}],{yf:function(v){return Math.round(v)+"%"}});
 chart($("g5"),ts2,[{n:"VPN gratuit (utilizatori)",c:"#22d3ee",v:P.map(function(x){return x.free_max})},{n:"abonamente active",c:"#D4AF37",v:P.map(function(x){return x.paid_max})},{n:"plătitori reali",c:"#22d38a",v:P.map(function(x){return x.real_max})}],{});
 chart($("g6"),ts2,[{n:"minim online",c:"#22d38a",v:P.map(function(x){return x.up_min===99?null:x.up_min})},{n:"total",c:"#63739a",v:P.map(function(x){return x.total})}],{});
}

// ---------- acțiuni ----------
function api(p,o){return fetch(p,Object.assign({credentials:"include"},o||{})).then(function(r){return r.json()})}
function load(){return api("/api/snapshot").then(function(d){D=d;if(!D.snap){$("upd").textContent="prima colectare rulează…";return}render()}).catch(function(e){$("upd").textContent="eroare: "+e})}
function setTag(k,v){api("/api/tag",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({key:k,tag:v})}).then(function(){return api("/api/collect",{method:"POST"})}).then(load)}
function delReg(n){if(!confirm("Scot „"+n+"” din registru?"))return;api("/api/registry?name="+encodeURIComponent(n),{method:"DELETE"}).then(load)}
function cmdNode(a,n){var msg=a==="drain"?"Scot nodul „"+n+"” din rotație?\n\nNu va mai primi clienți noi. Clienții conectați acum rămân conectați.":"Readuc nodul „"+n+"” în rotație?\n\nVa primi din nou clienți noi.";
 if(!confirm(msg))return;api("/api/cp/"+a,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:n})}).then(function(r){if(r.error)alert("Nu s-a putut: "+r.error);return api("/api/collect",{method:"POST"})}).then(load)}
$("rg_add").onclick=function(){var b={name:$("rg_name").value.trim(),provider:$("rg_prov").value.trim(),location:$("rg_loc").value.trim(),country:$("rg_cc").value.trim().toUpperCase(),port_mbps:$("rg_port").value,brand:$("rg_brand").value,ip:$("rg_ip").value.trim(),status:$("rg_st").value,notes:$("rg_notes").value.trim()};
 if(!b.name){alert("Numele e obligatoriu");return}api("/api/registry",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(b)}).then(load)};
$("cp_add").onclick=function(){var n=$("cp_name").value.trim(),u=$("cp_url").value.trim();if(!n||!u){alert("Numele și adresa agentului sunt obligatorii");return}
 if(!confirm("Activez nodul „"+n+"” ("+u+") pentru clienți?\n\nControl-plane-ul va începe să aloce clienți pe el."))return;
 $("cp_msg").textContent="se activează…";api("/api/cp/register-node",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:n,url:u})}).then(function(r){$("cp_msg").textContent=r.ok?"activat ✓":"eroare: "+(r.error||r.body||r.status);return api("/api/collect",{method:"POST"})}).then(load)};
$("refresh").onclick=function(){$("upd").textContent="se colectează (~15 s)…";api("/api/collect",{method:"POST"}).then(load)};
var rsz;window.addEventListener("resize",function(){clearTimeout(rsz);rsz=setTimeout(function(){var h=(location.hash||"#acum").slice(1);if(h==="grafice")drawSeries();else if(D)render()},200)});
showTab();load().then(function(){showTab()});pollLive();setInterval(pollLive,10000);setInterval(load,60000);
</script></body></html>`;
