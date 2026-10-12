# -*- coding: utf-8 -*-
"""Patch idempotent pentru portal: înregistrează blueprint-ul hunt și adaugă în index.html butonul ▸ HUNT, tab-ul, pagina, i18n și loader-ul JS.
Rulează pe portal: python3 patch_portal.py /opt/fasterup-portal/app/__init__.py /var/www/fasterup-portal/index.html"""
import sys

init_path, html_path = sys.argv[1], sys.argv[2]


def sub_once(s, anchor, new, where="after"):
    assert s.count(anchor) == 1, "ancoră negăsită sau multiplă: %r" % anchor[:80]
    return s.replace(anchor, anchor + new if where == "after" else new + anchor)


# ---------------- app/__init__.py
s = open(init_path, encoding="utf-8").read()
if "api_hunt" not in s:
    s = sub_once(s, "from app.routes.api_mleo import bp as mleo_bp", "\n    from app.routes.api_hunt import bp as hunt_bp")
    s = sub_once(s, 'app.register_blueprint(mleo_bp, url_prefix="/api")', '\n    app.register_blueprint(hunt_bp, url_prefix="/api")')
    open(init_path, "w", encoding="utf-8").write(s)
    print("__init__.py: blueprint hunt înregistrat")
else:
    print("__init__.py: deja înregistrat")

# ---------------- index.html
h = open(html_path, encoding="utf-8").read()
if 'data-page="hunt"' in h:
    print("index.html: deja conține HUNT")
    sys.exit(0)

BTN = '<a href="#" onclick="var t=document.querySelector(\'.tab[data-page=hunt]\');if(t)t.click();return false;" class="ext-btn" title="CYBER3 Threat Hunt — vânătoare proactivă de amenințări">▸ HUNT</a>'
h = sub_once(h, '<a href="/api/wazuh-dashboard" target="_blank" class="ext-btn">▸ WAZUH</a>', BTN)

h = sub_once(h, '    <button class="tab" data-page="workstations" data-i18n="tab_workstations">Workstations</button>\n',
             '    <button class="tab" data-page="hunt" data-i18n="tab_hunt">Threat Hunt</button>\n')

PAGE = '''  <div class="page" data-page="hunt">
    <div class="card">
      <div class="card-head">
        <div class="card-title">◎ CYBER3 Threat Hunt — vânătoare proactivă de amenințări</div>
        <div class="card-meta"><span class="live"></span><span id="huntMeta">—</span></div>
      </div>
      <div class="card-body">
        <div id="huntCounts" style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px"></div>
        <div class="faint" style="font-size:12px;line-height:1.6">
          Vânătoare automată (la fiecare 6 ore, fereastră de 7 zile) a tiparelor de compromitere pe care pragurile obișnuite de alertare nu le scot în evidență:
          <b>H1</b> răspuns reușit la atac · <b>H2</b> încărcare de cod acceptată · <b>H3</b> stager PowerShell urmat de C2 ·
          <b>H4</b> comunicare C2 permisă · <b>H5</b> volum mare ieșit · <b>H6</b> honeytoken · <b>H7</b> acces la distanță pe o stație nouă · <b>H8</b> senzor fără alerte de rețea.
        </div>
        <div style="margin-top:10px;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
          <label class="faint" style="font-size:12px">Severitate:
            <select id="huntSev" onchange="loadHunt()"><option value="">toate</option><option>CRITIC</option><option>ÎNALT</option><option>MEDIU</option><option>INFO</option></select></label>
          <label class="faint" style="font-size:12px"><input type="checkbox" id="huntInfo" onchange="loadHunt()"> include INFO (cloud cunoscut)</label>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-body no-pad">
        <table class="data-table">
          <thead><tr><th>Severitate</th><th>Vânătoare</th><th>Senzor</th><th>Gazdă</th><th>Constatare</th><th>Prima apariție</th><th>Ultima</th><th>Nr.</th></tr></thead>
          <tbody id="huntTable"><tr><td colspan="8" class="faint">Se încarcă…</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>
'''
h = sub_once(h, '  <div class="page" data-page="workstations">', PAGE, where="before")

h = sub_once(h, "    tab_workstations: 'Workstations',\n", "    tab_hunt: 'Threat Hunt',\n")
h = sub_once(h, "    tab_workstations: 'Stații EDR',\n", "    tab_hunt: 'Threat Hunt',\n")

JS = '''function huntEsc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function huntTime(t){if(!t)return '-';try{var d=new Date(t);return d.toLocaleString('ro-RO',{timeZone:'Europe/Bucharest',day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});}catch(e){return t;}}
function loadHunt(){
  var sev=(document.getElementById('huntSev')||{}).value||'';var inf=(document.getElementById('huntInfo')||{}).checked?'1':'0';
  var tb=document.getElementById('huntTable');if(!tb)return;
  fetch('/api/hunt/findings?include_info='+inf+(sev?'&severity='+encodeURIComponent(sev):''),{credentials:'include',cache:'no-store'})
  .then(function(r){return r.json();}).then(function(d){
    var cls={'CRITIC':'dec-block','ÎNALT':'dec-escal','MEDIU':'dec-monitor','INFO':'dec-ignore'};
    var c=d.counts||{};var ce=document.getElementById('huntCounts');
    if(ce){ce.innerHTML=['CRITIC','ÎNALT','MEDIU','INFO'].map(function(k){return '<span class="alert-decision '+cls[k]+'">'+k+': '+(c[k]||0)+'</span>';}).join('');}
    var m=document.getElementById('huntMeta');if(m){m.textContent=d.generated?('ULTIMA RULARE '+huntTime(d.generated)+' · FEREASTRĂ 7 ZILE'):'ÎNCĂ NERULAT';}
    var f=d.findings||[];
    if(!f.length){tb.innerHTML='<tr><td colspan="8" class="faint">Nicio constatare în fereastra curentă.</td></tr>';return;}
    tb.innerHTML=f.map(function(x){
      return '<tr><td><span class="alert-decision '+(cls[x.severity]||'dec-ignore')+'">'+huntEsc(x.severity)+'</span>'+(x['new']?' <span class="mini-tag">NOU</span>':'')+'</td>'+
        '<td class="mono" title="'+huntEsc((d.hunts||{})[x.hunt]||'')+'">'+huntEsc(x.hunt)+'</td>'+
        '<td class="mono">'+huntEsc(x.agent)+'</td><td class="mono">'+huntEsc(x.host)+'</td>'+
        '<td><b>'+huntEsc(x.title)+'</b><div class="faint" style="font-size:11px">'+huntEsc(x.detail)+'</div></td>'+
        '<td class="mono faint">'+huntTime(x.first_seen)+'</td><td class="mono faint">'+huntTime(x.last_seen)+'</td><td class="table-num">'+huntEsc(x.count)+'</td></tr>';
    }).join('');
  }).catch(function(){tb.innerHTML='<tr><td colspan="8" class="faint">Serviciul Threat Hunt nu răspunde.</td></tr>';});
}
var huntTabBtn=document.querySelector('.tab[data-page="hunt"]');if(huntTabBtn)huntTabBtn.addEventListener('click',loadHunt);
'''
h = sub_once(h, "var wsTabBtn=document.querySelector('.tab[data-page=\"workstations\"]');", JS, where="before")
open(html_path, "w", encoding="utf-8").write(h)
print("index.html: buton ▸ HUNT, tab, pagină, i18n, loader adăugate")
