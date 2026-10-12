# -*- coding: utf-8 -*-
"""Patch idempotent index.html: cardul „Carantină propusă (MLEO)” în pagina ▸ HUNT.
Utilizare: python3 patch_contain.py /var/www/fasterup-portal/index.html"""
import sys
p = sys.argv[1]
h = open(p, encoding="utf-8").read()
if 'id="huntContain"' in h:
    print("index.html: cardul de carantină există deja"); sys.exit(0)

def sub_once(s, anchor, new, where="after"):
    assert s.count(anchor) == 1, "ancoră negăsită sau multiplă: %r" % anchor[:80]
    return s.replace(anchor, anchor + new if where == "after" else new + anchor)

CARD = '''    <div class="card">
      <div class="card-head">
        <div class="card-title">⛔ Carantină propusă — MLEO (stații interne compromise)</div>
        <div class="card-meta"><span class="mini-tag">OBSERVARE</span> <span id="huntContainMeta">—</span></div>
      </div>
      <div class="card-body no-pad">
        <div class="faint" style="font-size:12px;line-height:1.6;padding:10px 14px">
          Semnale: vânătorile H3 / H4 / H6 și deciziile CyberBot pe troian / C2 (regula 100216) pentru adrese interne. Identitatea IP→MAC se stabilește strict pe senzorul clientului.
          Dispozitivele critice (servere, centrale, DNS, gateway) primesc doar notificare. În această etapă propunerile NU se execută.
        </div>
        <table class="data-table">
          <thead><tr><th>Stare</th><th>Senzor</th><th>Stație</th><th>MAC</th><th>Sursă</th><th>Motiv</th><th>Acțiune propusă</th><th>Ultimul semnal</th><th>Nr.</th></tr></thead>
          <tbody id="huntContain"><tr><td colspan="9" class="faint">Se încarcă…</td></tr></tbody>
        </table>
      </div>
    </div>
'''
anchor = '<tbody id="huntTable"><tr><td colspan="8" class="faint">Se încarcă…</td></tr></tbody>\n        </table>\n      </div>\n    </div>\n'
h = sub_once(h, anchor, CARD)

JS = '''function loadHuntContain(){
  var tb=document.getElementById('huntContain');if(!tb)return;
  fetch('/api/hunt/containment',{credentials:'include',cache:'no-store'}).then(function(r){return r.json();}).then(function(d){
    var it=d.items||[];var m=document.getElementById('huntContainMeta');if(m)m.textContent=it.length+' PROPUNERI';
    if(!it.length){tb.innerHTML='<tr><td colspan="9" class="faint">Nicio stație internă de izolat.</td></tr>';return;}
    tb.innerHTML=it.map(function(x){
      var st=x.state==='notify'?'<span class="alert-decision dec-monitor">DOAR NOTIFICARE</span>':'<span class="alert-decision dec-block">PROPUS</span>';
      return '<tr><td>'+st+'</td><td class="mono">'+huntEsc(x.sensor)+'</td><td class="mono">'+huntEsc(x.ip)+'</td><td class="mono faint">'+huntEsc(x.mac||'-')+'</td>'+
        '<td class="mono">'+huntEsc(x.source)+'</td><td>'+huntEsc(x.reason)+'</td><td>'+huntEsc(x.action)+'</td>'+
        '<td class="mono faint">'+huntTime((x.last_signal||x.ts)*1000)+'</td><td class="table-num">'+huntEsc(x.signals)+'</td></tr>';
    }).join('');
  }).catch(function(){tb.innerHTML='<tr><td colspan="9" class="faint">MLEO nu răspunde.</td></tr>';});
}
if(huntTabBtn)huntTabBtn.addEventListener('click',loadHuntContain);
'''
h = sub_once(h, "var huntTabBtn=document.querySelector('.tab[data-page=\"hunt\"]');if(huntTabBtn)huntTabBtn.addEventListener('click',loadHunt);\n", JS)
open(p, "w", encoding="utf-8").write(h)
print("index.html: card carantină MLEO adăugat")
