# -*- coding: utf-8 -*-
"""Patch idempotent index.html: butoane Aprobă / Respinge / Eliberează în cardul MLEO (vizibile doar supervisorului).
Utilizare: python3 patch_contain2.py /var/www/fasterup-portal/index.html"""
import sys
p = sys.argv[1]
h = open(p, encoding="utf-8").read()
if "function mleoAct(" in h:
    print("index.html: butoanele MLEO există deja"); sys.exit(0)
a = h.index("function loadHuntContain(){")
b = h.index("if(huntTabBtn)huntTabBtn.addEventListener('click',loadHuntContain);")
JS = '''function loadHuntContain(){
  var tb=document.getElementById('huntContain');if(!tb)return;
  fetch('/api/hunt/containment',{credentials:'include',cache:'no-store'}).then(function(r){return r.json();}).then(function(d){
    var it=d.items||[];var sup=!!d.can_approve;
    var m=document.getElementById('huntContainMeta');
    if(m)m.textContent=it.filter(function(x){return x.state==='active';}).length+' ACTIVE · '+it.filter(function(x){return x.state==='proposed';}).length+' PROPUSE';
    if(!it.length){tb.innerHTML='<tr><td colspan="10" class="faint">Nicio stație internă de izolat.</td></tr>';return;}
    var lab={proposed:['dec-block','PROPUS'],notify:['dec-monitor','DOAR NOTIFICARE'],active:['dec-block','ÎN CARANTINĂ'],released:['dec-ignore','ELIBERAT'],rejected:['dec-ignore','RESPINS'],expired:['dec-ignore','EXPIRAT']};
    tb.innerHTML=it.map(function(x){
      var l=lab[x.state]||['dec-ignore',x.state];
      var st='<span class="alert-decision '+l[0]+'">'+l[1]+'</span>';
      var who='';
      if(x.state==='active')who='<div class="faint" style="font-size:11px">aprobat de '+huntEsc(x.approved_by)+' · expiră '+huntTime(x.expires*1000)+'</div>';
      if(x.released_by)who='<div class="faint" style="font-size:11px">'+huntEsc(x.released_by)+' · '+huntTime(x.released_at*1000)+'</div>';
      var act='';
      if(sup&&x.state==='proposed')act='<button class="ext-btn" onclick="mleoAct(\\'approve\\',\\''+x.txid+'\\',\\''+huntEsc(x.ip)+'\\')">Aprobă</button> <button class="ext-btn" onclick="mleoAct(\\'release\\',\\''+x.txid+'\\',\\''+huntEsc(x.ip)+'\\')">Respinge</button>';
      if(sup&&x.state==='active')act='<button class="ext-btn" onclick="mleoAct(\\'release\\',\\''+x.txid+'\\',\\''+huntEsc(x.ip)+'\\')">Eliberează</button>';
      return '<tr><td>'+st+who+'</td><td class="mono">'+huntEsc(x.sensor)+'</td><td class="mono">'+huntEsc(x.ip)+'</td><td class="mono faint">'+huntEsc(x.mac||'-')+'</td>'+
        '<td class="mono">'+huntEsc(x.source)+'</td><td>'+huntEsc(x.reason)+'</td><td>'+huntEsc(x.action)+'</td>'+
        '<td class="mono faint">'+huntTime((x.last_signal||x.ts)*1000)+'</td><td class="table-num">'+huntEsc(x.signals)+'</td><td style="white-space:nowrap">'+act+'</td></tr>';
    }).join('');
  }).catch(function(){tb.innerHTML='<tr><td colspan="10" class="faint">MLEO nu răspunde.</td></tr>';});
}
function mleoAct(verb,tx,ip){
  var q={approve:'Puneți în CARANTINĂ DE IEȘIRE stația '+ip+' pentru 24 de ore? Stația rămâne în rețeaua internă, dar pierde accesul la Internet.',
         release:'Confirmați eliberarea / respingerea pentru '+ip+'?'}[verb];
  if(!confirm(q))return;
  fetch('/api/hunt/containment/'+encodeURIComponent(tx)+'/'+verb,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:'{}'})
  .then(function(r){return r.json();}).then(function(d){
    alert(d.ok?('OK — '+(d.sensor_output||d.state)):('EȘEC — '+(d.error||'')+(d.sensor_output?'\\n'+d.sensor_output:'')));loadHuntContain();
  }).catch(function(){alert('Eroare de comunicare cu portalul.');});
}
'''
h = h[:a] + JS + h[b:]
h = h.replace('<th>Ultimul semnal</th><th>Nr.</th></tr></thead>\n          <tbody id="huntContain">', '<th>Ultimul semnal</th><th>Nr.</th><th></th></tr></thead>\n          <tbody id="huntContain">', 1)
h = h.replace('În această etapă propunerile NU se execută.', 'Carantina se aplică DOAR la aprobarea supervisorului, pentru 24 de ore (expiră automat), și poate fi ridicată oricând cu „Eliberează”.', 1)
h = h.replace('<span class="mini-tag">OBSERVARE</span> <span id="huntContainMeta">', '<span class="mini-tag">APROBARE SUPERVISOR</span> <span id="huntContainMeta">', 1)
open(p, "w", encoding="utf-8").write(h)
print("index.html: butoane MLEO (doar supervisor) adăugate")
