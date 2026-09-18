// Cascada de 7 straturi: amenințări care cad și sunt absorbite strat cu strat (pur decorativ, fără date).
(function () {
  var cv = document.getElementById('d7-rain');
  if (!cv || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  var box = cv.parentElement, ctx = cv.getContext('2d');
  var parts = [], bands = [], raf = 0, running = false;
  var COL = ['#3b82f6', '#f59e0b', '#22d3ee', '#34d399', '#a78bfa', '#2dd4bf', '#fb7185'];
  var STOP = [0.34, 0.30, 0.28, 0.34, 0.30, 0.40, 1];

  function layout() {
    var r = box.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
    cv.width = r.width * dpr; cv.height = r.height * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    bands = Array.prototype.map.call(box.querySelectorAll('.d7-row'), function (el) {
      var b = el.getBoundingClientRect(); return b.top + b.height / 2 - r.top;
    });
  }
  function step() {
    var w = box.clientWidth, h = box.clientHeight;
    ctx.clearRect(0, 0, w, h);
    if (parts.length < 90 && Math.random() < 0.7)
      parts.push({ x: Math.random() * w, y: -6, v: 1.1 + Math.random() * 1.6, layer: 0, r: 1.3 + Math.random() * 1.4 });
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      if (p.dead) { p.flash -= 0.06; continue; }
      p.y += p.v;
      if (p.layer < bands.length && p.y >= bands[p.layer]) {
        if (Math.random() < STOP[p.layer]) { p.dead = true; p.flash = 1; p.fy = bands[p.layer]; p.fc = COL[p.layer]; }
        p.layer++;
      }
      if (!p.dead) {
        ctx.globalAlpha = 0.85; ctx.fillStyle = '#ff3b4e';
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 7); ctx.fill();
        ctx.globalAlpha = 0.2; ctx.fillRect(p.x - 0.6, p.y - 10, 1.2, 10);
      }
    }
    for (var j = 0; j < parts.length; j++) {
      var q = parts[j];
      if (q.dead && q.flash > 0) {
        ctx.globalAlpha = Math.max(0, q.flash); ctx.strokeStyle = q.fc; ctx.lineWidth = 1.4;
        ctx.beginPath(); ctx.arc(q.x, q.fy, (1 - q.flash) * 13 + 2, 0, 7); ctx.stroke();
      }
    }
    ctx.globalAlpha = 1;
    parts = parts.filter(function (p) { return p.y < h + 12 && !(p.dead && p.flash <= 0); });
    raf = requestAnimationFrame(step);
  }
  function start() { if (running) return; running = true; layout(); step(); }
  function stop() { running = false; cancelAnimationFrame(raf); }
  // rulează doar cât timp cascada e pe ecran
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(function (e) { e[0].isIntersecting ? start() : stop(); }).observe(box);
  } else { start(); }
  var t; window.addEventListener('resize', function () { clearTimeout(t); t = setTimeout(function () { if (running) layout(); }, 180); });
})();
