// Live threat-indicator count — pulled from the CYBER3 edge manifest (same threat DB
// the FasterUp SOC uses), with fallback to the hardcoded data-count if the fetch fails.
const MANIFEST = 'https://cyber3-edge.cyber3.workers.dev/v1/manifest';

function animateCount(el) {
  const target = +el.dataset.count, dur = 1600, t0 = performance.now();
  const suffix = el.dataset.suffix || '';
  (function tick(t) {
    const p = Math.min(1, (t - t0) / dur);
    el.textContent = Math.floor(p * target).toLocaleString('en-US') + suffix;
    if (p < 1) requestAnimationFrame(tick);
    else el.textContent = target.toLocaleString('en-US') + suffix;
  })(t0);
}

function observe() {
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => { if (e.isIntersecting) { animateCount(e.target); io.unobserve(e.target); } });
  }, { threshold: 0.4 });
  document.querySelectorAll('[data-count]').forEach((el) => io.observe(el));
}

(async function () {
  try {
    const r = await fetch(MANIFEST, { cache: 'no-store' });
    if (r.ok) {
      const d = await r.json();
      if (d && Number.isFinite(d.count) && d.count > 0) {
        document.querySelectorAll('[data-count]').forEach((el) => { el.dataset.count = d.count; });
      }
    }
  } catch (e) { /* fallback: keep the hardcoded data-count */ }
  observe();
})();
