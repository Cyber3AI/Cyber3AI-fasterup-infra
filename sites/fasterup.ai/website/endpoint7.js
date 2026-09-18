// Galeria capturilor CYBER3 EDR/XDR for Desktop: miniatura aleasă devine imaginea mare.
(function () {
  document.querySelectorAll('.x7-th').forEach(function (b) {
    b.addEventListener('click', function () {
      var main = document.getElementById(b.dataset.g + '-main');
      if (!main) return;
      main.src = b.dataset.src;
      main.alt = b.dataset.alt;
      document.querySelectorAll('.x7-th[data-g="' + b.dataset.g + '"]').forEach(function (o) { o.classList.toggle('on', o === b); });
    });
  });
})();
