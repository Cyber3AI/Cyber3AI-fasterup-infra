#!/bin/bash
# Rulează PE MANAGER ca root. C3-FIX-20261014-PAGINI: generatorul MISP de domenii se oprea la pagina 60 (≈47% din indicatori).
# Plafon nou 400 pagini + avertisment în jurnal dacă e atins. Backup, compilare, rulare o dată, verificare (număr + base64).
# Dacă rularea eșuează, generatorul vechi e restaurat (fișierul /srv/cyber3/misp-domains.lst rămâne cel bun — generatorul nu-l suprascrie la eșec).
set -u
G=/usr/local/sbin/cyber3-refresh-domains.py; OUT=/srv/cyber3/misp-domains.lst; LOG=/var/log/cyber3-domains-refresh.log; TS=$(date -u +%Y%m%d-%H%M%S)
grep -q 'C3-FIX-20261014-PAGINI' $G && echo "patch deja aplicat" || {
  cp -a $G $G.bak-pagini-$TS
  python3 - "$G" <<'PY' || { echo "ABORT: patch eșuat — nimic schimbat"; exit 2; }
import sys
p = sys.argv[1]; s = open(p).read()
a = "    while page <= 60:\n"
b = "    if len(domains) < 1000:\n"
assert s.count(a) == 1 and s.count(b) == 1, "ancore negăsite"
s = s.replace(a, "    # C3-FIX-20261014-PAGINI: era <= 60 (lua mereu aceleasi 300k atribute = ~47% din MISP). Plafon de siguranta 400.\n    while page <= 400:\n", 1)
s = s.replace(b, "    if page > 400:\n        log(\"AVERTISMENT: plafonul de 400 pagini atins - lista poate fi trunchiata\")\n" + b, 1)
open(p, "w").write(s); print("patch aplicat")
PY
  python3 -m py_compile $G || { cp -a $G.bak-pagini-$TS $G; echo "ABORT: compilare — restaurat"; exit 2; }
}
SHA0=$(sha256sum $OUT | cut -c1-12); N0=$(wc -l < $OUT)
echo "înainte: $N0 domenii, sha $SHA0 — rulez generatorul (~10 min)..."
T0=$(date +%s); /usr/bin/python3 $G >/dev/null 2>&1; RC=$?
echo "generator rc=$RC în $(( $(date +%s)-T0 )) s | jurnal: $(tail -1 $LOG)"
[ $RC = 0 ] || { cp -a $G.bak-pagini-$TS $G 2>/dev/null; echo "EȘEC — generator restaurat; fișierul distribuit rămâne cel vechi"; exit 1; }
N1=$(wc -l < $OUT)
python3 - "$OUT" <<'PY' || { echo "EȘEC verificare base64"; exit 1; }
import sys, base64
bad = n = 0
for l in open(sys.argv[1], 'rb'):
    s = l.strip()
    if not s: continue
    n += 1
    try: base64.b64decode(s, validate=True)
    except Exception: bad += 1
print(f"verificare: {n} linii, {bad} non-base64")
sys.exit(1 if bad else 0)
PY
echo "DUPĂ: $N1 domenii (era $N0), sha $(sha256sum $OUT | cut -c1-12), $(du -h $OUT | cut -f1), $(stat -c '%U:%G %a' $OUT)"
[ "$N1" -gt "$N0" ] || { echo "ATENȚIE: numărul nu a crescut — NU distribui"; exit 1; }
echo "MANAGER OK"
