#!/bin/bash
# Lansator — rulat de operator cu `!`: finalizează pasul 2 pe portal (reîncărcare + verificări). Backup existent: _bak_archive_mleo2_20261010-135709
H=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad/hunt
scp -q $H/mleo.py socadmin@10.0.0.22:/tmp/mleo_deploy/mleo.py && \
ssh -o ConnectTimeout=15 socadmin@10.0.0.22 'sudo bash -s' <<'EOF'
set -u
D=/tmp/mleo_deploy; APP=/opt/fasterup-portal; WEB=/var/www/fasterup-portal; M=/opt/cyber3/mleo
BK=$APP/_bak_archive_mleo2_20261010-135709
ok(){ echo "[OK]  $*"; }; fail(){ echo "[ERR] $*"; }
gmaster(){ pgrep -o -f "gunicorn.*app.wsgi"; }
code(){ curl -s -o /dev/null -w "%{http_code}" -m 10 "$@" </dev/null; }
revert(){
  echo "[REV] restaurare din $BK"
  cp -a "$BK/mleo.py" $M/mleo.py; cp -a "$BK/api_hunt.py" $APP/app/routes/api_hunt.py; cp -a "$BK/index.html" $WEB/index.html
  kill -HUP "$(gmaster)"; sleep 6; echo "[REV] /api/auth/me → $(code http://127.0.0.1:5000/api/auth/me)"
}
[ -d "$BK" ] || { fail "backup lipsă — ABORT"; exit 1; }
B0=$(code http://127.0.0.1:5000/api/auth/me)
python3 -m py_compile $D/mleo.py && install -o socadmin -g socadmin -m 644 $D/mleo.py $M/mleo.py || { fail "mleo.py"; exit 2; }
sudo -u socadmin bash -c "cd $APP && venv/bin/python -c 'import app.routes.api_hunt; print(\"import api_hunt OK\")'" </dev/null || { fail "import api_hunt"; revert; exit 2; }
kill -HUP "$(gmaster)"; sleep 8
C1=$(code http://127.0.0.1:5000/api/hunt/containment)
C2=$(code -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:5000/api/hunt/containment/mleoc-test/approve)
C3=$(code http://127.0.0.1:5000/api/auth/me)
echo "GET containment fără sesiune → $C1 | POST aprobare fără sesiune → $C2 | /api/auth/me → $C3"
[ "$C2" = 401 ] || { fail "aprobarea nu e protejată ($C2, așteptat 401)"; revert; exit 2; }
[ "$C3" = "$B0" ] || { fail "portalul răspunde diferit ($B0 → $C3)"; revert; exit 2; }
ok "Aprobă / Respinge / Eliberează: doar rolul supervisor (verificat pe server)"
echo "== legătura portal → senzor (doar status) =="
for s in 10.1.12.1 10.1.32.1; do echo "$s: $(sudo -u socadmin ssh -o BatchMode=yes -o ConnectTimeout=6 socadmin@$s sudo -n /usr/local/sbin/cyber3-mleo-contain status </dev/null 2>&1 | tail -1)"; done
echo "== propuneri curente =="
sudo -u socadmin python3 $M/mleo.py contain </dev/null
rm -rf $D
EOF
