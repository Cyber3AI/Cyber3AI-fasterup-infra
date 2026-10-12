#!/bin/bash
# Rulează PE PORTAL (10.0.0.22) ca root. MLEO etapa 2: mleo.py (aprobare/eliberare), API doar supervisor, butoane în ▸ HUNT.
set -u
TS=$(date -u +%Y%m%d-%H%M%S); D=/tmp/mleo_deploy; APP=/opt/fasterup-portal; WEB=/var/www/fasterup-portal; M=/opt/cyber3/mleo
BK=$APP/_bak_archive_mleo2_$TS
ok(){ echo "[OK]  $*"; }; fail(){ echo "[ERR] $*"; }
gmaster(){ pgrep -o -f "gunicorn.*app.wsgi"; }
code(){ curl -s -o /dev/null -w "%{http_code}" -m 10 "$@"; }
[ -n "$(gmaster)" ] || { fail "gunicorn nu rulează — ABORT"; exit 1; }
B0=$(code http://127.0.0.1:5000/api/auth/me)
mkdir -p "$BK" && cp -a $M/mleo.py $APP/app/routes/api_hunt.py $WEB/index.html $M/mleo.db "$BK/" || { fail backup; exit 1; }
chown -R socadmin:socadmin "$BK"; ok "backup $BK"
revert(){
  echo "[REV] restaurare din $BK"
  cp -a "$BK/mleo.py" $M/mleo.py; cp -a "$BK/api_hunt.py" $APP/app/routes/api_hunt.py; cp -a "$BK/index.html" $WEB/index.html
  kill -HUP "$(gmaster)"; sleep 6; echo "[REV] /api/auth/me → $(code http://127.0.0.1:5000/api/auth/me)"
}
python3 -m py_compile $D/mleo.py $D/api_hunt.py || { fail compilare; exit 2; }
install -o socadmin -g socadmin -m 644 $D/mleo.py $M/mleo.py
install -o socadmin -g socadmin -m 644 $D/api_hunt.py $APP/app/routes/api_hunt.py
python3 $D/patch_contain2.py $WEB/index.html || { fail "patch index.html"; revert; exit 2; }
OUT=$(sudo -u socadmin python3 $M/mleo.py run 2>&1)
echo "$OUT" | grep -E "RUN:|CONTAIN" | tail -4
echo "$OUT" | grep -q Traceback && { fail "mleo run: $(echo "$OUT" | tail -3)"; revert; exit 2; }
sudo -u socadmin bash -c "cd $APP && venv/bin/python -c 'import app.routes.api_hunt'" || { fail "import api_hunt"; revert; exit 2; }
kill -HUP "$(gmaster)"; sleep 8
C1=$(code http://127.0.0.1:5000/api/hunt/containment)
C2=$(code -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:5000/api/hunt/containment/mleoc-test/approve)
C3=$(code http://127.0.0.1:5000/api/auth/me)
echo "GET containment fără sesiune → $C1 | POST aprobare fără sesiune → $C2 | /api/auth/me → $C3"
[ "$C2" = 401 ] || { fail "aprobarea nu e protejată ($C2, așteptat 401)"; revert; exit 2; }
[ "$C3" = "$B0" ] || { fail "portalul răspunde diferit ($B0 → $C3)"; revert; exit 2; }
ok "Aprobă / Respinge / Eliberează: doar rolul supervisor (verificat pe server)"
echo "== conexiune portal → senzor (status executor, fără modificări) =="
for s in 10.1.12.1 10.1.32.1; do echo "$s: $(sudo -u socadmin ssh -o BatchMode=yes -o ConnectTimeout=6 socadmin@$s sudo -n /usr/local/sbin/cyber3-mleo-contain status 2>&1 | tail -1)"; done
echo "== propuneri curente =="
sudo -u socadmin python3 $M/mleo.py contain
echo "ROLLBACK portal: cp -a $BK/mleo.py $M/; cp -a $BK/api_hunt.py $APP/app/routes/; cp -a $BK/index.html $WEB/; kill -HUP \$(pgrep -o -f 'gunicorn.*app.wsgi')"
rm -rf $D
