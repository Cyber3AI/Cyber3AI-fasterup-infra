#!/bin/bash
# Rulează PE PORTAL (10.0.0.22) ca root. MLEO etapa 1 — OBSERVARE: identitate pe senzor + propuneri de carantină. Nu atinge senzorii.
set -u
TS=$(date -u +%Y%m%d-%H%M%S); D=/tmp/mleo_deploy; APP=/opt/fasterup-portal; WEB=/var/www/fasterup-portal; M=/opt/cyber3/mleo
BK=$APP/_bak_archive_mleo_$TS
ok(){ echo "[OK]  $*"; }; fail(){ echo "[ERR] $*"; }
gmaster(){ pgrep -o -f "gunicorn.*app.wsgi"; }
code(){ curl -s -o /dev/null -w "%{http_code}" -m 10 "http://127.0.0.1:5000$1"; }
echo "== MLEO etapa 1 (observare) $(date -u +%FT%TZ) =="
[ -n "$(gmaster)" ] || { fail "gunicorn nu rulează — ABORT"; exit 1; }
B0=$(code /api/auth/me)
mkdir -p "$BK" && cp -a $M/mleo.py $APP/app/routes/api_hunt.py $WEB/index.html "$BK/" && cp -a $M/mleo.db "$BK/mleo.db" || { fail "backup"; exit 1; }
chown -R socadmin:socadmin "$BK"; ok "backup în $BK (mleo.py, mleo.db, api_hunt.py, index.html)"
revert(){
  echo "[REV] restaurare din $BK"
  cp -a "$BK/mleo.py" $M/mleo.py; cp -a "$BK/api_hunt.py" $APP/app/routes/api_hunt.py; cp -a "$BK/index.html" $WEB/index.html
  kill -HUP "$(gmaster)"; sleep 6; echo "[REV] /api/auth/me → $(code /api/auth/me)"
}
python3 -m py_compile $D/mleo.py $D/api_hunt.py || { fail "compilare"; exit 2; }
systemctl stop cyber3-mleo.timer
install -o socadmin -g socadmin -m 644 $D/mleo.py $M/mleo.py
[ -f $M/mleo-critical.conf ] || install -o socadmin -g socadmin -m 644 $D/mleo-critical.conf $M/mleo-critical.conf
install -o socadmin -g socadmin -m 644 $D/api_hunt.py $APP/app/routes/api_hunt.py
python3 $D/patch_contain.py $WEB/index.html || { fail "patch index.html"; revert; systemctl start cyber3-mleo.timer; exit 2; }
ok "instalat: mleo.py, mleo-critical.conf, api_hunt.py (/api/hunt/containment), card în ▸ HUNT"
echo "== rulare MLEO =="
OUT=$(systemctl start cyber3-mleo.service 2>&1; journalctl -u cyber3-mleo.service --since "-2min" --no-pager | tail -12)
echo "$OUT" | grep -E "RUN:|CONTAIN|Traceback|Error" | tail -8
echo "$OUT" | grep -q "Traceback" && { fail "MLEO a dat eroare"; revert; systemctl start cyber3-mleo.timer; exit 2; }
grep -q "contain_new=" <(tail -n 30 $M/mleo.log) || { fail "rularea nu a ajuns la etapa de carantină"; revert; systemctl start cyber3-mleo.timer; exit 2; }
systemctl start cyber3-mleo.timer; ok "timer MLEO repornit: $(systemctl is-active cyber3-mleo.timer)"
sudo -u socadmin bash -c "cd $APP && venv/bin/python -c 'import app.routes.api_hunt as m; print(\"import api_hunt OK\")'" || { fail "import api_hunt"; revert; exit 2; }
kill -HUP "$(gmaster)"; sleep 8
C1=$(code /api/hunt/containment); C2=$(code /api/auth/me)
case "$C1" in 401|302|200) ok "/api/hunt/containment → $C1 fără sesiune (autentificare cerută)";; *) fail "/api/hunt/containment → $C1"; revert; exit 2;; esac
[ "$C2" = "$B0" ] || { fail "portalul răspunde diferit ($B0 → $C2)"; revert; exit 2; }
echo "== VERIFICARE =="
sudo -u socadmin python3 $M/mleo.py contain
echo "senzori atinși: 0 (etapa de observare)"
echo "ROLLBACK: cp -a $BK/mleo.py $M/; cp -a $BK/api_hunt.py $APP/app/routes/; cp -a $BK/index.html $WEB/; kill -HUP \$(pgrep -o -f 'gunicorn.*app.wsgi')"
rm -rf $D
