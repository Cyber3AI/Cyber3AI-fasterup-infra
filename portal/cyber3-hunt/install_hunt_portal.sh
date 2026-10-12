#!/bin/bash
# Rulează PE PORTAL (10.0.0.22) ca root. Fișierele vin în /tmp/hunt_deploy.
set -u
TS=$(date -u +%Y%m%d-%H%M%S); D=/tmp/hunt_deploy; APP=/opt/fasterup-portal; WEB=/var/www/fasterup-portal
BK=$APP/_bak_archive_hunt_$TS
ok(){ echo "[OK]  $*"; }; fail(){ echo "[ERR] $*"; }
gmaster(){ pgrep -o -f "gunicorn.*app.wsgi"; }
code(){ curl -s -o /dev/null -w "%{http_code}" -m 10 "http://127.0.0.1:5000$1"; }

echo "== portal $(date -u +%FT%TZ) =="
[ -n "$(gmaster)" ] || { fail "gunicorn nu rulează — ABORT"; exit 1; }
B0=$(code /api/auth/me); ok "portal răspunde înainte (/api/auth/me → $B0)"
mkdir -p "$BK" && cp -a $APP/app/__init__.py "$BK/" && cp -a $WEB/index.html "$BK/" || { fail "backup"; exit 1; }
chown -R socadmin:socadmin "$BK"; ok "backup în $BK"

revert(){
  echo "[REV] restaurare din $BK"
  cp -a "$BK/__init__.py" $APP/app/__init__.py; cp -a "$BK/index.html" $WEB/index.html
  rm -f $APP/app/routes/api_hunt.py
  kill -HUP "$(gmaster)"; sleep 6
  echo "[REV] /api/auth/me → $(code /api/auth/me)"
}

install -d -o socadmin -g socadmin /opt/cyber3/hunt $APP/data/threat_hunt
install -o socadmin -g socadmin -m 644 $D/threat_hunt.py /opt/cyber3/hunt/threat_hunt.py
install -o socadmin -g socadmin -m 644 $D/api_hunt.py $APP/app/routes/api_hunt.py
ok "motor → /opt/cyber3/hunt/threat_hunt.py; API → app/routes/api_hunt.py"

python3 $D/patch_portal.py $APP/app/__init__.py $WEB/index.html || { fail "patch"; revert; exit 2; }

sudo -u socadmin bash -c "cd $APP && venv/bin/python -c 'import app.routes.api_hunt as m; print(\"import api_hunt OK:\", m.bp.name)'" || { fail "import api_hunt"; revert; exit 2; }

echo "== prima rulare a vânătorii (7 zile) =="
sudo -u socadmin $APP/venv/bin/python /opt/cyber3/hunt/threat_hunt.py --days 7 --notify --out $APP/data/threat_hunt/latest.json || { fail "rularea motorului"; revert; exit 2; }

kill -HUP "$(gmaster)"; sleep 8
C1=$(code /api/hunt/summary); C2=$(code /api/auth/me)
if [ "$C1" = "401" ] || [ "$C1" = "302" ] || [ "$C1" = "200" ]; then
  ok "rută /api/hunt/summary înregistrată (→ $C1 fără sesiune = autentificare cerută); /api/auth/me → $C2"
else
  fail "/api/hunt/summary → $C1 (așteptat 401)"; revert; exit 2
fi
[ "$C2" = "$B0" ] || { fail "portalul răspunde diferit după reload ($B0 → $C2)"; revert; exit 2; }

install -m 644 $D/cyber3-threat-hunt.service /etc/systemd/system/cyber3-threat-hunt.service
install -m 644 $D/cyber3-threat-hunt.timer /etc/systemd/system/cyber3-threat-hunt.timer
systemctl daemon-reload && systemctl enable --now cyber3-threat-hunt.timer >/dev/null 2>&1
ok "timer: $(systemctl is-active cyber3-threat-hunt.timer), următoarea rulare: $(systemctl show cyber3-threat-hunt.timer -p NextElapseUSecRealtime --value)"

echo "== VERIFICARE =="
echo "buton ▸ HUNT în pagină: $(grep -c '▸ HUNT' $WEB/index.html)"
python3 - <<PY
import json
d = json.load(open("$APP/data/threat_hunt/latest.json", encoding="utf-8"))
import collections
c = collections.Counter(f["severity"] for f in d["findings"] if f["hunt"] != "ERR")
print("constatări 7 zile:", dict(c), "| erori:", sum(1 for f in d["findings"] if f["hunt"] == "ERR"))
for f in d["findings"][:8]:
    print("  %-6s %-3s %-10s %-16s %s" % (f["severity"], f["hunt"], f["agent"], f["host"], f["title"][:70]))
PY
echo "ROLLBACK: cp -a $BK/__init__.py $APP/app/__init__.py; cp -a $BK/index.html $WEB/index.html; rm $APP/app/routes/api_hunt.py; kill -HUP \$(pgrep -o -f 'gunicorn.*app.wsgi'); systemctl disable --now cyber3-threat-hunt.timer"
rm -rf $D
