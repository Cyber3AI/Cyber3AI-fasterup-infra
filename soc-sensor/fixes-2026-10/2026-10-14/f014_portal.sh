#!/bin/bash
# Rulat de operator pe Acer: ! bash <acest fișier>
# Înrolează f014 în portal (PAS 7): slot clients F014 (clonă generică a rândului F012), registrul de scan SENSORS,
# harta MLEO. Backup la tot, verificare de sintaxă, auto-revert, reîncărcare gunicorn (HUP). Fără nume reale de client.
ssh -o ConnectTimeout=15 socadmin@192.168.0.22 'bash -s' <<'REMOTE'
set -u
TS=$(date -u +%Y%m%d-%H%M%S); cd /opt/fasterup-portal
F=app/routes/api_scan_common.py; M=/opt/cyber3/mleo/mleo.py
cp -a $F $F.bak-pre-f014-$TS; sudo cp -a $M $M.bak-pre-f014-$TS
revert(){ cp -a $F.bak-pre-f014-$TS $F; sudo cp -a $M.bak-pre-f014-$TS $M; echo "REVERT făcut"; exit 1; }

# 1) registrul de scan (portalul afișează scanări doar pentru senzorii din SENSORS)
if ! grep -q "'F014'" $F; then
  sed -i "/^    'F012': /a\\    'F014':      {'host': '10.1.14.1', 'agent': '026', 'org': 'FASTERUP_DIRECT', 'scan_ok': True}," $F
fi
./venv/bin/python -m py_compile $F || revert
echo "SENSORS: $(grep "'F014'" $F | tr -s ' ')"

# 2) harta MLEO (identitate senzor -> wg1, agent -> senzor)
grep -q '"f014"' $M || sudo sed -i 's|"f012":"10.1.12.1",|"f012":"10.1.12.1","f014":"10.1.14.1",|; s|"025":"f012",|"025":"f012","026":"f014",|' $M
sudo ./venv/bin/python -m py_compile $M 2>/dev/null || python3 -m py_compile $M || revert
echo "MLEO: $(grep -c '"f014"' $M) intrare wg1, $(grep -c '"026":"f014"' $M) intrare agent"

# 3) slot clients F014 = clonă a rândului F012, cu cod/agent/notă generică (în DB-ul care conține F012)
for DB in portal.db data/portal.db; do
  ./venv/bin/python - "$DB" "$TS" <<'PY'
import sqlite3, sys, shutil
db, ts = sys.argv[1], sys.argv[2]
c = sqlite3.connect(db)
try:
    cols = [r[1] for r in c.execute("pragma table_info(clients)")]
except Exception:
    cols = []
if not cols or not c.execute("select 1 from clients where code='F012'").fetchone():
    print(f"{db}: fără rând F012 — sărit"); sys.exit(0)
if c.execute("select 1 from clients where code='F014'").fetchone():
    print(f"{db}: F014 există deja"); sys.exit(0)
c.close(); shutil.copy2(db, f"{db}.bak-pre-f014-{ts}"); c = sqlite3.connect(db)
src = [x for x in cols if x != 'id']
sel = []
for x in src:
    if x == 'code': sel.append("'F014'")
    elif x == 'wazuh_agent_id': sel.append("'026'")
    elif x == 'notes': sel.append("'Senzor client direct (generic)'")
    elif x in ('created_at', 'updated_at'): sel.append("datetime('now')")
    else: sel.append(x)
c.execute(f"insert into clients ({','.join(src)}) select {','.join(sel)} from clients where code='F012'")
c.commit()
print(f"{db}: inserat", dict(zip(cols, c.execute("select * from clients where code='F014'").fetchone())))
print(f"{db}: integrity", c.execute("pragma integrity_check").fetchone()[0])
PY
done

# 4) reîncărcare gunicorn (HUP pe master) + verificare
MP=$(pgrep -o -f 'gunicorn.*fasterup|gunicorn' ); sudo kill -HUP $MP && echo "gunicorn HUP (pid $MP)"
sleep 4; echo "portal HTTP: $(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/ || curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/)"
echo GATA
REMOTE
