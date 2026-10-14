#!/bin/bash
# Rulează PE SENZOR ca root. Pasul 1 (14.10.2026): wrapper-ul cyber3-apply-domains NU mai face reload-rules
# (interzis pe senzor inline viu după incidentul icisoc108): doar validează base64 + pune fișierul pe disc;
# Suricata îl încarcă la următorul restart (cel nocturn din logrotate). + sudoers + cheia portalului dacă lipsesc.
# Nu atinge Suricata, Wazuh sau rețeaua.
set -u
H=$(hostname); TS=$(date -u +%Y%m%d-%H%M%S)
W=/usr/local/sbin/cyber3-apply-domains; SUD=/etc/sudoers.d/cyber3-domains
PORTAL_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDzdEUG9madO0dCGtu6wbUE0fDKBQvlrMUh3gHYPwDct portal@fasterup-portal'
[ -f $W ] && cp -a $W $W.bak-noreload-$TS
cat > $W.new <<'WEOF'
#!/bin/bash
# CYBER3 — aplică datasetul de domenii MISP primit de la portal. sudo NOPASSWD (doar acest fișier).
# GARDĂ: refuză dataset care NU e base64 valid (Suricata type:string) — păstrează versiunea bună de pe senzor.
# 14.10.2026: FĂRĂ reload-rules (interzis pe senzor inline viu) — datasetul se încarcă la următorul restart Suricata (nocturn, logrotate).
set -e
SRC=/tmp/cyber3-domains-staged.lst
D=/etc/suricata/datasets/misp-domains.lst
[ -s "$SRC" ] || { echo "eroare: staged lipsă"; exit 1; }
N=$(wc -l < "$SRC"); [ "$N" -ge 1000 ] || { echo "eroare: prea mic ($N)"; exit 1; }
python3 - "$SRC" <<'PYEOF' || { echo "eroare: staged NU e base64 valid — refuz aplicarea (păstrez datasetul curent)"; rm -f "$SRC"; exit 1; }
import sys, base64
for l in open(sys.argv[1], 'rb'):
    s = l.strip()
    if not s: continue
    base64.b64decode(s, validate=True)
PYEOF
if [ -f "$D" ] && cmp -s "$SRC" "$D"; then rm -f "$SRC"; echo "neschimbat ($N domenii)"; exit 0; fi
[ -f "$D" ] && cp "$D" "$D.bak" || true
install -m 644 -o root -g root "$SRC" "$D"; rm -f "$SRC"
echo "aplicat $N domenii (base64) pe disc; se încarcă la următorul restart Suricata"
WEOF
bash -n $W.new || { echo "[$H] EROARE sintaxă wrapper"; rm -f $W.new; exit 2; }
install -m 755 -o root -g root $W.new $W; rm -f $W.new
if [ ! -f $SUD ]; then
  echo "socadmin ALL=(root) NOPASSWD: $W" > $SUD.new; chmod 440 $SUD.new
  visudo -cf $SUD.new >/dev/null && mv $SUD.new $SUD || { rm -f $SUD.new; echo "[$H] EROARE sudoers"; exit 2; }
fi
AK=/home/socadmin/.ssh/authorized_keys
install -d -m 700 -o socadmin -g socadmin /home/socadmin/.ssh
grep -qF "$PORTAL_KEY" $AK 2>/dev/null || { echo "$PORTAL_KEY" >> $AK; chown socadmin:socadmin $AK; chmod 600 $AK; ADDED=1; }
echo "[$H] wrapper fără reload ($(grep -v "^#" $W | grep -c reload-rules) apeluri reload active) | sudoers $(test -f $SUD && echo OK) | cheie portal $([ "${ADDED:-0}" = 1 ] && echo ADĂUGATĂ || echo existentă) | suricata neatinsă: $(systemctl show suricata -p ActiveEnterTimestamp --value)"
