EXP="$1"; [ "$(hostname)" = "$EXP" ] || { echo ABORT; exit 3; }
BR=$(ls -d /sys/class/net/*/bridge | head -1 | cut -d/ -f5)
echo "[$EXP] porturi punte: $(ls /sys/class/net/$BR/brif | tr '\n' ' ')"
for p in $(ls /sys/class/net/$BR/brif); do
  echo "== $p: top adrese SURSĂ (sens intrare pe port), 20 s"
  timeout 20 tcpdump -i $p -Q in -nn -q -c 15000 ip 2>/dev/null | awk '{s=$3; sub(/\.[0-9]+$/,"",s); print s}' | sort | uniq -c | sort -rn | head -5 | sed 's/^/   /'
done
echo "allowlist (fără Google/DNS): $(grep -vE '^\s*#|^\s*$' /etc/cyber3/ar-allowlist.txt | grep -vE '^(8\.8|1\.|9\.9|149\.112|208\.67|142\.25|172\.217|216\.|74\.125|64\.233|209\.85|172\.253|108\.177|193\.231|81\.12|96\.45|94\.140|213\.154)' | tr '\n' ' ')"
