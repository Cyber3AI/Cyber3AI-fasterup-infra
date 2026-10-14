Y=/etc/suricata/suricata.yaml; RP=$(grep -E '^default-rule-path:' $Y | awk '{print $2}'); RP=${RP:-/var/lib/suricata/rules}
RF=$(awk '/^rule-files:/{f=1;next} f&&/^[[:space:]]*-/{printf "%s ",$2;next} f{exit}' $Y)
L=$(grep -E "rules successfully loaded" /var/log/suricata/suricata.log 2>/dev/null | tail -1 | grep -oE '[0-9]+ rule files processed. [0-9]+ rules successfully loaded')
echo "$(hostname) | rule-files: $RF| local.rules: $(test -f $RP/cyber3-local.rules && grep -c 'sid:' $RP/cyber3-local.rules || echo LIPSĂ) | 3900001 în suricata.rules: $(grep -c 'sid:3900001;' $RP/suricata.rules 2>/dev/null) | $L"
