#!/bin/bash
# READ-ONLY. Persistența schimbărilor 15–16.10: drop.conf reputație (supraviețuiește suricata-update nocturn), reguli DROP în fișier,
# HOME_NET în yaml, allowlist, CYBER3_BLOCK live == rules.v4 (blocări/deblocări salvate pentru boot).
export LC_ALL=C
H=$(hostname); EXP="${1:-}"; [ -z "$EXP" ] || [ "$H" = "$EXP" ] || { echo "[$H] ABORT hostname (aștept $EXP)"; exit 3; }
R=/var/lib/suricata/rules/suricata.rules; REP='(Spamhaus (DROP|EDROP) Listed|Dshield Block Listed|CINS Active Threat Intelligence Poor Reputation)'
DC=$(grep -cE '^re:.*(Spamhaus|Dshield|CINS)' /etc/suricata/drop.conf 2>/dev/null)
RD=$(grep -cE "^drop .*$REP" $R 2>/dev/null); RA=$(grep -cE "^alert .*$REP" $R 2>/dev/null)
UPD=$(systemctl cat cyber3-suricata-update.service 2>/dev/null | grep -E '^ExecStart' | head -1 | cut -c1-80)
UCONF=$(grep -E '^drop-conf' /etc/suricata/update.yaml 2>/dev/null | head -1)
HN=$(grep -E '^[[:space:]]*HOME_NET:' /etc/suricata/suricata.yaml 2>/dev/null | head -1 | sed 's/^ *HOME_NET: *//')
LIVE=$(iptables -S CYBER3_BLOCK 2>/dev/null | grep -c -- '-j DROP'); SAVED=$(grep -c -- '-A CYBER3_BLOCK .*-j DROP' /etc/iptables/rules.v4 2>/dev/null)
DIFF=$(diff <(iptables -S CYBER3_BLOCK 2>/dev/null | grep -- '-j DROP' | sort) <(grep -- '-A CYBER3_BLOCK .*-j DROP' /etc/iptables/rules.v4 2>/dev/null | sort) | grep -c '^[<>]')
PB=$(systemctl is-enabled cyber3-permaban.timer 2>/dev/null)
echo "[$H] drop.conf_rep=$DC | fișier: rep_DROP=$RD rep_alert=$RA | update.yaml drop-conf: ${UCONF:-implicit} | HOME_NET=$HN | CYBER3_BLOCK live=$LIVE salvat=$SAVED dif=$DIFF | permaban.timer=$PB"
