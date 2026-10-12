#!/bin/bash
# Lansator — rulat de operator cu `!`: instalează CYBER3 Threat Hunt pe portal (10.0.0.22).
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad/hunt
ssh -o ConnectTimeout=15 socadmin@10.0.0.22 'rm -rf /tmp/hunt_deploy; mkdir -p /tmp/hunt_deploy' && \
scp -q $S/threat_hunt.py $S/api_hunt.py $S/patch_portal.py $S/cyber3-threat-hunt.service $S/cyber3-threat-hunt.timer socadmin@10.0.0.22:/tmp/hunt_deploy/ && \
ssh -o ConnectTimeout=15 socadmin@10.0.0.22 'sudo bash -s' < $S/install_hunt_portal.sh
