#!/bin/bash
# Lansator — rulat de operator cu `!`: MLEO etapa 1 (observare) pe portal 10.0.0.22.
S=/tmp/claude-1000/-mnt-c-Users-acer/932c8328-6b9f-4757-b531-4f7194a9bc7c/scratchpad/hunt
ssh -o ConnectTimeout=15 socadmin@10.0.0.22 'rm -rf /tmp/mleo_deploy; mkdir -p /tmp/mleo_deploy' && \
scp -q $S/mleo.py $S/api_hunt.py $S/patch_contain.py $S/mleo-critical.conf socadmin@10.0.0.22:/tmp/mleo_deploy/ && \
ssh -o ConnectTimeout=15 socadmin@10.0.0.22 'sudo bash -s' < $S/install_mleo_contain.sh
