#!/bin/bash
# SENTINEL v4.1.1 LIVE scan — DVWS (Damn Vulnerable Web Sockets)
# Authorized local training target: web on 127.0.0.1:8888, WebSocket server
# on 127.0.0.1:8080 (11 challenge channels). The target's own pages construct
# the WS URLs — discovery is OBSERVED (JS extraction), not guessed.
# --logic-active: WS elicitation hellos + reflection canaries are
# STATE_CHANGING-class probes (an unknown channel may write on any message).
set -x
cd /home/z/my-project/build-v411
timeout 560 python3 -m sentinel.cli scan http://127.0.0.1:8888/ \
  --allow-private --logic-active \
  --out /home/z/my-project/gap-validation/results/scan_dvws_LIVE.json \
  --db /home/z/my-project/gap-validation/results/dvws_live.db 2>&1 | tail -30
