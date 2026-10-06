#!/bin/bash
cd /home/z/my-project/build-v425
python3 sentinel/cli.py scan http://127.0.0.1:4290   --allow-private --oast local   --auth-user admin --auth-pass adminpass   --auth-url "http://127.0.0.1:4290/index.php?page=login.php"   --auth-user-field username --auth-pass-field password   --seed owsp-recon4 --max-pages 120   --out /home/z/my-project/build-v425/results/owsp/mutillidae/recon4.json --db /home/z/my-project/build-v425/results/owsp/mutillidae/recon4.db > /home/z/my-project/build-v425/results/owsp/mutillidae/recon4.log 2>&1
RC=$?
echo "rc=$RC $(date +%H:%M:%S)" > /home/z/my-project/build-v425/results/owsp/mutillidae/recon4.DONE
