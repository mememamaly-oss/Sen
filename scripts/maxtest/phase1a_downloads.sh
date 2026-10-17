#!/bin/bash
# Maximum internal test — Phase 1a: persistent downloads of training targets
# (setsid-detached so the sandbox does not reap us between tool calls)
cd /home/z/my-project/live-targets
S=/home/z/my-project/live-targets/dl_status.txt
: > $S
echo "start $(date -u +%H:%M:%S)" >> $S
curl -sL --retry 3 -o js-20.2.0.tgz "https://github.com/juice-shop/juice-shop/releases/download/v20.2.0/juice-shop-20.2.0_node22_linux_x64.tgz" \
  && echo "JS OK $(stat -c%s js-20.2.0.tgz)" >> $S || echo "JS FAIL" >> $S
curl -sL --retry 3 -o webgoat-server-8.2.2.jar "https://github.com/WebGoat/WebGoat/releases/download/v8.2.2/webgoat-server-8.2.2.jar" \
  && echo "WG OK $(stat -c%s webgoat-server-8.2.2.jar)" >> $S || echo "WG FAIL" >> $S
curl -sL --retry 3 -o webwolf-8.2.2.jar "https://github.com/WebGoat/WebGoat/releases/download/v8.2.2/webwolf-8.2.2.jar" \
  && echo "WW OK $(stat -c%s webwolf-8.2.2.jar)" >> $S || echo "WW FAIL" >> $S
echo "done $(date -u +%H:%M:%S)" >> $S
