#!/usr/bin/env python3
"""U10/U11: memory + CPU measurement of a full fixture scan (in-process resource tracking)."""
import subprocess, sys, time, json, os, resource

Z = '/home/z/my-project/readiness/ziprun2'
EV = '/home/z/my-project/readiness/evidence'

t0 = time.time()
p = subprocess.Popen(
    [sys.executable, f'{Z}/sentinel/cli.py', 'scan', 'http://127.0.0.1:8778',
     '--allow-private', '--no-browser', '--no-oast', '--max-pages', '12',
     '--db', f'{EV}/q_mem.db', '--out', f'{EV}/q_mem.json'],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
peak_rss = 0
cpu_samples = []
while p.poll() is None:
    try:
        with open(f'/proc/{p.pid}/status') as f:
            for line in f:
                if line.startswith('VmRSS:'):
                    peak_rss = max(peak_rss, int(line.split()[1]))  # kB
                    break
        with open(f'/proc/{p.pid}/stat') as f:
            parts = f.read().split()
            utime, stime = int(parts[13]), int(parts[14])
            cpu_samples.append(utime + stime)  # ticks (100/s)
    except (FileNotFoundError, ProcessLookupError, IndexError):
        break
    time.sleep(0.3)
elapsed = time.time() - t0
cpu_ticks = cpu_samples[-1] if cpu_samples else 0
cpu_s = cpu_ticks / 100.0

d = json.load(open(f'{EV}/q_mem.json')) if os.path.exists(f'{EV}/q_mem.json') else {}
res = {
    'exit': p.returncode,
    'elapsed_s': round(elapsed, 1),
    'peak_rss_mb': round(peak_rss / 1024, 1),
    'cpu_user_plus_sys_s': round(cpu_s, 1),
    'scan': {k: d.get('stats', {}).get(k) for k in ('requests', 'duration', 'endpoints', 'verified')},
}
json.dump(res, open(f'{EV}/U_memory.json', 'w'), indent=1)
print(json.dumps(res, indent=1))
