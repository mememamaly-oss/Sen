#!/usr/bin/env python3
import json, time, sys
dec = json.JSONDecoder()
t0 = time.time()
out = []
for i in [1, 2, 3]:
    s = open(f'/home/z/my-project/readiness/evidence/A03_bench_zip_{i}.json').read()
    out.append(f'run{i} read {len(s)}B at {round(time.time()-t0,1)}s')
    obj, consumed = dec.raw_decode(s)
    out.append(f'  f1={obj["f1"]} conf={obj["confusion"]} stats={obj["stats"]}')
    tail = s[consumed:]
    out.append(f'  tail lines={len(tail.splitlines())}')
print('\n'.join(out))
print('DONE in', round(time.time() - t0, 1), 's')
