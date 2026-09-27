#!/usr/bin/env python3
"""Parse Google Fonts CSS for Cairo, download arabic+latin subsets per weight, emit local @font-face CSS."""
import re, os, urllib.request

os.chdir("/home/z/my-project/sentinel/results/fonts")
css = open("cairo.css").read()

blocks = re.findall(r"/\* (\w[\w-]*) \*/\s*@font-face\s*\{(.*?)\}", css, re.S)
out_css, seen = [], set()
for subset, body in blocks:
    if subset not in ("arabic", "latin"):
        continue
    w = re.search(r"font-weight:\s*(\d+)", body).group(1)
    url = re.search(r"url\((https://[^)]+)\)", body).group(1)
    fname = f"cairo-{w}-{subset}.woff2"
    if fname not in seen:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        open(fname, "wb").write(urllib.request.urlopen(req, timeout=30).read())
        seen.add(fname)
        print(f"downloaded {fname} ({os.path.getsize(fname)}B)")
    ur = re.search(r"unicode-range:\s*([^;]+);", body).group(1)
    out_css.append(f"@font-face {{ font-family:'Cairo'; font-style:normal; font-weight:{w}; "
                   f"src:url('fonts/{fname}') format('woff2'); unicode-range:{ur}; }}")

open("cairo-local.css", "w").write("\n".join(out_css))
print("\n--- cairo-local.css written with", len(out_css), "faces ---")
