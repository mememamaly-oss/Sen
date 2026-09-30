#!/usr/bin/env python3
"""Modified fixture v2: new page LINKED from the homepage + new form field on an existing surface."""
src = open('/home/z/my-project/readiness/evidence/fixture_modified.py').read()

# 1) link the extra page from the homepage
old_home = '''        if path == "/" :
            return self._send(200, HEADER_TMPL.format(body="<h1>Sentinel Benchmark Fixture</h1>"))'''
new_home = '''        if path == "/" :
            return self._send(200, HEADER_TMPL.format(body="<h1>Sentinel Benchmark Fixture</h1>"
                "<p><a href='/extra/report'>Extra Report</a></p>"))'''
assert old_home in src
src = src.replace(old_home, new_home, 1)
open('/home/z/my-project/readiness/evidence/fixture_modified.py', 'w').write(src)
print("homepage now links /extra/report")
