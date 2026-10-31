---
name: Bug report
about: Something in Sen behaves incorrectly
title: "[bug] "
labels: bug
assignees: ''
---

**Describe the bug**
A clear and concise description of what the bug is.

**Component**
- [ ] Engine (`sentinel/`, Python CLI)
- [ ] Platform (`src/`, Next.js app)
- [ ] CI / GitHub Action
- [ ] Reports / compliance mappings
- [ ] Other

**To reproduce**
Steps, command line, or workflow snippet. For engine issues include the
exact command, e.g.:

```bash
python3 -m sentinel.cli scan http://127.0.0.1:PORT --out result.json
```

**Expected behavior**
What you expected to happen.

**Actual behavior**
What happened instead — include console output, exit code, or the
relevant part of `result.json`.

**Environment**
- Sen version / commit:
- Python version:
- OS:
- (platform only) bun/node version, browser:

**Additional context**
Screenshots, store DB excerpts, or anything else useful.

Note: vulnerabilities in Sen itself go through `SECURITY.md`, not this
template.
