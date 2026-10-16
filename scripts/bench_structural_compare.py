#!/usr/bin/env python3
"""bench_structural_compare.py — structural comparison of two or more
SENTINEL benchmark run JSONs.

RECREATED (3rd incarnation) after the 8th/9th/10th container rollbacks:
the round-26 original lived in download/ (never committed, destroyed);
the axis-3 M5 recreation at scripts/ was used for the 867dbf5 gate but
also never committed — destroyed again. THIS copy is the one committed to
git (per the standing tools-restore clause: rebuild -> commit -> push
immediately; never left bare on disk across another flip).

Spec (unchanged across incarnations; outputs must reproduce the committed
axis-3 bench log lines verbatim):
  STRUCTURE (must be equal):
    - path_tuples: the ordered (type, path, param, risk) tuple list, one per
      finding, in findings order (path = URL path component of the finding url)
    - norm_url_tuples: the ordered port-normalized finding urls
      (scheme://host:port/... -> scheme://host/...)
    - struct_meta: run_id + confusion + ground_truth_sha256 + findings count
  INFORMATIONAL (scan-cost, never structure): requests, duration.

Usage:
  bench_structural_compare.py REFERENCE_JSON COMPARE_JSON [COMPARE_JSON ...]
Prints one summary line per file, one verdict line per comparison, and a
final verdict. Exit 0 iff every comparison is IDENTICAL.
"""
import json
import sys
from urllib.parse import urlsplit


def norm_port(url):
    """Port-normalize a URL: strip an explicit :port (any port) from the
    authority so per-run ephemeral fixture ports compare equal."""
    try:
        p = urlsplit(url)
    except Exception:
        return url
    if p.scheme and p.netloc:
        host = p.hostname or ""
        return "%s://%s%s" % (p.scheme, host, p.path + (("?" + p.query) if p.query else "") + (("#" + p.fragment) if p.fragment else ""))
    return url


def load(path):
    with open(path, "r") as fh:
        return json.load(fh)


def path_tuples(doc):
    out = []
    for f in doc.get("findings", []):
        u = urlsplit(f.get("url", ""))
        out.append((f.get("type"), u.path, f.get("parameter"), f.get("risk")))
    return out


def norm_url_tuples(doc):
    return [norm_port(f.get("url", "")) for f in doc.get("findings", [])]


def summary_line(path, doc):
    c = doc.get("confusion", {})
    conf = "(%s, %s, %s, %s)" % (c.get("TP"), c.get("FP"), c.get("FN"), c.get("TN"))
    st = doc.get("stats", {})
    return "%s: run_id=%s confusion=%s P=%s R=%s F1=%s requests=%s findings=%s gt=%s" % (
        path, doc.get("run_id"), conf, doc.get("precision"), doc.get("recall"),
        doc.get("f1"), st.get("requests"), len(doc.get("findings", [])),
        doc.get("ground_truth_sha256"))


def eq_list(a, b):
    return a == b


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    ref_path = argv[1]
    ref = load(ref_path)
    print(summary_line(ref_path, ref))
    ref_pt = path_tuples(ref)
    ref_nu = norm_url_tuples(ref)
    ref_meta = (ref.get("run_id"), ref.get("confusion"),
                ref.get("ground_truth_sha256"), len(ref.get("findings", [])))
    all_eq = True
    for cp in argv[2:]:
        doc = load(cp)
        print(summary_line(cp, doc))
        pt_eq = eq_list(ref_pt, path_tuples(doc))
        nu_eq = eq_list(ref_nu, norm_url_tuples(doc))
        meta_eq = ref_meta == (doc.get("run_id"), doc.get("confusion"),
                               doc.get("ground_truth_sha256"),
                               len(doc.get("findings", [])))
        ident = pt_eq and nu_eq and meta_eq
        all_eq = all_eq and ident
        print("vs %s: path_tuples=%s norm_url_tuples=%s struct_meta=%s (info: requests %s vs %s) -> %s" % (
            cp, "EQ" if pt_eq else "NE", "EQ" if nu_eq else "NE",
            "EQ" if meta_eq else "NE", ref.get("stats", {}).get("requests"),
            doc.get("stats", {}).get("requests"), "IDENTICAL" if ident else "DIFF"))
    print("VERDICT: %s" % ("ALL IDENTICAL" if all_eq else "DIFFERENCES FOUND"))
    return 0 if all_eq else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
