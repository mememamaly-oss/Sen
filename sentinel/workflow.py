"""SENTINEL v3.0.0 — Workflow / Business-Logic Intelligence Engine (Phase 58).

Everything SENTINEL tested before v3.0.0 lives at the REQUEST level: one
endpoint, one parameter, one response. This engine moves the frame of
reference to the PROCESS level — the ordered, stateful sequences an
application uses to do real work:

    login -> select account -> enter amount -> create transfer -> confirm

It learns those sequences from what the scan already discovered, then asks
the EIGHT questions a human business-logic pentester asks (and a per-parameter
scanner structurally cannot). The first five are the v3.0.0 battery; the
three cross-identity questions are the v4.0.0 Digital Twin battery:

  1. STEP BYPASS            can a later step run without its mandatory
                            predecessor?            (create without select)
  2. OUT-OF-ORDER           can the FINAL step run without the step that
                            produces its input?     (confirm a transfer that
                                                     was never created)
  3. VALUE TAMPER           can an already-approved value be changed at
                            execution time?         (amount swapped between
                                                     create and confirm)
  4. DUPLICATE EXECUTION    does replaying the final step execute the
                            operation again?        (no idempotency)
  5. PRIVILEGE BOUND        can a lower-privilege session execute a step
                            the UI itself declares privileged?
                            ("admin only" wire mode)
  6. CROSS-USER             can identity B execute a workflow object that
                            identity A minted?      (no object ownership
                                                     check server-side)
  7. CROSS-OBJECT           can the final step execute an object of a
                            DIFFERENT type/context  (type confusion across
                                                     the object model)
  8. CROSS-STATE            can the final step execute an object the flow
                            itself moved to a cancelled/rejected state?
                            (rollback/cancel paths not enforced)

Cross-identity questions 6-8 run ONLY when their precondition is observable
(the other identity's state oracle actually shows the foreign resource, a
cancel path exists in the flow's own forms, a foreign-shaped object id is
visible in the oracle). Absent preconditions are loud honest skips, never
guesses — and never counted as attacks that ran.

LEARN (safe, --workflow): a guided walk submits each form of a flow cluster
once with small canary values, following the chain the application itself
lays out (each landing page carries the next form), and observes which GET
page echoes the produced resource identifiers — the STATE ORACLE. The
word-level diff of a resource's oracle line before and after the final step
(e.g. PENDING -> EXECUTED) is the EXECUTION MARKER vocabulary.

ATTACK (opt-in, --logic-active): every manipulation runs on a FRESH isolated
session with canary values, and is reported ONLY when the state oracle PROVES
the outcome — a new canary-bearing object, a second execution of the same
resource, or an executed line carrying the tampered canary. A server that
merely fails to reject is NOT a finding; the disallowed thing must actually
happen. Unprovable manipulations (no oracle, no marker, no second role) are
skipped loudly in the stats, never guessed.

Safety contract: bounded budgets everywhere (clusters, steps, options,
attacks), login/logout-shaped surfaces never submitted, fresh sessions per
manipulation, canaries on every state-changing field, and the whole attack
battery behind an explicit flag.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser

from .core import (Endpoint, Evidence, Finding, FindingStatus, ParamLocation,
                   Severity, Verification)
from .http_engine import RequestEngine, RequestMutation

# ------------------------------------------------------------------ vocabulary
AMOUNT_WORDS = ("amount", "amt", "quantity", "qty", "price", "sum", "total", "value")
TOKEN_WORDS = ("csrf", "token", "nonce", "authenticity")
PRIV_WORDS = ("admin", "administrator", "manager", "privileged", "staff only",
              "internal only", "operator", "supervisor")
FLOW_WORDS = ("transfer", "payment", "pay", "checkout", "order", "wire",
              "subscribe", "register", "signup", "booking", "shipment")
SESSION_KILLER_RE = re.compile(r"(log-?out|log-?off|sign-?out|sign-?off)", re.I)
ASSET_RE = re.compile(r"\.(css|js|mjs|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|pdf|zip|gz|map|sql)([?#]|$)", re.I)

CANARY_CREATE = "1111"      # amounts synthesized while walking a flow
CANARY_TAMPER = "2222"      # the swapped amount in the tamper manipulation
FRESH_RES_SUFFIX = "99001"  # synthesized never-created resource identifier


@dataclass
class WorkflowConfig:
    max_clusters: int = 5        # flow clusters walked per scan (best score first;
                                  # fixture v10 grew to three wf clusters + the
                                  # two flat test directories — four starved
                                  # the original vulnerable wizard out)
    max_steps: int = 6           # steps per guided walk
    max_pages: int = 5           # cluster GET pages fetched (anchor + oracle)
    max_options: int = 2         # privilege-declared options baselined per flow
    max_flow_attacks: int = 12   # attack manipulations PER FLOW (the v4.1.0
                                  # battery: 8 core invariants + 4 branch/state
                                  # manipulations; precondition-absent attacks
                                  # do NOT consume this budget)


# ------------------------------------------------------------------ form parsing
class _FlowFormParser(HTMLParser):
    """Form parser that understands <select>/<option> (the crawler's parser
    records plain inputs only — option LABELS are where the UI declares
    privilege boundaries, so this engine parses pages itself)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._f: dict | None = None
        self._sel: dict | None = None
        self._opt: list | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._f = {"action": a.get("action", ""),
                       "method": (a.get("method") or "GET").upper(), "fields": []}
        elif tag == "select" and self._f is not None and a.get("name"):
            self._sel = {"name": a["name"], "options": []}
            self._f["fields"].append(self._sel)
        elif tag == "option" and self._sel is not None:
            self._opt = [a.get("value", ""), a.get("label") or ""]
            self._sel["options"].append(self._opt)
        elif tag == "input" and self._f is not None:
            if a.get("type") not in ("submit", "button", "reset") and a.get("name"):
                self._f["fields"].append({"name": a["name"], "value": a.get("value", ""),
                                          "type": a.get("type", "text")})
        elif tag == "textarea" and self._f is not None and a.get("name"):
            self._f["fields"].append({"name": a["name"], "value": "", "type": "textarea"})

    def handle_data(self, data):
        # option labels are element TEXT, not attributes — the privilege
        # declaration ("admin only") lives there
        if self._opt is not None and not self._opt[1] and data.strip():
            self._opt[1] = data.strip()

    def handle_endtag(self, tag):
        if tag == "option":
            self._opt = None
        elif tag == "select":
            self._sel = None
        elif tag == "form" and self._f is not None:
            if self._f["fields"]:
                self.forms.append(self._f)
            self._f = None


def parse_forms(html: str) -> list[dict]:
    p = _FlowFormParser()
    try:
        p.feed(html or "")
    except Exception:
        return []
    return p.forms


def _is_token(name: str) -> bool:
    return any(w in (name or "").lower() for w in TOKEN_WORDS)


def _is_amount(name: str) -> bool:
    return any(w in (name or "").lower() for w in AMOUNT_WORDS)


def _privilege_options(forms: list[dict]) -> list[tuple[str, str, str]]:
    """(field_name, option_value, label) for options whose LABEL declares a
    privileged boundary — the UI itself saying 'only admins get this'."""
    out = []
    for form in forms:
        for f in form["fields"]:
            if isinstance(f, dict) and f.get("options"):
                for val, label in f["options"]:
                    if any(w in (label or "").lower() for w in PRIV_WORDS):
                        triple = (f["name"], val, label)
                        if triple not in out:
                            out.append(triple)
    return out


# ------------------------------------------------------------------ helpers
def _strip_tags(line: str) -> str:
    return re.sub(r"<[^>]+>", " ", line or "")


def _lines_with(body: str, value: str) -> list[str]:
    """Tag-stripped record units containing the exact value. Units split on
    newlines AND on list-item/table-row boundaries (two executions of one
    resource appear as two units, whether or not the HTML has newlines)."""
    if not value:
        return []
    units = re.split(r"(?=</?(?:li|tr)\b)|\n", body or "")
    return [_strip_tags(u) for u in units if value in u]


def _word_delta(a: str, b: str) -> tuple[list, list]:
    wa, wb = (a or "").split(), (b or "").split()
    return ([w for w in wb if w not in wa], [w for w in wa if w not in wb])


def _synth_fresh_resource(value: str) -> str:
    """A resource value with the observed SHAPE but never produced by the app:
    'TRF-0007' -> 'TRF-99001' (prefix preserved, id unreachable)."""
    m = re.match(r"^(.*?)(\d+)$", value or "")
    if m and m.group(1):
        return m.group(1) + FRESH_RES_SUFFIX
    return (value or "res") + "-" + FRESH_RES_SUFFIX


# ------------------------------------------------------------------ data model
@dataclass
class WalkStep:
    action: str                     # absolute action URL
    fields: list = field(default_factory=list)   # [(name, value)] as submitted
    status: int = 0
    landing: str = ""               # response body


@dataclass
class FlowKnowledge:
    """Everything the guided walks learned about one flow."""
    cluster: str = ""                               # cluster directory path
    entry: str = ""                                 # anchor GET page URL
    steps: list = field(default_factory=list)       # legitimate chain (WalkStep)
    members: dict = field(default_factory=dict)     # path -> Endpoint (cluster)
    oracle_url: str = ""                            # state-oracle GET URL
    resource_params: dict = field(default_factory=dict)  # name -> example value
    producer_idx: int = -1                          # step that MINTS the resource
    exec_added: list = field(default_factory=list)  # words gained on execution
    exec_removed: list = field(default_factory=list)
    priv_options: list = field(default_factory=list)     # (field, value, label)
    priv_baselines: dict = field(default_factory=dict)   # option value -> functional?
    cancel_paths: list = field(default_factory=list)     # cancel-shaped form actions seen in landings
    drop_reason: str = ""                           # honest-negative reason
    # ---------------- v4.1.0 Workflow Graph 2.0 (branching & state intelligence)
    branches: list = field(default_factory=list)         # [{field,value,label,form_action,restricted,privileged,default}]
    branch_transfer: dict = field(default_factory=dict)  # {field, select_step, hidden_step} — later step TRUSTS the branch choice
    restricted_options: list = field(default_factory=list)  # (field, value, label) restriction-vocab options (not privilege-vocab)
    approval_idx: int = -1                               # step index that APPROVES the resource
    rollback_paths: list = field(default_factory=list)    # rollback-vocab actions (distinct from cancel)
    step_states: list = field(default_factory=list)       # per-step [{before,after}] oracle state pairs
    exercised_options: list = field(default_factory=list)  # [[name, value]] select options a walk actually SUBMITTED
    graph: dict = field(default_factory=dict)             # the exported WorkflowGraph (nodes+edges+provenance)


def _options_of(form: dict) -> list[tuple[str, str, str]]:
    """(field, value, label) for every SELECT option of one form."""
    out = []
    for f in form.get("fields", []):
        if isinstance(f, dict) and f.get("options") is not None:
            for val, label in f["options"]:
                out.append((f["name"], val, label))
    return out


def _is_privileged_label(label: str) -> bool:
    return bool(re.search(r"(admin|administrator|manager|root|superuser|privilege[sd]?|authoriz)",
                          label or "", re.I))


def build_graph(k: FlowKnowledge) -> dict:
    """Project one learned flow into a REAL graph: step nodes with state
    pairs / dependencies / provenance, and typed edges (next, branch,
    approval, cancel_of, rollback_of). Walked steps are observed (confidence
    1.0); discovered-but-unexercised paths are inferred edges with explicit
    provenance — never presented as facts the walk proved."""
    from .planner import classify_operation
    nodes, edges = [], []
    for i, s in enumerate(k.steps):
        fields = s.fields or []
        tokens = [n for n, _ in fields if _is_token(n)]
        res_refs = [v for n, v in fields if n in k.resource_params and v]
        st = (k.step_states[i] if i < len(k.step_states)
              else {"before": "", "after": ""})
        nodes.append({
            "id": f"S{i}", "kind": "approval" if i == k.approval_idx else "step",
            "action": urllib.parse.urlsplit(s.action).path, "index": i,
            "identity": "primary-session",
            "preconditions": ([f"token:{t}" for t in tokens] +
                              (["predecessor-step-executed"] if i > 0 else [])),
            "parameters": [n for n, _ in fields],
            "extracted_tokens": tokens,
            "referenced_objects": res_refs,
            "state_before": st.get("before", "")[:160],
            "state_after": st.get("after", "")[:160],
            "impact_class": classify_operation(s.action, "POST", fields)["impact"],
            "dependencies": ([{"kind": "token", "on": t} for t in tokens] +
                             [{"kind": "object", "on": r} for r in res_refs] +
                             ([{"kind": "session", "on": f"S{i-1}"}] if i > 0 else [])),
            "provenance": "guided-walk submission (observed)",
            "confidence": 1.0 if s.status else 0.7})
        if i > 0:
            edges.append({"src": f"S{i-1}", "dst": f"S{i}", "kind": "next",
                          "condition": "", "belief": "observed",
                          "provenance": "walk followed this transition"})
    # conditional branch edges: every non-default select option of a walked
    # form is an alternative path through the flow. belief is honest:
    #   observed  a walk/baseline actually SUBMITTED this option
    #   declared the form declares the option; no walk chose it
    exercised = {(n, v) for n, v in (k.exercised_options or [])}
    exercised |= {(br["field"], br["value"]) for br in k.branches
                  if k.priv_baselines.get(br["value"])}
    for br in k.branches:
        edges.append({"src": f"S{br.get('select_step', 0)}", "dst": f"S{br.get('hidden_step', br.get('select_step', 0))}",
                      "kind": "branch", "condition": f"{br['field']}={br['value']}",
                      "belief": "observed" if (br["field"], br["value"]) in exercised else "declared",
                      "provenance": f"select option '{br.get('label', br['value'])}' "
                                    f"({'restricted' if br.get('restricted') else 'privileged' if br.get('privileged') else 'open'} branch)",
                      "restricted": bool(br.get("restricted")),
                      "privileged": bool(br.get("privileged"))})
    # approval edge: the approving step gates the executing step
    if k.approval_idx >= 0 and k.approval_idx + 1 < len(k.steps):
        edges.append({"src": f"S{k.approval_idx}", "dst": f"S{k.approval_idx + 1}",
                      "kind": "approval", "condition": "approved",
                      "belief": "observed",
                      "provenance": "approve-vocabulary step between producer and executor"})
    # cancel / rollback edges: discovered but NOT exercised by the walk —
    # inferred, never presented as observed transitions
    final_id = f"S{len(k.steps) - 1}" if k.steps else ""
    for c in k.cancel_paths[:4]:
        edges.append({"src": final_id, "dst": urllib.parse.urlsplit(c).path,
                      "kind": "cancel_of", "condition": "", "belief": "inferred",
                      "provenance": "cancel-vocabulary form action in a walk landing (not exercised)"})
    for rb in k.rollback_paths[:4]:
        edges.append({"src": final_id, "dst": urllib.parse.urlsplit(rb).path,
                      "kind": "rollback_of", "condition": "", "belief": "inferred",
                      "provenance": "rollback-vocabulary form action in a walk landing (not exercised)"})
    return {"nodes": nodes, "edges": edges,
            "counts": {"nodes": len(nodes), "edges": len(edges),
                       "branches": len(k.branches),
                       "approval_steps": 1 if k.approval_idx >= 0 else 0,
                       "cancel_paths": len(k.cancel_paths),
                       "rollback_paths": len(k.rollback_paths)}}


def _forms_of(k: FlowKnowledge, s) -> list[dict]:
    """In-cluster forms of one walk step (parsed lazily, cached on the step)."""
    cache = getattr(s, "_forms_cache", None)
    if cache is None:
        try:
            cache = _in_cluster_forms_static(s.landing, s.action, k.cluster)
        except Exception:
            cache = []
        try:
            s._forms_cache = cache
        except Exception:
            pass
    return cache


def _in_cluster_forms_static(html: str, page_url: str, cluster: str) -> list[dict]:
    out = []
    for f in parse_forms(html or ""):
        if f["method"] != "POST":
            continue
        action = urllib.parse.urljoin(page_url, f["action"] or page_url)
        path = (urllib.parse.urlsplit(action).path or "")
        if (path == cluster or path.startswith(cluster.rstrip("/") + "/")) \
                and not SESSION_KILLER_RE.search(action):
            out.append(dict(f, action=action))
    return out


CANCEL_RE = re.compile(r"/(cancel|rollback|revert|reject|void|abort)(/|$|\.)", re.I)
# v4.1.0 vocabulary split: CANCEL (terminate in flight) vs ROLLBACK (return to
# an earlier state, reopening values) vs APPROVE (privilege gate between
# creation and execution). The three carry different abuse classes.
ROLLBACK_RE = re.compile(r"/(rollback|revert|undo)(/|$|\.)", re.I)
APPROVE_RE = re.compile(r"/(approve|authoriz|signoff|sign-off|sign_off|sanction)(/|$|\.)", re.I)
# restriction vocabulary that is NOT privilege vocabulary: labels declaring a
# membership/verification boundary ("premium members only") rather than a role
# hierarchy ("admin only" — already covered by the privilege attack).
RESTRICTED_RE = re.compile(r"(premium|verified|vip|gold|platinum|member[rs]? only|staff|internal|trusted|elite|kyc)", re.I)
FOREIGN_ID_RE = re.compile(r"\b([A-Z]{2,6}-\d{2,6})\b")


def _resource_prefix(value: str) -> str:
    m = re.match(r"^([A-Za-z]+)-\d+$", value or "")
    return (m.group(1) if m else "").upper()


# ------------------------------------------------------------------ the engine
class WorkflowEngine:
    """Learn multi-step flows, then test the five business-logic invariants."""

    def __init__(self, cfg: WorkflowConfig | None = None, planner=None):
        self.cfg = cfg or WorkflowConfig()
        self.planner = planner      # v4.1.0: real-time Safe Attack Planner
        self.requests = 0            # requests on PRIVATE engines (added to stats)
        self.log: list[dict] = []    # auditable trail of every manipulation

    def _gate(self, k, name: str) -> bool:
        """v4.1.0 Phase V41-10: every attack passes the Safe Attack Planner
        BEFORE any request — a blocked attack is a loud skip with its policy,
        never a silent omission."""
        if self.planner is None:
            return True
        verdict = self.planner.gate(
            "".join(["/", k.cluster.strip("/"), "/", name]), "POST",
            note="wf-atk")
        if not verdict.get("allowed", False):
            self.log.append({"verdict": "skipped", "note": "planner blocked: "
                             + verdict.get("policy", ""), "precondition": True,
                             "attack": name, "flow": k.cluster,
                             "planner_blocked": True})
            return False
        return True

    # -------------------------------------------------- transport helpers
    def _send(self, engine, m):
        before = engine.requests_sent
        r = engine.send(m)
        if engine is not getattr(self, "_main_engine", None):
            self.requests += engine.requests_sent - before
        return r

    def _get(self, engine, url, note="wf-get"):
        return self._send(engine, RequestMutation(
            endpoint=Endpoint(url=url, method="GET"), note=note))

    def _post(self, engine, url, fields, note="wf-post"):
        from .core import Parameter
        params = [Parameter(n, ParamLocation.BODY, v).classify() for n, v in fields]
        return self._send(engine, RequestMutation(
            endpoint=Endpoint(url=url, method="POST", parameters=params), note=note))

    # -------------------------------------------------- form synthesis
    @staticmethod
    def _synth_fields(form: dict, canary: str = CANARY_CREATE,
                      overrides: dict | None = None) -> list:
        """Deterministic values for one form: tokens and hidden fields carried
        verbatim (they ARE the chain), amount-ish fields get the canary,
        selects take their first option unless overridden."""
        out, overrides = [], dict(overrides or {})
        for f in form["fields"]:
            name = f["name"]
            if name in overrides:
                out.append((name, overrides.pop(name)))
            elif isinstance(f, dict) and f.get("options") is not None:
                out.append((name, f["options"][0][0] if f["options"] else ""))
            elif _is_token(name) or f.get("type") == "hidden":
                out.append((name, f.get("value", "")))
            elif _is_amount(name):
                out.append((name, canary))
            else:
                out.append((name, f.get("value") or "1"))
        # REPRO FIX (2026-10-31): leftover overrides are APPENDED as extra
        # form fields instead of dropped — how a walk stamps its
        # deterministic mint marker (wfWalkMarker) for content-addressed
        # object ids in the fixture. Existing callers override declared
        # fields only, so their output is unchanged.
        for name, v in overrides.items():
            out.append((name, v))
        return out

    def _token_refresh(self, fields: list, fresh_token_fields: list) -> list:
        """Swap token-kind values for the FRESH session's tokens."""
        fresh = {n: v for n, v in fresh_token_fields if _is_token(n)}
        return [(n, fresh.get(n, v)) if _is_token(n) else (n, v) for n, v in fields]

    # -------------------------------------------------- clustering
    @staticmethod
    def _path_of(url: str) -> str:
        return urllib.parse.urlsplit(url).path or ""

    def _cluster_members(self, endpoints: list, login_urls: set) -> dict[str, dict]:
        """Group endpoints by directory path. Root, assets, login/logout
        surfaces and the configured auth flow are never flow members."""
        clusters: dict[str, dict] = {}
        for ep in sorted(endpoints, key=lambda e: e.url):
            path = self._path_of(ep.url)
            if not path or path == "/" or ASSET_RE.search(path):
                continue
            if SESSION_KILLER_RE.search(path):
                continue
            if any(u and (self._path_of(u) == path
                          or u.split("?")[0].rstrip("/") == ep.url.split("?")[0].rstrip("/"))
                   for u in login_urls):
                continue
            directory = path.rsplit("/", 1)[0] or "/"
            if directory == "/":
                continue          # flat single-segment surfaces are not flows
            clusters.setdefault(directory, {}).setdefault(path, ep)
        return clusters

    @staticmethod
    def _eligible(members: dict) -> bool:
        """Fast pre-filter only: a cluster needs at least one crawl-known POST
        (an anchor form's action) and one GET page. The REAL filter is the
        guided walk itself — chain steps two and three levels deep (create,
        confirm) live behind POST landings a GET crawler can never see, so
        requiring them pre-discovered would make the engine structurally
        blind to exactly the flows it exists to learn."""
        posts = [ep for ep in members.values() if (ep.method or "GET").upper() != "GET"]
        gets = [ep for ep in members.values() if (ep.method or "GET").upper() == "GET"]
        return len(posts) >= 1 and len(gets) >= 1 and len(members) >= 2

    @staticmethod
    def _score(directory: str, members: dict) -> tuple:
        """Flow-worded directories strongly preferred (a 30-endpoint flat test
        directory must not crowd out a 5-endpoint transfer wizard), then size."""
        flowish = 1 if any(w in directory.lower() for w in FLOW_WORDS) else 0
        return (flowish * 10 + len(members), len(members))

    # -------------------------------------------------- guided walk
    def _origin(self, members: dict) -> str:
        u = urllib.parse.urlsplit(next(iter(members.values())).url)
        return f"{u.scheme}://{u.netloc}"

    def _in_cluster_forms(self, html: str, page_url: str, cluster: str) -> list[dict]:
        """POST forms whose action lives UNDER the cluster directory — whether
        or not the crawler ever saw that target before. Deep chain steps
        (create, confirm) exist only behind POST landings; requiring crawl
        membership here would hide them (live-caught in the first v3.0.0
        benchmark: 0 flows learned, 5 FN, while the safe twin stayed silent —
        the honest-negative discipline worked, the discovery did not)."""
        out = []
        for f in parse_forms(html):
            if f["method"] != "POST":
                continue
            action = urllib.parse.urljoin(page_url, f["action"] or page_url)
            path = self._path_of(action)
            if (path == cluster or path.startswith(cluster.rstrip("/") + "/")) \
                    and not SESSION_KILLER_RE.search(action):
                out.append(dict(f, action=action))
        return out

    def _walk(self, members: dict, engine, option_overrides: dict | None = None,
              canary: str = CANARY_CREATE, max_chain: int | None = None,
              after_step=None):
        """The guided walk: fetch cluster GET pages to find the ANCHOR (a GET
        page carrying an in-cluster POST form), submit that form, then follow
        the chain — each landing page carries the next form. `after_step(step,
        response)` fires after every submitted step (the marker learner
        snapshots the state oracle BETWEEN steps — post-hoc snapshots all show
        the final state and the execution delta becomes invisible). Returns
        (steps, entry_url, pending_form, entry_fields) where pending_form is
        the form the chain WOULD submit next (None when the chain ended)."""
        origin = self._origin(members)
        cluster = self._path_of(next(iter(members.values())).url).rsplit("/", 1)[0]
        gets = sorted(((p, ep) for p, ep in members.items()
                       if (ep.method or "GET").upper() == "GET"),
                      key=lambda kv: kv[0])[: self.cfg.max_pages]
        entry, entry_forms, entry_fields = "", [], []
        for path, gep in gets:
            # ENG-16 (live-caught on ginandjuice.shop): the anchor fetch used
            # the BARE path, but query-param pages (/catalog/product?productId=1)
            # only render their form for a valid query — a param-less GET
            # returned an error page with no forms and the whole cluster was
            # dropped as "no_anchor". The endpoint's QUERY parameters carry
            # the discovered values (DISC-07): rebuild the URL with them.
            url = origin + path
            q = "&".join(f"{urllib.parse.quote(p.name)}={urllib.parse.quote(p.value or '')}"
                         for p in (gep.parameters or [])
                         if p.location == ParamLocation.QUERY and p.value)
            if q:
                url += "?" + q
            r = self._get(engine, url, "wf-anchor")
            if r.error or not r.body:
                continue
            forms = self._in_cluster_forms(r.body, url, cluster)
            if forms:
                entry, entry_forms = url, forms
                entry_fields = self._synth_fields(forms[0])
                self._last_entry_form = dict(forms[0], _page=url)   # v4.1.0: branch
                # discovery needs the anchor form's options (zero extra requests)
                break
        if not entry:
            return None, "", None, []
        steps: list[WalkStep] = []
        page_url, forms, seen = entry, entry_forms, set()
        limit = max_chain if max_chain is not None else self.cfg.max_steps

        def _pending():
            """The form the chain would submit next: first UNSEEN in-cluster
            POST form on the current page (None when the chain ended)."""
            return next((f for f in forms if self._path_of(f["action"]) not in seen),
                        None)

        while len(steps) < limit:
            nxt = _pending()
            if nxt is None:
                return steps, entry, None, entry_fields
            fields = self._synth_fields(nxt, canary=canary,
                                        overrides=option_overrides)
            r = self._post(engine, nxt["action"], fields, "wf-walk")
            seen.add(self._path_of(nxt["action"]))
            step = WalkStep(action=nxt["action"], fields=fields,
                            status=r.status, landing=r.body or "")
            steps.append(step)
            if after_step is not None:
                try:
                    after_step(step, r)
                except Exception:
                    pass
            if r.error or not r.ok:
                return steps, entry, None, entry_fields
            page_url, forms = nxt["action"], self._in_cluster_forms(r.body or "",
                                                                    nxt["action"], cluster)
        return steps, entry, _pending(), entry_fields

    # -------------------------------------------------- phase 1: learn
    def learn(self, directory: str, members: dict, engine) -> FlowKnowledge:
        k = FlowKnowledge(cluster=directory, members=members)
        steps, entry, pending, entry_fields = self._walk(members, engine)
        if not entry:
            k.drop_reason = "no_anchor"
            return k
        k.entry, k.steps = entry, steps
        if len(steps) < 2:
            k.drop_reason = "chain_too_short"
            return k
        # -- resource linkage: hidden fields that appear in a step's landing
        # form but in no earlier form NOR in the step's own submitted fields —
        # the object ids one step MINTS and a later step consumes. (The step's
        # own fields are registered BEFORE its landing is scanned: the confirm
        # form carries a hidden echo of the amount the create step submitted —
        # that is data continuity, not resource production.)
        known = {n for n, _ in entry_fields}
        for s in steps:
            known |= {n for n, _ in s.fields}
            for form in self._in_cluster_forms(s.landing, s.action, k.cluster):
                for f in form["fields"]:
                    if isinstance(f, dict) and f.get("type") == "hidden" \
                            and f["name"] not in known and not _is_token(f["name"]):
                        k.resource_params[f["name"]] = f.get("value", "")
        if not k.resource_params:
            k.drop_reason = "no_resource_linkage"
            return k
        res_name = next(iter(k.resource_params))
        # -- state oracle: the cluster GET page that echoes the resource value
        origin = self._origin(members)
        for path in sorted(members)[: self.cfg.max_pages]:
            ep = members[path]
            if (ep.method or "GET").upper() != "GET":
                continue
            r = self._get(engine, origin + path, "wf-oracle")
            if not r.error and res_name and any(
                    v and v in (r.body or "") for v in k.resource_params.values()):
                k.oracle_url = ep.url
                break
        if not k.oracle_url:
            k.drop_reason = "no_state_oracle"
            return k
        # -- execution markers: walk the chain AGAIN on the same session,
        # snapshotting the oracle AFTER EVERY STEP, LIVE (a post-hoc snapshot
        # would show the final state everywhere and the delta would be
        # invisible — live-caught: the first v3.0.0 run dropped both flows as
        # no_execution_marker). The producer step is the one whose landing
        # CARRIES the fresh resource id; its snapshot's line is the
        # pre-execution form, the final step's snapshot the executed form.
        snaps: list[str] = []
        steps2, _, _, _ = self._walk(members, engine,
                                     after_step=lambda s, r: snaps.append(
                                         self._get(engine, k.oracle_url,
                                                   "wf-marker").body or ""))
        if not steps2 or not snaps:
            k.drop_reason = "marker_walk_failed"
            return k
        res_val2 = ""
        for i, s in enumerate(steps2):
            for form in self._in_cluster_forms(s.landing, s.action, k.cluster):
                for f in form["fields"]:
                    if isinstance(f, dict) and f.get("name") == res_name \
                            and f.get("value"):
                        # v4.1.0 fix: the MINTING step is the FIRST landing that
                        # carries the id (later steps echo the same id in their
                        # own forms — taking the last one mis-attributed the
                        # producer on approval-chain flows; on the vulnapp shape
                        # both readings agree, so v4.0.0 behavior is unchanged)
                        if not res_val2:
                            res_val2, k.producer_idx = f["value"], i
        if not res_val2 or k.producer_idx < 0 or k.producer_idx >= len(snaps):
            k.drop_reason = "marker_walk_failed"
            return k
        la = (_lines_with(snaps[k.producer_idx], res_val2) or [""])[-1]
        lb = (_lines_with(snaps[-1], res_val2) or [""])[-1]
        added, removed = _word_delta(la, lb)
        k.exec_added = [w for w in added if len(w) > 2]
        k.exec_removed = [w for w in removed if len(w) > 2]
        if not k.exec_added:
            k.drop_reason = "no_execution_marker"
            return k
        # -- privilege-declared options + rollback paths across every form the
        # chain exposes (cancel-shaped forms are the CROSS-STATE precondition)
        seen_opts: list[tuple[str, str, str]] = []
        for s in [WalkStep(action=entry, landing="")] + steps:
            for form in self._in_cluster_forms(s.landing, s.action, k.cluster):
                for triple in _privilege_options([form]):
                    if triple not in seen_opts:
                        seen_opts.append(triple)
                if CANCEL_RE.search(self._path_of(form["action"])) \
                        and form["action"] not in k.cancel_paths:
                    k.cancel_paths.append(form["action"])
        k.priv_options = sorted(seen_opts)[: self.cfg.max_options]

        # ---- v4.1.0 Workflow Graph 2.0 — everything below is derived from data
        # the walks ALREADY fetched (zero extra requests):
        #   (a) branch options: every non-default select option of every form
        #       the walk saw (anchor form + step landings), classified
        #       privileged / restricted / open
        #   (b) branch transfer: a select field of an EARLIER submitted form
        #       whose name rides a LATER form as a hidden field — the later
        #       step TRUSTS the branch choice from the request
        #   (c) approval step: approve-vocabulary step in the walked chain
        #   (d) rollback paths: rollback-vocabulary actions (split from cancel)
        #   (e) per-step state pairs: the marker walk's oracle snapshots
        # step index at which each form is SUBMITTED: anchor form -> step 0,
        # forms_by_step[i] (landing of step i) -> step i+1
        anchor_form = getattr(self, "_last_entry_form", None) or {}
        forms_by_step: list[list[dict]] = [self._in_cluster_forms(s.landing, s.action,
                                                                k.cluster)
                                           for s in steps]
        # (field, value, label, submitted_at_step, form_action)
        option_sites: list[tuple[str, str, str, int, str]] = []
        if anchor_form:
            option_sites += [(fn, v, lb, 0, self._path_of(anchor_form["action"]))
                             for fn, v, lb in _options_of(anchor_form)]
        for i, forms in enumerate(forms_by_step):
            for form in forms:
                option_sites += [(fn, v, lb, i + 1, self._path_of(form["action"]))
                                 for fn, v, lb in _options_of(form)]
        default_opts: dict[str, str] = {}
        for fn, v, lb, _, _ in option_sites:
            default_opts.setdefault(fn, v)    # first option of a select = default
        seen_branches: set[tuple] = set()
        for fn, v, lb, submitted_at, action_path in option_sites:
            if v == default_opts.get(fn):
                continue        # the default path IS the walked chain, not a branch
            key = (fn, v)
            if key in seen_branches:
                continue
            seen_branches.add(key)
            k.branches.append({
                "field": fn, "value": v, "label": lb,
                "form_action": action_path,
                "select_step": submitted_at, "hidden_step": submitted_at,
                "privileged": _is_privileged_label(lb),
                "restricted": bool(RESTRICTED_RE.search(lb or ""))
                              and not _is_privileged_label(lb),
                "default": False})
        # branch transfer: select field submitted at step i whose name rides a
        # form submitted at a LATER step as a hidden field
        select_at: dict[str, int] = {}
        for fn, v, lb, submitted_at, _ in option_sites:
            select_at.setdefault(fn, submitted_at)
        later_forms = [(i + 1, form) for i, forms in enumerate(forms_by_step)
                       for form in forms]
        for submit_at, form in later_forms:
            if not k.branch_transfer:
                for f in form.get("fields", []):
                    if isinstance(f, dict) and f.get("type") == "hidden" \
                            and f.get("name") in select_at \
                            and select_at[f["name"]] < submit_at:
                        k.branch_transfer = {"field": f["name"],
                                             "select_step": select_at[f["name"]],
                                             "hidden_step": submit_at}
        if k.branch_transfer:
            for br in k.branches:
                if br["field"] == k.branch_transfer["field"]:
                    br["hidden_step"] = k.branch_transfer["hidden_step"]
        # approval step: approve-vocabulary ACTION among the walked steps
        for i, s in enumerate(steps):
            if APPROVE_RE.search(self._path_of(s.action)):
                k.approval_idx = i
                break
        # rollback-vocabulary paths (cancel stays in cancel_paths)
        for forms in forms_by_step + ([anchor_form] if anchor_form else []):
            for form in forms:
                if isinstance(form, dict) and form.get("action") \
                        and ROLLBACK_RE.search(self._path_of(form["action"])) \
                        and form["action"] not in k.rollback_paths:
                    k.rollback_paths.append(form["action"])
        # per-step state pairs from the marker walk snapshots (snaps[i] is the
        # oracle AFTER step i; the resource line at that moment is the state)
        k.step_states = []
        for i in range(len(steps)):
            before = (_lines_with(snaps[i - 1], res_val2) or [""])[-1] if i > 0 \
                else ""
            after = (_lines_with(snaps[i], res_val2) or [""])[-1] \
                if i < len(snaps) else ""
            k.step_states.append({"before": before.strip()[:160],
                                  "after": after.strip()[:160]})
        # which select options did the walks actually SUBMIT (default choices
        # and any overrides)? — the graph's belief distinction needs this
        select_names = set(select_at)
        k.exercised_options = sorted({(n, v) for s in steps for n, v in (s.fields or [])
                                      if n in select_names})
        k.graph = build_graph(k)
        return k

    # -------------------------------------------------- oracle helpers
    def _walk_resource(self, steps, res_name: str, cluster: str) -> str:
        """The resource value a walk's OWN chain minted: the LAST value the
        resource param takes across the walk's landing forms. Every walk mints
        a fresh id — searching the LEARN-time examples instead (the first
        v3.0.0 bug of this class) finds nothing and starves the privilege
        baseline + attack."""
        val = ""
        for s in steps or []:
            for form in self._in_cluster_forms(s.landing, s.action, cluster):
                for f in form["fields"]:
                    if isinstance(f, dict) and f.get("name") == res_name \
                            and f.get("value"):
                        val = f["value"]
        return val

    def _oracle(self, engine, k: FlowKnowledge, note="wf-oracle") -> str:
        r = self._get(engine, k.oracle_url, note)
        return (r.body or "") if not r.error else ""

    def _executed(self, line: str, k: FlowKnowledge) -> bool:
        return any(w in (line or "") for w in k.exec_added)

    # ---------------------------------------------- v4.2.0 VF-04: proof protocol
    # A workflow finding's `passed` flag is DERIVED from raw state-oracle
    # observations by _derive_wf_proof(), NEVER stamped by the caller. Every
    # call site MUST pass proof={"rule": <closed-set name>, "obs": {...raw...}};
    # a call without a proof raises, a call with an unknown rule raises, and a
    # derivation that fails yields REJECTED — mechanism, not convention.
    @staticmethod
    def _derive_wf_proof(proof: dict) -> bool:
        rule, obs = proof["rule"], proof.get("obs") or {}
        ok = bool(obs.get("ok", True))
        pre, post = (obs.get("pre") or ""), (obs.get("post") or "")
        marker = str(obs.get("marker", ""))
        ew = obs.get("exec_words") or []
        if rule == "lines-added":
            new = [l for l in _lines_with(post, marker)
                   if l not in set(_lines_with(pre, marker))]
            return ok and bool(new)
        if rule == "marker-executed":
            lines = _lines_with(post, marker)
            return ok and bool(lines) and any(w in lines[-1] for w in ew)
        if rule == "line-match":
            lines = _lines_with(post, marker)
            line = lines[-1] if lines else ""
            mc, mnc = str(obs.get("must_contain", "")), str(obs.get("must_not_contain", ""))
            return (ok and bool(line) and mc in line
                    and (not mnc or mnc not in line) and any(w in line for w in ew))
        if rule == "occurrences-grew":
            return ok and len(_lines_with(post, marker)) > len(_lines_with(pre, marker))
        if rule == "state-flip-executed":
            lines, pre_lines = _lines_with(post, marker), _lines_with(pre, marker)
            line = lines[-1] if lines else ""
            pre_line = pre_lines[-1] if pre_lines else ""
            return (ok and bool(line) and any(w in line for w in ew)
                    and not any(w in pre_line for w in ew))
        raise ValueError(f"unknown workflow proof rule {rule!r} — add an explicit "
                         "derivation branch in _derive_wf_proof (fail-closed)")

    @staticmethod
    def _finding(vtype: str, url: str, param: str, evidence: Evidence,
                 notes: str, authz_context: str = "",
                 state_before: str = "", state_after: str = "",
                 proof: dict | None = None) -> Finding:
        if not isinstance(proof, dict) or "rule" not in proof or "obs" not in proof:
            raise ValueError(
                "workflow findings REQUIRE an explicit state-oracle proof: "
                "proof={'rule': ..., 'obs': {...}} — the passed flag is DERIVED "
                "from raw observations by _derive_wf_proof (v4.2.0 VF-04); "
                "stamped passed=True is forbidden")
        delta = WorkflowEngine._derive_wf_proof(proof)
        f = Finding(vtype, Severity.HIGH, url, param, "POST", [evidence],
                    status=FindingStatus.CANDIDATE)
        f.verification = Verification(
            method=f"oracle:workflow-state-delta:{proof['rule']}",
            passed=delta, confidence=0.9 if delta else 0.15, rounds=1,
            notes=(notes + f" | derived={proof['rule']}"
                   + (f" marker={proof['obs'].get('marker', '')!r}"
                      if proof['obs'].get('marker') else "")))
        f.status = FindingStatus.VERIFIED if delta else FindingStatus.REJECTED
        f.authz_context = authz_context
        # ENG-18: carry the workflow-oracle state pair into the proof file
        f.state_before = (state_before or "").strip()[:160]
        f.state_after = (state_after or "").strip()[:160]
        return f

    # -------------------------------------------------- phase 2: attacks
    def _fresh_session(self, scope, bus, auth_profile, timeout) -> RequestEngine | None:
        """A brand-new logged-in engine (isolated cookie jar + fresh app
        state). None when the login fails (honest skip upstream)."""
        from .auth import AuthEngine
        eng = RequestEngine(scope, bus, timeout=timeout)
        if not AuthEngine(auth_profile, eng, bus).login():
            return None
        return eng

    def _atk_bypass(self, k: FlowKnowledge, engine, entry_fields) -> tuple[Finding | None, dict]:
        """1. STEP BYPASS — submit the producer step directly on a session that
        never ran its predecessor. Verified iff the oracle gains a NEW
        canary-bearing object line (the object was created anyway)."""
        if k.producer_idx < 1:
            return None, {"verdict": "skipped", "note": "producer is the first step"}
        producer = k.steps[k.producer_idx]
        fields = self._token_refresh(producer.fields, entry_fields)
        pre = self._oracle(engine, k, "wf-atk-bypass-pre")
        r = self._post(engine, producer.action, fields, "wf-atk-bypass")
        post = self._oracle(engine, k, "wf-atk-bypass-post")
        new = [l for l in _lines_with(post, CANARY_CREATE)
               if l not in set(_lines_with(pre, CANARY_CREATE))]
        if not (r.ok and new):
            return None, {"verdict": "no_proof", "status": r.status,
                          "note": "no new canary-bearing object in the state oracle"}
        param = next((n for n, _ in fields if not _is_token(n)), "")
        f = self._finding(
            "business_logic_step_bypass", producer.action, param,
            Evidence("mandatory_step_bypassed",
                     f"step {self._path_of(producer.action)} created an object on a "
                     f"session that never ran its predecessor "
                     f"{self._path_of(k.steps[k.producer_idx - 1].action)} — oracle "
                     f"gained the line '{new[0].strip()[:120]}' — the mandatory "
                     "earlier step is not enforced server-side", r.request_id),
            f"state oracle gained a canary object without the predecessor step: "
            f"'{new[0].strip()[:100]}'",
            state_before=f"pre-bypass oracle: no {CANARY_CREATE}-bearing object for this session",
            state_after=new[0].strip()[:120],
            proof={"rule": "lines-added",
                   "obs": {"ok": r.ok, "pre": pre, "post": post, "marker": CANARY_CREATE}})
        return f, {"verdict": "verified", "status": r.status,
                   "line": new[0].strip()[:120]}

    def _atk_out_of_order(self, k: FlowKnowledge, engine, entry_fields) -> tuple[Finding | None, dict]:
        """2. OUT-OF-ORDER — the FINAL step with a never-created resource id.
        Verified iff the oracle shows that id EXECUTED."""
        if not k.resource_params:
            return None, {"verdict": "skipped", "note": "no resource linkage"}
        final = k.steps[-1]
        res_name = next(iter(k.resource_params))
        fresh_val = _synth_fresh_resource(k.resource_params[res_name])
        fields = self._token_refresh(final.fields, entry_fields)
        fields = [(n, fresh_val if n == res_name
                   else (CANARY_TAMPER if _is_amount(n) else v)) for n, v in fields]
        pre_order = self._oracle(engine, k, "wf-atk-order-pre")
        r = self._post(engine, final.action, fields, "wf-atk-order")
        post = self._oracle(engine, k, "wf-atk-order-post")
        lines = _lines_with(post, fresh_val)
        if not (r.ok and lines and self._executed(lines[-1], k)):
            return None, {"verdict": "no_proof", "status": r.status,
                          "note": f"synthetic resource {fresh_val} not executed"}
        f = self._finding(
            "business_logic_out_of_order", final.action, res_name,
            Evidence("final_step_without_producer",
                     f"the final step {self._path_of(final.action)} EXECUTED a "
                     f"never-created resource ({res_name}={fresh_val}) straight from "
                     f"POSTed parameters — oracle line '{lines[-1].strip()[:120]}' — "
                     "implicit creation + execution: the producing step was skipped",
                     r.request_id),
            f"oracle shows the synthetic resource executed: '{lines[-1].strip()[:100]}'",
            state_before=f"pre-order oracle: synthetic resource {fresh_val} absent"
                         + (f" ({len(_lines_with(pre_order, fresh_val))} lines)" if _lines_with(pre_order, fresh_val) else ""),
            state_after=lines[-1].strip()[:120],
            proof={"rule": "marker-executed",
                   "obs": {"ok": r.ok, "post": post, "marker": fresh_val,
                           "exec_words": k.exec_added}})
        return f, {"verdict": "verified", "status": r.status, "resource": fresh_val}

    def _atk_tamper(self, k: FlowKnowledge, engine, entry_fields) -> tuple[Finding | None, dict]:
        """3. VALUE TAMPER — walk the chain legitimately up to the final step,
        then submit the final step with a DIFFERENT amount. Verified iff the
        executed oracle line carries the tampered canary and not the approved
        one."""
        if len(k.steps) < 2 or k.producer_idx < 0:
            return None, {"verdict": "skipped", "note": "chain too short"}
        pre = self._oracle(engine, k, "wf-atk-tamper-pre")
        # live walk up to (excluding) the final step; the pending form is the
        # final step's form with the FRESH resource id and approved canary
        steps, _, pending, _ = self._walk(k.members, engine,
                                          max_chain=len(k.steps) - 1)
        if not steps or pending is None:
            return None, {"verdict": "no_proof", "note": "walk to final step failed"}
        res_name = next(iter(k.resource_params))
        res_val = ""
        for f in pending["fields"]:
            if f.get("name") == res_name:
                res_val = f.get("value", "")
        if not res_val:
            return None, {"verdict": "no_proof",
                          "note": "fresh resource value not observable"}
        mid = self._oracle(engine, k, "wf-atk-tamper-mid")
        if res_val not in mid:
            return None, {"verdict": "no_proof",
                          "note": "created resource not visible in the oracle"}
        # synthesize the final step's fields, then FORCE the amount to the
        # tamper canary — the approved value rides a HIDDEN field, so plain
        # synthesis would carry it verbatim; the tamper is precisely changing it
        fields = [(n, CANARY_TAMPER if _is_amount(n) else v)
                  for n, v in self._synth_fields(pending)]
        r = self._post(engine, pending["action"], fields, "wf-atk-tamper")
        post = self._oracle(engine, k, "wf-atk-tamper-post")
        line = (_lines_with(post, res_val) or [""])[-1]
        if not (r.ok and line and CANARY_TAMPER in line and CANARY_CREATE not in line
                and self._executed(line, k)):
            return None, {"verdict": "no_proof", "status": r.status,
                          "note": "approved value not overridable/executed"}
        param = next((n for n, _ in fields if _is_amount(n)), "")
        f = self._finding(
            "business_logic_value_tamper", pending["action"], param,
            Evidence("post_approval_override",
                     f"the final step executed {res_name}={res_val} with the TAMPERED "
                     f"value ({CANARY_TAMPER}) replacing the approved one "
                     f"({CANARY_CREATE}) — oracle line '{line.strip()[:120]}' — values "
                     "are re-trusted at execution time instead of bound at approval",
                     r.request_id),
            f"executed oracle line carries the tampered value: '{line.strip()[:100]}'",
            state_before=f"{res_val} approved with amount {CANARY_CREATE} (hidden field of the final form)",
            state_after=line.strip()[:120],
            proof={"rule": "line-match",
                   "obs": {"ok": r.ok, "post": post, "marker": res_val,
                           "must_contain": CANARY_TAMPER, "must_not_contain": CANARY_CREATE,
                           "exec_words": k.exec_added}})
        return f, {"verdict": "verified", "status": r.status,
                   "line": line.strip()[:120]}

    def _atk_duplicate(self, k: FlowKnowledge, engine, entry_fields) -> tuple[Finding | None, dict]:
        """4. DUPLICATE EXECUTION — run the full chain, then replay the final
        step once. Verified iff the same resource shows MORE oracle lines
        after the replay than before it."""
        if len(k.steps) < 2:
            return None, {"verdict": "skipped", "note": "chain too short"}
        steps, _, _, _ = self._walk(k.members, engine)
        if not steps or len(steps) < 2:
            return None, {"verdict": "no_proof", "note": "full walk failed"}
        final = steps[-1]
        res_name = next(iter(k.resource_params))
        res_val = ""
        for n, v in final.fields:
            if n == res_name:
                res_val = v
        mid = self._oracle(engine, k, "wf-atk-dup-mid")
        if not res_val or res_val not in mid:
            return None, {"verdict": "no_proof",
                          "note": "executed resource not observable in the oracle"}
        r = self._post(engine, final.action, final.fields, "wf-atk-dup-replay")
        post = self._oracle(engine, k, "wf-atk-dup-post")
        n_mid, n_post = len(_lines_with(mid, res_val)), len(_lines_with(post, res_val))
        if not (r.ok and n_post > n_mid):
            return None, {"verdict": "no_proof", "status": r.status,
                          "note": f"executions {n_mid} -> {n_post}"}
        f = self._finding(
            "business_logic_duplicate_execution", final.action, res_name,
            Evidence("non_idempotent_replay",
                     f"replaying the final step executed {res_name}={res_val} AGAIN: "
                     f"oracle occurrences {n_mid} -> {n_post} — no one-shot consumption "
                     "(missing idempotency guard)", r.request_id),
            f"same resource executed twice: {n_mid} -> {n_post} oracle occurrences",
            state_before=f"occurrences {n_mid}: '{((_lines_with(mid, res_val) or [''])[-1]).strip()[:100]}'",
            state_after=f"occurrences {n_post}: '{((_lines_with(post, res_val) or [''])[-1]).strip()[:100]}'",
            proof={"rule": "occurrences-grew",
                   "obs": {"ok": r.ok, "pre": mid, "post": post, "marker": res_val}})
        return f, {"verdict": "verified", "status": r.status,
                   "executions": f"{n_mid}->{n_post}"}

    def _walk_to_producer(self, k: FlowKnowledge, engine, flow_tag: str = ""):
        """Partial walk up to (excluding) the final step; returns
        (pending_form, res_val) where pending_form is the FINAL step's form
        carrying the fresh resource id, or (None, '').

        REPRO FIX (2026-10-31, caught by the CI reproducibility gate): with
        flow_tag, the walk's creates carry a deterministic per-flow marker so
        the fixture derives a CONTENT-ADDRESSED object id — the global
        sequential counter made the minted id depend on concurrent
        interleaving (exactly +8 between two runs), moving the audit Merkle
        root per run and breaking the "same seed -> the same root" contract."""
        extra: dict = {}
        if flow_tag:
            import hashlib as _hl
            extra["wfWalkMarker"] = "wfm-" + _hl.sha1(
                f"{k.cluster}|{flow_tag}".encode("utf-8")).hexdigest()[:12]
        steps, _, pending, _ = self._walk(k.members, engine,
                                          option_overrides=extra or None,
                                          max_chain=max(1, len(k.steps) - 1))
        if not steps or pending is None:
            return None, ""
        res_name = next(iter(k.resource_params), "")
        res_val = ""
        for f in pending["fields"]:
            if f.get("name") == res_name:
                res_val = f.get("value", "")
        return pending, res_val

    def _atk_cross_user(self, k: FlowKnowledge, engine_a, entry_fields_low,
                        low_engine, low_role: str) -> tuple[Finding | None, dict]:
        """6. CROSS-USER EXECUTION — identity B executes a workflow object that
        identity A minted. PRECONDITION: B's state oracle shows A's resource as
        a SHARED object (the id was NOT already visible to B before A minted
        it — a pre-existing id is a same-name object in a SEPARATE store, the
        classic per-session identifier collision, not shared visibility).
        Verified iff B's submission moves A's resource to the executed state
        in A's oracle."""
        if not k.resource_params or len(k.steps) < 2:
            return None, {"verdict": "skipped", "note": "no resource linkage",
                          "precondition": True}
        view_b_before = self._oracle(low_engine, k, "wf-atk-xuser-before")
        pending, res_val = self._walk_to_producer(k, engine_a, flow_tag="cross-user")
        if pending is None or not res_val:
            return None, {"verdict": "no_proof", "note": "walk to producer failed"}
        view_b = self._oracle(low_engine, k, "wf-atk-xuser-view")
        if res_val not in view_b:
            return None, {"verdict": "skipped",
                          "note": "cross_identity_oracle_unavailable "
                                  "(the second identity cannot observe this object)",
                          "precondition": True}
        if res_val in view_b_before:
            return None, {"verdict": "skipped",
                          "note": "identifier collision between separate stores "
                                  "(the id pre-existed in the second identity's "
                                  "oracle — not a shared object)",
                          "precondition": True}
        # B submits the final step on A's object with B's OWN tokens
        fields = self._token_refresh(
            [(n, v) for n, v in self._synth_fields(pending)], entry_fields_low)
        pre_a = self._oracle(engine_a, k, "wf-atk-xuser-pre")
        r = self._post(low_engine, pending["action"], fields, "wf-atk-xuser")
        post_a = self._oracle(engine_a, k, "wf-atk-xuser-post")
        line = (_lines_with(post_a, res_val) or [""])[-1]
        if not (r.ok and line and self._executed(line, k)
                and not self._executed((_lines_with(pre_a, res_val) or [""])[-1], k)):
            return None, {"verdict": "no_proof", "status": r.status,
                          "note": "second identity could not execute the owner's object"}
        f = self._finding(
            "business_logic_cross_user_execution", pending["action"],
            next(iter(k.resource_params)),
            Evidence("cross_identity_object_execution",
                     f"identity B (role={low_role}) EXECUTED object {res_val} minted by "
                     f"identity A via {self._path_of(pending['action'])} — the owner's "
                     f"state oracle gained the executed line '{line.strip()[:120]}' — "
                     "object ownership is not enforced server-side", r.request_id),
            f"owner's oracle shows the object executed by the other identity: "
            f"'{line.strip()[:100]}'",
            authz_context=f"attacker=role:{low_role} object_owner=primary",
            state_before=((_lines_with(pre_a, res_val) or ["(object absent from owner's oracle)"])[-1]).strip()[:120],
            state_after=line.strip()[:120],
            proof={"rule": "state-flip-executed",
                   "obs": {"ok": r.ok, "pre": pre_a, "post": post_a, "marker": res_val,
                           "exec_words": k.exec_added}})
        return f, {"verdict": "verified", "status": r.status, "role": low_role,
                   "resource": res_val}

    def _atk_cross_object(self, k: FlowKnowledge, engine,
                          entry_fields) -> tuple[Finding | None, dict]:
        """7. CROSS-OBJECT EXECUTION — the final step with the id of an object
        of a DIFFERENT type/context visible in the state oracle (a foreign
        entity the flow never mints). PRECONDITION: such an id is observable.
        Verified iff the oracle shows that foreign object executed."""
        if not k.resource_params or len(k.steps) < 2:
            return None, {"verdict": "skipped", "note": "no resource linkage",
                          "precondition": True}
        res_name = next(iter(k.resource_params))
        oracle = self._oracle(engine, k, "wf-atk-xobj-view")
        own_prefix = _resource_prefix(k.resource_params[res_name])
        own_vals = {v for v in k.resource_params.values() if v}
        foreign = ""
        for line in _lines_with(oracle, "-"):
            for cand in FOREIGN_ID_RE.findall(_strip_tags(line)):
                if _resource_prefix(cand) != own_prefix and cand not in own_vals:
                    foreign = cand
                    break
            if foreign:
                break
        if not foreign:
            return None, {"verdict": "skipped",
                          "note": "no foreign-typed object visible in the state oracle",
                          "precondition": True}
        final = k.steps[-1]
        fields = self._token_refresh(
            [(n, foreign if n == res_name else v) for n, v in final.fields],
            entry_fields)
        pre_xobj = self._oracle(engine, k, "wf-atk-xobj-pre")
        r = self._post(engine, final.action, fields, "wf-atk-xobj")
        post = self._oracle(engine, k, "wf-atk-xobj-post")
        lines = _lines_with(post, foreign)
        if not (r.ok and lines and self._executed(lines[-1], k)):
            return None, {"verdict": "no_proof", "status": r.status,
                          "note": f"foreign object {foreign} not executed"}
        pre_line = (_lines_with(pre_xobj, foreign) or [""])[-1]
        f = self._finding(
            "business_logic_cross_object_execution", final.action, res_name,
            Evidence("cross_object_type_confusion",
                     f"the final step {self._path_of(final.action)} EXECUTED {foreign} — "
                     f"an object of a DIFFERENT type than this flow produces "
                     f"(prefix {_resource_prefix(foreign) or '?'} vs {own_prefix or '?'}) "
                     f"— oracle line '{lines[-1].strip()[:120]}' — object type/context "
                     "is not validated server-side", r.request_id),
            f"foreign-typed object executed by the flow: '{lines[-1].strip()[:100]}'",
            state_before=(pre_line.strip()[:120] or f"foreign object {foreign} present, not executed"),
            state_after=lines[-1].strip()[:120],
            proof={"rule": "marker-executed",
                   "obs": {"ok": r.ok, "post": post, "marker": foreign,
                           "exec_words": k.exec_added}})
        return f, {"verdict": "verified", "status": r.status, "resource": foreign}

    def _atk_cross_state(self, k: FlowKnowledge, engine,
                         entry_fields) -> tuple[Finding | None, dict]:
        """8. CROSS-STATE EXECUTION — mint the object, move it to a CANCELLED
        state via the flow's own rollback path, then execute it anyway.
        PRECONDITION: a cancel/rollback-shaped form exists in the flow's own
        landings. Verified iff the oracle shows the cancelled object EXECUTED."""
        if not k.cancel_paths or not k.resource_params or len(k.steps) < 2:
            return None, {"verdict": "skipped", "note": "no rollback path in this flow",
                          "precondition": True}
        res_name = next(iter(k.resource_params))
        pending, res_val = self._walk_to_producer(k, engine, flow_tag="cross-state")
        if pending is None or not res_val:
            return None, {"verdict": "no_proof", "note": "walk to producer failed"}
        cancel_action = k.cancel_paths[0]
        cancel_fields = self._token_refresh(
            [(n, res_val if n == res_name else v) for n, v in self._synth_fields(pending)],
            entry_fields)
        r_cancel = self._post(engine, cancel_action, cancel_fields, "wf-atk-xstate-cancel")
        mid = self._oracle(engine, k, "wf-atk-xstate-mid")
        mid_line = (_lines_with(mid, res_val) or [""])[-1]
        if not (r_cancel.ok and res_val in mid):
            return None, {"verdict": "no_proof", "status": r_cancel.status,
                          "note": "rollback path did not move the object"}
        # execute the (now cancelled) object through the final step
        fields = self._token_refresh(
            [(n, v) for n, v in self._synth_fields(pending)], entry_fields)
        r = self._post(engine, pending["action"], fields, "wf-atk-xstate-exec")
        post = self._oracle(engine, k, "wf-atk-xstate-post")
        line = (_lines_with(post, res_val) or [""])[-1]
        if not (r.ok and line and self._executed(line, k)):
            return None, {"verdict": "no_proof", "status": r.status,
                          "note": "cancelled object was not executable"}
        f = self._finding(
            "business_logic_cross_state_execution", pending["action"], res_name,
            Evidence("cross_state_execution",
                     f"the object {res_val} was moved to a cancelled/rolled-back state "
                     f"via {self._path_of(cancel_action)} (oracle line "
                     f"'{mid_line.strip()[:80]}') and then EXECUTED anyway by "
                     f"{self._path_of(pending['action'])} — oracle line "
                     f"'{line.strip()[:120]}' — the state machine does not protect "
                     "rolled-back objects from execution", r.request_id),
            f"cancelled object executed: '{line.strip()[:100]}'",
            state_before=mid_line.strip()[:120],
            state_after=line.strip()[:120],
            proof={"rule": "marker-executed",
                   "obs": {"ok": r.ok, "post": post, "marker": res_val,
                           "exec_words": k.exec_added}})
        return f, {"verdict": "verified", "status": r.status,
                   "rollback": self._path_of(cancel_action)}

    def _atk_privilege(self, k: FlowKnowledge, low_engine, entry_fields,
                       low_role: str) -> tuple[Finding | None, dict]:
        """5. PRIVILEGE BOUND — walk the chain under a LOWER-privilege session
        choosing the option the UI labels privileged. Verified iff that
        session's oracle shows the option EXECUTED (baseline: the option is
        functional for the primary role — a control broken for everyone is
        never reported as an escalation)."""
        if not k.priv_options:
            return None, {"verdict": "skipped", "note": "no privilege-declared option"}
        fname, opt, label = k.priv_options[0]
        if not k.priv_baselines.get(opt):
            return None, {"verdict": "skipped",
                          "note": f"option {opt} not functional for the primary role"}
        pre = self._oracle(low_engine, k, "wf-atk-priv-pre")
        steps, _, _, _ = self._walk(k.members, low_engine,
                                    option_overrides={fname: opt})
        if not steps:
            return None, {"verdict": "no_proof", "note": "low-privilege walk failed"}
        mid = self._oracle(low_engine, k, "wf-atk-priv-post")
        res_val = self._walk_resource(steps, next(iter(k.resource_params)), k.cluster)
        if not res_val or res_val in pre or res_val not in mid:
            return None, {"verdict": "no_proof",
                          "note": "low-privilege walk produced no observable object"}
        line = (_lines_with(mid, res_val) or [""])[-1]
        if not (opt in line and self._executed(line, k)):
            return None, {"verdict": "no_proof",
                          "note": f"option {opt} not executed by role={low_role}"}
        f = self._finding(
            "business_logic_privilege_escalation", k.steps[-1].action, fname,
            Evidence("declared_privilege_not_enforced",
                     f"the UI declares option {fname}={opt} '{label}' as privileged, "
                     f"yet a role={low_role} session EXECUTED it — oracle line "
                     f"'{line.strip()[:120]}' — the declared boundary is not enforced "
                     "server-side", ""),
            f"low-privilege session executed the admin-declared option: "
            f"'{line.strip()[:100]}'",
            authz_context=f"attacker=role:{low_role} declared_privilege={opt}",
            state_before=f"option {fname}={opt} '{label}' declared privileged (admin only)",
            state_after=line.strip()[:120],
            proof={"rule": "line-match",
                   "obs": {"post": mid, "marker": res_val, "must_contain": opt,
                           "must_not_contain": "", "exec_words": k.exec_added}})
        return f, {"verdict": "verified", "role": low_role, "option": opt}

    # ------------------------------------------- v4.1.0 branch & state attacks
    # Each attack has an applicable(k) gate consumed BEFORE any fresh session
    # is created: a structurally-absent precondition is a loud, zero-request
    # boundary — never a wasted login, never a fabricated attack.

    @staticmethod
    def _atk_branch_bypass_applicable(k: FlowKnowledge) -> str:
        """'' when runnable, else the honest reason."""
        if not k.branch_transfer:
            return "no branch-transfer pattern (a select whose choice rides a later step as a hidden field)"
        if not any(b["field"] == k.branch_transfer["field"] for b in k.branches):
            return "the transferred field has no non-default branch option"
        return ""

    def _atk_branch_bypass(self, k: FlowKnowledge, engine,
                           entry_fields) -> tuple[Finding | None, dict]:
        """9. BRANCH BYPASS — the branch-selecting step never runs, but the
        branch value is FORGED into the later step's hidden field and that
        step is submitted directly. Verified iff the state oracle gains a
        line carrying the branch value: the object entered the conditional
        branch without its condition ever being produced."""
        field = k.branch_transfer["field"]
        branch = next(b for b in k.branches if b["field"] == field)
        step_idx = k.branch_transfer["hidden_step"]
        step = k.steps[step_idx] if step_idx < len(k.steps) else k.steps[-1]
        fields = self._token_refresh(
            [(n, branch["value"] if n == field else v) for n, v in step.fields],
            entry_fields)
        pre = self._oracle(engine, k, "wf-atk-brbypass-pre")
        r = self._post(engine, step.action, fields, "wf-atk-brbypass")
        post = self._oracle(engine, k, "wf-atk-brbypass-post")
        new = [l for l in _lines_with(post, branch["value"])
               if l not in set(_lines_with(pre, branch["value"]))]
        if not (r.ok and new):
            return None, {"verdict": "no_proof", "status": r.status,
                          "note": f"branch {field}={branch['value']} not entered without its condition step"}
        f = self._finding(
            "business_logic_branch_bypass", step.action, field,
            Evidence("branch_condition_not_enforced",
                     f"the conditional branch {field}={branch['value']} "
                     f"('{branch.get('label', '')}') was entered by {self._path_of(step.action)} "
                     f"on a session that NEVER ran the branch-selecting step "
                     f"S{k.branch_transfer['select_step']} — the hidden field is trusted from the "
                     f"request — oracle gained '{new[0].strip()[:120]}'", r.request_id),
            f"oracle gained a line carrying the forged branch value: "
            f"'{new[0].strip()[:100]}'",
            state_before=f"pre-attack oracle: no {branch['value']}-bearing object for this session",
            state_after=new[0].strip()[:120],
            proof={"rule": "lines-added",
                   "obs": {"ok": r.ok, "pre": pre, "post": post, "marker": branch["value"]}})
        return f, {"verdict": "verified", "status": r.status,
                   "branch": f"{field}={branch['value']}",
                   "line": new[0].strip()[:120]}

    @staticmethod
    def _atk_unauth_branch_applicable(k: FlowKnowledge) -> str:
        if not any(b.get("restricted") for b in k.branches):
            return "no restriction-declared branch option (non-privilege vocabulary)"
        return ""

    def _atk_unauthorized_branch(self, k: FlowKnowledge, low_engine, entry_fields,
                                 low_role: str) -> tuple[Finding | None, dict]:
        """10. UNAUTHORIZED BRANCH — a branch the UI declares restricted to a
        membership/verification boundary ('premium members only') is chosen by
        a LOWER-privilege session mid-walk. Verified iff that session's oracle
        shows the branch EXECUTED (baseline: the branch is functional for the
        primary identity — a branch broken for everyone is a bug, not an
        escalation)."""
        branch = next(b for b in k.branches if b.get("restricted"))
        if not k.priv_baselines.get(branch["value"]):
            return None, {"verdict": "skipped",
                          "note": f"branch {branch['value']} not functional for the primary identity",
                          "precondition": True}
        pre = self._oracle(low_engine, k, "wf-atk-ubranch-pre")
        steps, _, _, _ = self._walk(k.members, low_engine,
                                    option_overrides={branch["field"]: branch["value"]})
        if not steps:
            return None, {"verdict": "no_proof", "note": "low-privilege walk failed"}
        mid = self._oracle(low_engine, k, "wf-atk-ubranch-post")
        res_val = self._walk_resource(steps, next(iter(k.resource_params)), k.cluster)
        if not res_val or res_val in pre or res_val not in mid:
            return None, {"verdict": "no_proof",
                          "note": "low-privilege walk produced no observable object"}
        line = (_lines_with(mid, res_val) or [""])[-1]
        if not (branch["value"] in line and self._executed(line, k)):
            return None, {"verdict": "no_proof",
                          "note": f"restricted branch {branch['value']} not executed by role={low_role}"}
        f = self._finding(
            "business_logic_unauthorized_branch", k.steps[-1].action, branch["field"],
            Evidence("declared_restriction_not_enforced",
                     f"the UI declares branch {branch['field']}={branch['value']} "
                     f"'{branch['label']}' restricted, yet a role={low_role} session "
                     f"EXECUTED it — oracle line '{line.strip()[:120]}' — the declared "
                     "membership boundary is not enforced server-side", ""),
            f"low-privilege session executed the restricted branch: "
            f"'{line.strip()[:100]}'",
            authz_context=f"attacker=role:{low_role} declared_restriction={branch['value']}",
            state_before=f"branch {branch['field']}={branch['value']} '{branch['label']}' declared restricted",
            state_after=line.strip()[:120],
            proof={"rule": "line-match",
                   "obs": {"post": mid, "marker": res_val, "must_contain": branch["value"],
                           "must_not_contain": "", "exec_words": k.exec_added}})
        return f, {"verdict": "verified", "role": low_role,
                   "branch": branch["value"]}

    @staticmethod
    def _atk_approval_bypass_applicable(k: FlowKnowledge) -> str:
        if k.approval_idx < 0:
            return "no approve-vocabulary step in the walked chain"
        if k.approval_idx >= len(k.steps) - 1:
            return "the approve step is the final step (nothing to bypass)"
        return ""

    def _atk_approval_bypass(self, k: FlowKnowledge, engine,
                             entry_fields) -> tuple[Finding | None, dict]:
        """11. APPROVAL BYPASS — the object is created but the approving step
        is SKIPPED; the executing step is submitted directly with the fresh
        object id. Verified iff the oracle shows the object EXECUTED while its
        state before the attack was never approved."""
        ai = k.approval_idx
        executor = k.steps[ai + 1]
        res_name = next(iter(k.resource_params), "")
        # partial walk: everything BEFORE the approve step -> pending = approve
        # form carrying the fresh (unapproved) object id
        steps, _, pending, _ = self._walk(k.members, engine, max_chain=ai)
        if not steps or pending is None:
            return None, {"verdict": "no_proof", "note": "walk to producer failed"}
        res_val = ""
        pending_vals = {f.get("name"): f.get("value", "")
                        for f in pending.get("fields", []) if isinstance(f, dict)}
        res_val = pending_vals.get(res_name, "")
        if not res_val:
            return None, {"verdict": "no_proof",
                          "note": "fresh object id not observable on the approve form"}
        pre = self._oracle(engine, k, "wf-atk-appr-pre")
        pre_line = (_lines_with(pre, res_val) or [""])[-1]
        # executor fields: learn-time shape, values carried over from the
        # FRESH pending form where names match; tokens from this session
        fields = []
        for n, v in executor.fields:
            if _is_token(n):
                fields.append((n, v))
            elif n in pending_vals and pending_vals[n]:
                fields.append((n, pending_vals[n]))
            elif n == res_name:
                fields.append((n, res_val))
            else:
                fields.append((n, v))
        fields = self._token_refresh(fields, entry_fields)
        r = self._post(engine, executor.action, fields, "wf-atk-appr")
        post = self._oracle(engine, k, "wf-atk-appr-post")
        line = (_lines_with(post, res_val) or [""])[-1]
        if not (r.ok and line and self._executed(line, k)
                and not self._executed(pre_line, k)):
            return None, {"verdict": "no_proof", "status": r.status,
                          "note": "unapproved object was not executable"}
        f = self._finding(
            "business_logic_approval_bypass", executor.action, res_name,
            Evidence("approval_not_enforced",
                     f"object {res_val} was EXECUTED by {self._path_of(executor.action)} "
                     f"without the approving step {self._path_of(k.steps[ai].action)} ever "
                     f"running — its state before the attack was "
                     f"'{pre_line.strip()[:80] or 'created, never approved'}' and after "
                     f"'{line.strip()[:120]}' — the approval gate is not enforced "
                     "server-side", r.request_id),
            f"never-approved object executed: '{line.strip()[:100]}'",
            state_before=(pre_line.strip()[:120] or
                          f"{res_val} created, approval step never ran"),
            state_after=line.strip()[:120],
            proof={"rule": "state-flip-executed",
                   "obs": {"ok": r.ok, "pre": pre, "post": post, "marker": res_val,
                           "exec_words": k.exec_added}})
        return f, {"verdict": "verified", "status": r.status,
                   "object": res_val,
                   "skipped_step": self._path_of(k.steps[ai].action)}

    @staticmethod
    def _atk_rollback_abuse_applicable(k: FlowKnowledge) -> str:
        if not k.rollback_paths:
            return "no rollback-vocabulary path in this flow"
        if not k.resource_params or len(k.steps) < 2:
            return "no resource linkage"
        return ""

    def _atk_rollback_abuse(self, k: FlowKnowledge, engine,
                            entry_fields) -> tuple[Finding | None, dict]:
        """12. ROLLBACK ABUSE — the object is rolled back to an earlier state
        (reopening its values), then executed with a TAMPERED value. Verified
        iff the executed oracle line carries the tamper canary: rollback
        reopens approved values for modification without re-approval."""
        res_name = next(iter(k.resource_params))
        # walk everything before the FINAL step -> pending = final form with
        # the fresh, fully-approved object
        pending, res_val = self._walk_to_producer(k, engine, flow_tag="rollback-abuse")
        if pending is None or not res_val:
            return None, {"verdict": "no_proof", "note": "walk to final step failed"}
        rollback_action = k.rollback_paths[0]
        rb_fields = self._token_refresh(
            [(n, res_val if n == res_name else v) for n, v in self._synth_fields(pending)],
            entry_fields)
        r_rb = self._post(engine, rollback_action, rb_fields, "wf-atk-rb-rollback")
        mid = self._oracle(engine, k, "wf-atk-rb-mid")
        mid_line = (_lines_with(mid, res_val) or [""])[-1]
        if not (r_rb.ok and res_val in mid):
            return None, {"verdict": "no_proof", "status": r_rb.status,
                          "note": "rollback path did not move the object"}
        # execute the rolled-back object with the TAMPERED value
        fields = self._token_refresh(
            [(n, CANARY_TAMPER if _is_amount(n) else v)
             for n, v in self._synth_fields(pending)], entry_fields)
        r = self._post(engine, pending["action"], fields, "wf-atk-rb-exec")
        post = self._oracle(engine, k, "wf-atk-rb-post")
        line = (_lines_with(post, res_val) or [""])[-1]
        if not (r.ok and line and CANARY_TAMPER in line and self._executed(line, k)):
            return None, {"verdict": "no_proof", "status": r.status,
                          "note": "rolled-back object not executable with a tampered value"}
        f = self._finding(
            "business_logic_rollback_abuse", pending["action"], res_name,
            Evidence("rollback_reopens_values",
                     f"object {res_val} was rolled back via "
                     f"{self._path_of(rollback_action)} (oracle line "
                     f"'{mid_line.strip()[:80]}') and then EXECUTED with the TAMPERED "
                     f"value ({CANARY_TAMPER}) replacing the approved one — oracle line "
                     f"'{line.strip()[:120]}' — rollback reopens approved values without "
                     "re-approval", r.request_id),
            f"rolled-back object executed with a new value: '{line.strip()[:100]}'",
            state_before=mid_line.strip()[:120],
            state_after=line.strip()[:120],
            proof={"rule": "line-match",
                   "obs": {"ok": r.ok, "post": post, "marker": res_val,
                           "must_contain": CANARY_TAMPER, "must_not_contain": "",
                           "exec_words": k.exec_added}})
        return f, {"verdict": "verified", "status": r.status,
                   "rollback": self._path_of(rollback_action)}

    # -------------------------------------------------- run
    def run(self, endpoints: list, main_engine, scope, bus, auth_profile,
            authz_sessions: dict | None = None, timeout: float = 12.0,
            logic_active: bool = False) -> dict:
        """Phase 58 entry point. Learning always runs (when a form session
        exists); the attack battery only with logic_active=True."""
        stats = {"enabled": True, "logic_active": logic_active,
                 "clusters_tried": 0, "flows_learned": 0, "attacks": 0,
                 "verified": 0, "skipped": [], "requests": 0}
        findings: list[Finding] = []
        flows: list[FlowKnowledge] = []
        if auth_profile is None or getattr(auth_profile, "mode", "form") != "form":
            stats.update(enabled=False, skipped=["no_form_session"])
            return {"findings": findings, "stats": stats, "flows": flows}
        self._main_engine = main_engine
        login_urls = {getattr(auth_profile, "login_url", ""),
                      getattr(auth_profile, "action_url", "")}
        clusters = self._cluster_members(endpoints, login_urls)
        ranked = sorted(((d, m) for d, m in clusters.items() if self._eligible(m)),
                        key=lambda t: (-self._score(t[0], t[1])[0],
                                       -self._score(t[0], t[1])[1], t[0]))
        for directory, members in ranked[: self.cfg.max_clusters]:
            stats["clusters_tried"] += 1
            k = self.learn(directory, members, main_engine)
            if k.drop_reason:
                stats["skipped"].append(f"{directory}:{k.drop_reason}")
                continue
            # privilege baselines under the PRIMARY session: an option broken
            # for everyone is a bug, not an escalation — never reported as one.
            res_name = next(iter(k.resource_params), "")
            for fname, opt, label in k.priv_options:
                pre = self._oracle(main_engine, k, "wf-base-pre")
                bsteps, _, _, _ = self._walk(members, main_engine,
                                             option_overrides={fname: opt})
                post = self._oracle(main_engine, k, "wf-base-post")
                fresh = self._walk_resource(bsteps, res_name, directory)
                line = (_lines_with(post, fresh) or [""])[-1] if fresh else ""
                k.priv_baselines[opt] = bool(fresh and opt in line
                                             and self._executed(line, k))
            stats["flows_learned"] += 1
            flows.append(k)
            # v4.1.0: restricted-branch baselines (the unauthorized-branch
            # attack needs the branch FUNCTIONAL under the primary identity;
            # an option broken for everyone is a bug, not an escalation).
            # Zero cost on flows without restriction-declared branches.
            baselined = {opt for _, opt, _ in k.priv_options}
            for br in k.branches:
                if not br.get("restricted") or br["value"] in baselined:
                    continue
                pre = self._oracle(main_engine, k, "wf-base-pre")
                bsteps, _, _, _ = self._walk(members, main_engine,
                                             option_overrides={br["field"]: br["value"]})
                post = self._oracle(main_engine, k, "wf-base-post")
                fresh = self._walk_resource(bsteps, res_name, directory)
                line = (_lines_with(post, fresh) or [""])[-1] if fresh else ""
                k.priv_baselines[br["value"]] = bool(
                    fresh and br["value"] in line and self._executed(line, k))
            # rebuild the graph now that baselines exist (belief upgrade:
            # exercised options become 'observed') — pure projection, zero IO
            k.graph = build_graph(k)
            # v4.1.0: restricted-branch baselines (the unauthorized-branch
            # attack needs the branch FUNCTIONAL under the primary identity;
            # an option broken for everyone is a bug, not an escalation).
            # Zero cost on flows without restriction-declared branches.
            baselined = {opt for _, opt, _ in k.priv_options}
            for br in k.branches:
                if not br.get("restricted") or br["value"] in baselined:
                    continue
                pre = self._oracle(main_engine, k, "wf-base-pre")
                bsteps, _, _, _ = self._walk(members, main_engine,
                                             option_overrides={br["field"]: br["value"]})
                post = self._oracle(main_engine, k, "wf-base-post")
                fresh = self._walk_resource(bsteps, res_name, directory)
                line = (_lines_with(post, fresh) or [""])[-1] if fresh else ""
                k.priv_baselines[br["value"]] = bool(
                    fresh and br["value"] in line and self._executed(line, k))
            # rebuild the graph now that baselines exist (belief upgrade:
            # exercised options become 'observed') — pure projection, zero IO
            k.graph = build_graph(k)
        if not logic_active:
            stats["requests"] = self.requests
            return {"findings": findings, "stats": stats, "flows": flows}
        # ---- attack battery (explicit opt-in): fresh session per manipulation.
        # The budget is PER FLOW (the five invariants are a flow-sized battery —
        # a global cap let the first flow consume the whole budget and starved
        # the rest: live-caught in benchmark trial 3, duplicate+privilege FN).
        # v4.0.0: the three cross-identity manipulations join the battery; a
        # manipulation whose OBSERVABLE PRECONDITION is absent (no shared
        # object visibility / no rollback path / no foreign-typed object) is a
        # loud skip and does NOT consume attack budget — it was never runnable.
        for k in flows:
            flow_attacks = 0
            # v4.1.0 gated battery: structurally-absent manipulations are
            # loud zero-request skips logged BEFORE any fresh session exists
            for name, gate in (("branch_bypass", self._atk_branch_bypass_applicable),
                               ("approval_bypass", self._atk_approval_bypass_applicable),
                               ("rollback_abuse", self._atk_rollback_abuse_applicable)):
                reason = gate(k)
                if reason:
                    detail = {"verdict": "skipped", "note": reason,
                              "precondition": True, "attack": name, "flow": k.cluster}
                    self.log.append(detail)
                    stats["skipped"].append(f"{k.cluster}:{name}:{reason[:60]}")
            for name, atk in (("step_bypass", self._atk_bypass),
                              ("out_of_order", self._atk_out_of_order),
                              ("value_tamper", self._atk_tamper),
                              ("duplicate", self._atk_duplicate),
                              ("branch_bypass", self._atk_branch_bypass),
                              ("approval_bypass", self._atk_approval_bypass),
                              ("rollback_abuse", self._atk_rollback_abuse),
                              ("cross_state", self._atk_cross_state),
                              ("cross_object", self._atk_cross_object)):
                if flow_attacks >= self.cfg.max_flow_attacks:
                    stats["skipped"].append(f"{k.cluster}:attack_budget")
                    break
                # v4.1.0: precondition gate BEFORE the fresh session — a
                # structurally-absent attack must never cost a login
                gate = {"branch_bypass": self._atk_branch_bypass_applicable,
                        "approval_bypass": self._atk_approval_bypass_applicable,
                        "rollback_abuse": self._atk_rollback_abuse_applicable}.get(name)
                if gate is not None:
                    reason = gate(k)
                    if reason:
                        stats["skipped"].append(f"{k.cluster}:{name}:{reason[:60]}")
                        continue
                if not self._gate(k, name):
                    stats["skipped"].append(f"{k.cluster}:{name}:planner_blocked")
                    continue
                eng = self._fresh_session(scope, bus, auth_profile, timeout)
                if eng is None:
                    stats["skipped"].append(f"{k.cluster}:fresh_login_failed")
                    continue
                entry_fields = []
                r = self._get(eng, k.entry, "wf-atk-entry")
                if not r.error:
                    forms = self._in_cluster_forms(r.body or "", k.entry, k.cluster)
                    entry_fields = self._synth_fields(forms[0]) if forms else []
                if not entry_fields:
                    stats["skipped"].append(f"{k.cluster}:entry_form_lost")
                    continue
                f, detail = atk(k, eng, entry_fields)
                detail.update(attack=name, flow=k.cluster)
                self.log.append(detail)
                if detail.get("precondition"):
                    # the manipulation was structurally unrunnable on this flow
                    # (no shared visibility / no rollback path / no foreign
                    # object) — an honest negative, not an attack that ran
                    stats["skipped"].append(f"{k.cluster}:{name}:"
                                             + detail.get("note", "precondition_absent")[:60])
                    continue
                flow_attacks += 1
                stats["attacks"] += 1
                if f:
                    findings.append(f)
                    stats["verified"] += 1
            # privilege + cross-user: need a strictly lower-privilege logged-in session
            lows = sorted((s for s in (authz_sessions or {}).values()
                           if s.get("rank", 3) > 0),
                          key=lambda s: s["account"].name)
            if not lows:
                stats["skipped"].append(f"{k.cluster}:no_lower_privilege_session")
            else:
                low = lows[0]
                entry_fields = []
                r = self._get(low["engine"], k.entry, "wf-atk-priv-entry")
                if not r.error:
                    forms = self._in_cluster_forms(r.body or "", k.entry, k.cluster)
                    entry_fields = self._synth_fields(forms[0]) if forms else []
                if entry_fields and self._gate(k, "privilege"):
                    f, detail = self._atk_privilege(k, low["engine"], entry_fields,
                                                    low["account"].role)
                    detail.update(attack="privilege", flow=k.cluster)
                    self.log.append(detail)
                    stats["attacks"] += 1
                    if f:
                        findings.append(f)
                        stats["verified"] += 1
                elif entry_fields:
                    stats["skipped"].append(f"{k.cluster}:privilege:planner_blocked")
                else:
                    stats["skipped"].append(f"{k.cluster}:low_entry_form_lost")
                # ---- v4.1.0 unauthorized branch: a restriction-declared branch
                # (membership/verification vocabulary) executed by the
                # lower-privilege identity mid-walk
                reason = self._atk_unauth_branch_applicable(k)
                if reason:
                    stats["skipped"].append(f"{k.cluster}:unauthorized_branch:{reason[:60]}")
                    self.log.append({"verdict": "skipped", "note": reason,
                                     "precondition": True, "attack": "unauthorized_branch",
                                     "flow": k.cluster})
                elif entry_fields:
                    if not self._gate(k, "unauthorized_branch"):
                        stats["skipped"].append(f"{k.cluster}:unauthorized_branch:planner_blocked")
                    else:
                        f, detail = self._atk_unauthorized_branch(k, low["engine"], entry_fields,
                                                                  low["account"].role)
                        detail.update(attack="unauthorized_branch", flow=k.cluster)
                        self.log.append(detail)
                        if detail.get("precondition"):
                            stats["skipped"].append(
                                f"{k.cluster}:unauthorized_branch:"
                                + detail.get("note", "precondition_absent")[:60])
                        else:
                            stats["attacks"] += 1
                            if f:
                                findings.append(f)
                                stats["verified"] += 1
                # ---- v4.0.0 cross-user: identity B executes identity A's object.
                # A mints on a FRESH primary session; B (the low-privilege
                # identity) executes it with B's own tokens.
                if flow_attacks < self.cfg.max_flow_attacks \
                        and self._gate(k, "cross_user"):
                    eng_a = self._fresh_session(scope, bus, auth_profile, timeout)
                    if eng_a is None:
                        stats["skipped"].append(f"{k.cluster}:fresh_login_failed")
                    else:
                        low_entry = entry_fields or []
                        if not low_entry:
                            stats["skipped"].append(f"{k.cluster}:low_entry_form_lost")
                        else:
                            f, detail = self._atk_cross_user(k, eng_a, low_entry,
                                                             low["engine"],
                                                             low["account"].role)
                            detail.update(attack="cross_user", flow=k.cluster)
                            self.log.append(detail)
                            if detail.get("precondition"):
                                stats["skipped"].append(
                                    f"{k.cluster}:cross_user:"
                                    + detail.get("note", "precondition_absent")[:60])
                            else:
                                flow_attacks += 1
                                stats["attacks"] += 1
                                if f:
                                    findings.append(f)
                                    stats["verified"] += 1
                elif flow_attacks < self.cfg.max_flow_attacks:
                    stats["skipped"].append(f"{k.cluster}:cross_user:planner_blocked")
        stats["requests"] = self.requests
        stats["attack_log"] = self.log
        return {"findings": findings, "stats": stats, "flows": flows}

    # -------------------------------------------------- reporting projection
    @staticmethod
    def flow_summary(k: FlowKnowledge) -> dict:
        return {
            "cluster": k.cluster,
            "entry": urllib.parse.urlsplit(k.entry).path,
            "steps": [{"action": urllib.parse.urlsplit(s.action).path,
                       "method": "POST"} for s in k.steps],
            "resource_params": sorted(k.resource_params),
            "state_oracle": urllib.parse.urlsplit(k.oracle_url).path,
            "execution_markers": {"gained": k.exec_added, "lost": k.exec_removed},
            "privilege_declared_options": [{"field": f, "value": v, "label": l}
                                           for f, v, l in k.priv_options],
            "rollback_paths": [urllib.parse.urlsplit(a).path
                                for a in k.cancel_paths],
            # ---- v4.1.0 Workflow Graph 2.0 projection
            "branches": [{"field": b["field"], "value": b["value"],
                          "label": b["label"], "class": (
                              "privileged" if b["privileged"] else
                              "restricted" if b["restricted"] else "open"),
                          "functional": k.priv_baselines.get(b["value"], None)}
                         for b in k.branches],
            "branch_transfer": dict(k.branch_transfer) if k.branch_transfer else None,
            "approval_step": (urllib.parse.urlsplit(k.steps[k.approval_idx].action).path
                              if k.approval_idx >= 0 else None),
            "cancel_paths": [urllib.parse.urlsplit(a).path
                              for a in k.cancel_paths
                              if a not in k.rollback_paths],
            "rollback_only_paths": [urllib.parse.urlsplit(a).path
                                    for a in k.rollback_paths],
            "state_transitions": [f"{s.get('before', '') or '-'} -> {s.get('after', '') or '-'}"
                                   for s in k.step_states],
            "graph": k.graph,
        }
