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
    max_flow_attacks: int = 8    # attack manipulations PER FLOW (eight
                                  # invariants; precondition-absent cross
                                  # manipulations do NOT consume this budget)


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
    cancel_paths: list = field(default_factory=list)     # rollback-shaped form actions seen in landings
    drop_reason: str = ""                           # honest-negative reason


CANCEL_RE = re.compile(r"/(cancel|rollback|revert|reject|void|abort)(/|$|\.)", re.I)
FOREIGN_ID_RE = re.compile(r"\b([A-Z]{2,6}-\d{2,6})\b")


def _resource_prefix(value: str) -> str:
    m = re.match(r"^([A-Za-z]+)-\d+$", value or "")
    return (m.group(1) if m else "").upper()


# ------------------------------------------------------------------ the engine
class WorkflowEngine:
    """Learn multi-step flows, then test the five business-logic invariants."""

    def __init__(self, cfg: WorkflowConfig | None = None):
        self.cfg = cfg or WorkflowConfig()
        self.requests = 0            # requests on PRIVATE engines (added to stats)
        self.log: list[dict] = []    # auditable trail of every manipulation

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

    @staticmethod
    def _finding(vtype: str, url: str, param: str, evidence: Evidence,
                 notes: str, authz_context: str = "",
                 state_before: str = "", state_after: str = "") -> Finding:
        f = Finding(vtype, Severity.HIGH, url, param, "POST", [evidence],
                    status=FindingStatus.CANDIDATE)
        f.verification = Verification(method="oracle:workflow-state-delta",
                                      passed=True, confidence=0.9, rounds=1, notes=notes)
        f.status = FindingStatus.VERIFIED
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
            state_after=new[0].strip()[:120])
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
            state_after=lines[-1].strip()[:120])
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
            state_after=line.strip()[:120])
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
            state_after=f"occurrences {n_post}: '{((_lines_with(post, res_val) or [''])[-1]).strip()[:100]}'")
        return f, {"verdict": "verified", "status": r.status,
                   "executions": f"{n_mid}->{n_post}"}

    def _walk_to_producer(self, k: FlowKnowledge, engine):
        """Partial walk up to (excluding) the final step; returns
        (pending_form, res_val) where pending_form is the FINAL step's form
        carrying the fresh resource id, or (None, '')."""
        steps, _, pending, _ = self._walk(k.members, engine,
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
        pending, res_val = self._walk_to_producer(k, engine_a)
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
            state_after=line.strip()[:120])
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
            state_after=lines[-1].strip()[:120])
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
        pending, res_val = self._walk_to_producer(k, engine)
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
            state_after=line.strip()[:120])
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
            state_after=line.strip()[:120])
        return f, {"verdict": "verified", "role": low_role, "option": opt}

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
            for name, atk in (("step_bypass", self._atk_bypass),
                              ("out_of_order", self._atk_out_of_order),
                              ("value_tamper", self._atk_tamper),
                              ("duplicate", self._atk_duplicate),
                              ("cross_state", self._atk_cross_state),
                              ("cross_object", self._atk_cross_object)):
                if flow_attacks >= self.cfg.max_flow_attacks:
                    stats["skipped"].append(f"{k.cluster}:attack_budget")
                    break
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
                if entry_fields:
                    f, detail = self._atk_privilege(k, low["engine"], entry_fields,
                                                    low["account"].role)
                    detail.update(attack="privilege", flow=k.cluster)
                    self.log.append(detail)
                    stats["attacks"] += 1
                    if f:
                        findings.append(f)
                        stats["verified"] += 1
                else:
                    stats["skipped"].append(f"{k.cluster}:low_entry_form_lost")
                # ---- v4.0.0 cross-user: identity B executes identity A's object.
                # A mints on a FRESH primary session; B (the low-privilege
                # identity) executes it with B's own tokens.
                if flow_attacks < self.cfg.max_flow_attacks:
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
        }
