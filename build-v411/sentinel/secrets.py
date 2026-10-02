"""SENTINEL v2.8.0 — Credential Exposure Engine (Phase 56).

Secrets detection over the responses the scan ALREADY receives (passive
baselines — zero extra requests at detection time). Three professional
disciplines beyond naive pattern matching:

  1. CLASSIFICATION — every match is a named credential class with its own
     severity (private key > live vendor key > credential-bearing URI > token
     in an unexpected place), not a generic "secret found".

  2. MASKING / DATA MINIMIZATION — raw secret values NEVER enter findings,
     events or reports. Evidence carries a deterministic mask (prefix + length)
     — enough to identify and dedupe the leak, never enough to reuse it.

  3. HONESTY GATES —
       * context gate: an app ISSUING its own tokens on authentication
         endpoints (login/jwt/oauth paths) is normal behavior, not exposure;
         jwt/generic classes are suppressed there.
       * span suppression: a vendor-specific match (ghp_..., AKIA...) also
         overlapping a generic key=value pattern is reported once, by its
         specific class — never double-counted.
       * placeholder rejection: masked-out values ("AKIA****", "xxxxx",
         "${VAR}", "<your-key>") are configuration hygiene, not leaks.

Findings are verification-gated like every active class (VR-19: a FRESH
fetch of the endpoint must expose the SAME credential class again —
reproducible exposure, not a one-off accident).
"""
from __future__ import annotations
import re

from .core import Endpoint, Evidence, Finding, FindingStatus, Severity


# ---------------------------------------------------------------- signatures
# (class, compiled regex, severity, description). Ordered: specific first.
SIGS: list[tuple[str, re.Pattern, Severity, str]] = [
    ("private_key",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
     Severity.CRITICAL, "Private key material exposed in a response"),
    ("aws_access_key",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     Severity.CRITICAL, "AWS access key ID exposed"),
    ("stripe_live_key",
     re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{16,}\b"),
     Severity.CRITICAL, "Stripe live-mode key exposed"),
    ("google_api_key",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
     Severity.HIGH, "Google API key exposed"),
    ("github_token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
     Severity.HIGH, "GitHub token exposed"),
    ("slack_token",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
     Severity.HIGH, "Slack token exposed"),
    ("db_connection_uri",
     re.compile(r"\b(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|redis|amqp)://"
                r"[^\s:@/\"']+:[^\s@/\"']+@[^\s\"']+"),
     Severity.HIGH, "Database connection URI with embedded credentials"),
    ("jwt_token",
     # NOTE: no trailing \b — the signature segment may be EMPTY (alg=none), and
     # a word boundary after a bare "." followed by a quote does not exist
     # (live-caught in the unit gate: the alg=none shape never matched).
     re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"),
     Severity.MEDIUM, "JWT token exposed in a non-authentication response"),
    ("generic_secret_assignment",
     re.compile(r"\b(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?key|"
                r"secret[_-]?key|password|passwd|api[_-]?token|auth[_-]?token)\b"
                r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9+/_\-]{12,})"),
     Severity.HIGH, "Hard-coded secret assignment (key=value) in a response"),
]

# classes suppressed on authentication-shaped endpoints (the app issuing its
# own tokens where tokens are SUPPOSED to be issued is not a leak)
CONTEXT_GATED = {"jwt_token", "generic_secret_assignment"}
AUTHISH_WORDS = ("login", "signin", "sign-in", "auth", "token", "jwt",
                 "session", "oauth", "credential", "apikey", "api-key")

# generic-class values that are placeholders, not secrets
PLACEHOLDER_RE = re.compile(r"^(?:x+|\*+|\.+$|<{2,.*>{2,}|\$\{[^}]*\}|%[^%]*%|"
                            r"your[_-a-z]*|change[_-]?me|insert[_-a-z]*|"
                            r"placeholder|redacted|hidden|masked)$", re.I)


def mask(value: str) -> str:
    """Deterministic, non-reversible-enough evidence mask: 4-char prefix +
    total length. Identifies and dedupes the leak without reusable material."""
    v = value or ""
    return f"{v[:4]}…({len(v)} chars)"


class SecretsScanner:
    """Pure function over (endpoint, response) -> candidate findings."""

    def __init__(self, signatures: list | None = None):
        self.signatures = signatures or SIGS

    @staticmethod
    def _context_gated(url: str) -> bool:
        low = (url or "").lower()
        return any(w in low for w in AUTHISH_WORDS)

    def scan(self, ep: Endpoint, resp, capture=None) -> list[Finding]:
        """One candidate per (credential class, endpoint) — multiple hits of the
        SAME class on one endpoint are a single finding (dedup merges them
        anyway); different classes are distinct findings with distinct keys.

        capture (Phase 57): optional callable
            (cls, raw, location, request_id, severity) -> record id | None
        wired by the orchestrator when a Credential Vault is armed. The raw
        value flows STRAIGHT into the vault (encrypted at rest) and never
        enters the Finding; the evidence carries the mask plus the vault
        record reference. capture=None keeps the exact v2.8.0 behavior:
        raw dropped immediately, mask-only evidence."""
        if resp is None or getattr(resp, "error", "") or not getattr(resp, "status", 0):
            return []
        body = resp.body or ""
        header_blob = " ".join(f"{k}: {v}" for k, v in sorted((resp.headers or {}).items()))
        haystack = body + "\n" + header_blob
        if not haystack.strip():
            return []
        gated = self._context_gated(ep.url)
        out: list[Finding] = []
        taken_spans: list[tuple[int, int]] = []
        for cls, rx, sev, desc in self.signatures:
            if gated and cls in CONTEXT_GATED:
                continue
            hit = None
            for m in rx.finditer(haystack):
                # placeholder values are hygiene, not leaks (generic class only
                # — a placeholder can never match the vendor formats anyway)
                if cls == "generic_secret_assignment" and PLACEHOLDER_RE.match(m.group(1)):
                    continue
                # span suppression: an already-reported, more specific class
                # covering this exact span wins
                s, e = m.span(0)
                if any(s < e2 and s2 < e for s2, e2 in taken_spans):
                    continue
                hit = m
                taken_spans.append((s, e))
                break                       # one finding per class per endpoint
            if hit is None:
                continue
            raw = hit.group(1) if hit.groups() else hit.group(0)
            loc = "body" if hit.start(0) <= len(body) else "headers"
            vault_ref = None
            if capture is not None:
                try:
                    vault_ref = capture(cls, raw, loc, resp.request_id,
                                        sev.value)
                except Exception:
                    vault_ref = None   # a vault failure must never kill the scan
            note = (f"encrypted in the credential vault as {vault_ref}"
                    if vault_ref else "raw value intentionally not retained")
            out.append(Finding(
                "credential_exposure", sev, ep.url, cls, ep.method or "GET",
                [Evidence(f"credential:{cls}",
                          f"{desc} — class={cls}, evidence {mask(raw)} "
                          f"(masked; {note}), "
                          f"location={loc}",
                          resp.request_id)],
                status=FindingStatus.CANDIDATE))
        return out
