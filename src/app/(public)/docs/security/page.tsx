"use client";

// P2-E: public security posture page — facts that are verifiable in-repo,
// no marketing, no invented contacts.

import { Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useI18n } from "@/lib/ui/i18n";

export default function SecurityDocsPage() {
  const { t } = useI18n();
  const facts: Array<[string, string[]]> = [
    [
      "Platform",
      [
        "scrypt password storage (no plaintext, no reversible hashes)",
        "login rate limiting (per-email + per-IP) and timing equalization for unknown accounts",
        "server-side session guard on every authenticated page; RBAC membership checks on every API route",
        "append-only audit log (no deletes, no edits) — every action attributable",
        "SSRF policy: private egress only for the managed demo target or explicit operator lab mode; the engine re-validates every connection and fails closed",
      ],
    ],
    [
      "Engine",
      [
        "verification-gated: a finding is only exported after an independent replay reproduces it",
        "deterministic seeds and PRNG isolation — same target, same findings (documented in tests/test_repro_prng_isolation.py)",
        "reports are signed (Ed25519); RFC 8032 test vectors pinned",
        "credential vault: raw values encrypted at rest, reveal requires an authorized key and is audit-logged",
        "the honesty contract: untested surfaces are listed with reasons; rejected candidates are exported for audit",
      ],
    ],
  ];

  return (
    <article className="max-w-3xl">
      <h1 className="flex items-center gap-2 text-2xl font-extrabold tracking-tight">
        <Zap className="size-5 text-primary" aria-hidden /> {t("docs.security")}
      </h1>
      <p className="mt-2 text-sm leading-6 text-muted-foreground" dir="ltr">
        Verifiable posture — every claim below maps to code and tests in the
        repository. SECURITY_AUDIT.md and KNOWN_LIMITATIONS.md are tracked
        in-repo and kept honest, including what the tool does NOT do.
      </p>

      {facts.map(([group, items]) => (
        <section key={group} className="mt-6">
          <h2 className="text-sm font-extrabold" dir="ltr">{group}</h2>
          <ul className="mt-2 space-y-1.5" dir="ltr">
            {items.map((it) => (
              <li key={it} className="flex gap-2 text-xs leading-6 text-muted-foreground">
                <span className="mt-2 size-1.5 shrink-0 rounded-full bg-primary" aria-hidden />
                <span>{it}</span>
              </li>
            ))}
          </ul>
        </section>
      ))}

      <div className="mt-8 flex flex-wrap gap-2" dir="ltr">
        <Badge variant="outline" className="num">19-axis security audit (2026-10-21) — RED → fixed</Badge>
        <Badge variant="outline" className="num">integrity pass 2026-10-30 · gitleaks clean</Badge>
      </div>
    </article>
  );
}
