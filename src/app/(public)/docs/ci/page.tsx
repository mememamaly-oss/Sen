"use client";

// P2-F: public CI integration guide — mirrors the shipped files exactly
// (.github/workflows/ci.yml in this repo + integrations/gitlab-ci template).

import { GitBranch } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useI18n } from "@/lib/ui/i18n";

const GH_ACTION = `# .github/workflows/ci.yml — the single-file pipeline this repo runs
# (quality wall + a real fixture scan + compliance drift guard).
on:
  push: { branches: ["**"] }
  pull_request:
jobs:
  web: # SaaS app on a real postgres service container
    services:
      postgres:
        image: postgres:17-alpine
        env: { POSTGRES_PASSWORD: postgres, POSTGRES_DB: sentinel }
        ports: ["5432:5432"]
        options: >-
          --health-cmd "pg_isready -U postgres" --health-interval 5s
          --health-timeout 3s --health-retries 12
    env:
      DATABASE_URL: postgresql://postgres:postgres@localhost:5432/sentinel
    steps:
      - uses: actions/checkout@v4
      - run: bunx prisma migrate deploy
      - run: bash scripts/run_integration_tests.sh`;

const GITLAB = `# your .gitlab-ci.yml — include the shipped template:
include:
  - project: "mememamaly-oss/Sen"
    ref: main
    file: "integrations/gitlab-ci/sen-scan.gitlab-ci.yml"

# then anywhere in your pipeline:
sentinel:scan:
  extends: .sentinel:scan
  variables:
    SENTINEL_TARGET_URL: "https://staging.example.internal"`;

export default function CiDocsPage() {
  const { t } = useI18n();
  return (
    <article className="max-w-3xl" dir="auto">
      <h1 className="flex items-center gap-2 text-2xl font-extrabold tracking-tight">
        <GitBranch className="size-5 text-primary" aria-hidden /> {t("docs.ci")}
      </h1>
      <p className="mt-2 text-sm leading-6 text-muted-foreground" dir="ltr">
        One GitHub workflow file + a GitLab CI template — developers are the real
        market gate, so the scanner ships as CI first.
      </p>

      <section className="mt-6">
        <h2 className="text-sm font-extrabold" dir="ltr">GitHub Actions</h2>
        <p className="mt-2 text-xs text-muted-foreground" dir="ltr">
          The repo itself runs <code>.github/workflows/ci.yml</code> — one YAML
          file: lint + typecheck + unit/integration tests on a real PostgreSQL
          service container, engine doctor + python suite, secret scan, a real
          scan of the bundled fixture with report artifacts, and a compliance
          drift guard. Copy it as your starting point:
        </p>
        <pre
          className="num mt-3 overflow-auto rounded-xl border bg-muted/50 p-4 text-[11.5px] leading-5"
          dir="ltr"
        >
          {GH_ACTION}
        </pre>
      </section>

      <section className="mt-8">
        <h2 className="text-sm font-extrabold" dir="ltr">GitLab CI</h2>
        <pre
          className="num mt-3 overflow-auto rounded-xl border bg-muted/50 p-4 text-[11.5px] leading-5"
          dir="ltr"
        >
          {GITLAB}
        </pre>
      </section>

      <div className="mt-8 flex flex-wrap gap-2">
        <Badge variant="outline" dir="ltr" className="num">CI exit contract: 0 / 1 policy / 2 incomplete / 3 engine</Badge>
        <Badge variant="outline" dir="ltr" className="num">SARIF 2.1.0 · HTML · JSON · EXECUTIVE · GLASS</Badge>
      </div>
    </article>
  );
}
