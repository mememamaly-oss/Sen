// ─────────────────────────────────────────────────────────────────────────────
// SENTINEL — PHASE 02 L1: UNIT TEST SUITE (spec §12/§13/§14/§20/§22/§23)
//
// Groups:
//   A. fixtures ×10        — expected nodes/edges/provenance/conflicts + golden twinHash
//   B. determinism ×3      — same input → same twinHash / IDs / counts / provenance
//   C. invariants          — INV-01..10 + INV-11..13 on every fixture + real data
//   D. equivalence gate    — no raw element lost (fixtures + real engine outputs)
//   E. adversarial         — no-hallucination: hostile inputs cannot force VERIFIED
//   F. malicious input     — HTML/script/SQL/long/dup/cyclic/invalid-provenance safety
//   G. performance         — 100 / 1k / 10k nodes, measured honestly
//
// Run: bun scripts/l1_twin_suite.ts
// Results → saas-data/l1-twin/l1_twin_unit_results.json   (exit 0 = all pass)
// ─────────────────────────────────────────────────────────────────────────────
import fs from "fs";
import path from "path";
import {
  ALL_FIXTURES, checkEquivalence, checkInvariants, normalizeTwin, why, verifiedClaimIsSound,
  type InvariantReport, type NormalizedTwin, type RawEngineResult,
} from "../src/lib/twin/index";

let PASS = 0;
let FAIL = 0;
const RESULTS: Record<string, unknown>[] = [];

function check(group: string, name: string, ok: boolean, detail = ""): boolean {
  PASS += ok ? 1 : 0;
  if (!ok) FAIL += 1;
  RESULTS.push({ group, name, status: ok ? "PASS" : "FAIL", detail: detail.slice(0, 400) });
  if (!ok) console.log(`  [FAIL] ${group}/${name} — ${detail.slice(0, 200)}`);
  return ok;
}

// ═══ A. FIXTURES ═════════════════════════════════════════════════════════════

interface FixtureExpectation {
  nodesMin?: number; edgesMin?: number;
  nodeTypes?: Record<string, number>;          // exact counts for selected types
  provenanceClaims?: Record<string, number>;   // exact claim-state counts
  conflicts?: number;
  knownUnknownsMin?: number;
}

const EXPECT: Record<string, FixtureExpectation> = {
  "complete-twin": {
    nodesMin: 30, edgesMin: 30,
    nodeTypes: { application: 1, host: 1, workflow: 1, workflow_step: 3, state: 2, branch: 1, api: 2, secret: 1 },
    provenanceClaims: { VERIFIED: 3, REFUTED: 1, UNKNOWN: 1 }, // 2 findings + 1 verified hyp / 1 refuted hyp / 1 untestable
    knownUnknownsMin: 1,
  },
  "partial-twin": { nodesMin: 3, edgesMin: 2, nodeTypes: { endpoint: 2 }, provenanceClaims: {} },
  "inferred-nodes": { nodesMin: 5, nodeTypes: { entity: 1, object: 1, hypothesis: 1 }, provenanceClaims: { UNKNOWN: 1 } },
  "verified-evidence": { nodeTypes: { finding: 1, evidence: 4 }, provenanceClaims: { VERIFIED: 1 } },
  "refuted-claim": { nodeTypes: { finding: 1 }, provenanceClaims: { REFUTED: 2 } },
  "unknown-state": { provenanceClaims: { UNKNOWN: 2 } }, // finding without passed verification + untestable hyp
  "missing-identity": { nodeTypes: { identity: 0 }, knownUnknownsMin: 1 },
  "missing-authorization": { nodeTypes: { role: 0, identity: 0 } },
  "blocked-boundary": { nodeTypes: { boundary: 2 } },
  "conflicting-evidence": { provenanceClaims: { CONFLICT: 2 }, conflicts: 2 },
  // supervisor ruling 2026-10-03: vacuous rejection preserves the verified
  // claim (priority over automatic demotion) — CONFLICT count is ZERO while
  // the conflict RECORD still exists (honest bookkeeping, INV-11-satisfied).
  "vacuous-rejection": { provenanceClaims: { VERIFIED: 1, REFUTED: 1, CONFLICT: 0 }, conflicts: 1 },
};

// Golden twinHashes — frozen determinism contract (fixture → sha256)
const GOLDEN: Record<string, string> = {
  "complete-twin": "f02c329cb57c63b74d06f4eb0ebe76d59769ca215331b66a93b0d4654b7a624a",
  "partial-twin": "f2ca6bd416b4f5fe1d43fefb2471b92b29fe2b7f457a693b498b0a01f7c3a9da",
  "inferred-nodes": "8a1ea5155de438f1e69c5ff43059873389a25e575593b09b278bc130c07af41b",
  "verified-evidence": "1b239754a35cd3068ddd2d951ee28d16da7769d82f0a6010e2cef95e74861e2b",
  "refuted-claim": "2f262b4ef7da0a2106f2b3d34ee0c1c288365c43ad73f26beaf7830e2b47785b",
  "unknown-state": "7a0f3a00ef887654f7445357322301071c17ea5b197fed899f1e1852efd8c136",
  "missing-identity": "a62c34a9c7033538832f5879deef34283f677cd1ed471fe1e984e360cf1c5590",
  "missing-authorization": "85d34e8beeeb3917eb2131d82af4b01d54388198abac03bd7474deac1eed487d",
  "blocked-boundary": "c80051adf06f3950b09c3b71f6cdd7222037787b3ae8c0ecad81f694e742f511",
  "conflicting-evidence": "14542bd1971990ad88e9e78b0c1dc370526915e4dd13b722b1d07418ba4e590c",
  "vacuous-rejection": "aa5def001f2de4449a99c68fa67ed832781de3fada9d8af43b9cfcba43a8884d",
};

function runFixture(name: string, raw: RawEngineResult): NormalizedTwin {
  const twin = normalizeTwin(raw);
  const inv = checkInvariants(twin, raw);
  const eq = checkEquivalence(raw, twin);
  check("fixtures", `${name}.invariants`, inv.pass, inv.violations.map((v) => `${v.invariant}:${v.detail}`).join("; "));
  check("fixtures", `${name}.equivalence`, eq.pass, eq.dimensions.filter((d) => d.missing.length).map((d) => `${d.dimension} missing ${d.missing.length}`).join("; "));
  const exp = EXPECT[name];
  if (exp) {
    if (exp.nodesMin) check("fixtures", `${name}.nodes>=${exp.nodesMin}`, twin.counts.nodes >= exp.nodesMin, `got ${twin.counts.nodes}`);
    if (exp.edgesMin) check("fixtures", `${name}.edges>=${exp.edgesMin}`, twin.counts.edges >= exp.edgesMin, `got ${twin.counts.edges}`);
    for (const [ty, c] of Object.entries(exp.nodeTypes ?? {})) {
      check("fixtures", `${name}.type[${ty}]=${c}`, (twin.counts.byNodeType[ty] ?? 0) === c, `got ${twin.counts.byNodeType[ty] ?? 0}`);
    }
    for (const [st, c] of Object.entries(exp.provenanceClaims ?? {})) {
      check("fixtures", `${name}.claim[${st}]=${c}`, twin.counts.claims[st as keyof typeof twin.counts.claims] === c,
        `got ${JSON.stringify(twin.counts.claims)}`);
    }
    if (exp.conflicts !== undefined) check("fixtures", `${name}.conflicts=${exp.conflicts}`, twin.counts.conflicts === exp.conflicts, `got ${twin.counts.conflicts}`);
    if (exp.knownUnknownsMin) check("fixtures", `${name}.knownUnknowns>=${exp.knownUnknownsMin}`, twin.counts.knownUnknowns >= exp.knownUnknownsMin, `got ${twin.counts.knownUnknowns}`);
  }
  if (GOLDEN[name]) {
    check("fixtures", `${name}.goldenHash`, twin.twinHash === GOLDEN[name], `${twin.twinHash.slice(0, 16)} != ${GOLDEN[name].slice(0, 16)}`);
  }
  return twin;
}

console.log("═══ A. FIXTURES ═══");
const fixtureTwins = new Map<string, NormalizedTwin>();
for (const f of ALL_FIXTURES) {
  fixtureTwins.set(f.name, runFixture(f.name, f.build()));
  console.log(`  ${f.id} ${f.name}: nodes=${fixtureTwins.get(f.name)!.counts.nodes} hash=${fixtureTwins.get(f.name)!.twinHash.slice(0, 12)}…`);
}

// ═══ B. DETERMINISM ×3 ═══════════════════════════════════════════════════════

console.log("═══ B. DETERMINISM ×3 ═══");
for (const f of ALL_FIXTURES) {
  const raw = f.build();
  const t1 = normalizeTwin(raw);
  const t2 = normalizeTwin(raw);
  const t3 = normalizeTwin(raw);
  const hashOk = t1.twinHash === t2.twinHash && t2.twinHash === t3.twinHash;
  check("determinism", `${f.name}.twinHash×3`, hashOk, `${t1.twinHash.slice(0, 8)} ${t2.twinHash.slice(0, 8)} ${t3.twinHash.slice(0, 8)}`);
  const idsOk = JSON.stringify(t1.nodes.map((n) => n.id)) === JSON.stringify(t2.nodes.map((n) => n.id))
    && JSON.stringify(t2.nodes.map((n) => n.id)) === JSON.stringify(t3.nodes.map((n) => n.id));
  check("determinism", `${f.name}.nodeIds×3`, idsOk);
  const edgesOk = JSON.stringify(t1.edges.map((e) => e.id)) === JSON.stringify(t3.edges.map((e) => e.id));
  check("determinism", `${f.name}.edgeIds×3`, edgesOk);
  const countsOk = JSON.stringify(t1.counts) === JSON.stringify(t3.counts);
  check("determinism", `${f.name}.counts×3`, countsOk);
  const provOk = JSON.stringify([t1.counts.provenance, t1.counts.claims]) === JSON.stringify([t3.counts.provenance, t3.counts.claims]);
  check("determinism", `${f.name}.provenance×3`, provOk);
  const rawHashOk = t1.rawHash === t2.rawHash && t2.rawHash === t3.rawHash;
  check("determinism", `${f.name}.rawHash×3`, rawHashOk);
}

// ═══ C+D. REAL ENGINE OUTPUTS (read-only): invariants + equivalence ═════════

console.log("═══ C/D. REAL ENGINE OUTPUTS ═══");
const REAL_FILES = [
  "build-v411/results/benchmark.json",
  "build-v411/results/live_v41/ginjuice.json",
  "build-v411/results/live_v41/webgoat_auth.json",
  "build-v411/results/live_v41/juiceshop.json",
  // v4.2.0 live scans (real engine output, all four authorized targets)
  "build-v420/results/live_v420/testfire.json",
  "build-v420/results/live_v420/ginjuice.json",
  "build-v420/results/live_v420/testasp.json",
  "build-v420/results/live_v420/testaspnet.json",
  // v4.2.1 live scans (journal-enabled engine output)
  "build-v421/results/live_v421/testfire.json",
  "build-v421/results/live_v421/ginjuice.json",
  "build-v421/results/live_v421/testasp.json",
  "build-v421/results/live_v421/testaspnet.json",
  "build-v421/results/live_v421/gruyere.json",
];
for (const file of REAL_FILES) {
  if (!fs.existsSync(file)) { check("real", `${path.basename(file)}.exists`, false); continue; }
  const raw = JSON.parse(fs.readFileSync(file, "utf8")) as RawEngineResult;
  const twin = normalizeTwin(raw);
  const inv: InvariantReport = checkInvariants(twin, raw);
  const eq = checkEquivalence(raw, twin);
  check("real", `${path.basename(file)}.invariants`, inv.pass, inv.violations.map((v) => `${v.invariant}:${v.detail}`).join("; ").slice(0, 200));
  check("real", `${path.basename(file)}.equivalence`, eq.pass, eq.dimensions.filter((d) => d.missing.length).map((d) => `${d.dimension}:${d.missing.length}`).join("; "));
  // determinism on real data too
  check("real", `${path.basename(file)}.determinism`, normalizeTwin(raw).twinHash === twin.twinHash);
}

// ═══ E. ADVERSARIAL / NO-HALLUCINATION ═══════════════════════════════════════

console.log("═══ E. ADVERSARIAL ═══");
import {
  advGraphqlNoVuln, advWsNoAuthProof, advRoleNoIdentity, advObjectNoOwnership,
  advIncompleteWorkflow, advMissingEvidence,
  f01Complete, f05Refuted, f06Unknown, f09BlockedBoundary, f02Partial,
} from "../src/lib/twin/fixtures";

// E1: endpoint without finding — endpoint exists, NO finding node, NO VERIFIED claim
{
  const t = normalizeTwin(f02Partial());
  check("adversarial", "E1.endpoint_without_finding", (t.counts.byNodeType.finding ?? 0) === 0 && t.counts.claims.VERIFIED === 0 && (t.counts.byNodeType.endpoint ?? 0) === 2,
    `findings=${t.counts.byNodeType.finding ?? 0} verified=${t.counts.claims.VERIFIED}`);
}
// E2: GraphQL schema without verified vulnerability
{
  const t = normalizeTwin(advGraphqlNoVuln());
  const apis = t.nodes.filter((n) => n.type === "api");
  check("adversarial", "E2.gql_no_vuln", apis.length === 1 && apis[0].provenance === "OBSERVED" && t.counts.claims.VERIFIED === 0,
    `apis=${apis.length} claims=${JSON.stringify(t.counts.claims)}`);
}
// E3: WebSocket channel without auth proof — no fabricated AUTHENTICATES edge
{
  const t = normalizeTwin(advWsNoAuthProof());
  const authEdges = t.edges.filter((e) => e.type === "AUTHENTICATES");
  check("adversarial", "E3.ws_no_auth_proof", authEdges.length === 0 && (t.counts.byNodeType.api ?? 0) === 1,
    `authEdges=${authEdges.length}`);
}
// E4: role without authenticated identity — NO identity node, NO HAS_ROLE edge
{
  const t = normalizeTwin(advRoleNoIdentity());
  check("adversarial", "E4.role_no_identity", (t.counts.byNodeType.identity ?? 0) === 0 && t.edges.every((e) => e.type !== "HAS_ROLE") && (t.counts.byNodeType.role ?? 0) === 1,
    `identities=${t.counts.byNodeType.identity ?? 0} roles=${t.counts.byNodeType.role ?? 0}`);
}
// E5: object without ownership evidence — INFERRED object, no ownership relation
{
  const t = normalizeTwin(advObjectNoOwnership());
  const objs = t.nodes.filter((n) => n.type === "object");
  const ownerEdges = t.edges.filter((e) => e.type === "HAS_ROLE" || e.type === "AUTHENTICATES");
  check("adversarial", "E5.object_no_ownership", objs.length === 1 && objs[0].provenance === "INFERRED" && ownerEdges.length === 0,
    `objs=${objs.length} prov=${objs[0]?.provenance}`);
}
// E6: incomplete workflow — only observed steps, no fabricated states/branches
{
  const t = normalizeTwin(advIncompleteWorkflow());
  check("adversarial", "E6.incomplete_workflow", (t.counts.byNodeType.workflow_step ?? 0) === 1 && (t.counts.byNodeType.state ?? 0) === 0 && (t.counts.byNodeType.branch ?? 0) === 0,
    `steps=${t.counts.byNodeType.workflow_step ?? 0} states=${t.counts.byNodeType.state ?? 0}`);
}
// E7: branch undiscovered — no branch nodes when raw has none
{
  const t = normalizeTwin(f02Partial());
  check("adversarial", "E7.no_branch_nodes", (t.counts.byNodeType.branch ?? 0) === 0);
}
// E8: evidence missing — finding stays UNKNOWN, never VERIFIED (F06)
{
  const t = normalizeTwin(f06Unknown());
  const f = t.nodes.find((n) => n.type === "finding");
  check("adversarial", "E8.missing_evidence_stays_UNKNOWN", f?.claim?.state === "UNKNOWN" && f.claim.evidenceRefs.length === 0,
    `state=${f?.claim?.state}`);
}
// E9: boundary BLOCKED — boundary node carries the blocked state
{
  const t = normalizeTwin(f09BlockedBoundary());
  const bds = t.nodes.filter((n) => n.type === "boundary");
  check("adversarial", "E9.boundary_blocked", bds.length === 2 && bds.every((b) => b.attrs.state === "BLOCKED") && bds.every((b) => b.provenance === "OBSERVED"),
    `boundaries=${bds.length} states=${bds.map((b) => b.attrs.state).join(",")}`);
}
// E10: finding REFUTED — claim REFUTED + REFUTED_BY edge (F05)
{
  const t = normalizeTwin(f05Refuted());
  const f = t.nodes.find((n) => n.type === "finding");
  const refutedBy = t.edges.filter((e) => e.type === "REFUTED_BY");
  check("adversarial", "E10.finding_refuted", f?.claim?.state === "REFUTED" && refutedBy.length >= 1,
    `state=${f?.claim?.state} refutedBy=${refutedBy.length}`);
}
// E11: verified-vs-verified trap — hostile raw marks candidate verified WITHOUT engine verification
{
  const raw = advMissingEvidence();
  const t = normalizeTwin(raw);
  const f = t.nodes.find((n) => n.type === "finding");
  check("adversarial", "E11.no_verification_no_VERIFIED", f?.claim?.state === "UNKNOWN" && t.counts.claims.VERIFIED === 0,
    `state=${f?.claim?.state}`);
}
// E12: hostile provenance strings in raw are NEVER trusted
{
  const raw = f01Complete();
  const hostile = raw.findings![0] as unknown as Record<string, unknown>;
  hostile.belief = "definitely-verified-hacked";
  hostile.provenance = "VERIFIED-BY-ATTACKER";
  const t = normalizeTwin(raw);
  const badProv = t.nodes.filter((n) => !["OBSERVED", "INFERRED", "VERIFIED", "REFUTED", "UNKNOWN"].includes(n.provenance));
  // the finding claim must remain VERIFIED only because the real verification record says so
  const f = t.nodes.find((n) => n.type === "finding" && n.key === "F-f01aaa0001");
  check("adversarial", "E12.hostile_provenance_ignored", badProv.length === 0 && f?.claim?.state === "VERIFIED",
    `badProv=${badProv.length} state=${f?.claim?.state}`);
}
// E13 (2026-10-03): the why() VERIFIED gate is WIRED INTO THE PIPELINE —
// every node/edge construction goes through why(), and a VERIFIED answer
// without evidence refs is fail-closed there (was dead code before).
{
  const wBad = why("VERIFIED", "engine claims verified", ["stats.proofs[0]"]); // no evidenceRefs
  const wGood = why("VERIFIED", "resolution record observed", ["stats.reasoning:hypotheses[0]"], { evidenceRefs: ["evidence:hyp:H1"] });
  const wRefuted = why("REFUTED", "negation observed", ["rejected_candidates[0]"]); // REFUTED: explicit-only, no fabrication
  check("adversarial", "E13.verified_gate_fails_closed",
    wBad.provenance === "UNKNOWN" && wBad.downgradedFrom === "VERIFIED" && !wBad.evidenceRefs
      && wBad.reason.includes("[gate:"),
    `wBad=${JSON.stringify(wBad).slice(0, 120)}`);
  check("adversarial", "E13.verified_gate_passes_with_evidence",
    wGood.provenance === "VERIFIED" && (wGood.evidenceRefs?.length ?? 0) === 1 && verifiedClaimIsSound(wGood),
    `wGood=${JSON.stringify(wGood).slice(0, 120)}`);
  check("adversarial", "E13.refuted_not_fabricated",
    wRefuted.provenance === "REFUTED" && wRefuted.evidenceRefs === undefined && verifiedClaimIsSound(wRefuted),
    `wRefuted=${JSON.stringify(wRefuted).slice(0, 120)}`);
}
// E14 (2026-10-03): INV-05 runs on the STORED path (no raw) and catches tampering
{
  const raw = f01Complete();
  const t = normalizeTwin(raw);
  const stored = checkInvariants(t); // NO raw — the stored/service.ts path
  check("adversarial", "E14.inv05_stored_path_pass", stored.pass,
    stored.violations.map((x) => `${x.invariant}:${x.detail}`).join(";").slice(0, 200));
  // tamper 1: flip the finding's verification evidence node passed true -> false
  const tampered = JSON.parse(JSON.stringify(t)) as NormalizedTwin;
  const verNode = tampered.nodes.find((n) => n.type === "evidence" && n.attrs.kind === "verification" && n.attrs.passed === true);
  if (verNode) verNode.attrs.passed = false;
  const caught1 = checkInvariants(tampered);
  check("adversarial", "E14.inv05_tamper_verification_caught",
    !caught1.pass && caught1.violations.some((x) => x.invariant === "INV-05"),
    caught1.violations.map((x) => `${x.invariant}:${x.detail}`).join(";").slice(0, 200) || "tamper node not found");
  // tamper 2: flip a verified hypothesis's resolution record to tested:refuted
  const tampered2 = JSON.parse(JSON.stringify(t)) as NormalizedTwin;
  const hypVer = tampered2.nodes.find((n) => n.type === "hypothesis" && n.claim?.state === "VERIFIED");
  const resNode = hypVer ? tampered2.nodes.find((n) => n.type === "evidence" && n.attrs.kind === "hypothesis-resolution" && String(n.attrs.status ?? "").startsWith("tested:verified")) : undefined;
  if (resNode) resNode.attrs.status = "tested:refuted";
  const caught2 = checkInvariants(tampered2);
  check("adversarial", "E14.inv05_tamper_hypothesis_caught",
    !caught2.pass && caught2.violations.some((x) => x.invariant === "INV-05"),
    caught2.violations.map((x) => `${x.invariant}:${x.detail}`).join(";").slice(0, 200) || (hypVer ? "resolution node not found" : "no verified hypothesis in fixture"));
  // tamper 3: strip a verified finding's captured chain (keep verification node)
  const tampered3 = JSON.parse(JSON.stringify(t)) as NormalizedTwin;
  const fVer = tampered3.nodes.find((n) => n.type === "finding" && n.claim?.state === "VERIFIED");
  if (fVer) {
    tampered3.edges = tampered3.edges.filter((e) => !(e.type === "EVIDENCED_BY" && e.from === fVer.id && e.to && tampered3.nodes.find((n) => n.id === e.to)?.attrs.kind !== "verification"));
  }
  const caught3 = checkInvariants(tampered3);
  check("adversarial", "E14.inv05_tamper_chain_stripped_caught",
    !caught3.pass && caught3.violations.some((x) => x.invariant === "INV-05"),
    caught3.violations.map((x) => `${x.invariant}:${x.detail}`).join(";").slice(0, 200) || "no verified finding in fixture");
}

// ═══ F. MALICIOUS INPUT SAFETY ═══════════════════════════════════════════════

console.log("═══ F. MALICIOUS INPUT ═══");
function hostileRaw(): RawEngineResult {
  const raw = f01Complete();
  const X = `<script>alert('XSS')</script>`;
  const SQL = "'; DROP TABLE twins; --";
  const LONG = "A".repeat(10000);
  raw.target = `https://hostile.example/<img src=x onerror=alert(1)>`;
  raw.findings![0].url = `https://hostile.example/${encodeURIComponent(X)}?q=${SQL}`;
  raw.findings![0].parameter = `${X}${SQL}`;
  raw.findings![0].evidence = [{ kind: X, detail: `${LONG}${SQL}` }];
  raw.stats!.coverage.endpoints[0].url = `https://hostile.example/${X}`;
  (raw.stats!.api_inventory as Record<string, unknown>).apis = [
    { protocol: "http", method: "GET", path: `/${X}`, parameters: [LONG], sources: [X], findings: 1, finding_types: [SQL], authentication: X, coverage_status: X },
  ];
  return raw;
}
{
  const raw = hostileRaw();
  let twin: NormalizedTwin | null = null;
  let threw = "";
  try { twin = normalizeTwin(raw); } catch (e) { threw = String(e); }
  check("malicious", "F1.normalization_survives", twin !== null && threw === "", threw.slice(0, 120));
  if (twin) {
    const inv = checkInvariants(twin, raw);
    check("malicious", "F2.invariants_hold", inv.pass, inv.violations.map((v) => `${v.invariant}:${v.detail}`).join("; ").slice(0, 200));
    // no raw control characters, no over-length strings anywhere in the twin
    const MAX = 258;
    let overlength = 0; let control = 0;
    const scan = (v: unknown) => {
      if (typeof v === "string") {
        if (v.length > MAX) overlength++;
        if (/[\u0000-\u001f]/.test(v.replace(/\u0000/g, ""))) control++;
      } else if (Array.isArray(v)) v.forEach(scan);
      else if (v && typeof v === "object") Object.values(v).forEach(scan);
    };
    scan(twin.nodes); scan(twin.edges); scan(twin.conflicts); scan(twin.knownUnknowns);
    check("malicious", "F3.length_caps", overlength === 0, `${overlength} over-length strings`);
    check("malicious", "F4.no_control_chars", control === 0, `${control} strings with control chars`);
    // JSON round-trip (API transport safety)
    let roundTrip = true;
    try { JSON.parse(JSON.stringify(twin)); } catch { roundTrip = false; }
    check("malicious", "F5.json_round_trip", roundTrip);
    // determinism holds under hostile input
    check("malicious", "F6.deterministic", normalizeTwin(hostileRaw()).twinHash === twin.twinHash);
  }
}
// duplicate nodes/edges in raw (identical coverage entries + identical findings)
{
  const raw = f01Complete();
  const cov = raw.stats!.coverage.endpoints as unknown[];
  cov.push(JSON.parse(JSON.stringify(cov[0])), JSON.parse(JSON.stringify(cov[0])));
  const t = normalizeTwin(raw);
  const inv = checkInvariants(t, raw);
  check("malicious", "F7.duplicate_entries_merge", inv.pass && t.nodes.every((n) => t.nodes.filter((x) => x.id === n.id).length === 1),
    inv.violations.map((v) => v.detail).join("; ").slice(0, 150));
}
// cyclic reference in raw (cannot come from JSON, must not crash hashing)
{
  const raw = f01Complete() as unknown as { stats: Record<string, unknown> };
  const cyc: Record<string, unknown> = {};
  cyc.self = cyc;
  raw.stats.hostile_cycle = cyc;
  let ok = true; let msg = "";
  try { normalizeTwin(raw as unknown as RawEngineResult); } catch (e) { ok = false; msg = String(e); }
  check("malicious", "F8.cyclic_reference_safe", ok, msg.slice(0, 120));
}
// malformed shapes: wrong types everywhere (arrays as dicts, numbers as strings…)
{
  const raw: RawEngineResult = {
    run_id: 12345, scanner: null, target: 42,
    findings: [{ id: ["array"], type: { x: 1 }, url: undefined, evidence: "not-an-array", verification: [1, 2] }],
    rejected_candidates: [null, 42, "x"],
    stats: { coverage: { endpoints: [{ method: 42, url: null }] }, api_inventory: { apis: "no" }, workflow: { flows: [null, "x", 7] }, boundary: { unresolved_detail: [{}] }, reasoning: { hypotheses: [{}] } },
  };
  let twin: NormalizedTwin | null = null; let threw = "";
  try { twin = normalizeTwin(raw); } catch (e) { threw = String(e); }
  const inv = twin ? checkInvariants(twin, raw) : null;
  check("malicious", "F9.malformed_shapes_safe", twin !== null && threw === "" && inv?.pass === true,
    threw.slice(0, 120) || (inv?.violations.map((v) => v.detail).join("; ") ?? "").slice(0, 150));
}
// invalid provenance strings can never enter the twin vocabulary
{
  const raw = hostileRaw();
  const t = normalizeTwin(raw);
  const valid = new Set(["OBSERVED", "INFERRED", "VERIFIED", "REFUTED", "UNKNOWN"]);
  const allProv = [...t.nodes.map((n) => n.provenance), ...t.edges.map((e) => e.provenance)];
  check("malicious", "F10.provenance_vocabulary_inviolable", allProv.every((p) => valid.has(p)), allProv.filter((p) => !valid.has(p)).join(","));
}
// tenant safety: nothing in the twin carries org/tenant identifiers from raw
{
  const raw = hostileRaw();
  (raw as Record<string, unknown>).orgId = "ORG-VICTIM-123";
  const t = normalizeTwin(raw);
  const leaked = JSON.stringify(t).includes("ORG-VICTIM-123");
  check("malicious", "F11.no_tenant_field_injection", !leaked);
}

// ═══ G. PERFORMANCE (honest measurements) ═══════════════════════════════════

console.log("═══ G. PERFORMANCE ═══");
function syntheticRaw(nEndpoints: number): RawEngineResult {
  const covEndpoints: unknown[] = [];
  const apis: unknown[] = [];
  const findings: unknown[] = [];
  for (let i = 0; i < nEndpoints; i++) {
    const p = `/perf/e${i}`;
    covEndpoints.push({ method: i % 4 === 3 ? "POST" : "GET", url: `https://perf.example${p}`, source: "seed", activity: ["passive", "active"], skips: [], baseline: 200 });
    apis.push({ protocol: "http", method: i % 4 === 3 ? "POST" : "GET", path: p, channel: "", sources: ["seed"], parameters: i % 2 === 0 ? [`p${i}`, `q${i}`] : [`p${i}`], findings: i % 5 === 0 ? 1 : 0, finding_types: [], authentication: "unknown", coverage_status: "tested" });
    if (i % 5 === 0) {
      findings.push({
        id: `F-perf${String(i).padStart(6, "0")}`, type: "info", severity: "low", status: "verified",
        confidence: 0.9, method: "GET", url: `https://perf.example${p}`, parameter: `p${i}`,
        evidence: [{ kind: "k", detail: "d" }], verification: { method: "m", passed: true, confidence: 0.9, rounds: 1, notes: "" },
        risk: 10, impact: {},
      });
    }
  }
  return {
    run_id: "run-perf", scanner: "sentinel-core/4.1.1", target: "https://perf.example/",
    findings: findings as never, rejected_candidates: [],
    stats: {
      coverage: { discovered: nEndpoints, tested: nEndpoints, untested: 0, coverage_pct: 100, endpoints: covEndpoints },
      api_inventory: { total: nEndpoints, by_protocol: { http: nEndpoints }, apis },
      digital_twin: { nodes: 0, edges: 0, identities: 0, roles: 0, entities: 0, surfaces_total: nEndpoints, flows: [] },
    },
  };
}

const perfResults: Record<string, unknown>[] = [];
for (const [label, n] of [["100 nodes", 25], ["1k nodes", 300], ["10k nodes", 3200]] as const) {
  const raw = syntheticRaw(n);
  const t0 = Date.now();
  const twin = normalizeTwin(raw);
  const normMs = Date.now() - t0;
  const t1 = Date.now();
  const inv = checkInvariants(twin, raw);
  const invMs = Date.now() - t1;
  const t2 = Date.now();
  const eq = checkEquivalence(raw, twin);
  const eqMs = Date.now() - t2;
  const jsonBytes = JSON.stringify(twin).length;
  const ok = inv.pass && eq.pass;
  check("performance", `${label}.valid`, ok, inv.violations.map((v) => v.detail).join("; ").slice(0, 150));
  perfResults.push({
    label, nodes: twin.counts.nodes, edges: twin.counts.edges,
    normalizeMs: normMs, invariantsMs: invMs, equivalenceMs: eqMs,
    graphJsonBytes: jsonBytes, twinHash: twin.twinHash.slice(0, 16),
  });
  console.log(`  ${label}: ${twin.counts.nodes} nodes / ${twin.counts.edges} edges — normalize ${normMs}ms, invariants ${invMs}ms, equivalence ${eqMs}ms, json ${(jsonBytes / 1024).toFixed(0)}KB`);
}

// ═══ SUMMARY ═════════════════════════════════════════════════════════════════

const summary = {
  suite: "l1-twin-unit",
  pass: PASS, fail: FAIL,
  totals: { fixtures: ALL_FIXTURES.length, checks: PASS + FAIL },
  goldenHashes: Object.fromEntries(ALL_FIXTURES.map((f) => [f.name, fixtureTwins.get(f.name)!.twinHash])),
  performance: perfResults,
  verdict: FAIL === 0 ? "PASS" : "FAIL",
  at: new Date().toISOString(),
};

const outDir = "saas-data/l1-twin";
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "l1_twin_unit_results.json"), JSON.stringify({ summary, results: RESULTS }, null, 1));
console.log(`\nL1 TWIN UNIT SUITE: ${PASS} passed, ${FAIL} failed → ${summary.verdict}`);
console.log(`Golden hashes (freeze into GOLDEN map):`);
for (const [name, h] of Object.entries(summary.goldenHashes)) console.log(`  "${name}": "${h}",`);
process.exit(FAIL === 0 ? 0 : 1);
