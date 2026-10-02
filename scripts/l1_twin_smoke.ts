// L1 smoke test — quick verification of the twin normalizer on all fixtures
// before wiring persistence/API/UI. Run: bun scripts/l1_twin_smoke.ts
import { normalizeTwin, checkInvariants, checkEquivalence, ALL_FIXTURES } from "../src/lib/twin/index";

let failed = 0;
for (const f of ALL_FIXTURES) {
  const raw = f.build();
  const twin = normalizeTwin(raw);
  const inv = checkInvariants(twin, raw);
  const eq = checkEquivalence(raw, twin);
  const det2 = normalizeTwin(raw);
  const det3 = normalizeTwin(raw);
  const detOk = det2.twinHash === twin.twinHash && det3.twinHash === twin.twinHash;
  const invOk = inv.pass;
  const eqOk = eq.pass;
  const ok = invOk && eqOk && detOk;
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"} ${f.id} ${f.name}`);
  console.log(`   nodes=${twin.counts.nodes} edges=${twin.counts.edges} claims=${JSON.stringify(twin.counts.claims)} conflicts=${twin.counts.conflicts} unknowns=${twin.counts.knownUnknowns}`);
  console.log(`   invariants=${inv.pass ? "PASS" : "FAIL(" + inv.violations.length + ")"} equivalence=${eq.pass ? "PASS" : "FAIL"} determinism=${detOk ? "PASS" : "FAIL"}`);
  console.log(`   twinHash=${twin.twinHash.slice(0, 16)}…`);
  if (!inv.pass) for (const v of inv.violations.slice(0, 6)) console.log(`   !! ${v.invariant}: ${v.detail}`);
  if (!eq.pass) for (const d of eq.dimensions.filter((x) => x.missing.length)) console.log(`   !! eq ${d.dimension}: missing ${JSON.stringify(d.missing.slice(0, 4))}`);
}
console.log(failed === 0 ? "SMOKE: ALL PASS" : `SMOKE: ${failed} FAILURES`);
process.exit(failed === 0 ? 0 : 1);
