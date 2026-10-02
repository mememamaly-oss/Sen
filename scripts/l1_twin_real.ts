// L1 real-data check — normalize REAL engine outputs (read-only) and verify
// invariants + equivalence + determinism. Run: bun scripts/l1_twin_real.ts
import fs from "fs";
import { normalizeTwin, checkInvariants, checkEquivalence, type RawEngineResult } from "../src/lib/twin/index";

const FILES = process.argv.slice(2).length
  ? process.argv.slice(2)
  : [
      "build-v411/results/benchmark.json",
      "build-v411/results/live_v41/ginjuice.json",
      "build-v411/results/live_v41/webgoat_auth.json",
      "build-v411/results/live_v41/juiceshop.json",
    ];

let failed = 0;
for (const file of FILES) {
  if (!fs.existsSync(file)) { console.log(`SKIP ${file} (missing)`); continue; }
  const raw = JSON.parse(fs.readFileSync(file, "utf8")) as RawEngineResult;
  const t0 = Date.now();
  const twin = normalizeTwin(raw);
  const ms = Date.now() - t0;
  const inv = checkInvariants(twin, raw);
  const eq = checkEquivalence(raw, twin);
  const t2 = normalizeTwin(raw); const t3 = normalizeTwin(raw);
  const det = t2.twinHash === twin.twinHash && t3.twinHash === twin.twinHash;
  const ok = inv.pass && eq.pass && det;
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"} ${file}`);
  console.log(`   nodes=${twin.counts.nodes} edges=${twin.counts.edges} normalize=${ms}ms`);
  console.log(`   provenance=${JSON.stringify(twin.counts.provenance)} claims=${JSON.stringify(twin.counts.claims)}`);
  console.log(`   conflicts=${twin.counts.conflicts} knownUnknowns=${twin.counts.knownUnknowns}`);
  console.log(`   byType=${JSON.stringify(twin.counts.byNodeType)}`);
  console.log(`   invariants=${inv.pass ? "PASS" : "FAIL"} equivalence=${eq.pass ? "PASS" : "FAIL"} determinism=${det ? "PASS" : "FAIL"} hash=${twin.twinHash.slice(0, 16)}…`);
  if (!inv.pass) for (const v of inv.violations.slice(0, 8)) console.log(`   !! ${v.invariant}: ${v.detail}`);
  if (!eq.pass) for (const d of eq.dimensions.filter((x) => x.missing.length)) console.log(`   !! eq ${d.dimension}: missing ${JSON.stringify(d.missing.slice(0, 5))}`);
}
console.log(failed === 0 ? "REAL-DATA: ALL PASS" : `REAL-DATA: ${failed} FAILURES`);
process.exit(failed === 0 ? 0 : 1);
