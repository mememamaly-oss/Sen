// Seed a poisoned finding + a poisoned report under the FIRST org of
// bola-admin@integration.test (owner order 2026-10-31, parts 2.3/2.4).
import fs from "fs";
import path from "path";
import { db } from "@/lib/db";

const admin = await db.user.findUniqueOrThrow({ where: { email: "bola-admin@integration.test" } });
const membership = await db.membership.findFirstOrThrow({
  where: { userId: admin.id, role: "OWNER" },
  orderBy: { createdAt: "asc" },
});
const orgId = membership.orgId;

const target = await db.target.create({
  data: { orgId, createdById: admin.id, name: "xss-proof target", url: "https://xssproof.invalid/" },
});
const scan = await db.scan.create({
  data: {
    orgId, targetId: target.id, createdById: admin.id, status: "COMPLETED",
    runId: "run-xss-browser-proof", optionsJson: "{}",
    statsJson: JSON.stringify({ coverage: { discovered: 1, tested: 1, untested: 0 } }),
    durationSec: 1, finishedAt: new Date(),
  },
});
const PAYLOAD = "<script>window.__xssPwned=1</script>";
const ATTR = "<img src=x onerror='window.__attrPwned=1'>";
const finding = await db.finding.create({
  data: {
    orgId, scanId: scan.id, targetId: target.id,
    engineId: "F-xssbrowser01", type: "xss_reflected", severity: "high",
    status: "verified", confidence: 0.95, risk: 80, method: "GET",
    url: `https://xssproof.invalid/search?q=${encodeURIComponent(PAYLOAD)}`,
    parameter: PAYLOAD,
    evidenceJson: JSON.stringify([{ kind: "reflection", detail: `reflected ${PAYLOAD} and ${ATTR}` }]),
    verificationJson: JSON.stringify({ method: "replay", passed: true }),
    impactJson: "{}",
  },
});
// the report viewer renders the FILE content in a sandboxed iframe — seed a
// deliberately hostile "engine-generated" report
const reportsDir = path.join(process.env.SENTINEL_DATA_DIR || "/tmp/sentinel-test-data", "reports");
fs.mkdirSync(reportsDir, { recursive: true });
const reportPath = path.join(reportsDir, `xss-proof-${Date.now()}.html`);
fs.writeFileSync(reportPath,
  `<html><body><h1>report</h1>${PAYLOAD}${ATTR}` +
  `<script>try{parent.document.body.setAttribute('data-pwned','1')}catch(e){document.body.setAttribute('data-escape-error','1')}</script>` +
  `<iframe srcdoc="<script>try{top.document.title='PWNED'}catch(e){}</script>"></iframe>` +
  `</body></html>`);
const report = await db.report.create({
  data: {
    orgId, scanId: scan.id, createdById: admin.id, format: "HTML",
    title: "xss proof report", filePath: reportPath, sizeBytes: fs.statSync(reportPath).size,
  },
});
console.log(JSON.stringify({ orgId, findingId: finding.id, reportId: report.id }));
process.exit(0);
