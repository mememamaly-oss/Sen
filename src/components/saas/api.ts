// Client-side API layer + shared types for the Burhan SaaS dashboard

export type Role = "OWNER" | "ADMIN" | "MEMBER" | "VIEWER";

export type OrgSummary = {
  id: string;
  name: string;
  slug: string;
  role: Role;
  createdAt: string;
  counts: { targets: number; scans: number; findings: number; reports: number; memberships: number };
};

export type Me = { user: { id: string; email: string; name: string | null }; orgs: OrgSummary[] };

export type TargetRow = {
  id: string;
  name: string;
  url: string;
  description: string | null;
  isDemo: boolean;
  owner: string;
  ownerId: string;
  scansCount: number;
  findingsCount: number;
  lastScan: { status: string; createdAt: string; finishedAt: string | null; scanner: string | null } | null;
  createdAt: string;
};

export type ScanRow = {
  id: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
  target: { id: string; name: string; url: string };
  createdBy: string;
  runId: string | null;
  scanner: string | null;
  durationSec: number | null;
  findingsCount: number;
  reportsCount: number;
  error: string | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  bySeverity?: Record<string, number>;
  stats?: Record<string, number | null> | null;
};

export type ScanProgress = {
  elapsedSec: number;
  pidAlive: boolean;
  cpuSec: number | null;
  connections: number;
  etaSec: number | null;
  logTail: string;
};

export type FindingRow = {
  id: string;
  engineId: string;
  type: string;
  severity: string;
  status: string;
  confidence: number;
  risk: number;
  method: string | null;
  url: string;
  parameter: string | null;
  hasProof?: boolean;
};

export type FindingDetail = {
  finding: FindingRow & { fingerprint: string | null; createdAt: string };
  scan: { id: string; runId: string | null; status: string; targetId: string; createdAt: string };
  target: { id: string; name: string; url: string };
  evidence: Array<{ kind?: string; detail?: string }>;
  verification: Record<string, unknown>;
  impact: Record<string, unknown>;
  reproduction: Record<string, unknown> | null;
  compliance: Record<string, unknown> | null;
  remediation: { title: string; summary: string; steps: string[] };
};

export type CoverageResponse = {
  scanId: string;
  status: string;
  coverage: {
    discovered?: number;
    tested?: number;
    passive?: number;
    secrets_scanned?: number;
    active?: number;
    authz_probed?: number;
    active_or_authz?: number;
    untested?: number;
    coverage_pct?: number;
    skip_reasons?: Record<string, number>;
    endpoints?: Array<{ method: string; url: string; source: string; activity: string[]; skips: string[]; baseline?: number }>;
    dimensions?: Record<string, Record<string, number>>;
  } | null;
  boundary: {
    records?: number;
    unresolved?: number;
    by_state?: Record<string, number>;
    by_category?: Record<string, number>;
    unresolved_detail?: Array<{ category: string; target: string; state: string; reason: string; remediation: string }>;
  } | null;
  crawl?: Record<string, unknown> | null;
  openapi?: Record<string, unknown> | null;
  note?: string;
};

// ── PHASE 02 L1: normalized Security Twin (read-only, versioned API) ─────────

export type TwinProvenance = "OBSERVED" | "INFERRED" | "VERIFIED" | "REFUTED" | "UNKNOWN";
export type TwinClaimState = "VERIFIED" | "REFUTED" | "UNKNOWN" | "CONFLICT";

export type TwinWhy = {
  provenance: TwinProvenance;
  reason: string;
  sourceRefs: string[];
  inferenceReason?: string;
  evidenceRefs?: string[];
};

export type TwinNode = {
  id: string;
  type: string;
  key: string;
  label: string;
  provenance: TwinProvenance;
  sourceRefs: string[];
  why: TwinWhy;
  attrs: Record<string, unknown>;
  claim?: { state: TwinClaimState; statement: string; evidenceRefs: string[]; conflictIds: string[] };
  conflictIds?: string[];
};

export type TwinEdge = {
  id: string;
  type: string;
  from: string;
  to: string;
  provenance: TwinProvenance;
  sourceRefs: string[];
  confidence: number;
  why: TwinWhy;
  attrs?: Record<string, unknown>;
};

export type TwinConflict = {
  id: string;
  kind: string;
  description: string;
  resolution: string;
  left: { claimRef: string; provenance: TwinProvenance; summary: string; sourceRefs: string[] };
  right: { claimRef: string; provenance: TwinProvenance; summary: string; sourceRefs: string[] };
};

export type TwinKnownUnknown = { id: string; dimension: string; description: string; sourceRefs: string[] };

export type TwinCounts = {
  nodes: number;
  edges: number;
  byNodeType: Record<string, number>;
  byEdgeType: Record<string, number>;
  provenance: Record<string, number>;
  edgeProvenance: Record<string, number>;
  claims: { VERIFIED: number; REFUTED: number; UNKNOWN: number; CONFLICT: number };
  conflicts: number;
  knownUnknowns: number;
};

export type NormalizedTwin = {
  schemaVersion: string;
  target: string;
  scope: {
    runId: string;
    scanner: string;
    rawSource: string;
    application: string;
    host: string;
    coverage: { discovered: number; tested: number; untested: number; coveragePct: number | null };
  };
  nodes: TwinNode[];
  edges: TwinEdge[];
  conflicts: TwinConflict[];
  knownUnknowns: TwinKnownUnknown[];
  counts: TwinCounts;
  twinHash: string;
  rawHash: string;
};

export type TwinResponse = {
  apiVersion: string;
  scanId: string;
  status: string;
  built?: boolean;
  invariants?: { pass: boolean; violations: number };
  twin: NormalizedTwin | null;
  note?: string;
};

export type ReportRow = {
  id: string;
  title: string;
  format: string;
  sizeBytes: number;
  createdAt: string;
  createdBy: string;
  scan: { id: string; runId: string | null; targetName: string } | null;
};

export type ReportDetail = {
  report: {
    id: string;
    title: string;
    format: string;
    sizeBytes: number;
    createdAt: string;
    createdBy: string;
    scan: { id: string; runId: string | null; scanner: string | null; targetName: string; targetUrl: string } | null;
  };
  ext: string;
  content: string;
};

export type MemberRow = {
  id: string;
  userId: string;
  email: string;
  name: string | null;
  role: Role;
  joinedAt: string;
};

export type AuditRow = {
  id: string;
  action: string;
  detail: Record<string, unknown>;
  by: string | null;
  createdAt: string;
};

export type OrgOverview = {
  org: { id: string; name: string; slug: string; createdAt: string; counts: Record<string, number> };
  role: Role;
  recentScans: Array<{
    id: string;
    status: string;
    createdAt: string;
    finishedAt: string | null;
    durationSec: number | null;
    targetName: string;
    findingsCount: number;
    scanner: string | null;
    coverage: { coverage_pct?: number } | null;
  }>;
  findingsBySeverity: Record<string, number>;
  lastCompleted: {
    id: string;
    finishedAt: string | null;
    scanner: string | null;
    coverage: { coverage_pct?: number } | null;
  } | null;
};

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    cache: "no-store",
  });
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    /* non-json */
  }
  if (!res.ok) {
    const msg = (data as { error?: string })?.error || `فشل الطلب (${res.status})`;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

export const api = {
  bootstrapStatus: () => req<{ needsBootstrap: boolean }>("/api/bootstrap"),
  bootstrap: (body: { email: string; name?: string; password: string; orgName?: string }) =>
    req<{ ok: boolean; userId: string; orgId: string }>("/api/bootstrap", { method: "POST", body: JSON.stringify(body) }),
  me: () => req<Me>("/api/me"),
  orgOverview: (orgId: string) => req<OrgOverview>(`/api/orgs/${orgId}`),

  createOrg: (name: string) =>
    req<{ id: string; name: string; slug: string; role: string }>("/api/orgs", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),

  targets: (orgId: string) => req<{ targets: TargetRow[] }>(`/api/targets?orgId=${orgId}`),
  createTarget: (body: { orgId: string; name?: string; url?: string; description?: string; isDemo?: boolean }) =>
    req<{ id: string }>("/api/targets", { method: "POST", body: JSON.stringify(body) }),
  deleteTarget: (orgId: string, id: string) => req<{ ok: boolean }>(`/api/targets/${id}?orgId=${orgId}`, { method: "DELETE" }),

  scans: (orgId: string, targetId?: string) =>
    req<{ scans: ScanRow[] }>(`/api/scans?orgId=${orgId}${targetId ? `&targetId=${targetId}` : ""}`),
  startScan: (body: { orgId: string; targetId: string; options?: Record<string, unknown> }) =>
    req<{ id: string; status: string }>("/api/scans", { method: "POST", body: JSON.stringify(body) }),
  scanDetail: (orgId: string, id: string) =>
    req<{ scan: ScanRow; progress: ScanProgress }>(`/api/scans/${id}?orgId=${orgId}`),
  cancelScan: (orgId: string, id: string) =>
    req<{ ok: boolean; cancelled: boolean }>(`/api/scans/${id}?orgId=${orgId}`, { method: "DELETE" }),

  scanFindings: (orgId: string, id: string, params?: string) =>
    req<{ findings: FindingRow[]; types: Array<{ type: string; count: number }> }>(
      `/api/scans/${id}/findings?orgId=${orgId}${params ? `&${params}` : ""}`
    ),
  scanCoverage: (orgId: string, id: string) => req<CoverageResponse>(`/api/scans/${id}/coverage?orgId=${orgId}`),

  scanTwin: (orgId: string, id: string) => req<TwinResponse>(`/api/v1/scans/${id}/twin?orgId=${orgId}`),

  findingDetail: (orgId: string, id: string) => req<FindingDetail>(`/api/findings/${id}?orgId=${orgId}`),

  reports: (orgId: string) => req<{ reports: ReportRow[] }>(`/api/reports?orgId=${orgId}`),
  createReport: (body: { orgId: string; scanId: string; format: string }) =>
    req<{ id: string }>("/api/reports", { method: "POST", body: JSON.stringify(body) }),
  reportDetail: (orgId: string, id: string) => req<ReportDetail>(`/api/reports/${id}?orgId=${orgId}`),

  members: (orgId: string) => req<{ members: MemberRow[] }>(`/api/orgs/${orgId}/members`),
  addMember: (orgId: string, body: { email: string; name?: string; password: string; role: string }) =>
    req<{ ok: boolean; userId: string; isNewUser: boolean }>(`/api/orgs/${orgId}/members`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  changeMemberRole: (orgId: string, mid: string, role: string) =>
    req<{ ok: boolean }>(`/api/orgs/${orgId}/members/${mid}`, { method: "PATCH", body: JSON.stringify({ role }) }),
  removeMember: (orgId: string, mid: string) =>
    req<{ ok: boolean }>(`/api/orgs/${orgId}/members/${mid}`, { method: "DELETE" }),

  audit: (orgId: string) => req<{ logs: AuditRow[] }>(`/api/audit?orgId=${orgId}`),
};

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("ar-LY", { dateStyle: "short", timeStyle: "medium", hour12: false });
}

export function fmtDuration(sec: number | null | undefined): string {
  if (sec === null || sec === undefined) return "—";
  if (sec < 60) return `${Math.round(sec)}ث`;
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return `${m}د ${s}ث`;
}
