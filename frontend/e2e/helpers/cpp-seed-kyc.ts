/**
 * cpp-aware KYC seeding glue (TRACK: seed — DOMAIN kyc).
 *
 * PROBLEM this solves: the inline per-test KYC seeders in kyc-eidv /
 * kyc-admin-dashboard / kyc-assignment / kyc specs write case rows (and
 * read-back / mutate them, and read/clear a user's kyc_tier) against a Python
 * DDB-Local at localhost:8001 keyed as `kyc_cases` / `users`. The C++ backend
 * reads a DIFFERENT store (moto :5005 on .82): tlc_kyc_cases (pk=KYC#<id>,
 * sk=META, GSI gsi_owner_pk / gsi_status_pk) and tlc_msg_users (key user_id,
 * attr kyc_tier). So under E2E_USE_CPP those inline seeds NEVER reach cpp and
 * the case GET / admin queue / tier read all come back empty or 404.
 *
 * FIX: when targeting cpp, invoke small arg-driven shims that live ON .82
 * (~/projects/testlogon-cpp/e2e/seed_shims/seed_kyc_case_full.py,
 * set_kyc_case_status.py, get_kyc_case.py, set_user_kyc_tier.py) over ssh, so
 * a correctly shaped row lands in / is read from cpp's OWN moto tables. The
 * default Python path is left completely untouched (callers gate on usingCpp()).
 *
 * This module is DISTINCT from the shared helpers/cpp-seed.ts (which already
 * owns cppSeedKycCase for the facial-comparison spec) to avoid cross-agent
 * edit conflicts. It reuses runCppShim + usingCpp from that module.
 *
 * VERIFIED live (2026-07-26) vs cpp :8443:
 *   seed submitted+enhanced case -> GET /v1/kyc/cases/{id} returns full case,
 *   /v1/kyc/cases/admin/queue?status=submitted lists it (risk_tier high);
 *   status mutate draft->under_review bumps version + gsi_status_pk;
 *   tier read/clear on tlc_msg_users; get_kyc_case returns the META item.
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

// ── full KYC case seed ───────────────────────────────────────────────────────
export interface CppKycCaseFile {
  type: string; // "selfie" | "id_front" | "id_back" | ...
  path?: string;
  size?: number;
  mime_type?: string;
  verification_state?: string;
}

export interface CppKycCaseOpts {
  caseId: string;
  userSub: string; // cpp SUB (owner) — NOT an email
  status?: string; // draft | submitted | under_review | approved | rejected | ...
  targetTier?: string | null; // tier_0..tier_4 (render-for-case reads this)
  intakeProfile?: string | null; // standard | enhanced | basic | null
  assignedAdminSub?: string | null;
  version?: number;
  slaDueAt?: number | null;
  escalationLevel?: number;
  files?: CppKycCaseFile[];
}

/**
 * Seed ONE full KYC case META row into cpp's tlc_kyc_cases (pk=KYC#<caseId>,
 * sk=META) with the GSI keys cpp's admin queue + owner index read. Superset of
 * cppSeedKycCase in the shared helper: carries status / intake_profile /
 * review.assigned_admin_sub / sla / version so the admin-dashboard + assignment
 * + eidv specs render non-empty under cpp.
 */
export function cppSeedKycCaseFull(opts: CppKycCaseOpts): void {
  runCppShim("seed_kyc_case_full.py", {
    case_id: opts.caseId,
    user_sub: opts.userSub,
    status: opts.status ?? "draft",
    target_tier: opts.targetTier ?? null,
    intake_profile: opts.intakeProfile ?? null,
    assigned_admin_sub: opts.assignedAdminSub ?? null,
    version: opts.version ?? 1,
    sla_due_at: opts.slaDueAt ?? null,
    escalation_level: opts.escalationLevel ?? 0,
    files: (opts.files ?? []).map((f) => ({
      type: f.type,
      path: f.path ?? "",
      ...(f.size != null ? { size: f.size } : {}),
      ...(f.mime_type ? { mime_type: f.mime_type } : {}),
      ...(f.verification_state ? { verification_state: f.verification_state } : {}),
    })),
  });
}

// ── status mutate / version read (kyc.spec setCaseStatusDirect/getVersion) ───
/**
 * Move a case to a new status + bump version in cpp's moto. Keeps the status/
 * owner GSI keys coherent so the admin queue still lists it. Returns the new
 * version. Mirrors setCaseStatusDirect() in kyc.spec.ts.
 */
export function cppSetKycCaseStatus(caseId: string, newStatus: string): number {
  const out = runCppShim("set_kyc_case_status.py", {
    case_id: caseId,
    status: newStatus,
  });
  const m = /ok\s+(-?\d+)/.exec(out);
  return m ? parseInt(m[1], 10) : -1;
}

/** Read a case's current version from cpp's moto (getCaseVersionDirect). -1 if absent. */
export function cppGetKycCaseVersion(caseId: string): number {
  const out = runCppShim("set_kyc_case_status.py", {
    case_id: caseId,
    read_only: true,
  });
  const m = /ok\s+(-?\d+)/.exec(out);
  return m ? parseInt(m[1], 10) : -1;
}

// ── case read-back (kyc-eidv getCaseItem) ────────────────────────────────────
/**
 * Read one KYC case META item back from cpp's moto as an object (eid_verification
 * / status / files / review). Mirrors getCaseItem() in kyc-eidv.spec.ts. Returns
 * {} if absent. The shim prints an 'ok' marker line then the JSON payload.
 */
export function cppGetKycCase(caseId: string): Record<string, unknown> {
  const out = runCppShim("get_kyc_case.py", { case_id: caseId });
  // last non-empty line is the JSON payload
  const lines = out.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const json = lines[lines.length - 1] ?? "{}";
  try {
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return {};
  }
}

// ── user kyc_tier read / clear (kyc-eidv getUserTier / clearTier) ────────────
/** Read a user's current kyc_tier from cpp's tlc_msg_users (0 if unset). */
export function cppGetUserKycTier(userSub: string): number {
  const out = runCppShim("set_user_kyc_tier.py", { user_sub: userSub, op: "read" });
  const m = /ok\s+(\d+)/.exec(out);
  return m ? parseInt(m[1], 10) : 0;
}

/** REMOVE a user's kyc_tier (+updated_at/history) in cpp's tlc_msg_users. */
export function cppClearUserKycTier(userSub: string): void {
  runCppShim("set_user_kyc_tier.py", { user_sub: userSub, op: "clear" });
}
