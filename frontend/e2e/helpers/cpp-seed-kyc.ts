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

// ── filemanager file node seed (kyc.spec injectFileNode) ───────────────
/**
 * Seed ONE filemanager FILE node into cpp's moto tlc_filemanager (PK=USER#<sub>,
 * SK=NODE#<path>) so h_cc_attach_file's fm_get_node_opt() resolves it. Mirrors
 * kyc.spec.ts injectFileNode(), which writes to the Python DDB-Local :8001
 * file_manager table cpp never reads. Reuses the existing seed_filemanager_video_node.py
 * shim (content_type overridable to image/jpeg for KYC selfie/id docs).
 * userSub MUST be the cpp SUB (fm_get_node_opt keys on s.user_sub), never an email.
 */
export function cppSeedFilemanagerNode(
  userSub: string,
  filePath: string,
  contentType = "image/jpeg",
): void {
  const name = filePath.split("/").pop() as string;
  runCppShim("seed_filemanager_video_node.py", {
    owner_user_id: userSub,
    path: filePath,
    name,
    content_type: contentType,
    s3_bucket: "test-bucket",
    s3_key: `e2e/fake/${name}`,
    size: 2048,
  });
}

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
  userSub: string; // cpp SUB (owner) — or an opaque analytics-cohort string
  status?: string; // draft | submitted | under_review | approved | rejected | ...
  targetTier?: string | null; // tier_0..tier_4 (render-for-case reads this)
  intakeProfile?: string | null; // standard | enhanced | basic | null
  country?: string | null; // ISO-2 (analytics geographic / anl_case_country)
  assignedAdminSub?: string | null;
  version?: number;
  createdAt?: number;
  submittedAt?: number; // submission.submitted_at (processing-time / deadlines)
  decidedAt?: number; // review.decided_at (processing-time / retention)
  purgedAt?: number | null; // review.purged_at (retention overdue)
  reasonCodes?: string[]; // review.reason_codes (rejection-reasons)
  decision?: string | null; // review.decision
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
    ...(opts.country != null ? { country: opts.country } : {}),
    assigned_admin_sub: opts.assignedAdminSub ?? null,
    version: opts.version ?? 1,
    ...(opts.createdAt != null ? { created_at: opts.createdAt } : {}),
    ...(opts.submittedAt != null ? { submitted_at: opts.submittedAt } : {}),
    ...(opts.decidedAt != null ? { decided_at: opts.decidedAt } : {}),
    ...(opts.purgedAt != null ? { purged_at: opts.purgedAt } : {}),
    ...(opts.reasonCodes != null ? { reason_codes: opts.reasonCodes } : {}),
    ...(opts.decision != null ? { decision: opts.decision } : {}),
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
/**
 * Read one row from cpp's tlc_kyc_cases by explicit pk/sk (e.g. a SAR record
 * pk=SAR#<id>, sk=META). Mirrors the direct :8001 get_item read-backs. {} if
 * absent.
 */
export function cppGetKycRow(pk: string, sk = "META"): Record<string, unknown> {
  const out = runCppShim("get_kyc_case.py", { pk, sk });
  const lines = out.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const json = lines[lines.length - 1] ?? "{}";
  try {
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return {};
  }
}

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

// ── KYC screening result seed (tlc_kyc_screening_results) ────────────────────
export interface CppKycScreeningOpts {
  caseId: string;
  userSub: string; // cpp SUB or analytics-cohort string
  result?: string; // clear | potential_match | confirmed_match
  reviewDecision?: string | null; // clear | escalate | null
  reviewedBy?: string | null;
  screenType?: string;
  screenKey?: string;
  screeningId?: string;
  createdAt: number;
}

/**
 * Seed ONE screening result row into cpp's tlc_kyc_screening_results
 * (PK=case_id, SK=screen_key). The compliance screening report scans that table
 * (created_at BETWEEN) and reads result / review_decision. Mirrors
 * seedScreening() in kyc-compliance-reports.spec.ts.
 */
export function cppSeedKycScreening(opts: CppKycScreeningOpts): void {
  runCppShim("seed_kyc_screening.py", {
    case_id: opts.caseId,
    user_sub: opts.userSub,
    result: opts.result ?? "clear",
    review_decision: opts.reviewDecision ?? null,
    ...(opts.reviewedBy != null ? { reviewed_by: opts.reviewedBy } : {}),
    ...(opts.screenType ? { screen_type: opts.screenType } : {}),
    ...(opts.screenKey ? { screen_key: opts.screenKey } : {}),
    ...(opts.screeningId ? { screening_id: opts.screeningId } : {}),
    created_at: opts.createdAt,
  });
}

// ── set nested identity on an existing case (id-scanner cross-reference) ─────
/**
 * Set the nested `identity` map (first/last name, DOB, nationality) on an
 * existing cpp KYC case so ids_cross_reference matches. Mirrors seedCaseIdentity()
 * in kyc-id-scanner.spec.ts (which update_items the :8001 case row).
 */
export function cppSetKycCaseIdentity(
  caseId: string,
  firstName: string,
  lastName: string,
  dob: string,
  nationality: string,
): void {
  runCppShim("set_kyc_case_identity.py", {
    case_id: caseId,
    first_name: firstName,
    last_name: lastName,
    date_of_birth: dob,
    nationality,
  });
}

// ── generic user-row field set/remove on tlc_msg_users (kyc-tiers) ───────────
/**
 * SET arbitrary attrs (email_verified / phone_verified / kyc_tier /
 * kyc_tier_history / kyc_tier_updated_at) on a user's tlc_msg_users row. Mirrors
 * setProfileField() in kyc-tiers.spec.ts.
 */
export function cppSetUserKycFields(
  userSub: string,
  fields: Record<string, string | number | boolean>,
): void {
  runCppShim("set_user_kyc_tier.py", { user_sub: userSub, op: "set", fields });
}

/** REMOVE named attrs from a user's tlc_msg_users row (removeProfileField). */
export function cppRemoveUserKycFields(userSub: string, fields: string[]): void {
  runCppShim("set_user_kyc_tier.py", { user_sub: userSub, op: "remove", fields });
}

// ── direct case admin-assign + encrypted-PII read (kyc-encryption/pii-section) ─
/**
 * Set review.assigned_admin_sub on an existing cpp case (read-modify-write).
 * Mirrors assignAdminDirect() (no REST endpoint). adminSub MUST be the cpp SUB
 * of the identity that will call /pii/decrypt (the decrypt gate matches
 * review.assigned_admin_sub == session sub).
 */
export function cppAssignKycAdmin(caseId: string, adminSub: string): void {
  runCppShim("assign_kyc_admin.py", { case_id: caseId, admin_sub: adminSub });
}

/**
 * Read the raw encrypted_pii map for a case from cpp's tlc_kyc_cases (at-rest
 * ciphertext shape). Mirrors readEncryptedPii(). {} if absent.
 */
export function cppGetKycCasePii(caseId: string): Record<string, unknown> {
  const out = runCppShim("get_kyc_case_pii.py", { case_id: caseId });
  const lines = out.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const json = lines[lines.length - 1] ?? "{}";
  try {
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/**
 * Delete a kyc-analytics cohort's cases (KYC#<prefix><i>/META for i<count) from
 * cpp's tlc_kyc_cases. Mirrors kyc-analytics.spec.ts's afterAll cleanup, whose
 * Python :8001 deletes never reach cpp — so seeded analytics cases otherwise
 * accumulate across runs and break count-bounded funnel/tier assertions.
 */
export function cppDeleteKycAnalyticsCases(prefix: string, count = 20): void {
  runCppShim("delete_kyc_analytics_cases.py", { prefix, count });
}


// ── liveness verification call seed (kyc-verification-call-panel) ────────────
export interface CppLivenessCallOpts {
  callId: string;
  caseId: string;
  userSub: string; // cpp SUB (owner)
  status?: string; // scheduled | in_progress | conducted | passed | failed | ...
  scheduledAt?: number;
  durationMinutes?: number;
  note?: string;
  verifierSub?: string;
  createdAt?: number;
}

/**
 * Seed ONE KYC liveness call into cpp's tlc_kyc_liveness_calls (PK=call_id;
 * ByCase GSI on case_id) so the admin case-detail VerificationCallPanel
 * (GET /ui/kyc/liveness-call/admin/case/{case_id}) renders. Mirrors
 * seedLivenessCall() in kyc-verification-call-panel.spec.ts, whose Python :8001
 * 'kyc_liveness_calls' write cpp never reads.
 */
export function cppSeedLivenessCall(opts: CppLivenessCallOpts): void {
  runCppShim("seed_liveness_call.py", {
    call_id: opts.callId,
    case_id: opts.caseId,
    user_sub: opts.userSub,
    status: opts.status ?? "scheduled",
    ...(opts.scheduledAt != null ? { scheduled_at: opts.scheduledAt } : {}),
    ...(opts.durationMinutes != null ? { duration_minutes: opts.durationMinutes } : {}),
    ...(opts.note != null ? { note: opts.note } : {}),
    ...(opts.verifierSub != null ? { verifier_sub: opts.verifierSub } : {}),
    ...(opts.createdAt != null ? { created_at: opts.createdAt } : {}),
  });
}
