/**
 * cpp-aware seeding glue for the APPEALS-MODERATION-TAIL domain (TRACK: seed).
 *
 * Owns the cpp-seed path for: user-appeals, voicemail, tax-documents,
 * tax-form-1099, payment-disputes (+ promo/moderation tail). Does NOT edit the
 * shared helpers/cpp-seed.ts — it only REUSES that module's `runCppShim` /
 * `usingCpp` primitives, so every seed call here inherits the per-worker ssh
 * ControlMaster multiplexing (ControlPath keyed by TEST_WORKER_INDEX) and never
 * reintroduces the MaxStartups connect-storm.
 *
 * PROBLEM: the inline per-test seeders in these specs write to the Python
 * DDB-Local at :8001 (UserEnforcementHistory / account_state / Appeals /
 * billing / MessageCallSessions / payment_incidents, keyed by EMAIL). The C++
 * backend reads its OWN moto on .82 (tlc_user_enforcement_history /
 * tlc_account_state / tlc_billing / tlc_message_call_sessions /
 * tlc_payment_incidents, keyed by SUB). So under E2E_USE_CPP those seeds never
 * reach cpp and the guarded reads (appeal-submit enforcement lookup, tax ledger
 * scan, dispute ownership) fail. These wrappers invoke arg-driven shims on .82
 * so the correctly shaped rows land in cpp's tables.
 *
 * The default Python path is untouched: every caller gates on usingCpp().
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

const SHIM_ENF = "seed_appeals-moderation-tail_enforcement.py";
const SHIM_ACC = "seed_appeals-moderation-tail_account_state.py";
const SHIM_TAX = "seed_appeals-moderation-tail_tax_ledger.py";
const SHIM_INC = "seed_appeals-moderation-tail_payment_incident.py";
const SHIM_DDB = "seed_appeals-moderation-tail_ddb_generic.py";
const SHIM_PROFILE = "seed_profile-social_profile.py"; // reused (tlc_profile row)

// ── user-appeals ─────────────────────────────────────────────────────────────

/** Seed ONE enforcement row into cpp's tlc_user_enforcement_history (keyed by
 *  the cpp SUB). Mirrors user-appeals.spec.ts::seedEnforcement. */
export function cppSeedEnforcement(opts: {
  userSub: string;
  enforcementId: string;
  enforcementType: "warn" | "ban";
  sourceTicketId?: string;
  createdByAdminUserId?: string;
  note?: string;
}): void {
  runCppShim(SHIM_ENF, {
    user_id: opts.userSub,
    enforcement_id: opts.enforcementId,
    enforcement_type: opts.enforcementType,
    ...(opts.sourceTicketId ? { source_ticket_id: opts.sourceTicketId } : {}),
    ...(opts.createdByAdminUserId
      ? { created_by_admin_user_id: opts.createdByAdminUserId }
      : {}),
    ...(opts.note ? { note: opts.note } : {}),
  });
}

/** Set an account_state ban row in cpp's tlc_account_state. */
export function cppSeedBan(userSub: string, sourceTicketId?: string): void {
  runCppShim(SHIM_ACC, {
    user_sub: userSub,
    op: "ban",
    ...(sourceTicketId ? { source_ticket_id: sourceTicketId } : {}),
  });
}

/** Clear an account_state row in cpp's tlc_account_state. */
export function cppClearBan(userSub: string): void {
  runCppShim(SHIM_ACC, { user_sub: userSub, op: "clear" });
}

/** Delete every tlc_appeals row for one user (via ByUserCreatedAt GSI), so the
 *  per-user "one pending appeal" 429 gate doesn't leak across runs. */
export function cppClearAppealsForUser(userSub: string): void {
  runCppShim(SHIM_DDB, {
    op: "clear_appeals_user",
    table: "tlc_appeals",
    user_id: userSub,
  });
}

// ── tax-documents / tax-form-1099 ────────────────────────────────────────────

export interface CppTaxLedgerEntry {
  reason: string;
  amount_cents: number;
  year: number;
  type?: string; // default "credit"
}

/** Seed billing-ledger rows into cpp's tlc_billing for the tax specs, keyed by
 *  the cpp SUB. Reproduces the spec's June-of-year ts spreading exactly. */
export function cppSeedTaxLedger(
  userSub: string,
  entries: CppTaxLedgerEntry[],
  testRun: string | number,
): void {
  runCppShim(SHIM_TAX, {
    user_sub: userSub,
    test_run: String(testRun),
    entries,
  });
}

/** Ensure a tlc_profile row exists for a sub (1099 tax_target_exists gate). */
export function cppSeedProfile(userSub: string, displayName: string): void {
  runCppShim(SHIM_PROFILE, { user_sub: userSub, display_name: displayName });
}

/** Plant an in-progress per-year 1099 batch LOCK row (lock_state=in_progress)
 *  so a second concurrent batch hits cpp's condition -> 429. */
export function cppSeedBatchLock(year: number): void {
  runCppShim(SHIM_TAX, { op: "batch_lock", user_sub: "batchlock", year });
}

/** Clean this run's tlc_billing LEDGER rows + wipe cached tlc_tax_documents /
 *  tlc_tax_forms_1099 rows for the user so seeded data recomputes fresh. */
export function cppCleanupTax(
  userSub: string,
  testRun: string | number,
  batchYears: number[] = [],
  allLedger = false,
): void {
  runCppShim(SHIM_TAX, {
    op: "cleanup",
    user_sub: userSub,
    test_run: String(testRun),
    batch_years: batchYears,
    // cpp's moto persists across runs; when the suite fully owns the user's
    // tax ledger, wipe ALL LEDGER rows (not just this run's) so prior-run
    // rows do not skew comparison/summary totals.
    all_ledger: allLedger,
  });
}

// ── payment-disputes ─────────────────────────────────────────────────────────

/** Seed ONE payment-incident row into cpp's tlc_payment_incidents. account_id /
 *  customer_id MUST be the cpp SUB (ownership check). */
export function cppSeedIncident(opts: {
  incidentId: string;
  provider: string;
  incidentType: string;
  status: string;
  accountSub: string;
  paymentReference?: string;
  amount?: string;
}): void {
  runCppShim(SHIM_INC, {
    incident_id: opts.incidentId,
    provider: opts.provider,
    incident_type: opts.incidentType,
    status: opts.status,
    account_id: opts.accountSub,
    ...(opts.paymentReference ? { payment_reference: opts.paymentReference } : {}),
    ...(opts.amount != null ? { amount: opts.amount } : {}),
  });
}

/** Delete ONE payment-incident row from cpp's tlc_payment_incidents. */
export function cppDeleteIncident(incidentId: string): void {
  runCppShim(SHIM_INC, { incident_id: incidentId, op: "delete" });
}

// ── voicemail (generic call-session put/get) ────────────────────────────────

/** Generic put into a mapped cpp moto table (MessageCallSessions ->
 *  tlc_message_call_sessions). Mirrors voicemail.spec.ts::ddbPut. */
export function cppDdbPut(
  table: string,
  item: Record<string, unknown>,
): void {
  runCppShim(SHIM_DDB, { op: "put", table, item });
}

/** Generic get from a mapped cpp moto table. Returns the parsed item or null. */
export function cppDdbGet(
  table: string,
  key: Record<string, string>,
): Record<string, unknown> | null {
  const out = runCppShim(SHIM_DDB, { op: "get", table, key });
  // shim prints the item JSON on the first line, then an 'ok' line.
  const first = out.split("\n")[0].trim();
  return first === "null" ? null : (JSON.parse(first) as Record<string, unknown>);
}
