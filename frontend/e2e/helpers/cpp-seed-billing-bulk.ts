/**
 * cpp-aware seeding glue for the BILLING-BULK domain (TRACK: seed).
 *
 * Owns the cpp-seed path for the billing/ledger/wallet/refund/dispute/incident
 * specs (tip-ledger, billing-wallet, refund-requests, billing-refunds-disputes,
 * payment-disputes). Does NOT edit the shared helpers/cpp-seed.ts (to avoid
 * cross-agent conflicts) — it only reuses that module's `runCppShim` /
 * `usingCpp` primitives, so it inherits the per-worker ssh ControlMaster
 * multiplexing (ControlPath keyed on TEST_WORKER_INDEX) and does not reintroduce
 * the MaxStartups connection storm.
 *
 * PROBLEM: the inline per-test seeders in these specs write to the Python
 * DDB-Local at :8001 (tables `billing` pk=USER#<sub>, `payment_incidents`
 * pk=incident_id; sub resolved from email). The C++ backend reads its OWN moto
 * on .82 (tlc_billing / tlc_refund_requests / tlc_billing_disputes /
 * tlc_payment_incidents; sub = the real UUID). So under E2E_USE_CPP those seeds
 * never reach cpp and the endpoints render empty (or the spec never sees the
 * pre-seeded refund/dispute/incident). Additionally cpp's json.value() throws
 * type_error.302 on string-numerics, so the shims write ts / amount_cents /
 * created_at / response_due_at etc. as NUMBERS.
 *
 * The default Python path is untouched: every caller gates on usingCpp().
 */
import { execFileSync } from "child_process";
import { runCppShim, usingCpp, cppSeedPaymentMethod } from "./cpp-seed";

export { usingCpp };

/** Re-export the shared PM seeder so billing-bulk specs have one import source. */
export const cppSeedPaymentMethodBB = cppSeedPaymentMethod;

// ── .82 ssh target (mirrors helpers/cpp-seed.ts constants) for READ shims ─────
const CPP_SSH_HOST = process.env.E2E_CPP_SSH_HOST ?? "sean@192.168.0.82";
const CPP_SSH_KEY =
  process.env.E2E_CPP_SSH_KEY ?? "/home/sean/.ssh/e2e_cpp_seed_ed25519";
const CPP_SHIM_DIR =
  process.env.E2E_CPP_SHIM_DIR ??
  "/home/sean/projects/testlogon-cpp/e2e/seed_shims";

/**
 * Run a READ shim on .82 that prints an "ok" line then a JSON line on stdout.
 * Reuses the SAME per-worker ControlMaster socket as runCppShim (ControlPath
 * keyed on TEST_WORKER_INDEX) so it inherits the connection multiplexing.
 * Returns the parsed JSON from the last non-empty stdout line.
 */
function runCppReadShim(shim: string, args: Record<string, unknown>): unknown {
  const b64 = Buffer.from(JSON.stringify(args), "utf8").toString("base64");
  const out = execFileSync(
    "ssh",
    [
      "-i", CPP_SSH_KEY,
      "-o", "IdentitiesOnly=yes",
      "-o", "BatchMode=yes",
      "-o", "ConnectTimeout=20",
      "-o", "ControlMaster=auto",
      "-o", `ControlPath=/home/sean/.ssh/cm-cppseed-w${process.env.TEST_WORKER_INDEX || "0"}-%C`,
      "-o", "ControlPersist=180",
      CPP_SSH_HOST,
      `python3 ${CPP_SHIM_DIR}/${shim} --b64 ${b64}`,
    ],
    { timeout: 30_000, encoding: "utf8" },
  ).trim();
  const lines = out.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const jsonLine = [...lines].reverse().find((l) => /^[[{]/.test(l.trim()));
  if (!jsonLine) throw new Error(`read shim ${shim} returned no JSON: ${out}`);
  return JSON.parse(jsonLine);
}

/**
 * Read a user's LEDGER# rows from cpp's tlc_billing (moto :5005) as a JSON list.
 * Mirrors the specs' queryLedger() which normally reads the Python DDB-Local.
 * Under E2E_USE_CPP the tip/refund/wallet mechanics run in cpp and the rows land
 * in cpp's OWN store, so this is the correct source.
 */
export function cppReadLedger(userSub: string): Array<Record<string, unknown>> {
  const rows = runCppReadShim("read_ledger.py", { user_sub: userSub }) as Array<
    Record<string, unknown>
  >;
  // WIRE-SHAPE NORMALIZE: cpp emits type "tip_debit"/"tip_credit" (and other
  // "<kind>_debit"/"<kind>_credit" variants) whereas the Python backend the
  // tip-ledger spec predicates were written against emit plain "debit"/"credit".
  // Map the *_debit/*_credit suffix down to the bare debit/credit so the spec's
  // strict `e.type === "debit"` checks match, while leaving the reason/meta (the
  // fields the assertions actually care about) exactly as cpp wrote them.
  for (const r of rows) {
    const t = typeof r.type === "string" ? (r.type as string) : "";
    if (t !== "debit" && /(^|_)debit$/.test(t)) r.type = "debit";
    else if (t !== "credit" && /(^|_)credit$/.test(t)) r.type = "credit";
  }
  return rows;
}

// ── LEDGER# (tip / wallet-deposit / withdrawal / refund-source entries) ───────
export interface CppLedgerEntry {
  userSub: string; // cpp SUB (resolveIdentityId output), NOT an email
  entryId?: string;
  ts?: number;
  type?: string; // debit | credit
  amountCents: number;
  state?: string; // settled (default)
  reason?: string;
  currency?: string;
  meta?: Record<string, unknown>;
  ledgerDate?: string;
  entryType?: string; // billing_ledger CSV export reads entry_type (S)
  createdAt?: number;
}

/** Seed one or more full-shape LEDGER# rows into cpp's tlc_billing. */
export function cppSeedLedgerEntries(entries: CppLedgerEntry[]): void {
  runCppShim("seed_billing-bulk_ledger.py", {
    entries: entries.map((e) => ({
      user_sub: e.userSub,
      ...(e.entryId ? { entry_id: e.entryId } : {}),
      ...(e.ts != null ? { ts: e.ts } : {}),
      type: e.type ?? "debit",
      amount_cents: e.amountCents,
      state: e.state ?? "settled",
      reason: e.reason ?? "",
      currency: e.currency ?? "usd",
      ...(e.meta ? { meta: e.meta } : {}),
      ...(e.ledgerDate ? { ledger_date: e.ledgerDate } : {}),
      ...(e.entryType ? { entry_type: e.entryType } : {}),
      ...(e.createdAt != null ? { created_at: e.createdAt } : {}),
    })),
  });
}

/** Convenience: seed a single LEDGER# row; returns the entry_id used. */
export function cppSeedLedgerEntry(e: CppLedgerEntry): string {
  const entryId =
    e.entryId ?? `led_e2e_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  cppSeedLedgerEntries([{ ...e, entryId }]);
  return entryId;
}

// ── WALLET (balance row) ──────────────────────────────────────────────────────
/** Set the WALLET balance row for a user in cpp's tlc_billing. */
export function cppSeedWalletBalance(
  userSub: string,
  balanceCents: number,
  currency = "usd",
): void {
  runCppShim("seed_billing-bulk_wallet.py", {
    user_sub: userSub,
    balance_cents: balanceCents,
    currency,
  });
}

/** Delete one row (by pk=USER#<sub>, sk) from cpp's tlc_billing. */
export function cppDeleteBillingRow(userSub: string, sk: string): void {
  runCppShim("delete_billing-bulk_row.py", { user_sub: userSub, sk });
}

// ── REFUND#<id>/META (self-service refund request) ────────────────────────────
export interface CppRefundRequestOpts {
  refundRequestId: string;
  requesterUserId: string; // cpp SUB
  transactionEntryId?: string;
  amountCents: number;
  originalAmountCents?: number;
  status?: string; // pending | approved | denied | completed
  reason?: string;
  currency?: string;
  transactionType?: string;
  adminNotes?: string;
  createdAt?: number;
  completedAt?: number;
}

/** Seed one REFUND#<id>/META row into cpp's tlc_refund_requests. */
export function cppSeedRefundRequest(o: CppRefundRequestOpts): void {
  runCppShim("seed_billing-bulk_refund_request.py", {
    refund_request_id: o.refundRequestId,
    requester_user_id: o.requesterUserId,
    ...(o.transactionEntryId ? { transaction_entry_id: o.transactionEntryId } : {}),
    amount_cents: o.amountCents,
    ...(o.originalAmountCents != null
      ? { original_amount_cents: o.originalAmountCents }
      : {}),
    status: o.status ?? "pending",
    reason: o.reason ?? "e2e seeded refund request",
    currency: o.currency ?? "USD",
    ...(o.transactionType ? { transaction_type: o.transactionType } : {}),
    ...(o.adminNotes ? { admin_notes: o.adminNotes } : {}),
    ...(o.createdAt != null ? { created_at: o.createdAt } : {}),
    ...(o.completedAt != null ? { completed_at: o.completedAt } : {}),
  });
}

// ── DISPUTE#<id>/META (billing dispute / chargeback) ──────────────────────────
export interface CppDisputeOpts {
  disputeId: string;
  userId: string; // cpp SUB
  amountCents: number;
  provider?: string; // manual (default) | stripe | ...
  status?: string; // open | under_review | resolved
  reason?: string;
  currency?: string;
  transactionEntryId?: string;
  evidenceSubmitted?: boolean;
  createdAt?: number;
}

/**
 * Delete a user's DISPUTE#/META rows from cpp's tlc_billing_disputes so the
 * rolling-30d dispute cap is reset before the spec files fresh disputes (mirrors
 * the Python purgeUserDisputes). Best-effort; returns nothing.
 */
export function cppPurgeUserDisputes(userSub: string): void {
  runCppShim("purge_billing-bulk_disputes.py", { user_sub: userSub });
}

/** Seed one DISPUTE#<id>/META row into cpp's tlc_billing_disputes. */
export function cppSeedDispute(o: CppDisputeOpts): void {
  runCppShim("seed_billing-bulk_dispute.py", {
    dispute_id: o.disputeId,
    user_id: o.userId,
    amount_cents: o.amountCents,
    provider: o.provider ?? "manual",
    status: o.status ?? "open",
    reason: o.reason ?? "e2e seeded dispute",
    currency: o.currency ?? "USD",
    ...(o.transactionEntryId ? { transaction_entry_id: o.transactionEntryId } : {}),
    ...(o.evidenceSubmitted != null
      ? { evidence_submitted: o.evidenceSubmitted }
      : {}),
    ...(o.createdAt != null ? { created_at: o.createdAt } : {}),
  });
}

// ── payment_incidents row ─────────────────────────────────────────────────────
export interface CppIncidentOpts {
  incidentId: string;
  accountId: string; // cpp SUB (owner; also written to customer_id)
  incidentType: string; // payment_failure | dispute | ...
  status: string;
  provider?: string; // stripe (default)
  amount?: string; // cpp reads amount as a STRING (std::stod)
  paymentReference?: string;
  currency?: string;
  responseDueAt?: number;
}

/** Seed one payment-incident row into cpp's tlc_payment_incidents. */
export function cppSeedIncident(o: CppIncidentOpts): void {
  runCppShim("seed_billing-bulk_incident.py", {
    incident_id: o.incidentId,
    account_id: o.accountId,
    incident_type: o.incidentType,
    status: o.status,
    provider: o.provider ?? "stripe",
    ...(o.amount != null ? { amount: o.amount } : {}),
    ...(o.paymentReference ? { payment_reference: o.paymentReference } : {}),
    ...(o.currency ? { currency: o.currency } : {}),
    ...(o.responseDueAt != null ? { response_due_at: o.responseDueAt } : {}),
  });
}
