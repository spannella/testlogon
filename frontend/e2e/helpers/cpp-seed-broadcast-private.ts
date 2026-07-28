/**
 * cpp-aware seeding glue for the broadcast-private + broadcast-private-chat
 * domains (TRACK: seed).
 *
 * WHY: those specs poke the Python DDB-Local :8001 directly to (a) flip a
 * PRIVATE session to active (cpp's accepted->active transition is dead code —
 * no API caller), and (b) read the billing LEDGER back. Neither reaches cpp.
 *
 * cpp truth:
 *   - private session: tlc_broadcast_private_sessions PK BCAST#<sid> SK
 *     PRIVATE#<pid> (bpv_pk). h_bpv_end requires status=="active" + reads
 *     started_at as a NUMBER, then writes ledger rows reason "Private session".
 *   - private chat: h_pchat_* writes ledger rows whose reason contains
 *     "Private chat"; go-live via POST /broadcast/sessions/{id}/start and
 *     enablement via PUT /broadcast/sessions/{id}/chat-tiers are real cpp APIs
 *     (preferred over DDB pokes — wired inline in the specs).
 *   - billing ledger: tlc_billing PK USER#<sub> SK LEDGER#<ts>#<eid>, fields
 *     type(debit/credit)/amount_cents/reason. user id MUST be the cpp SUB.
 *
 * Re-uses runCppShim/usingCpp. The Python path is untouched (gate on usingCpp()).
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

/**
 * Flip a broadcast PRIVATE session (BCAST#<sid> / PRIVATE#<pid>) to status
 * "active" + started_at=now-120 in cpp's tlc_broadcast_private_sessions, so a
 * subsequent /private/{id}/end computes a >0 billed minute. Mirrors
 * broadcast-private.spec.ts activatePrivateSession().
 */
export function cppActivateBroadcastPrivateSession(sessionId: string, requestId: string): void {
  runCppShim("activate_broadcast_private_session.py", {
    session_id: sessionId,
    request_id: requestId,
  });
}

/**
 * Count a user's LEDGER# rows in cpp's tlc_billing whose reason == reasonEq
 * (default "Private session"). Mirrors broadcast-private.spec.ts
 * queryBillingLedger(). userSub MUST be the cpp SUB.
 */
export function cppQueryBillingLedger(userSub: string, reasonEq = "Private session"): { count: number } {
  const out = runCppShim("read_billing_ledger.py", {
    user_sub: userSub,
    mode: "count",
    reason_eq: reasonEq,
  });
  // shim prints "ok {json}" on one line; strip the ok-gate token.
  const json = out.replace(/^ok\s+/, "");
  return JSON.parse(json) as { count: number };
}

export interface CppLedgerRow {
  type: string;
  amount_cents: number;
  reason: string;
}

/**
 * Return a user's LEDGER# rows in cpp's tlc_billing whose reason contains
 * reasonSubstr (default "Private chat"), so the spec can filter by .type in TS.
 * Mirrors broadcast-private-chat.spec.ts queryBillingLedger(). userSub MUST be
 * the cpp SUB.
 */
export function cppQueryBillingLedgerRows(userSub: string, reasonSubstr = "Private chat"): CppLedgerRow[] {
  const out = runCppShim("read_billing_ledger.py", {
    user_sub: userSub,
    mode: "rows",
    reason_substr: reasonSubstr,
  });
  const json = out.replace(/^ok\s+/, "");
  return (JSON.parse(json) as { rows: CppLedgerRow[] }).rows;
}
