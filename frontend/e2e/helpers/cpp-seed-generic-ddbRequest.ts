/**
 * cpp-aware seeding glue for the SHARED ddbRequest(:8001) domain
 * (TRACK: seed / DOMAIN: generic-ddbRequest).
 *
 * PROBLEM this solves: many specs (activity-feed, alerts, analytics-depth, ...)
 * seed rows INLINE by shelling out to Python that writes to a Python DDB-Local
 * at localhost:8001 (tables "alerts" / "AnalyticsRollups" / "billing", keyed by
 * the caller's EMAIL as sub, and with ts/read_at as NUMBER). The C++ backend
 * reads a COMPLETELY DIFFERENT store: moto :5005 on .82, tables tlc_alerts /
 * tlc_analytics_rollups / tlc_billing, keyed by the real cpp SUB (a UUID), and —
 * for alerts — with ts/read_at as STRING. So under E2E_USE_CPP those inline
 * seeds NEVER reach cpp and the UI/endpoints render empty (404 / empty arrays).
 *
 * FIX: when targeting cpp, translate each PutItem into a call to a small
 * arg-driven shim that lives ON .82
 * (~/projects/testlogon-cpp/e2e/seed_shims/seed_generic-ddbRequest_*.py),
 * invoked over ssh, so ONE correctly-shaped item lands in cpp's OWN moto table.
 * The identity (spec passes an email/alias as user_sub) is resolved to the real
 * cpp SUB via resolveIdentityId() before seeding. The default Python path is
 * left completely untouched (callers gate on usingCpp()).
 *
 * This module owns ONLY the generic-ddbRequest cpp-seed path. It deliberately
 * does NOT edit the shared cpp-seed.ts (to avoid cross-agent conflicts); it
 * reuses that module's runCppShim() transport + usingCpp() detector.
 */
import { runCppShim, usingCpp } from "./cpp-seed";
import { resolveIdentityId } from "./session";

export { usingCpp };

// ── alerts (tlc_alerts) ──────────────────────────────────────────────────────

export interface GenAlertSpec {
  user_sub: string; // email/alias on the spec side; resolved to cpp SUB here
  event: string;
  ts?: number;
  outcome?: string;
  title?: string;
  details?: Record<string, unknown>;
  read?: boolean;
  read_at?: number;
  priority?: string;
  category?: string;
  action_url?: string;
  source_type?: string;
  source_id?: string;
  actors?: unknown[];
  actor_count?: number;
}

/**
 * Seed one or more alert rows into cpp's tlc_alerts (PK user_sub=cpp SUB,
 * SK alert_id). Returns the generated [{alert_id, ts}] (same shape the inline
 * Python seeder returns) so specs can await/track individual alert ids.
 * No-op-safe: only call when usingCpp().
 */
export function cppSeedAlerts(
  specs: GenAlertSpec[],
): Array<{ alert_id: string; ts: number }> {
  const alerts = specs.map((s) => ({
    ...s,
    user_sub: resolveIdentityId(s.user_sub),
  }));
  const out = runCppShim("seed_generic-ddbRequest_alerts.py", { alerts });
  // shim prints "ok <n>\n<json-array>"; parse the last non-empty line as JSON.
  const lines = out.trim().split(/\r?\n/).filter((l) => l.trim() !== "");
  const last = lines[lines.length - 1] ?? "[]";
  try {
    return JSON.parse(last) as Array<{ alert_id: string; ts: number }>;
  } catch {
    return [];
  }
}

// ── analytics daily rollups (tlc_analytics_rollups) ──────────────────────────

export interface GenRollupRow {
  user_sub: string; // email/alias -> resolved to cpp SUB
  date: string; // YYYY-MM-DD
  data: Record<string, unknown>; // revenue_cents / total_views / top_content_ids / ...
}

/**
 * Seed creator daily analytics-rollup rows into cpp's tlc_analytics_rollups
 * (PK CREATOR#<sub>, SK DAILY#<date>). Read by /ui/analytics/{top-content,
 * overview,revenue,audience}. No-op-safe: only call when usingCpp().
 */
export function cppSeedAnalyticsRollups(rows: GenRollupRow[]): void {
  const mapped = rows.map((r) => ({
    ...r,
    user_sub: resolveIdentityId(r.user_sub),
  }));
  runCppShim("seed_generic-ddbRequest_analytics_rollups.py", { rows: mapped });
}

/** Convenience: seed a single rollup day (mirrors the inline seedRollupRow). */
export function cppSeedRollupRow(
  userSub: string,
  dateStr: string,
  data: Record<string, unknown>,
): void {
  cppSeedAnalyticsRollups([{ user_sub: userSub, date: dateStr, data }]);
}

// ── billing ledger (tlc_billing) ─────────────────────────────────────────────

export interface GenLedgerEntry {
  user_sub: string; // email/alias -> resolved to cpp SUB
  content_id?: string;
  video_id?: string;
  reason: string;
  amount_cents: number;
  type?: string; // e.g. "ad_revenue_credit" (breakdown filter)
  ts?: number;   // epoch seconds (breakdown cutoff filter)
  meta?: Record<string, unknown>;
}

/**
 * Seed billing-ledger rows into cpp's tlc_billing (PK USER#<sub>,
 * SK LEDGER#<id>). Read by /ui/analytics/content/{id} revenue_breakdown and
 * other per-creator ledger scans. No-op-safe: only call when usingCpp().
 */
export function cppSeedBillingLedger(entries: GenLedgerEntry[]): void {
  const mapped = entries.map((e) => ({
    ...e,
    user_sub: resolveIdentityId(e.user_sub),
  }));
  runCppShim("seed_generic-ddbRequest_billing_ledger.py", { entries: mapped });
}

/** Convenience: single ledger entry (mirrors the inline seedBillingLedger). */
export function cppSeedLedgerEntry(
  userSub: string,
  contentId: string,
  reason: string,
  amountCents: number,
): void {
  cppSeedBillingLedger([
    { user_sub: userSub, content_id: contentId, reason, amount_cents: amountCents },
  ]);
}

// ── ad transparency (tlc_billing AD_TRANSPARENCY#) ───────────────────────────

export interface GenTransparencyRow {
  user_sub: string; // email/alias -> resolved to cpp SUB
  account_id: string;
  company_name: string;
  month: string; // YYYY-MM
  impression_count: number;
  click_count: number;
  revenue_cents: number;
}

/**
 * Seed AD_TRANSPARENCY# rows into cpp's tlc_billing (PK USER#<sub>,
 * SK AD_TRANSPARENCY#<account>#<month>). Read by
 * GET /ui/ads/content-controls/transparency. No-op-safe: only call when usingCpp().
 */
export function cppSeedAdTransparency(rows: GenTransparencyRow[]): void {
  const mapped = rows.map((r) => ({
    ...r,
    user_sub: resolveIdentityId(r.user_sub),
  }));
  runCppShim("seed_generic-ddbRequest_transparency.py", { rows: mapped });
}
