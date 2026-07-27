/**
 * cpp-native seed wrappers for the alerts-broadcast-calendar domain.
 *
 * Phase 2 harness-seed conversion: under E2E_USE_CPP the inline Python seeders
 * in alerts-delivery / contacts / (etc.) write the Python DDB-Local tables,
 * which the C++ backend never reads. These wrappers call the matching .82
 * seed_shims (over the shared per-worker ControlMaster ssh in runCppShim) so
 * the cpp moto (:5005) gets the rows cpp actually reads.
 *
 * ALL wrappers no-op unless usingCpp(); the Python path is byte-identical.
 * Every user_sub/user_id passed here MUST already be the cpp SUB
 * (resolveIdentityId()) — subs are ephemeral per login, so callers resolve at
 * runtime, never hardcode.
 *
 * This file is DISTINCT from the other cpp-seed-*.ts files (no shared edits).
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

// ── alert_prefs (tlc_alert_prefs, PK user_sub; six/eight list fields) ─────────
export interface CppAlertPrefsOpts {
  userSub: string; // cpp SUB (resolveIdentityId), NOT the email
  emails?: string[];
  smsNumbers?: string[];
  emailEventTypes?: string[];
  smsEventTypes?: string[];
  toastEventTypes?: string[];
  pushEventTypes?: string[];
  webhookUrls?: string[];
  webhookEventTypes?: string[];
}

/**
 * Upsert Alice's (or anyone's) alert delivery prefs into cpp's tlc_alert_prefs
 * so /ui/alerts/email_prefs + the email/SMS fan-out see the seeded addresses
 * and per-event opt-ins. Mirrors injectAlertPrefs() in alerts-delivery.spec.ts.
 * Full replace (PutItem), matching cpp persist_prefs semantics.
 */
export function cppSeedAlertPrefs(opts: CppAlertPrefsOpts): void {
  if (!usingCpp()) return;
  runCppShim("seed_alerts-broadcast-calendar_alert_prefs.py", {
    user_sub: opts.userSub,
    emails: opts.emails ?? [],
    sms_numbers: opts.smsNumbers ?? [],
    email_event_types: opts.emailEventTypes ?? [],
    sms_event_types: opts.smsEventTypes ?? [],
    toast_event_types: opts.toastEventTypes ?? [],
    push_event_types: opts.pushEventTypes ?? [],
    webhook_urls: opts.webhookUrls ?? [],
    webhook_event_types: opts.webhookEventTypes ?? [],
  });
}

/** Clear a user's alert prefs to the empty (opted-out) default under cpp. */
export function cppClearAlertPrefs(userSub: string): void {
  if (!usingCpp()) return;
  runCppShim("seed_alerts-broadcast-calendar_alert_prefs.py", {
    user_sub: userSub, // all list fields default to [] in the shim
  });
}

// ── user directory search (tlc_user_search, PK token) ────────────────────────
export interface CppSearchUser {
  userId: string; // cpp SUB (resolveIdentityId), NOT the email
  displayName: string;
  email?: string;
}

/**
 * Seed directory-search prefix tokens so GET /messaging/contacts/search?q=..
 * (h_contacts_search over tlc_user_search) returns these users. Mirrors the
 * UserSearch half of seedBobProfile() in contacts.spec.ts. Tokenises exactly
 * like cpp build_prefix_tokens plus per-word prefixes (so a single-word query
 * matches a multi-word display name).
 */
export function cppSeedUserSearch(users: CppSearchUser[]): void {
  if (!usingCpp()) return;
  runCppShim("seed_alerts-broadcast-calendar_user_search.py", {
    users: users.map((u) => ({
      user_id: u.userId,
      display_name: u.displayName,
      ...(u.email != null ? { email: u.email } : {}),
    })),
  });
}

// ── contacts cleanup (tlc_contacts, PK owner_id) ─────────────────────────────
/**
 * Delete all of a user's contact rows from cpp's tlc_contacts. Mirrors
 * cleanupAliceContacts() in contacts.spec.ts — cpp persists contacts across
 * runs, so without this the /contacts page + Add-Contact dialog accumulate
 * duplicate rows (Playwright strict-mode violations). ownerSub = cpp SUB.
 */
export function cppCleanupContacts(ownerSub: string): void {
  if (!usingCpp()) return;
  runCppShim("seed_alerts-broadcast-calendar_contacts_cleanup.py", {
    owner_id: ownerSub,
  });
}
