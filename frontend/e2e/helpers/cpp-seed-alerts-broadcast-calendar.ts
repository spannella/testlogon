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

// ── alerts (tlc_alerts, PK user_sub / SK alert_id) ───────────────────────────
/**
 * Event → priority map, byte-identical to cpp's alert_priority_for()
 * (app/main.cpp:3904) and the Python get_alert_priority()
 * (app/services/alert_priority.py). Used so seeded alerts carry the SAME
 * priority cpp would compute. cpp's alert_out ECHOES a stored `priority` when
 * present (`it.contains("priority") ? item_s : alert_priority_for`), so the
 * seed MUST write the value cpp would otherwise derive — otherwise the shim's
 * default "normal" would mask urgent/low events (206.x).
 */
const CPP_ALERT_PRIORITY: Record<string, string> = {
  login_failure: "urgent", mfa_failure: "urgent", challenge_failed: "urgent",
  access_denied: "urgent", security_event: "urgent", device_new: "urgent",
  device_location_mismatch: "urgent", rate_limited: "urgent",
  new_follower: "low", post_liked: "low", post_reaction: "low", post_shared: "low",
  login_success: "low", mfa_success: "low", api_key_created: "low",
  device_trust: "low", challenge_created: "low", challenge_revoked: "low",
  calendar_event_created: "low", calendar_event_updated: "low",
  calendar_event_deleted: "low",
};

export function cppAlertPriorityFor(event: string, alertType?: string): string {
  const key = alertType || event;
  return CPP_ALERT_PRIORITY[key] ?? "normal";
}

export interface CppSeedAlert {
  userSub: string; // cpp SUB (resolveIdentityId), NOT the email
  event: string;
  title?: string;
  outcome?: string;
  details?: Record<string, unknown>;
  read?: boolean;
  priority?: string; // if omitted, derived from event/details.alert_type like cpp
  category?: string;
  actionUrl?: string;
}

/**
 * Seed one-or-more alert rows into cpp's tlc_alerts so /ui/alerts,
 * /ui/alerts/unread-count and the bell UI see them. Mirrors writeTestAlert()
 * in notification-enhancements.spec.ts (Python write_alert). cpp has NO
 * UNREAD_COUNT sentinel — unread-count LIVE-counts read=false rows — so an
 * inserted read:false row makes the count native-correct with no sentinel bump.
 * priority is derived from the event (matching cpp) unless explicitly supplied.
 */
export function cppSeedAlerts(alerts: CppSeedAlert[]): void {
  if (!usingCpp()) return;
  runCppShim("seed_profile-social_alerts.py", {
    alerts: alerts.map((a) => {
      const alertType =
        (a.details && typeof a.details["alert_type"] === "string"
          ? (a.details["alert_type"] as string)
          : undefined);
      return {
        user_sub: a.userSub,
        event: a.event,
        title: a.title ?? "",
        outcome: a.outcome ?? "success",
        details: a.details ?? {},
        read: a.read ?? false,
        priority: a.priority ?? cppAlertPriorityFor(a.event, alertType),
        ...(a.category != null ? { category: a.category } : {}),
        ...(a.actionUrl != null ? { action_url: a.actionUrl } : {}),
      };
    }),
  });
}

/**
 * Reset a user's alert state to the empty/all-read baseline under cpp by
 * DELETING every tlc_alerts row for the sub (cpp has no sentinel to zero).
 * Mirrors resetAliceAlerts() in notification-enhancements.spec.ts. After this
 * /ui/alerts/unread-count returns 0.
 */
export function cppResetAlerts(userSub: string): void {
  if (!usingCpp()) return;
  runCppShim("delete_alerts.py", { user_sub: userSub });
}
