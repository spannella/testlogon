/**
 * cpp-aware reset glue for google-calendar-integration.spec.ts (TRACK: seed).
 *
 * PROBLEM: 77.4 "disconnect without active connection returns 404" assumes the
 * user has NO Google Calendar connection. cpp resolves the fixed connection id
 * "google-primary" and only 404s when that row is ABSENT; a prior run leaves a
 * (disconnected) google-primary row owned by the user, so cpp returns 200. This
 * wrapper deletes the user's google connection rows from cpp's own moto
 * (tlc_calendar_integrations) via the reset_google_calendar_connection.py shim
 * before the tests, so disconnect hits !conn -> 404.
 *
 * Reuses the shared cpp-seed.ts runCppShim primitive. No-op off the cpp path.
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

const SHIM = "reset_google_calendar_connection.py";

/** Delete the user's Google Calendar connection rows in cpp's moto so the
 *  "no active connection" disconnect test observes a clean slate. userSub MUST
 *  be the cpp SUB. No-op unless usingCpp(). */
export function cppResetGoogleCalendar(userSub: string): void {
  if (!usingCpp()) return;
  runCppShim(SHIM, { user_sub: userSub });
}
