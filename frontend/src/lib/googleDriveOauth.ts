// Pure helpers for the project file-provider "Connect Google Drive" OAuth flow.
//
// The backend exposes a two-legged OAuth handshake for the google_drive file
// provider:
//   POST /v1/projects/providers/google_drive/oauth/start
//       -> { provider, authorization_url, state, expires_at }
//   POST /v1/projects/providers/google_drive/oauth/callback  { code, state }
//       -> ProviderCredential
//
// The browser leaves to `authorization_url`, the provider redirects back to our
// app with `?code=...&state=...` (and, on user-decline, `?error=...`). This
// module holds the small amount of pure, network-free logic the UI needs to
// interpret that redirect and stash/restore the return context. Kept here so it
// is unit-testable in isolation. No React / no network.

/** The query-string marker the flow tags onto the return URL so we only treat
 *  a redirect as *ours* (google_drive) and not some other provider's. */
export const GOOGLE_DRIVE_PROVIDER = "google_drive";

/** Parsed shape of a google-drive OAuth redirect landing on our page. */
export interface GoogleDriveCallbackParams {
  /** Authorization code to exchange, when the user approved. */
  code: string | null;
  /** Opaque signed state to round-trip back to the backend. */
  state: string | null;
  /** Provider tag we appended to the return URL (may be absent on legacy links). */
  provider: string | null;
  /** Provider-supplied error slug when the user declined / consent failed. */
  error: string | null;
}

/**
 * Parse an OAuth-callback query string (e.g. `window.location.search`) into its
 * relevant parts. Accepts a leading "?" or not; tolerates empty input.
 */
export function parseGoogleDriveCallbackParams(search: string): GoogleDriveCallbackParams {
  const params = new URLSearchParams(search || "");
  const norm = (v: string | null): string | null => {
    if (v == null) return null;
    const t = v.trim();
    return t.length > 0 ? t : null;
  };
  return {
    code: norm(params.get("code")),
    state: norm(params.get("state")),
    provider: norm(params.get("provider")),
    error: norm(params.get("error")),
  };
}

/**
 * True when a parsed redirect is a completable google-drive callback: it carries
 * both a code and state, is not an error redirect, and — when a provider tag is
 * present — the tag is google_drive. (A missing provider tag is tolerated so a
 * bare `?code=&state=` return still completes.)
 */
export function isGoogleDriveCallback(p: GoogleDriveCallbackParams): boolean {
  if (p.error) return false;
  if (!p.code || !p.state) return false;
  if (p.provider != null && p.provider !== GOOGLE_DRIVE_PROVIDER) return false;
  return true;
}

/**
 * Build the return URL the app should hand to the OAuth `start` call / use to
 * recognise its own redirect. Appends `provider=google_drive` to `basePath`
 * without clobbering existing query params. Pure string building.
 */
export function buildGoogleDriveReturnUrl(origin: string, basePath: string): string {
  const cleanOrigin = (origin || "").replace(/\/+$/, "");
  const [path, existing = ""] = (basePath || "/").split("?", 2);
  const params = new URLSearchParams(existing);
  params.set("provider", GOOGLE_DRIVE_PROVIDER);
  return `${cleanOrigin}${path}?${params.toString()}`;
}

/**
 * Strip the OAuth handshake params (`code`, `state`, `provider`, `error`) from a
 * query string, returning the remaining query WITHOUT a leading "?" (empty
 * string when nothing is left). Used to scrub the URL after completing/declining
 * so a refresh does not re-fire the callback.
 */
export function stripGoogleDriveCallbackParams(search: string): string {
  const params = new URLSearchParams(search || "");
  for (const key of ["code", "state", "provider", "error"]) {
    params.delete(key);
  }
  return params.toString();
}
