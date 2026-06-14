package com.testlogon.android.core.network

/**
 * AND-395 - per-request marker (attached via a Retrofit `@Tag`) that opts a call OUT of the
 * authenticated-session machinery: the CSRF interceptor (AND-012) must NOT attach the
 * `X-CSRF-Token` header and the 401-refresh authenticator (AND-013) must NOT fire
 * `POST /ui/session/refresh` for these requests.
 *
 * The public-questionnaire respondent surface (epic E51) is ANONYMOUS: a cookie-less, never-logged-in
 * user resolves a published slug and starts a response session with no auth context (FR-5). Tagging
 * `getPublished` + `startSession` with [Anonymous] guarantees a 401 here is surfaced as a retryable
 * error ("session expired / not found") rather than bouncing the public user toward login.
 *
 * Mechanism note: this is the ANDROID-SIDE equivalent of the web client gating CSRF/refresh on cookie
 * presence + `isAuthenticated`; the web reference has no per-call tag (see AND-395 spec §8 / audit #14).
 *
 * Read in an OkHttp interceptor / authenticator via `request.tag(Anonymous::class.java) != null`.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
object Anonymous
