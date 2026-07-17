/**
 * Shared retry-on-429 helper for rate-limited E2E flows.
 *
 * Several money/commerce flows sit behind per-user/per-session rate limiters
 * (dispute filing, tipping, refund requests). When specs run sequentially the
 * back-to-back calls can trip the limiter and return HTTP 429, producing a
 * flaky failure that is NOT a product bug. This helper transparently waits out
 * the limiter window (honoring the backend`s `retry_after_ms` / `Retry-After`
 * hint when present) and retries.
 *
 * Modeled on the inline `tipWithRetry` pattern in broadcast-tips.spec.ts, but
 * generic over any thunk that returns a Playwright APIResponse-like object with
 * a `.status()` method, so it can wrap `apiPost`, `page.request.post`, etc.
 *
 * Usage:
 *   import { retryOn429 } from "./helpers/retry";
 *   const resp = await retryOn429(() => apiPost(page, "alice", "/api/.../disputes", body));
 */

export interface StatusResponse {
  status(): number;
  json(): Promise<any>;
  headers?(): Record<string, string>;
}

export interface RetryOptions {
  /** Max retries after the first attempt (default 4). */
  maxRetries?: number;
  /** Fallback wait when the backend gives no retry hint, ms (default 3200). */
  defaultWaitMs?: number;
  /** Hard cap on any single wait, ms (default 5000). */
  maxWaitMs?: number;
}

/**
 * Invoke `fn`; if it returns 429, wait out the limiter window and retry up to
 * `maxRetries` times. Returns the first non-429 response, or the last 429 if
 * all retries are exhausted (so the caller can still assert on it).
 */
export async function retryOn429<T extends StatusResponse>(
  fn: () => Promise<T>,
  opts: RetryOptions = {},
): Promise<T> {
  const { maxRetries = 4, defaultWaitMs = 3200, maxWaitMs = 5000 } = opts;
  let resp = await fn();
  for (let attempt = 0; attempt < maxRetries && resp.status() === 429; attempt++) {
    let waitMs = defaultWaitMs;
    try {
      const body = await resp.json().catch(() => ({}));
      const hinted =
        body?.detail?.retry_after_ms ??
        body?.retry_after_ms ??
        (body?.detail?.retry_after ? body.detail.retry_after * 1000 : undefined) ??
        (body?.retry_after ? body.retry_after * 1000 : undefined);
      if (typeof hinted === "number" && hinted > 0) waitMs = hinted;
      else if (typeof resp.headers === "function") {
        const h = resp.headers();
        const ra = h["retry-after"];
        if (ra && !Number.isNaN(Number(ra))) waitMs = Number(ra) * 1000;
      }
    } catch {
      /* fall back to defaultWaitMs */
    }
    await new Promise((r) => setTimeout(r, Math.min(waitMs + 200, maxWaitMs)));
    resp = await fn();
  }
  return resp;
}
