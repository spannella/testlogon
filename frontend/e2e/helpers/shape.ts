/**
 * Response-shape guards for the cpp E2E harness (TRACK: other-NPE).
 *
 * PROBLEM: many specs do `(await resp.json() as T[]).find(...)` / `.map(...)`
 * / `.length` directly on a parsed body. When cpp returns a DIFFERENT shape on
 * that route (an error object, a { items: [...] } / { messages: [...] } wrapper,
 * or an empty 4xx body) the raw `.find is not a function` / "reading 'find' of
 * undefined" TypeError aborts the whole test file mid-describe, hiding the real
 * signal and taking sibling tests down with it. These guards turn that into a
 * NORMAL, localized assertion failure (or transparently unwrap a known wrapper),
 * so the failure is countable and the file keeps running.
 *
 * They are shape-only and backend-agnostic: safe on BOTH the Python and cpp
 * paths (a genuine array is returned untouched), so no isCpp() gate is needed.
 */
import { expect } from "@playwright/test";

/**
 * Coerce a parsed JSON body to an array. Accepts a bare array, or a single-key
 * wrapper object whose value is an array (items/messages/results/data/... — the
 * shapes cpp actually uses). If it cannot find an array, returns [] so the
 * caller's `.find`/`.map` runs and the subsequent assertion fails cleanly
 * instead of throwing a TypeError.
 */
export function asArray<T = any>(body: unknown): T[] {
  if (Array.isArray(body)) return body as T[];
  if (body && typeof body === "object") {
    const o = body as Record<string, unknown>;
    for (const k of ["items", "messages", "results", "data", "entries", "posts", "requests", "payouts", "list"]) {
      if (Array.isArray(o[k])) return o[k] as T[];
    }
  }
  return [];
}

/**
 * Assert `body` is a usable array (bare or via a known wrapper) and return it.
 * Fails with an informative message showing the actual shape when it is not,
 * rather than letting a downstream `.find` throw a bare TypeError.
 */
export function expectArray<T = any>(body: unknown, what = "response body"): T[] {
  const arr = asArray<T>(body);
  if (!Array.isArray(body) && arr.length === 0 && !(body && typeof body === "object")) {
    expect(Array.isArray(body), `${what} should be an array (or {items|messages|...}); got: ${JSON.stringify(body)?.slice(0, 200)}`).toBe(true);
  }
  return arr;
}
