// FE-141 (EPIC E, <- BE-141): pure helpers for resolving media URLs against a
// real CDN base and for driving upload progress + retry. No DOM, no network —
// all side-effecting concerns (XHR, import.meta.env) live in the callers.

/** Max number of upload attempts beyond the first before giving up. */
export const MAX_UPLOAD_RETRIES = 3;

/** Encode each path segment of an S3 key while preserving the "/" separators. */
export function encodeMediaKey(key: string): string {
  return key
    .split("/")
    .map((seg) => encodeURIComponent(seg))
    .join("/");
}

const stripTrailingSlash = (s: string): string => s.replace(/\/+$/, "");
const stripLeadingSlash = (s: string): string => s.replace(/^\/+/, "");

const isAbsoluteUrl = (s: string): boolean => /^https?:\/\//i.test(s);

export type MediaRef = string | { bucket?: string; key?: string; url?: string };

export interface ResolveMediaOpts {
  /** Real CDN origin/base (e.g. https://cdn.example.com). Empty/undefined -> mock. */
  cdnBase?: string;
  /** API base to join relative paths against when no CDN is configured. */
  apiBase?: string;
}

/**
 * Resolve a media reference to a URL suitable for an <img>/<video>/<audio> src.
 * - already-absolute http(s) URL (or explicit `url` field) -> returned as-is
 * - relative path string -> joined to cdnBase (else apiBase, else returned as-is)
 * - {bucket,key} -> `${cdnBase}/${bucket}/${encodeMediaKey(key)}`, else the
 *   existing `/mock/s3/...` fallback so dev/mock behavior is unchanged.
 */
export function resolveMediaUrl(
  input: MediaRef | undefined | null,
  opts: ResolveMediaOpts = {},
): string | undefined {
  if (input == null) return undefined;
  const cdnBase = opts.cdnBase ? stripTrailingSlash(opts.cdnBase) : "";
  const apiBase = opts.apiBase ? stripTrailingSlash(opts.apiBase) : "";

  if (typeof input === "string") {
    const s = input.trim();
    if (!s) return undefined;
    if (isAbsoluteUrl(s)) return s;
    // Relative path: prefer CDN, then API base, else leave as-is.
    const base = cdnBase || apiBase;
    if (!base) return s;
    return `${base}/${stripLeadingSlash(s)}`;
  }

  // Object form. An explicit absolute/relative url wins.
  if (typeof input.url === "string" && input.url.trim()) {
    return resolveMediaUrl(input.url, opts);
  }
  const { bucket, key } = input;
  if (!bucket || !key) return undefined;
  const encodedKey = encodeMediaKey(key);
  if (cdnBase) return `${cdnBase}/${bucket}/${encodedKey}`;
  // Mock fallback (matches the legacy buildS3ObjectUrl output exactly).
  return `/mock/s3/${bucket}/${encodedKey}`;
}

/**
 * Whether an upload failure with the given HTTP status (or 0 for a network
 * error) is worth retrying. Retries on: network (0), 408, 429, and any 5xx.
 */
export function isRetryableUploadStatus(status: number): boolean {
  if (status === 0) return true; // network error / aborted / no response
  if (status === 408 || status === 429) return true;
  if (status >= 500 && status <= 599) return true;
  return false;
}

/** Exponential backoff (ms) for the Nth retry attempt (1-indexed), capped. */
export function uploadBackoffMs(attempt: number): number {
  const n = Math.max(1, Math.floor(attempt));
  const base = 500 * 2 ** (n - 1); // 500, 1000, 2000, ...
  return Math.min(base, 8000);
}

/** Clamp a loaded/total pair to an integer 0..100 progress percent. */
export function uploadProgressPct(loaded: number, total: number): number {
  if (!Number.isFinite(loaded) || !Number.isFinite(total) || total <= 0) return 0;
  const pct = Math.round((loaded / total) * 100);
  if (pct < 0) return 0;
  if (pct > 100) return 100;
  return pct;
}
