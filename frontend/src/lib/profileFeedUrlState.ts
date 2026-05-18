export interface ProfileFeedUrlState {
  q?: string;
  from?: string;
  to?: string;
  hasMedia?: boolean;
  cursor?: string;
}

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const firstNonEmpty = (...values: Array<string | null>): string | undefined => {
  for (const value of values) {
    const trimmed = (value ?? "").trim();
    if (trimmed) return trimmed;
  }
  return undefined;
};

export function parseProfileFeedUrlState(params: URLSearchParams): ProfileFeedUrlState {
  const q = firstNonEmpty(params.get("pf_q"), params.get("q"));
  const fromRaw = firstNonEmpty(params.get("pf_from"), params.get("from"));
  const toRaw = firstNonEmpty(params.get("pf_to"), params.get("to"));
  const hasMediaRaw = firstNonEmpty(params.get("pf_has_media"), params.get("has_media"));
  const cursor = firstNonEmpty(params.get("pf_cursor"), params.get("cursor"));

  const from = fromRaw && DATE_RE.test(fromRaw) ? fromRaw : undefined;
  const to = toRaw && DATE_RE.test(toRaw) ? toRaw : undefined;
  const hasMedia =
    hasMediaRaw === "1" || hasMediaRaw === "true"
      ? true
      : hasMediaRaw === "0" || hasMediaRaw === "false"
        ? false
        : undefined;

  return {
    ...(q ? { q } : {}),
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
    ...(typeof hasMedia === "boolean" ? { hasMedia } : {}),
    ...(cursor ? { cursor } : {}),
  };
}

export function writeProfileFeedUrlState(
  current: URLSearchParams,
  patch: ProfileFeedUrlState,
): URLSearchParams {
  const next = new URLSearchParams(current);

  const setOrDelete = (key: string, value?: string) => {
    if (!value) next.delete(key);
    else next.set(key, value);
  };

  if ("q" in patch) setOrDelete("pf_q", patch.q?.trim());
  if ("from" in patch) setOrDelete("pf_from", patch.from && DATE_RE.test(patch.from) ? patch.from : undefined);
  if ("to" in patch) setOrDelete("pf_to", patch.to && DATE_RE.test(patch.to) ? patch.to : undefined);
  if ("hasMedia" in patch) setOrDelete("pf_has_media", typeof patch.hasMedia === "boolean" ? (patch.hasMedia ? "1" : "0") : undefined);
  if ("cursor" in patch) setOrDelete("pf_cursor", patch.cursor);

  return next;
}
