/**
 * UNIFIED cross-instrument watchlist (framework-free, pure functions).
 *
 * The market browser shipped a symbol-only watchlist persisted at
 * `md.watchlist.v1` as a bare `number[]` (an ordered list of `symbol_id`s).
 * This module GENERALIZES that store to hold three kinds of instrument —
 * exchange symbols, creator revenue-share tokens, and strategy funds — as
 * ordered `WatchItem`s, while transparently MIGRATING any legacy symbol-only
 * payload found under the same key. Insertion order is preserved.
 *
 * Everything here is pure + storage-agnostic where practical: the mutation
 * helpers take/return arrays; a thin localStorage + event layer at the bottom
 * lets React components subscribe (`watchlist:changed`) and stay in sync.
 */

export type WatchKind = "symbol" | "token" | "strategy";

/** One watched instrument. `id` is a string for tokens/strategies and the
 *  stringified `symbol_id` for symbols (so the store is uniformly keyed). */
export interface WatchItem {
  kind: WatchKind;
  id: string;
}

/** Persistence key — UNCHANGED from the legacy symbol watchlist so existing
 *  entries are picked up and migrated in place (no orphaned key). */
export const WATCHLIST_KEY = "md.watchlist.v1";

/** Broadcast event name; components re-read on this (same-tab) + `storage`. */
export const WATCHLIST_EVENT = "watchlist:changed";

const KIND_ORDER: Record<WatchKind, number> = { symbol: 0, token: 1, strategy: 2 };
const KIND_LABEL: Record<WatchKind, string> = {
  symbol: "Symbol",
  token: "Token",
  strategy: "Strategy",
};

/** Stable composite key for an item — used for identity + React keys. */
export function watchKey(kind: WatchKind, id: string | number): string {
  return `${kind}:${id}`;
}

/** Human-facing badge label for a kind. */
export function kindLabel(kind: WatchKind): string {
  return KIND_LABEL[kind] ?? kind;
}

function isWatchKind(v: unknown): v is WatchKind {
  return v === "symbol" || v === "token" || v === "strategy";
}

/** True if `item` is in `list`. */
export function isWatched(list: WatchItem[], kind: WatchKind, id: string | number): boolean {
  const key = watchKey(kind, id);
  return list.some((w) => watchKey(w.kind, w.id) === key);
}

/** Return a new list with the item toggled (added to the end if absent). */
export function toggleWatch(list: WatchItem[], kind: WatchKind, id: string | number): WatchItem[] {
  const sid = String(id);
  const key = watchKey(kind, sid);
  if (list.some((w) => watchKey(w.kind, w.id) === key)) {
    return list.filter((w) => watchKey(w.kind, w.id) !== key);
  }
  return [...list, { kind, id: sid }];
}

/** Return a new list with the item removed (no-op if absent). */
export function removeWatch(list: WatchItem[], kind: WatchKind, id: string | number): WatchItem[] {
  const key = watchKey(kind, id);
  return list.filter((w) => watchKey(w.kind, w.id) !== key);
}

/**
 * Coerce ANY persisted payload into a clean `WatchItem[]`.
 *  - A bare `number[]` (or numeric-string[]) is the LEGACY symbol watchlist →
 *    each entry becomes `{kind:"symbol", id}` (default kind on migration).
 *  - An array of `{kind,id}` objects is the new shape → validated + normalized
 *    (ids coerced to string, unknown kinds dropped).
 * Duplicates (by composite key) are removed, first occurrence wins, order kept.
 */
export function migrateLegacy(raw: unknown): WatchItem[] {
  if (!Array.isArray(raw)) return [];
  const out: WatchItem[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    let item: WatchItem | null = null;
    if (typeof entry === "number" && Number.isFinite(entry)) {
      item = { kind: "symbol", id: String(entry) };
    } else if (typeof entry === "string" && entry.trim() !== "") {
      // A bare string in the legacy array is treated as a symbol id.
      item = { kind: "symbol", id: entry };
    } else if (entry && typeof entry === "object") {
      const k = (entry as Record<string, unknown>).kind;
      const idv = (entry as Record<string, unknown>).id;
      if (isWatchKind(k) && (typeof idv === "string" || typeof idv === "number")) {
        const id = String(idv);
        if (id.trim() !== "") item = { kind: k, id };
      }
    }
    if (!item) continue;
    const key = watchKey(item.kind, item.id);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

/**
 * Deterministic display order: group by kind (symbol → token → strategy),
 * preserving each item's original insertion order within its kind. Returns a
 * new array; input is not mutated.
 */
export function sortWatchItems(list: WatchItem[]): WatchItem[] {
  return list
    .map((item, i) => ({ item, i }))
    .sort((a, b) => {
      const ko = KIND_ORDER[a.item.kind] - KIND_ORDER[b.item.kind];
      return ko !== 0 ? ko : a.i - b.i;
    })
    .map((x) => x.item);
}

// ── Storage + event layer (thin; the pure API above is what tests target) ──

/** Read + migrate the persisted watchlist. Safe on SSR / storage errors. */
export function loadWatchlist(): WatchItem[] {
  try {
    if (typeof localStorage === "undefined") return [];
    const raw = localStorage.getItem(WATCHLIST_KEY);
    return migrateLegacy(raw ? JSON.parse(raw) : []);
  } catch {
    return [];
  }
}

/** Persist + broadcast a same-tab change so all listeners re-read. */
export function saveWatchlist(list: WatchItem[]): void {
  try {
    if (typeof localStorage === "undefined") return;
    localStorage.setItem(WATCHLIST_KEY, JSON.stringify(list));
    if (typeof window !== "undefined") {
      window.dispatchEvent(new Event(WATCHLIST_EVENT));
    }
  } catch {
    /* ignore quota / disabled storage */
  }
}
