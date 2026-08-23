import { useCallback, useEffect, useState } from "react";
import {
  loadWatchlist,
  saveWatchlist,
  isWatched,
  toggleWatch as toggleWatchPure,
  removeWatch as removeWatchPure,
  WATCHLIST_EVENT,
  WATCHLIST_KEY,
  type WatchItem,
  type WatchKind,
} from "@/lib/watchlist";

/**
 * React binding for the UNIFIED cross-instrument watchlist.
 *
 * Wraps the pure `@/lib/watchlist` store with localStorage persistence and a
 * cross-component/cross-tab sync layer: every consumer reads the same list and
 * a `toggle` from one surface (a star on the token detail page, say) reflects
 * instantly on the /watchlist page and the market browser's Watchlist tab.
 *
 * Legacy symbol-only payloads are migrated transparently on first read
 * (see `migrateLegacy`), so the existing symbol watchlist keeps working.
 */
export function useWatchlist() {
  const [items, setItems] = useState<WatchItem[]>(loadWatchlist);

  // Re-read on same-tab mutations (custom event) + other-tab writes (storage).
  useEffect(() => {
    const reread = () => setItems(loadWatchlist());
    const onStorage = (e: StorageEvent) => {
      if (e.key === null || e.key === WATCHLIST_KEY) reread();
    };
    window.addEventListener(WATCHLIST_EVENT, reread);
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener(WATCHLIST_EVENT, reread);
      window.removeEventListener("storage", onStorage);
    };
  }, []);

  const toggle = useCallback((kind: WatchKind, id: string | number) => {
    setItems((prev) => {
      const next = toggleWatchPure(prev, kind, id);
      saveWatchlist(next);
      return next;
    });
  }, []);

  const remove = useCallback((kind: WatchKind, id: string | number) => {
    setItems((prev) => {
      const next = removeWatchPure(prev, kind, id);
      saveWatchlist(next);
      return next;
    });
  }, []);

  const has = useCallback(
    (kind: WatchKind, id: string | number) => isWatched(items, kind, id),
    [items],
  );

  return { items, has, toggle, remove };
}
