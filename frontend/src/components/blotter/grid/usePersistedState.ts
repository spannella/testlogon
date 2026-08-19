// Tiny localStorage-backed useState.  On mount, seeds from storage;
// on every setState, writes back.  Guards against SSR / disabled
// storage / JSON errors so a corrupt key doesn't crash the app.

import { useCallback, useEffect, useRef, useState } from 'react';

export function usePersistedState<T>(
  key: string,
  initial: T | (() => T),
): [T, React.Dispatch<React.SetStateAction<T>>] {
  const [state, setState] = useState<T>(() => {
    try {
      const raw = typeof window !== 'undefined' ? window.localStorage.getItem(key) : null;
      if (raw != null) return JSON.parse(raw) as T;
    } catch { /* corrupt — fall through */ }
    return typeof initial === 'function' ? (initial as () => T)() : initial;
  });

  // Skip the first write so we don't stomp storage with the initial value.
  const firstRef = useRef(true);
  useEffect(() => {
    if (firstRef.current) { firstRef.current = false; return; }
    try {
      window.localStorage.setItem(key, JSON.stringify(state));
    } catch { /* quota / private mode — ignore */ }
  }, [key, state]);

  return [state, setState];
}

// Convenience clear() so a "reset layout" button can nuke a whole prefix.
export function clearPersistedKeys(prefix: string) {
  try {
    for (let i = window.localStorage.length - 1; i >= 0; i--) {
      const k = window.localStorage.key(i);
      if (k && k.startsWith(prefix)) window.localStorage.removeItem(k);
    }
  } catch { /* ignore */ }
}

// Setter wrapper that also removes the item on `null` — handy for
// callers that want a "reset to default" affordance.
export function useResettablePersistedState<T>(key: string, initial: T | (() => T)) {
  const [state, setState] = usePersistedState<T>(key, initial);
  const reset = useCallback(() => {
    try { window.localStorage.removeItem(key); } catch { /* ignore */ }
    setState(typeof initial === 'function' ? (initial as () => T)() : initial);
  }, [key, initial, setState]);
  return { state, setState, reset };
}
