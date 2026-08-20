import * as React from "react";

/**
 * Global keyboard-shortcut engine for power-user trading + navigation.
 *
 * Design goals:
 *  - Fires shortcuts ONLY when the user is not typing in an input / textarea /
 *    contenteditable, and no modal owns focus.
 *  - Supports gmail-style "g then key" chord sequences with a ~1s window.
 *  - Never intercepts Cmd/Ctrl/Alt combinations already owned elsewhere
 *    (Cmd/Ctrl+K stays with the command palette).
 *  - Respects a persisted user toggle (localStorage "kbd.enabled", default on).
 *  - The pure sequence-matching logic (matchSequence) is exported for testing.
 */

// --- Types -------------------------------------------------------------------

export type ShortcutGroup = "Navigation" | "Trading" | "General";

/** A single-key (bare) shortcut, e.g. "/" or "?" or "b". */
export interface SingleShortcut {
  kind: "single";
  /** The bare key, lower-cased (e.g. "/", "?", "b"). */
  key: string;
  label: string;
  group: ShortcutGroup;
  /** Human-readable key hint for the help overlay (defaults derived from key). */
  hint?: string;
}

/** A two-key chord shortcut, e.g. g then m. */
export interface ChordShortcut {
  kind: "chord";
  /** First key, lower-cased (e.g. "g"). */
  first: string;
  /** Second key, lower-cased (e.g. "m"). */
  second: string;
  label: string;
  group: ShortcutGroup;
  hint?: string;
}

export type ShortcutDef = SingleShortcut | ChordShortcut;

/** An entry in the registry: a definition plus the action to run. */
export interface ShortcutEntry {
  def: ShortcutDef;
  action: () => void;
}

// --- localStorage toggle -----------------------------------------------------

const ENABLED_KEY = "kbd.enabled";

export function readKbdEnabled(): boolean {
  try {
    const raw = localStorage.getItem(ENABLED_KEY);
    // Default ON: only "false" disables it.
    return raw !== "false";
  } catch {
    return true;
  }
}

export function writeKbdEnabled(enabled: boolean): void {
  try {
    localStorage.setItem(ENABLED_KEY, enabled ? "true" : "false");
  } catch {
    // ignore storage failures (private mode etc.)
  }
}

// --- Focus / modal guards ----------------------------------------------------

/**
 * True when the currently focused element is an input, textarea, select, or
 * contenteditable -- i.e. the user is typing and shortcuts must NOT hijack keys.
 */
export function isTypingTarget(target: EventTarget | null): boolean {
  const el =
    (target as HTMLElement | null) ??
    (typeof document !== "undefined" ? (document.activeElement as HTMLElement | null) : null);
  if (!el) return false;
  const tag = el.tagName?.toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select") return true;
  if (el.isContentEditable) return true;
  return false;
}

/**
 * True when a modal/dialog currently owns focus. Radix dialogs render an
 * element with role="dialog" and data-state="open"; when one is open we let it
 * own the keyboard (Esc, arrow keys, etc.) and stay out of the way.
 */
export function isModalOpen(): boolean {
  if (typeof document === "undefined") return false;
  return !!document.querySelector(
    '[role="dialog"][data-state="open"], [role="alertdialog"][data-state="open"]',
  );
}

// --- Pure sequence matcher (unit-tested) -------------------------------------

export interface SequenceState {
  /** The pending first chord key, or null when idle. */
  pendingFirst: string | null;
  /** Epoch ms when the pending key was recorded (for the timeout window). */
  pendingAt: number;
}

export const IDLE_SEQUENCE: SequenceState = { pendingFirst: null, pendingAt: 0 };

/** How long (ms) the second key of a chord is awaited. */
export const CHORD_WINDOW_MS = 1000;

export interface SequenceMatchResult {
  /** Next sequence state after processing this key. */
  state: SequenceState;
  /** The matched entry to fire, if any. */
  matched: ShortcutEntry | null;
  /** True when the key was consumed (caller should preventDefault). */
  consumed: boolean;
}

/**
 * Pure reducer for the shortcut sequence state machine.
 *
 * Given the current pending state, the pressed key, the registry, and the
 * current time, it returns the next state, whether a shortcut matched, and
 * whether the key was consumed. It performs NO DOM or side effects, so it is
 * fully unit-testable.
 *
 * Rules:
 *  - If a chord first-key is pending and still within CHORD_WINDOW_MS, a
 *    matching second key fires that chord; any other key cancels the pending
 *    chord (and is then evaluated fresh as a potential new sequence start).
 *  - A bare key matching a single shortcut fires it.
 *  - A bare key that is the first of any chord starts a pending sequence.
 */
export function matchSequence(
  state: SequenceState,
  key: string,
  entries: ShortcutEntry[],
  now: number,
): SequenceMatchResult {
  const k = key.toLowerCase();

  // Resolve an expired pending chord back to idle before evaluating.
  let pending = state.pendingFirst;
  if (pending && now - state.pendingAt > CHORD_WINDOW_MS) {
    pending = null;
  }

  if (pending) {
    const chord = entries.find(
      (e) => e.def.kind === "chord" && e.def.first === pending && e.def.second === k,
    );
    if (chord) {
      return { state: IDLE_SEQUENCE, matched: chord, consumed: true };
    }
    // No match: cancel the pending chord and re-evaluate this key fresh.
    return matchSequence(IDLE_SEQUENCE, k, entries, now);
  }

  // No pending chord. First, a bare single-key shortcut?
  const single = entries.find((e) => e.def.kind === "single" && e.def.key === k);
  if (single) {
    return { state: IDLE_SEQUENCE, matched: single, consumed: true };
  }

  // Does this key start a chord?
  const startsChord = entries.some((e) => e.def.kind === "chord" && e.def.first === k);
  if (startsChord) {
    return {
      state: { pendingFirst: k, pendingAt: now },
      matched: null,
      consumed: true,
    };
  }

  // Nothing matched; leave idle, do not consume.
  return { state: IDLE_SEQUENCE, matched: null, consumed: false };
}

// --- Registry context (for the trade view to register scoped handlers) -------

interface RegistryApi {
  register: (entries: ShortcutEntry[]) => () => void;
  getEntries: () => ShortcutEntry[];
  enabled: boolean;
  setEnabled: (v: boolean) => void;
  pendingFirst: string | null;
}

const RegistryContext = React.createContext<RegistryApi | null>(null);

/**
 * Provider that owns the global keydown listener, the shortcut registry, the
 * enabled toggle, and the chord state machine. Mount once in the app chrome.
 */
export function KeyboardShortcutsProvider({
  baseEntries,
  children,
}: {
  /** Always-on entries (navigation + general) contributed by the provider host. */
  baseEntries: ShortcutEntry[];
  children: React.ReactNode;
}) {
  const [extra, setExtra] = React.useState<ShortcutEntry[][]>([]);
  const [enabled, setEnabledState] = React.useState<boolean>(() => readKbdEnabled());
  const [pendingFirst, setPendingFirst] = React.useState<string | null>(null);

  const seqRef = React.useRef<SequenceState>(IDLE_SEQUENCE);
  const clearTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const setEnabled = React.useCallback((v: boolean) => {
    setEnabledState(v);
    writeKbdEnabled(v);
  }, []);

  const register = React.useCallback((entries: ShortcutEntry[]) => {
    setExtra((prev) => [...prev, entries]);
    return () => {
      setExtra((prev) => prev.filter((e) => e !== entries));
    };
  }, []);

  // Flatten base + scoped entries. Base first so scoped can shadow if needed.
  const allEntries = React.useMemo<ShortcutEntry[]>(
    () => [...baseEntries, ...extra.flat()],
    [baseEntries, extra],
  );
  const entriesRef = React.useRef(allEntries);
  entriesRef.current = allEntries;

  const getEntries = React.useCallback(() => entriesRef.current, []);

  const enabledRef = React.useRef(enabled);
  enabledRef.current = enabled;

  React.useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (!enabledRef.current) return;
      if (e.defaultPrevented) return;
      // Leave all Cmd/Ctrl/Alt combos to their owners (palette, browser, etc.).
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      // IME composition must never be intercepted.
      if (e.isComposing) return;
      // A modal owns its own keyboard (Esc, arrows, etc.) -- stay out.
      if (isModalOpen()) return;

      // Normalize the pressed key. Single printable keys pass through as-is;
      // a small allow-list of named keys (Escape) also participates so the
      // trade view can bind Esc. Everything else (Tab, arrows, F-keys, bare
      // modifier presses) is ignored.
      const raw = e.key;
      let key: string;
      if (raw.length === 1) {
        key = raw;
      } else if (raw === "Escape") {
        key = "escape";
      } else {
        return;
      }

      // Never hijack keys while typing -- EXCEPT Escape, which is never text
      // input and is how the user blurs/clears the trade-ticket fields.
      if (key !== "escape" && isTypingTarget(e.target)) return;

      const result = matchSequence(seqRef.current, key, entriesRef.current, Date.now());
      seqRef.current = result.state;
      setPendingFirst(result.state.pendingFirst);

      if (clearTimerRef.current) clearTimeout(clearTimerRef.current);
      if (result.state.pendingFirst) {
        clearTimerRef.current = setTimeout(() => {
          seqRef.current = IDLE_SEQUENCE;
          setPendingFirst(null);
        }, CHORD_WINDOW_MS);
      }

      if (result.consumed) e.preventDefault();
      if (result.matched) {
        result.matched.action();
      }
    }

    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      if (clearTimerRef.current) clearTimeout(clearTimerRef.current);
    };
  }, []);

  const api = React.useMemo<RegistryApi>(
    () => ({ register, getEntries, enabled, setEnabled, pendingFirst }),
    [register, getEntries, enabled, setEnabled, pendingFirst],
  );

  return <RegistryContext.Provider value={api}>{children}</RegistryContext.Provider>;
}

/** Access the registry API (enabled toggle, pending chord key, etc.). */
export function useKeyboardShortcutsApi(): RegistryApi | null {
  return React.useContext(RegistryContext);
}

/**
 * Register a set of scoped shortcut entries for as long as the calling
 * component is mounted. Used by the trade view for b/s/p/q/Esc.
 */
export function useRegisterShortcuts(entries: ShortcutEntry[]): void {
  const api = React.useContext(RegistryContext);
  React.useEffect(() => {
    if (!api) return;
    return api.register(entries);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, entries]);
}
