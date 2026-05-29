import { useEffect, useCallback, useRef, useState } from "react";

export interface Shortcut {
  /** Key combination, e.g., "ctrl+k", "escape", "?", "ctrl+1" */
  key: string;
  /** Human-readable label for the help overlay */
  label: string;
  /** Category grouping for the help overlay */
  group: "Navigation" | "Messaging" | "Actions" | "General";
  /** The action to execute */
  action: () => void;
  /** If true, the shortcut fires even when an input/textarea is focused */
  activeInInput?: boolean;
}

/**
 * Normalize a KeyboardEvent into a key string like "ctrl+k", "shift+?", etc.
 */
function normalizeKeyEvent(e: KeyboardEvent): string {
  const parts: string[] = [];
  if (e.ctrlKey || e.metaKey) parts.push("ctrl");
  if (e.shiftKey) parts.push("shift");
  if (e.altKey) parts.push("alt");
  const key = e.key.toLowerCase();
  if (!["control", "meta", "shift", "alt"].includes(key)) {
    parts.push(key);
  }
  return parts.join("+");
}

/**
 * Check if the currently focused element is an input, textarea, or
 * contenteditable element.
 */
export function isInputFocused(): boolean {
  const el = document.activeElement;
  if (!el) return false;
  const tag = el.tagName.toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select") return true;
  if ((el as HTMLElement).isContentEditable) return true;
  return false;
}

/**
 * Custom hook that registers a global keydown listener for all shortcuts.
 * Mount this once at the app root (e.g., in AppShell or Header).
 */
export function useGlobalShortcuts(shortcuts: Shortcut[]) {
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      const normalized = normalizeKeyEvent(e);
      for (const shortcut of shortcuts) {
        if (shortcut.key !== normalized) continue;
        if (!shortcut.activeInInput && isInputFocused()) continue;
        e.preventDefault();
        shortcut.action();
        return;
      }
    },
    [shortcuts],
  );

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);
}

/**
 * Get all registered shortcuts grouped by category for display in the help overlay.
 */
export function getGroupedShortcuts(shortcuts: Shortcut[]): Record<string, Shortcut[]> {
  const groups: Record<string, Shortcut[]> = {};
  for (const s of shortcuts) {
    if (!groups[s.group]) groups[s.group] = [];
    groups[s.group]!.push(s);
  }
  return groups;
}

// ─── Chord sequence support ──────────────────────────────────────────────────

export interface ChordMapping {
  /** First key in the chord, e.g. "g" */
  first: string;
  /** Second key in the chord, e.g. "m" */
  second: string;
  /** Human-readable label for the help overlay */
  label: string;
  /** Category grouping */
  group: "Navigation" | "Messaging" | "Actions" | "General";
  /** The action to execute when the chord completes */
  action: () => void;
}

/**
 * Custom hook that handles two-key chord sequences (e.g., g then m).
 *
 * The hook listens for bare key presses (no modifiers). When a key matching
 * the first element of any chord is pressed, it enters "pending" state and
 * waits up to 1 second for the second key. If the second key matches, the
 * chord action fires. Otherwise the chord is cancelled.
 *
 * @param chords - Array of chord mappings
 * @param onChordStart - Called with the first key when a chord begins
 * @param onChordEnd - Called when a chord completes or times out
 */
export function useChordShortcuts(
  chords: ChordMapping[],
  onChordStart?: (firstKey: string) => void,
  onChordEnd?: () => void,
) {
  const pendingFirst = useRef<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      // Never activate chords in inputs or during IME composition
      if (isInputFocused()) return;
      if (e.isComposing) return;

      // Never activate when modifier keys are held
      if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;

      const key = e.key.toLowerCase();

      if (pendingFirst.current) {
        // We are waiting for the second key of a chord
        const match = chords.find(
          (c) => c.first === pendingFirst.current && c.second === key,
        );

        // Clear pending state regardless of match
        if (timerRef.current) clearTimeout(timerRef.current);
        pendingFirst.current = null;
        onChordEnd?.();

        if (match) {
          e.preventDefault();
          match.action();
        }
        // If no match, chord is cancelled — fall through (key types normally)
        return;
      }

      // Check if this key starts any chord
      const isChordStart = chords.some((c) => c.first === key);
      if (isChordStart) {
        e.preventDefault();
        pendingFirst.current = key;
        onChordStart?.(key);

        timerRef.current = setTimeout(() => {
          pendingFirst.current = null;
          onChordEnd?.();
        }, 1000);
      }
    },
    [chords, onChordStart, onChordEnd],
  );

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [handleKeyDown]);
}

/**
 * Hook that manages the chord indicator UI state.
 * Returns the pending first key (or null) for display in a floating indicator.
 */
export function useChordIndicator() {
  const [pendingKey, setPendingKey] = useState<string | null>(null);

  const onChordStart = useCallback((key: string) => {
    setPendingKey(key);
  }, []);

  const onChordEnd = useCallback(() => {
    setPendingKey(null);
  }, []);

  return { pendingKey, onChordStart, onChordEnd };
}
