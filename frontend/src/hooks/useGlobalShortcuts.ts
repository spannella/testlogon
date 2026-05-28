import { useEffect, useCallback } from "react";

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
function isInputFocused(): boolean {
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
