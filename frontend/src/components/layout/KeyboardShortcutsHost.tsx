import * as React from "react";
import { useNavigate } from "react-router-dom";
import {
  KeyboardShortcutsProvider,
  useKeyboardShortcutsApi,
  type ShortcutEntry,
} from "@/hooks/useKeyboardShortcuts";
import ShortcutsHelp from "@/components/layout/ShortcutsHelp";

/**
 * Opens the global command palette by dispatching the synthetic Cmd/Ctrl+K
 * keydown that CommandPalette's single global listener owns. Keeping this as a
 * dispatch (rather than shared state) avoids coupling to the palette internals.
 */
function openCommandPalette() {
  const isMac =
    typeof navigator !== "undefined" && navigator.userAgent.includes("Mac");
  window.dispatchEvent(
    new KeyboardEvent("keydown", {
      key: "k",
      ctrlKey: !isMac,
      metaKey: isMac,
      bubbles: true,
    }),
  );
}

/**
 * Floating indicator that shows the pending chord first-key (e.g. after "g").
 */
function ChordIndicator() {
  const api = useKeyboardShortcutsApi();
  const pending = api?.pendingFirst;
  if (!pending) return null;
  return (
    <div
      data-testid="kbd-chord-indicator"
      className="fixed bottom-4 right-4 z-50 animate-in fade-in slide-in-from-bottom-2 duration-150"
    >
      <div className="rounded-lg border border-border bg-card p-3 shadow-lg">
        <div className="flex items-center gap-2">
          <kbd className="rounded bg-primary/10 px-2 py-0.5 font-mono text-sm font-bold text-primary">
            {pending.toUpperCase()}
          </kbd>
          <span className="text-sm text-muted-foreground">then a key...</span>
        </div>
        <p className="mt-1 text-[10px] text-muted-foreground">
          Press a key within 1s (Esc cancels)
        </p>
      </div>
    </div>
  );
}

/**
 * Listens for the app-wide "open-shortcuts-help" custom event so the command
 * palette / settings can open the overlay without prop drilling.
 */
function useHelpOpener(setOpen: (v: boolean) => void) {
  React.useEffect(() => {
    const handler = () => setOpen(true);
    window.addEventListener("open-shortcuts-help", handler);
    return () => window.removeEventListener("open-shortcuts-help", handler);
  }, [setOpen]);
}

/**
 * App-chrome host for the keyboard-shortcut engine. Mount once (in AppShell)
 * inside the authenticated layout so shortcuts are active when logged in.
 *
 * Provides the always-on Navigation + General shortcuts. Trade-view shortcuts
 * (b/s/p/q/Esc) register themselves via useRegisterShortcuts when the trade
 * ticket is mounted.
 */
export default function KeyboardShortcutsHost({
  children,
}: {
  children: React.ReactNode;
}) {
  const navigate = useNavigate();
  const [helpOpen, setHelpOpen] = React.useState(false);
  useHelpOpener(setHelpOpen);

  const baseEntries = React.useMemo<ShortcutEntry[]>(() => {
    const nav = (
      second: string,
      label: string,
      path: string,
    ): ShortcutEntry => ({
      def: { kind: "chord", first: "g", second, label, group: "Navigation" },
      action: () => navigate(path),
    });

    return [
      // --- Navigation (g + key) ---
      nav("h", "Go to Home", "/home"),
      nav("m", "Go to Markets", "/markets"),
      nav("p", "Go to Portfolio", "/portfolio"),
      nav("l", "Go to PnL", "/pnl"),
      nav("r", "Go to Reports", "/reports"),
      nav("w", "Go to Watchlist", "/markets"),
      nav("b", "Go to Blotter", "/blotter"),
      nav("a", "Go to Price alerts", "/markets/price-alerts"),
      nav("s", "Go to Settings", "/settings"),

      // --- General ---
      {
        def: { kind: "single", key: "/", label: "Search (command palette)", group: "General" },
        action: openCommandPalette,
      },
      {
        def: { kind: "single", key: "?", label: "Show this help", group: "General" },
        action: () => setHelpOpen(true),
      },
    ];
  }, [navigate]);

  return (
    <KeyboardShortcutsProvider baseEntries={baseEntries}>
      {children}
      <ChordIndicator />
      <ShortcutsHelp open={helpOpen} onOpenChange={setHelpOpen} />
    </KeyboardShortcutsProvider>
  );
}

/** Fire the app-wide event that opens the shortcuts help overlay. */
export function openShortcutsHelp() {
  window.dispatchEvent(new CustomEvent("open-shortcuts-help"));
}
