import { create } from "zustand";
import { persist } from "zustand/middleware";
import { getPreferences, patchPreferences } from "@/api/endpoints/preferences";
import type { UiPreferences } from "@/api/endpoints/preferences";

export type Theme = "system" | "light" | "dark";

// Debounce timer for server sync
let syncTimer: ReturnType<typeof setTimeout> | null = null;

function debouncedSyncToServer(prefs: Partial<UiPreferences>) {
  if (syncTimer) clearTimeout(syncTimer);
  syncTimer = setTimeout(() => {
    patchPreferences(prefs).catch(() => {
      // Fire-and-forget: swallow errors.
      // The preference is already applied locally.
    });
  }, 500);
}

interface UiState {
  /** Current theme preference */
  theme: Theme;
  /** Whether the sidebar is collapsed to icon-only mode */
  sidebarCollapsed: boolean;
  /** Last 5 commands executed from the command palette */
  recentCommands: string[];
  /** Whether server-side preferences have been loaded */
  prefsLoaded: boolean;

  setTheme: (theme: Theme) => void;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  trackRecentCommand: (label: string) => void;
  loadServerPreferences: () => Promise<void>;
}

export const useUiStore = create<UiState>()(
  persist(
    (set, get) => ({
      theme: "system",
      sidebarCollapsed: false,
      recentCommands: [],
      prefsLoaded: false,

      setTheme: (theme) => {
        set({ theme });
        debouncedSyncToServer({ theme });
      },

      toggleSidebar: () => {
        const next = !get().sidebarCollapsed;
        set({ sidebarCollapsed: next });
        debouncedSyncToServer({ sidebar_collapsed: next });
      },

      setSidebarCollapsed: (collapsed) => {
        set({ sidebarCollapsed: collapsed });
        debouncedSyncToServer({ sidebar_collapsed: collapsed });
      },

      trackRecentCommand: (label) =>
        set((s) => {
          const filtered = s.recentCommands.filter((c) => c !== label);
          return { recentCommands: [label, ...filtered].slice(0, 5) };
        }),

      loadServerPreferences: async () => {
        try {
          const prefs = await getPreferences();
          const updates: Partial<UiState> = { prefsLoaded: true };
          if (prefs.theme) updates.theme = prefs.theme;
          if (prefs.sidebar_collapsed !== undefined) {
            updates.sidebarCollapsed = prefs.sidebar_collapsed;
          }
          set(updates);
        } catch {
          // Network error or not authenticated -- keep localStorage values
          set({ prefsLoaded: true });
        }
      },
    }),
    {
      name: "ui-store",
      partialize: (state) => ({
        theme: state.theme,
        sidebarCollapsed: state.sidebarCollapsed,
        recentCommands: state.recentCommands,
      }),
    },
  ),
);
