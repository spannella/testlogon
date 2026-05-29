import { create } from "zustand";
import { persist } from "zustand/middleware";
import { getPreferences, patchPreferences } from "@/api/endpoints/preferences";
import type { UiPreferences, AccentColor, FontSize, Density } from "@/api/endpoints/preferences";

export type Theme = "system" | "light" | "dark";
export type { AccentColor, FontSize, Density };

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
  /** Last 10 search queries from the command palette / search page */
  recentSearches: string[];
  /** Whether server-side preferences have been loaded */
  prefsLoaded: boolean;
  /** Accent color preset */
  accentColor: AccentColor;
  /** Custom accent hex (when accentColor is "custom") */
  customAccentHex: string;
  /** Font size preference */
  fontSize: FontSize;
  /** UI density preference */
  density: Density;
  /** High contrast mode */
  highContrast: boolean;

  setTheme: (theme: Theme) => void;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  trackRecentCommand: (label: string) => void;
  trackRecentSearch: (query: string) => void;
  removeRecentSearch: (query: string) => void;
  clearRecentSearches: () => void;
  loadServerPreferences: () => Promise<void>;
  setAccentColor: (color: AccentColor) => void;
  setCustomAccentHex: (hex: string) => void;
  setFontSize: (size: FontSize) => void;
  setDensity: (density: Density) => void;
  setHighContrast: (enabled: boolean) => void;
}

export const useUiStore = create<UiState>()(
  persist(
    (set, get) => ({
      theme: "system",
      sidebarCollapsed: false,
      recentCommands: [],
      recentSearches: [],
      prefsLoaded: false,
      accentColor: "blue",
      customAccentHex: "",
      fontSize: "default",
      density: "comfortable",
      highContrast: false,

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

      trackRecentSearch: (query) =>
        set((s) => {
          const filtered = s.recentSearches.filter((q) => q !== query);
          return { recentSearches: [query, ...filtered].slice(0, 10) };
        }),

      removeRecentSearch: (query) =>
        set((s) => ({
          recentSearches: s.recentSearches.filter((q) => q !== query),
        })),

      clearRecentSearches: () => set({ recentSearches: [] }),

      setAccentColor: (color) => {
        set({ accentColor: color });
        const state = get();
        const prefs: Partial<UiPreferences> = { accent_color: color };
        if (color === "custom" && state.customAccentHex) {
          prefs.custom_accent_hex = state.customAccentHex;
        }
        debouncedSyncToServer(prefs);
      },

      setCustomAccentHex: (hex) => {
        set({ customAccentHex: hex, accentColor: "custom" });
        debouncedSyncToServer({ accent_color: "custom", custom_accent_hex: hex });
      },

      setFontSize: (size) => {
        set({ fontSize: size });
        debouncedSyncToServer({ font_size: size });
      },

      setDensity: (density) => {
        set({ density });
        debouncedSyncToServer({ density });
      },

      setHighContrast: (enabled) => {
        set({ highContrast: enabled });
        debouncedSyncToServer({ high_contrast: enabled });
      },

      loadServerPreferences: async () => {
        try {
          const prefs = await getPreferences();
          const updates: Partial<UiState> = { prefsLoaded: true };
          if (prefs.theme) updates.theme = prefs.theme;
          if (prefs.sidebar_collapsed !== undefined) {
            updates.sidebarCollapsed = prefs.sidebar_collapsed;
          }
          if (prefs.accent_color) updates.accentColor = prefs.accent_color;
          if (prefs.custom_accent_hex) updates.customAccentHex = prefs.custom_accent_hex;
          if (prefs.font_size) updates.fontSize = prefs.font_size;
          if (prefs.density) updates.density = prefs.density;
          if (prefs.high_contrast !== undefined) updates.highContrast = prefs.high_contrast;
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
        recentSearches: state.recentSearches,
        accentColor: state.accentColor,
        customAccentHex: state.customAccentHex,
        fontSize: state.fontSize,
        density: state.density,
        highContrast: state.highContrast,
      }),
    },
  ),
);
