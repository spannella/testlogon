import { create } from "zustand";
import { persist } from "zustand/middleware";

interface ShortcutState {
  /** User-defined custom key bindings. Keys are shortcut labels, values are key combos. */
  customBindings: Record<string, string>;
  /** Global toggle to enable/disable all keyboard shortcuts */
  shortcutsEnabled: boolean;

  setBinding: (label: string, key: string) => void;
  resetBinding: (label: string) => void;
  resetAllBindings: () => void;
  setShortcutsEnabled: (enabled: boolean) => void;
}

export const useShortcutStore = create<ShortcutState>()(
  persist(
    (set) => ({
      customBindings: {},
      shortcutsEnabled: true,

      setBinding: (label, key) =>
        set((s) => ({
          customBindings: { ...s.customBindings, [label]: key },
        })),

      resetBinding: (label) =>
        set((s) => {
          const { [label]: _, ...rest } = s.customBindings;
          return { customBindings: rest };
        }),

      resetAllBindings: () => set({ customBindings: {} }),

      setShortcutsEnabled: (enabled) => set({ shortcutsEnabled: enabled }),
    }),
    {
      name: "shortcut-store",
      partialize: (state) => ({
        customBindings: state.customBindings,
        shortcutsEnabled: state.shortcutsEnabled,
      }),
    },
  ),
);
