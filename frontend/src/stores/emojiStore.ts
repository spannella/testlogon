// MSG-006: Emoji store — recently-used emojis + skin-tone preference.
// Persisted to localStorage via zustand's persist middleware (which wraps
// setItem in its own error handling, so quota errors are swallowed gracefully).

import { create } from "zustand";
import { persist } from "zustand/middleware";

const MAX_RECENT = 32;

interface EmojiState {
  /** Most-recently-used emojis, newest first, capped at 32. */
  recentEmojis: string[];
  /** Skin-tone modifier codepoint string ("" = default). */
  skinTone: string;

  addRecent: (emoji: string) => void;
  setSkinTone: (modifier: string) => void;
}

export const useEmojiStore = create<EmojiState>()(
  persist(
    (set) => ({
      recentEmojis: [],
      skinTone: "",

      addRecent: (emoji) =>
        set((s) => {
          const next = [emoji, ...s.recentEmojis.filter((e) => e !== emoji)].slice(
            0,
            MAX_RECENT,
          );
          return { recentEmojis: next };
        }),

      setSkinTone: (modifier) => set({ skinTone: modifier }),
    }),
    {
      name: "emoji-store",
      partialize: (state) => ({
        recentEmojis: state.recentEmojis,
        skinTone: state.skinTone,
      }),
    },
  ),
);
