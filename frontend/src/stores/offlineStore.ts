import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { SendTextMessageReq, CreatePostReq } from "@/api/types";

// ─── Action type union ────────────────────────────────────────────

export interface OfflineActionSendMessage {
  id: string;
  type: "send_message";
  enqueuedAt: number;
  payload: {
    conversationId: string;
    req: SendTextMessageReq;
  };
}

export interface OfflineActionCreatePost {
  id: string;
  type: "create_post";
  enqueuedAt: number;
  payload: CreatePostReq;
}

export type OfflineAction = OfflineActionSendMessage | OfflineActionCreatePost;

// ─── Store shape ──────────────────────────────────────────────────

interface OfflineState {
  queue: OfflineAction[];
  isOnline: boolean;

  setOnline: (online: boolean) => void;
  addToQueue: (action: Omit<OfflineAction, "id" | "enqueuedAt">) => void;
  removeFromQueue: (id: string) => void;
  clearQueue: () => void;
}

export const useOfflineStore = create<OfflineState>()(
  persist(
    (set) => ({
      queue: [],
      isOnline: typeof navigator !== "undefined" ? navigator.onLine : true,

      setOnline: (online) => set({ isOnline: online }),

      addToQueue: (action) =>
        set((s) => ({
          queue: [
            ...s.queue,
            {
              ...action,
              id: `offline-${Date.now()}-${Math.random().toString(36).slice(2)}`,
              enqueuedAt: Date.now(),
            } as OfflineAction,
          ],
        })),

      removeFromQueue: (id) =>
        set((s) => ({ queue: s.queue.filter((a) => a.id !== id) })),

      clearQueue: () => set({ queue: [] }),
    }),
    {
      name: "offline-store",
      // isOnline is transient — always re-derive from navigator on hydration
      partialize: (state) => ({ queue: state.queue }),
    },
  ),
);
