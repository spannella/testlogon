import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { SendTextMessageReq, CreatePostReq } from "@/api/types";
import { writeToSyncQueue } from "@/lib/syncQueueDb";

// ─── Action type union ────────────────────────────────────────────

export interface OfflineActionSendMessage {
  id: string;
  type: "send_message";
  enqueuedAt: number;
  __status?: "pending" | "sending" | "failed";
  __error?: string;
  __retryCount?: number;
  payload: {
    conversationId: string;
    req: SendTextMessageReq;
  };
}

export interface OfflineActionCreatePost {
  id: string;
  type: "create_post";
  enqueuedAt: number;
  __status?: "pending" | "sending" | "failed";
  __error?: string;
  __retryCount?: number;
  payload: CreatePostReq;
}

export type OfflineAction = OfflineActionSendMessage | OfflineActionCreatePost;

// ─── Dead-letter item ────────────────────────────────────────────

export type DeadLetterItem = OfflineAction & {
  retryCount: number;
  lastError: string;
};

// ─── Helpers ─────────────────────────────────────────────────────

/** Parse the ui_csrf cookie value from document.cookie */
function getCsrfFromCookie(): string {
  try {
    const match = document.cookie
      .split(";")
      .map((c) => c.trim())
      .find((c) => c.startsWith("ui_csrf="));
    return match ? match.split("=")[1] ?? "" : "";
  } catch {
    return "";
  }
}

/** Try to register Background Sync if SyncManager is available */
function tryRegisterSync(): void {
  try {
    if ("serviceWorker" in navigator && "SyncManager" in window) {
      navigator.serviceWorker.ready.then((reg) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (reg as any).sync?.register("flush-offline-queue").catch(() => {
          // sync registration failed — main thread flush will handle it
        });
      });
    }
  } catch {
    // SyncManager not available
  }
}

// ─── Store shape ──────────────────────────────────────────────────

interface OfflineState {
  queue: OfflineAction[];
  deadLetter: DeadLetterItem[];
  isOnline: boolean;

  setOnline: (online: boolean) => void;
  addToQueue: (action: Omit<OfflineAction, "id" | "enqueuedAt">) => void;
  addToQueueWithId: (id: string, action: Omit<OfflineAction, "id" | "enqueuedAt">) => void;
  removeFromQueue: (id: string) => void;
  clearQueue: () => void;
  updateActionStatus: (id: string, status: "pending" | "sending" | "failed", error?: string) => void;
  retryAction: (id: string) => void;

  moveToDeadLetter: (id: string, retryCount: number, lastError: string) => void;
  retryDeadLetter: (id: string) => void;
  discardDeadLetter: (id: string) => void;
  clearDeadLetter: () => void;
}

export const useOfflineStore = create<OfflineState>()(
  persist(
    (set, get) => ({
      queue: [],
      deadLetter: [],
      isOnline: typeof navigator !== "undefined" ? navigator.onLine : true,

      setOnline: (online) => set({ isOnline: online }),

      addToQueue: (action) => {
        const id = `offline-${Date.now()}-${Math.random().toString(36).slice(2)}`;
        const enqueuedAt = Date.now();
        const newAction = { ...action, id, enqueuedAt } as OfflineAction;

        set((s) => ({ queue: [...s.queue, newAction] }));

        // Fire-and-forget write to IndexedDB for Background Sync
        const csrfToken = getCsrfFromCookie();
        void writeToSyncQueue(newAction, csrfToken);

        // Register Background Sync
        tryRegisterSync();
      },

      addToQueueWithId: (id, action) => {
        const enqueuedAt = Date.now();
        const newAction = { ...action, id, enqueuedAt } as OfflineAction;

        set((s) => ({ queue: [...s.queue, newAction] }));

        // Fire-and-forget write to IndexedDB for Background Sync
        const csrfToken = getCsrfFromCookie();
        void writeToSyncQueue(newAction, csrfToken);

        // Register Background Sync
        tryRegisterSync();
      },

      removeFromQueue: (id) =>
        set((s) => ({ queue: s.queue.filter((a) => a.id !== id) })),

      clearQueue: () => set({ queue: [] }),

      updateActionStatus: (id, status, error) =>
        set((s) => ({
          queue: s.queue.map((a) =>
            a.id === id
              ? { ...a, __status: status, __error: error }
              : a,
          ),
        })),

      retryAction: (id) =>
        set((s) => ({
          queue: s.queue.map((a) =>
            a.id === id
              ? {
                  ...a,
                  __status: "pending" as const,
                  __error: undefined,
                  __retryCount: (a.__retryCount ?? 0) + 1,
                }
              : a,
          ),
        })),

      moveToDeadLetter: (id, retryCount, lastError) =>
        set((s) => {
          const item = s.queue.find((a) => a.id === id);
          if (!item) {
            // Item might have already been removed from queue (e.g., by SW)
            // but we still want to add it to dead letter
            return {
              deadLetter: [
                ...s.deadLetter,
                {
                  id,
                  type: "send_message" as const,
                  enqueuedAt: Date.now(),
                  payload: { conversationId: "", req: { text: "Unknown item" } },
                  retryCount,
                  lastError,
                } as DeadLetterItem,
              ],
            };
          }
          return {
            queue: s.queue.filter((a) => a.id !== id),
            deadLetter: [
              ...s.deadLetter,
              { ...item, retryCount, lastError } as DeadLetterItem,
            ],
          };
        }),

      retryDeadLetter: (id) => {
        const state = get();
        const item = state.deadLetter.find((d) => d.id === id);
        if (!item) return;
        // Move back to queue, re-enqueue in IDB
        const { retryCount: _rc, lastError: _le, ...action } = item;
        set((s) => ({
          deadLetter: s.deadLetter.filter((d) => d.id !== id),
          queue: [...s.queue, action as OfflineAction],
        }));
        const csrfToken = getCsrfFromCookie();
        void writeToSyncQueue(action, csrfToken);
        tryRegisterSync();
      },

      discardDeadLetter: (id) =>
        set((s) => ({ deadLetter: s.deadLetter.filter((d) => d.id !== id) })),

      clearDeadLetter: () => set({ deadLetter: [] }),
    }),
    {
      name: "offline-store",
      // isOnline is transient — always re-derive from navigator on hydration
      partialize: (state) => ({ queue: state.queue, deadLetter: state.deadLetter }),
    },
  ),
);
