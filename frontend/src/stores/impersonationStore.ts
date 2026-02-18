import { create } from "zustand";
import { persist } from "zustand/middleware";

interface ImpersonationState {
  token: string | null;
  impersonationId: string | null;
  actorSub: string | null;
  effectiveSub: string | null;
  expiresAt: number | null;

  start: (payload: {
    token: string;
    impersonationId: string;
    actorSub: string;
    effectiveSub: string;
    expiresAt: number;
  }) => void;
  clear: () => void;
  isActive: () => boolean;
}

export const useImpersonationStore = create<ImpersonationState>()(
  persist(
    (set, get) => ({
      token: null,
      impersonationId: null,
      actorSub: null,
      effectiveSub: null,
      expiresAt: null,

      start: ({ token, impersonationId, actorSub, effectiveSub, expiresAt }) =>
        set({ token, impersonationId, actorSub, effectiveSub, expiresAt }),

      clear: () =>
        set({ token: null, impersonationId: null, actorSub: null, effectiveSub: null, expiresAt: null }),

      isActive: () => {
        const s = get();
        if (!s.token || !s.impersonationId || !s.effectiveSub) return false;
        if (!s.expiresAt) return true;
        return s.expiresAt > Math.floor(Date.now() / 1000);
      },
    }),
    {
      name: "impersonation-store",
      partialize: (state) => ({
        token: state.token,
        impersonationId: state.impersonationId,
        actorSub: state.actorSub,
        effectiveSub: state.effectiveSub,
        expiresAt: state.expiresAt,
      }),
    },
  ),
);
