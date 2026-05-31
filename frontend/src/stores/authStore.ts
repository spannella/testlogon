import { create } from "zustand";
import { persist } from "zustand/middleware";

interface AuthState {
  /** Cognito user sub (user ID) */
  userId: string | null;
  /** Short-lived access token */
  accessToken: string | null;
  /** Whether the user is logged in */
  isAuthenticated: boolean;
  /** Reason for the most recent logout (e.g. "session_expired") */
  logoutReason: string | null;

  /** DELEGATE-002: creator ID being managed in delegate mode */
  managingCreatorId: string | null;
  /** DELEGATE-002: display name of the managed creator */
  managingCreatorName: string | null;

  login: (userId: string, accessToken: string) => void;
  setAccessToken: (token: string) => void;
  logout: (reason?: string) => void;
  clearLogoutReason: () => void;
  /** DELEGATE-002: enter delegate managing mode for a creator */
  setManagingCreator: (creatorId: string | null, name?: string | null) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      userId: null,
      accessToken: null,
      isAuthenticated: false,
      logoutReason: null,
      managingCreatorId: null,
      managingCreatorName: null,

      login: (userId, accessToken) =>
        set({ userId, accessToken, isAuthenticated: true, logoutReason: null }),

      setAccessToken: (accessToken) =>
        set({ accessToken }),

      logout: (reason?: string) => {
        const prevUserId = get().userId;
        set({
          userId: null,
          accessToken: null,
          isAuthenticated: false,
          logoutReason: reason ?? null,
          managingCreatorId: null,
          managingCreatorName: null,
        });
        // Clear offline cache for the logged-out user (fire-and-forget)
        if (prevUserId) {
          import("@/lib/offlineCache")
            .then(({ clearAllCacheForUser }) =>
              clearAllCacheForUser(prevUserId),
            )
            .catch(() => {
              // Cache cleanup is best-effort
            });
        }
      },

      clearLogoutReason: () => set({ logoutReason: null }),

      setManagingCreator: (creatorId, name) =>
        set({
          managingCreatorId: creatorId,
          managingCreatorName: name ?? null,
        }),
    }),
    {
      name: "auth-store",
      partialize: (state) => ({
        userId: state.userId,
        accessToken: state.accessToken,
        isAuthenticated: state.isAuthenticated,
        logoutReason: state.logoutReason,
      }),
    },
  ),
);
