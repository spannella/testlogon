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

  login: (userId: string, accessToken: string) => void;
  setAccessToken: (token: string) => void;
  logout: (reason?: string) => void;
  clearLogoutReason: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      userId: null,
      accessToken: null,
      isAuthenticated: false,
      logoutReason: null,

      login: (userId, accessToken) =>
        set({ userId, accessToken, isAuthenticated: true, logoutReason: null }),

      setAccessToken: (accessToken) =>
        set({ accessToken }),

      logout: (reason?: string) =>
        set({ userId: null, accessToken: null, isAuthenticated: false, logoutReason: reason ?? null }),

      clearLogoutReason: () => set({ logoutReason: null }),
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
