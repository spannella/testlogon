import { create } from "zustand";
import type { TenantBranding } from "@/api/types";

interface TenantState {
  branding: TenantBranding | null;
  loading: boolean;
  error: string | null;
  setBranding: (branding: TenantBranding) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
}

export const useTenantStore = create<TenantState>()((set) => ({
  branding: null,
  loading: false,
  error: null,
  setBranding: (branding) => set({ branding, loading: false, error: null }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error, loading: false }),
}));
