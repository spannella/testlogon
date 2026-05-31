// frontend/src/api/endpoints/contentBoost.ts
import { api } from "@/api/client";
import type {
  ContentBoost,
  ContentBoostCancelResponse,
  ContentBoostCreateInput,
  ContentBoostListResponse,
  ContentBoostSpend,
} from "@/api/types";

export const contentBoostApi = {
  list: (activeOnly = false) =>
    api.get<ContentBoostListResponse>("/ui/ads/boost", {
      active_only: String(activeOnly),
    }),
  get: (boostId: string) =>
    api.get<ContentBoost>(`/ui/ads/boost/${boostId}`),
  getSpend: (boostId: string) =>
    api.get<ContentBoostSpend>(`/ui/ads/boost/${boostId}/spend`),
  create: (body: ContentBoostCreateInput) =>
    api.post<ContentBoost>("/ui/ads/boost", body),
  cancel: (boostId: string) =>
    api.post<ContentBoostCancelResponse>(`/ui/ads/boost/${boostId}/cancel`),
};
