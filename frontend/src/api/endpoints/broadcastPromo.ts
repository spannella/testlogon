// BCAST-010 — Broadcast Newsfeed Promotion API endpoints.
import { api } from "@/api/client";
import type {
  BroadcastPromoLinkResponse,
  BroadcastPromoLiveResponse,
  BroadcastPromoDeleteResponse,
} from "@/api/types";

export const promoteBroadcast = (broadcastId: string) =>
  api.post<BroadcastPromoLinkResponse>(`/ui/broadcast/promo/${broadcastId}`);

export const getBroadcastPromo = (broadcastId: string) =>
  api.get<BroadcastPromoLinkResponse>(`/ui/broadcast/promo/${broadcastId}`);

export const syncBroadcastPromo = (broadcastId: string) =>
  api.post<BroadcastPromoLinkResponse>(`/ui/broadcast/promo/${broadcastId}/sync`);

export const unpromoteBroadcast = (broadcastId: string) =>
  api.del<BroadcastPromoDeleteResponse>(`/ui/broadcast/promo/${broadcastId}`);

export const listLivePromotedBroadcasts = () =>
  api.get<BroadcastPromoLiveResponse>("/ui/broadcast/promo/live");
