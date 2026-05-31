import { api } from "../client";
import type {
  VodRentalAccess,
  VodRentalList,
  VodRentalPlayback,
  VodRentalStartRequest,
  VodRentalStartResponse,
  VodRentalStatus,
} from "../types";

// VOD-019 rental / view-once access layer.
// All endpoints are buyer-scoped under /ui/vod/rental.

export const startRental = (videoId: string, body: VodRentalStartRequest) =>
  api.post<VodRentalStartResponse>(`/ui/vod/rental/${videoId}/start`, body);

export const getRentalAccess = (videoId: string) =>
  api.get<VodRentalAccess>(`/ui/vod/rental/${videoId}/access`);

export const issueRentalPlayback = (videoId: string) =>
  api.post<VodRentalPlayback>(`/ui/vod/rental/${videoId}/playback`);

export const completeRentalPlayback = (videoId: string) =>
  api.post<{ ok: boolean; tier: string; views_remaining: number; consumed: boolean }>(
    `/ui/vod/rental/${videoId}/playback-complete`,
  );

export const getRentalStatus = (videoId: string) =>
  api.get<VodRentalStatus>(`/ui/vod/rental/${videoId}/status`);

export const listRentals = (limit?: number) =>
  api.get<VodRentalList>(
    "/ui/vod/rental/list",
    limit ? { limit: String(limit) } : undefined,
  );
