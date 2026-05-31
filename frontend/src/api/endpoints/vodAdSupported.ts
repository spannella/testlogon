import { api } from "@/api/client";
import type {
  VodAdSupportedSession,
  VodAdSupportedStartRequest,
  VodAdSupportedStartResponse,
  VodAdBreakReportRequest,
  VodAdBreakReportResponse,
} from "@/api/types";

// VOD-018: Ad-Supported Viewing Tier API client.
export const vodAdSupportedApi = {
  getSession: (videoId: string) =>
    api.get<VodAdSupportedSession>(
      `/ui/vod/ad-supported/${videoId}/session`,
    ),

  start: (videoId: string, body: VodAdSupportedStartRequest = {}) =>
    api.post<VodAdSupportedStartResponse>(
      `/ui/vod/ad-supported/${videoId}/start`,
      body,
    ),

  reportBreak: (videoId: string, body: VodAdBreakReportRequest) =>
    api.post<VodAdBreakReportResponse>(
      `/ui/vod/ad-supported/${videoId}/break`,
      body,
    ),
};
