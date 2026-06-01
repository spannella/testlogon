import { api } from "@/api/client";
import type {
  VodWatermarkDownloadResponse,
  VodWatermarkDownloadStatusResponse,
  VodWatermarkRenderListResponse,
  VodWatermarkExtractResponse,
} from "@/api/types";

// VOD-020: per-viewer watermarked download flow.
// All endpoints are viewer-scoped under /ui/vod/watermark-download.

export const requestVodWatermarkDownload = (videoId: string) =>
  api.post<VodWatermarkDownloadResponse>(`/ui/vod/watermark-download/${videoId}`);

export const pollVodWatermarkStatus = (videoId: string) =>
  api.get<VodWatermarkDownloadStatusResponse>(
    `/ui/vod/watermark-download/${videoId}/status`,
  );

export const listVodWatermarkRenders = (videoId: string) =>
  api.get<VodWatermarkRenderListResponse>(
    `/ui/vod/watermark-download/${videoId}/renders`,
  );

export const extractVodWatermark = (payload?: string) =>
  api.post<VodWatermarkExtractResponse>(`/ui/vod/watermark-download/extract`, {
    payload: payload ?? null,
  });
