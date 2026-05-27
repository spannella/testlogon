/**
 * VOD-020: Watermarked Downloads — API client
 */

import { api } from "../client";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface WatermarkDownloadResponse {
  status: "ready" | "processing";
  download_url?: string;
  cached: boolean;
  job_id: string;
}

export interface WatermarkStatusResponse {
  status: "ready" | "processing" | "failed" | "not_found";
  job_id?: string;
  download_url?: string;
  output_size_bytes?: number;
  created_at?: number;
  error?: string;
}

export interface WatermarkToggleResponse {
  ok: boolean;
  watermark_downloads: boolean;
}

export interface DownloadHistoryItem {
  job_id: string;
  video_id: string;
  user_id: string;
  watermark_payload: string;
  created_at: number;
  output_size_bytes?: number;
}

export interface DownloadHistoryResponse {
  items: DownloadHistoryItem[];
}

// ─── API calls ──────────────────────────────────────────────────────────────

export const requestWatermarkedDownload = (videoId: string) =>
  api.post<WatermarkDownloadResponse>(
    `/ui/videos/${videoId}/download/watermarked`,
  );

export const pollWatermarkStatus = (videoId: string) =>
  api.get<WatermarkStatusResponse>(
    `/ui/videos/${videoId}/download/watermarked/status`,
  );

export const toggleWatermarkDownloads = (
  videoId: string,
  enabled: boolean,
) =>
  api.patch<WatermarkToggleResponse>(`/ui/videos/${videoId}/watermark`, {
    watermark_downloads: enabled,
  });

export const getVideoDownloadHistory = (videoId: string) =>
  api.get<DownloadHistoryResponse>(
    `/ui/videos/${videoId}/download-history`,
  );

export const getMyDownloads = () =>
  api.get<DownloadHistoryResponse>("/ui/videos/my-downloads");
