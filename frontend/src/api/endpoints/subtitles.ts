import { api } from "../client";
import type { SubtitleTrack, SubtitleListOut, SubtitleDeleteOut } from "../types";

export const uploadSubtitle = (videoId: string, formData: FormData) =>
  api.upload<SubtitleTrack>(`/ui/videos/${videoId}/subtitles`, formData);

export const listSubtitles = (videoId: string) =>
  api.get<SubtitleListOut>(`/ui/videos/${videoId}/subtitles`);

export const deleteSubtitle = (videoId: string, trackId: string) =>
  api.del<SubtitleDeleteOut>(`/ui/videos/${videoId}/subtitles/${trackId}`);

export const updateSubtitle = (
  videoId: string,
  trackId: string,
  data: { label?: string; is_default?: boolean }
) =>
  api.patch<SubtitleTrack>(`/ui/videos/${videoId}/subtitles/${trackId}`, data);
