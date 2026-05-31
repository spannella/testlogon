import { api } from "@/api/client";
import type {
  StartSshRecordingIn,
  AppendSshRecordingEventsIn,
  SshRecordingOut,
  SshRecordingListOut,
  SshRecordingPlaybackOut,
} from "@/api/types";

const BASE = "/ui/compute/ssh-recordings";

export const listSshRecordings = (hostname?: string) =>
  api.get<SshRecordingListOut>(BASE, hostname ? { hostname } : undefined);

export const getSshRecording = (recordingId: string) =>
  api.get<SshRecordingOut>(`${BASE}/${recordingId}`);

export const startSshRecording = (body: StartSshRecordingIn) =>
  api.post<SshRecordingOut>(BASE, body);

export const appendSshRecordingEvents = (
  recordingId: string,
  body: AppendSshRecordingEventsIn,
) => api.post<SshRecordingOut>(`${BASE}/${recordingId}/events`, body);

export const stopSshRecording = (recordingId: string) =>
  api.post<SshRecordingOut>(`${BASE}/${recordingId}/stop`);

export const getSshRecordingPlayback = (recordingId: string) =>
  api.get<SshRecordingPlaybackOut>(`${BASE}/${recordingId}/playback`);

export const deleteSshRecording = (recordingId: string) =>
  api.del<{ ok: boolean }>(`${BASE}/${recordingId}`);
