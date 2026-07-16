/**
 * Hook for managing WebRTC call recording with mutual consent (CALL-009).
 *
 * Handles:
 * - Recording request/consent protocol via API calls
 * - MediaRecorder lifecycle (start/stop/collect chunks)
 * - Upload of recorded Blob via presigned URL
 * - State management for UI indicators
 */
import * as React from "react";
import { api as apiClient } from "@/api/client";

export type RecordingState =
  | "idle"
  | "requesting"
  | "consent_pending"
  | "recording"
  | "stopping"
  | "uploading"
  | "complete"
  | "error";

export interface UseCallRecordingParams {
  callId: string | null | undefined;
  userId: string;
  localStream: MediaStream | null | undefined;
  remoteStream: MediaStream | null | undefined;
  isConnected: boolean;
  enabled?: boolean;
}

export interface UseCallRecordingReturn {
  recordingState: RecordingState;
  recordingId: string | null;
  duration: number;
  isInitiator: boolean;
  requestRecording: () => Promise<void>;
  respondToRequest: (accept: boolean) => Promise<void>;
  stopRecording: () => void;
  error: string | null;
  consentPendingFrom: string | null;
}

// API helpers
// NOTE: the `api` client returns the parsed JSON body directly (there is no
// axios-style `.data` envelope), so these helpers return the body as-is.
async function apiRequestRecording(callId: string) {
  return apiClient.post<{ recording_id: string }>(
    `/messages/calls/${callId}/recording/request`,
  );
}

async function apiConsentRecording(callId: string) {
  return apiClient.post<{ recording_id: string }>(
    `/messages/calls/${callId}/recording/consent`,
  );
}

async function apiDeclineRecording(callId: string) {
  return apiClient.post<{ ok: boolean }>(
    `/messages/calls/${callId}/recording/decline`,
  );
}

async function apiPresignUpload(callId: string, contentType: string, fileSizeBytes: number) {
  return apiClient.post<{ upload_url: string; recording_id: string }>(
    `/messages/calls/${callId}/recording/upload/presign`,
    {
      content_type: contentType,
      file_size_bytes: fileSizeBytes,
    },
  );
}

async function apiCompleteUpload(callId: string, recordingId: string, durationSeconds: number) {
  return apiClient.post<{ ok: boolean }>(
    `/messages/calls/${callId}/recording/upload/complete`,
    {
      recording_id: recordingId,
      duration_seconds: durationSeconds,
    },
  );
}

function selectMimeType(): string {
  if (typeof MediaRecorder === "undefined") return "video/webm";
  if (MediaRecorder.isTypeSupported("video/webm;codecs=vp8,opus")) return "video/webm;codecs=vp8,opus";
  if (MediaRecorder.isTypeSupported("video/mp4;codecs=h264,aac")) return "video/mp4;codecs=h264,aac";
  return "video/webm";
}

export function useCallRecording({
  callId,
  userId,
  localStream,
  remoteStream,
  isConnected,
  enabled = true,
}: UseCallRecordingParams): UseCallRecordingReturn {
  const [state, setState] = React.useState<RecordingState>("idle");
  const [recordingId, setRecordingId] = React.useState<string | null>(null);
  const [duration, setDuration] = React.useState(0);
  const [isInitiator, setIsInitiator] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [consentPendingFrom, setConsentPendingFrom] = React.useState<string | null>(null);

  const mediaRecorderRef = React.useRef<MediaRecorder | null>(null);
  const chunksRef = React.useRef<Blob[]>([]);
  const startTimeRef = React.useRef<number>(0);
  const durationTimerRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const audioCtxRef = React.useRef<AudioContext | null>(null);

  // Listen for recording events from SSE
  React.useEffect(() => {
    if (!enabled || !callId) return;

    function handleCallEvent(e: Event) {
      const detail = (e as CustomEvent).detail;
      if (!detail) return;
      const eventType = detail.event_type || detail.type;

      if (eventType === "call.recording_request") {
        const requestedBy = detail.requested_by || detail.sender_id;
        if (requestedBy !== userId) {
          setState("consent_pending");
          setConsentPendingFrom(requestedBy);
        }
      } else if (eventType === "call.recording_accept") {
        setState("recording");
        if (detail.recording_id) setRecordingId(detail.recording_id);
      } else if (eventType === "call.recording_decline") {
        setState("idle");
        setConsentPendingFrom(null);
        setRecordingId(null);
      } else if (eventType === "call.recording_started") {
        setState("recording");
        if (detail.recording_id) setRecordingId(detail.recording_id);
      } else if (eventType === "call.recording_stopped") {
        setState("stopping");
      }
    }

    window.addEventListener("messaging:call-event", handleCallEvent);
    return () => window.removeEventListener("messaging:call-event", handleCallEvent);
  }, [enabled, callId, userId]);

  // Duration timer
  React.useEffect(() => {
    if (state === "recording") {
      startTimeRef.current = Date.now();
      durationTimerRef.current = setInterval(() => {
        setDuration(Math.floor((Date.now() - startTimeRef.current) / 1000));
      }, 1000);
    } else {
      if (durationTimerRef.current) {
        clearInterval(durationTimerRef.current);
        durationTimerRef.current = null;
      }
      if (state === "idle") setDuration(0);
    }
    return () => {
      if (durationTimerRef.current) clearInterval(durationTimerRef.current);
    };
  }, [state]);

  const requestRecording = React.useCallback(async () => {
    if (!callId || !enabled || !isConnected) return;
    try {
      setState("requesting");
      setIsInitiator(true);
      const data = await apiRequestRecording(callId);
      setRecordingId(data.recording_id);
      setState("consent_pending");
      setConsentPendingFrom(null);
    } catch (err: unknown) {
      setState("error");
      setError(err instanceof Error ? err.message : "Failed to request recording");
    }
  }, [callId, enabled, isConnected]);

  const respondToRequest = React.useCallback(async (accept: boolean) => {
    if (!callId) return;
    try {
      if (accept) {
        const data = await apiConsentRecording(callId);
        setRecordingId(data.recording_id);
        setState("recording");
        setConsentPendingFrom(null);
      } else {
        await apiDeclineRecording(callId);
        setState("idle");
        setConsentPendingFrom(null);
        setRecordingId(null);
      }
    } catch (err: unknown) {
      setState("error");
      setError(err instanceof Error ? err.message : "Failed to respond to recording request");
    }
  }, [callId]);

  // Start MediaRecorder when state transitions to "recording"
  React.useEffect(() => {
    if (state !== "recording" || !remoteStream) return;

    const mimeType = selectMimeType();
    try {
      // For simplicity in v1, record the remote stream (what the user hears/sees)
      // If local stream also available, mix audio
      let streamToRecord: MediaStream;

      if (localStream && remoteStream) {
        // Mix audio from both streams
        const audioCtx = new AudioContext();
        audioCtxRef.current = audioCtx;
        const destination = audioCtx.createMediaStreamDestination();

        for (const track of localStream.getAudioTracks()) {
          const source = audioCtx.createMediaStreamSource(new MediaStream([track]));
          source.connect(destination);
        }
        for (const track of remoteStream.getAudioTracks()) {
          const source = audioCtx.createMediaStreamSource(new MediaStream([track]));
          source.connect(destination);
        }

        // Combine remote video + mixed audio
        const tracks: MediaStreamTrack[] = [
          ...remoteStream.getVideoTracks(),
          ...destination.stream.getAudioTracks(),
        ];
        streamToRecord = new MediaStream(tracks);
      } else {
        streamToRecord = remoteStream;
      }

      const recorder = new MediaRecorder(streamToRecord, {
        mimeType: mimeType.split(";")[0], // Use base mime type
        videoBitsPerSecond: 1_500_000,
        audioBitsPerSecond: 128_000,
      });

      chunksRef.current = [];
      recorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          chunksRef.current.push(event.data);
        }
      };

      recorder.onstop = () => {
        // Handled in stopRecording
      };

      recorder.start(10_000); // Collect data every 10 seconds
      mediaRecorderRef.current = recorder;
    } catch {
      // MediaRecorder not available (e.g., headless test environment)
      // Continue without actual recording
    }

    return () => {
      if (mediaRecorderRef.current && mediaRecorderRef.current.state !== "inactive") {
        try {
          mediaRecorderRef.current.stop();
        } catch {
          // ignore
        }
      }
      if (audioCtxRef.current) {
        try {
          audioCtxRef.current.close();
        } catch {
          // ignore
        }
        audioCtxRef.current = null;
      }
    };
  }, [state, localStream, remoteStream]);

  const stopRecording = React.useCallback(() => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== "inactive") {
      mediaRecorderRef.current.stop();
    }
    setState("stopping");

    // Upload the recording
    if (callId && recordingId && chunksRef.current.length > 0) {
      const mimeType = selectMimeType().split(";")[0] ?? "video/webm";
      const blob = new Blob(chunksRef.current, { type: mimeType });
      const durationSec = Math.max(1, Math.floor((Date.now() - startTimeRef.current) / 1000));

      setState("uploading");
      apiPresignUpload(callId, mimeType, blob.size)
        .then(async (presignData) => {
          // Upload the blob
          await fetch(presignData.upload_url, {
            method: "PUT",
            body: blob,
            headers: { "Content-Type": mimeType },
          });
          // Complete
          await apiCompleteUpload(callId, presignData.recording_id, durationSec);
          setState("complete");
        })
        .catch((err) => {
          setState("error");
          setError(err instanceof Error ? err.message : "Upload failed");
        });
    } else {
      setState("complete");
    }
  }, [callId, recordingId]);

  // Reset recording state when call disconnects
  React.useEffect(() => {
    if (!isConnected && state === "recording") {
      stopRecording();
    }
  }, [isConnected, state, stopRecording]);

  return {
    recordingState: state,
    recordingId,
    duration,
    isInitiator,
    requestRecording,
    respondToRequest,
    stopRecording,
    error,
    consentPendingFrom,
  };
}
