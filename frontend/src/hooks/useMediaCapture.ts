/**
 * useMediaCapture — encapsulates getUserMedia logic with permission state
 * tracking, error categorization, and track management for WebRTC calls.
 */
import * as React from "react";
import type { DirectCallMode } from "@/api/endpoints/messaging";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type MediaCaptureStatus =
  | "idle"
  | "requesting"
  | "active"
  | "denied"
  | "not_found"
  | "error";

export type MediaCaptureErrorType =
  | "NotAllowedError"
  | "NotFoundError"
  | "NotReadableError"
  | "OverconstrainedError"
  | "AbortError"
  | "unknown";

export interface MediaCaptureError {
  type: MediaCaptureErrorType;
  message: string;
  originalError?: unknown;
}

export type PermissionState = "prompt" | "granted" | "denied" | "unknown";

export interface UseMediaCaptureReturn {
  stream: MediaStream | null;
  error: MediaCaptureError | null;
  permissionState: PermissionState;
  isAcquiring: boolean;
  acquire: (mode: DirectCallMode) => Promise<MediaStream | null>;
  release: () => void;
  switchCamera: () => Promise<void>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildConstraints(
  mode: DirectCallMode,
  preferredVideoDeviceId?: string,
): MediaStreamConstraints {
  const audio: MediaTrackConstraints | boolean = true;

  if (mode === "audio") {
    return { audio, video: false };
  }

  const video: MediaTrackConstraints = {
    width: { ideal: 1280, max: 1920 },
    height: { ideal: 720, max: 1080 },
    frameRate: { ideal: 30, max: 30 },
    ...(preferredVideoDeviceId
      ? { deviceId: { exact: preferredVideoDeviceId } }
      : { facingMode: "user" }),
  };

  return { audio, video };
}

function categorizeError(err: unknown): MediaCaptureError {
  if (err instanceof DOMException || (err instanceof Error && "name" in err)) {
    const name = (err as DOMException).name;
    switch (name) {
      case "NotAllowedError":
        return {
          type: "NotAllowedError",
          message:
            "Microphone/camera access denied. Please allow access in your browser settings.",
          originalError: err,
        };
      case "NotFoundError":
        return {
          type: "NotFoundError",
          message:
            "No microphone or camera found. Please connect a device and try again.",
          originalError: err,
        };
      case "NotReadableError":
        return {
          type: "NotReadableError",
          message:
            "Your microphone or camera is in use by another application.",
          originalError: err,
        };
      case "OverconstrainedError":
        return {
          type: "OverconstrainedError",
          message: "Camera does not support the requested resolution.",
          originalError: err,
        };
      case "AbortError":
        return {
          type: "AbortError",
          message: "Media capture was interrupted.",
          originalError: err,
        };
      default:
        break;
    }
  }
  return {
    type: "unknown",
    message: "An unexpected error occurred while accessing media devices.",
    originalError: err,
  };
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useMediaCapture(): UseMediaCaptureReturn {
  const [stream, setStream] = React.useState<MediaStream | null>(null);
  const [error, setError] = React.useState<MediaCaptureError | null>(null);
  const [permissionState, setPermissionState] =
    React.useState<PermissionState>("unknown");
  const [isAcquiring, setIsAcquiring] = React.useState(false);

  // Track the current video device index for switchCamera
  const videoDevicesRef = React.useRef<MediaDeviceInfo[]>([]);
  const currentVideoIndexRef = React.useRef(0);
  const currentModeRef = React.useRef<DirectCallMode>("audio");

  // Query permission state on mount
  React.useEffect(() => {
    let cancelled = false;

    async function queryPermission() {
      try {
        if (!navigator.permissions?.query) return;
        const status = await navigator.permissions.query({
          name: "microphone" as PermissionName,
        });
        if (!cancelled) {
          setPermissionState(status.state as PermissionState);
        }
        status.onchange = () => {
          if (!cancelled) {
            setPermissionState(status.state as PermissionState);
          }
        };
      } catch {
        // permissions.query may not be supported for microphone in all browsers
      }
    }

    queryPermission();
    return () => {
      cancelled = true;
    };
  }, []);

  const release = React.useCallback(() => {
    setStream((prev) => {
      if (prev) {
        for (const track of prev.getTracks()) {
          track.stop();
        }
      }
      return null;
    });
    setError(null);
  }, []);

  const acquire = React.useCallback(
    async (mode: DirectCallMode): Promise<MediaStream | null> => {
      // Check API availability
      if (
        typeof navigator === "undefined" ||
        !navigator.mediaDevices?.getUserMedia
      ) {
        const err: MediaCaptureError = {
          type: "unknown",
          message: "Media devices API is not available in this browser.",
        };
        setError(err);
        setPermissionState("denied");
        return null;
      }

      setIsAcquiring(true);
      setError(null);
      currentModeRef.current = mode;

      try {
        const constraints = buildConstraints(mode);
        const mediaStream =
          await navigator.mediaDevices.getUserMedia(constraints);
        setStream(mediaStream);
        setPermissionState("granted");
        setIsAcquiring(false);

        // Re-enumerate devices now that permission is granted (labels become available)
        try {
          const devices = await navigator.mediaDevices.enumerateDevices();
          videoDevicesRef.current = devices.filter(
            (d) => d.kind === "videoinput",
          );
        } catch {
          // Non-fatal
        }

        return mediaStream;
      } catch (err) {
        // If OverconstrainedError on video, retry with relaxed constraints
        if (
          mode === "video" &&
          err instanceof DOMException &&
          err.name === "OverconstrainedError"
        ) {
          try {
            const relaxedStream = await navigator.mediaDevices.getUserMedia({
              audio: true,
              video: true,
            });
            setStream(relaxedStream);
            setPermissionState("granted");
            setIsAcquiring(false);
            return relaxedStream;
          } catch (retryErr) {
            const categorized = categorizeError(retryErr);
            setError(categorized);
            if (categorized.type === "NotAllowedError") {
              setPermissionState("denied");
            }
            setIsAcquiring(false);
            return null;
          }
        }

        const categorized = categorizeError(err);
        setError(categorized);

        if (categorized.type === "NotAllowedError") {
          setPermissionState("denied");
        }

        setIsAcquiring(false);
        return null;
      }
    },
    [],
  );

  const switchCamera = React.useCallback(async () => {
    if (!stream || currentModeRef.current !== "video") return;

    const devices = videoDevicesRef.current;
    if (devices.length < 2) return;

    // Cycle to the next video device
    currentVideoIndexRef.current =
      (currentVideoIndexRef.current + 1) % devices.length;
    const nextDevice = devices[currentVideoIndexRef.current];
    if (!nextDevice) return;
    const nextDeviceId = nextDevice.deviceId;

    try {
      const newStream = await navigator.mediaDevices.getUserMedia({
        video: { deviceId: { exact: nextDeviceId } },
      });
      const newVideoTrack = newStream.getVideoTracks()[0];
      if (!newVideoTrack) return;

      // Replace the video track in the existing stream
      const oldVideoTrack = stream.getVideoTracks()[0];
      if (oldVideoTrack) {
        stream.removeTrack(oldVideoTrack);
        oldVideoTrack.stop();
      }
      stream.addTrack(newVideoTrack);
      // Trigger re-render
      setStream(stream);
    } catch {
      // Switching failed — keep the current track
    }
  }, [stream]);

  // Cleanup on unmount
  React.useEffect(() => {
    return () => {
      // eslint-disable-next-line react-hooks/exhaustive-deps
      setStream((prev) => {
        if (prev) {
          for (const track of prev.getTracks()) {
            track.stop();
          }
        }
        return null;
      });
    };
  }, []);

  return {
    stream,
    error,
    permissionState,
    isAcquiring,
    acquire,
    release,
    switchCamera,
  };
}
