/**
 * useScreenShare — hook for screen sharing in WebRTC calls (CALL-013).
 *
 * Manages getDisplayMedia lifecycle, track replacement on an existing
 * RTCPeerConnection (via replaceTrack — no SDP renegotiation needed),
 * and cleanup on unmount or call end.
 */
import * as React from "react";
import { acquireScreenMedia, isScreenShareSupported } from "@/lib/webrtc";

// ─── Types ──────────────────────────────────────────────────────

interface UseScreenShareParams {
  /** The active RTCPeerConnection to replace tracks on. */
  peerConnection: RTCPeerConnection | null;
  /** The original camera MediaStream to restore when sharing stops. */
  localCameraStream: MediaStream | null;
  /** Whether the call is in connected state and screen share is available. */
  enabled: boolean;
  /** Callback when sharing starts successfully. */
  onShareStart?: () => void;
  /** Callback when sharing stops (user action or browser stop). */
  onShareStop?: () => void;
  /** Callback on error (permission denied, API unavailable). */
  onError?: (message: string) => void;
}

interface UseScreenShareReturn {
  /** Whether the user is currently sharing their screen. */
  isSharing: boolean;
  /** The screen capture MediaStream, if active. */
  screenStream: MediaStream | null;
  /** Toggle screen sharing on/off. */
  toggleScreenShare: () => Promise<void>;
  /** Force stop screen sharing (for cleanup). */
  stopScreenShare: () => void;
  /** Whether the browser supports screen sharing. */
  isSupported: boolean;
}

// ─── Hook ───────────────────────────────────────────────────────

export function useScreenShare(params: UseScreenShareParams): UseScreenShareReturn {
  const {
    peerConnection,
    localCameraStream: _localCameraStream,
    enabled,
    onShareStart,
    onShareStop,
    onError,
  } = params;
  // localCameraStream is available for future use (e.g. dual-stream architecture)
  void _localCameraStream;

  const [isSharing, setIsSharing] = React.useState(false);
  const [screenStream, setScreenStream] = React.useState<MediaStream | null>(null);

  // Stable refs for callbacks
  const onShareStartRef = React.useRef(onShareStart);
  const onShareStopRef = React.useRef(onShareStop);
  const onErrorRef = React.useRef(onError);
  onShareStartRef.current = onShareStart;
  onShareStopRef.current = onShareStop;
  onErrorRef.current = onError;

  // Ref to track the original camera video track for restoration
  const cameraTrackRef = React.useRef<MediaStreamTrack | null>(null);

  // Debounce flag: true while a getDisplayMedia() picker is open
  const acquiringRef = React.useRef(false);

  // Check API availability once
  const isSupported = React.useMemo(() => isScreenShareSupported(), []);

  /**
   * Stop screen sharing: restore camera track and clean up.
   */
  const stopScreenShare = React.useCallback(() => {
    if (!isSharing && !screenStream) return;

    // Restore camera track on the video sender
    const pc = peerConnection;
    const cameraTrack = cameraTrackRef.current;
    if (pc && pc.connectionState !== "closed" && cameraTrack) {
      const videoSender = pc.getSenders().find(
        (s) => s.track?.kind === "video" || (s.track === null && cameraTrack.kind === "video"),
      );
      if (videoSender) {
        videoSender.replaceTrack(cameraTrack).catch(() => {
          // Best-effort restoration
        });
      }
    }

    // Stop screen stream tracks (removes browser "sharing" indicator)
    if (screenStream) {
      screenStream.getTracks().forEach((t) => t.stop());
    }

    setScreenStream(null);
    setIsSharing(false);
    cameraTrackRef.current = null;
    acquiringRef.current = false;

    onShareStopRef.current?.();
  }, [isSharing, screenStream, peerConnection]);

  /**
   * Toggle screen sharing on/off.
   */
  const toggleScreenShare = React.useCallback(async () => {
    // If currently sharing, stop
    if (isSharing) {
      stopScreenShare();
      return;
    }

    // Debounce: don't open picker if one is already open
    if (acquiringRef.current) return;

    // Validate prerequisites
    if (!peerConnection || peerConnection.connectionState === "closed") {
      onErrorRef.current?.("No active peer connection.");
      return;
    }

    acquiringRef.current = true;

    try {
      // 1. Acquire screen media
      const stream = await acquireScreenMedia();
      const screenTrack = stream.getVideoTracks()[0];

      if (!screenTrack) {
        stream.getTracks().forEach((t) => t.stop());
        onErrorRef.current?.("No video track in screen capture.");
        acquiringRef.current = false;
        return;
      }

      // 2. Find the video sender on the peer connection
      const videoSender = peerConnection.getSenders().find(
        (s) => s.track?.kind === "video",
      );

      if (!videoSender) {
        stream.getTracks().forEach((t) => t.stop());
        onErrorRef.current?.("No video sender available. Is camera enabled?");
        acquiringRef.current = false;
        return;
      }

      // 3. Preserve the camera track for later restoration
      cameraTrackRef.current = videoSender.track;

      // 4. Replace the camera track with the screen track
      await videoSender.replaceTrack(screenTrack);

      // 5. Listen for browser "Stop sharing" bar click
      screenTrack.onended = () => {
        stopScreenShare();
      };

      // 6. Update state
      setScreenStream(stream);
      setIsSharing(true);
      acquiringRef.current = false;

      // 7. Expose for E2E tests
      if (import.meta.env.DEV) {
        (window as unknown as Record<string, unknown>).__rtcScreenStream = stream;
      }

      onShareStartRef.current?.();
    } catch (err) {
      acquiringRef.current = false;

      if (err instanceof DOMException) {
        if (err.name === "NotAllowedError") {
          onErrorRef.current?.("Screen sharing was cancelled.");
          return;
        }
        if (err.name === "NotFoundError") {
          onErrorRef.current?.("Screen sharing is not supported in this browser.");
          return;
        }
      }

      onErrorRef.current?.(
        `Screen sharing failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }, [isSharing, peerConnection, stopScreenShare]);

  // Clean up on unmount or when call ends
  React.useEffect(() => {
    if (!enabled && isSharing) {
      stopScreenShare();
    }
  }, [enabled, isSharing, stopScreenShare]);

  // Clean up on unmount
  React.useEffect(() => {
    return () => {
      if (screenStream) {
        screenStream.getTracks().forEach((t) => t.stop());
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    isSharing,
    screenStream,
    toggleScreenShare,
    stopScreenShare,
    isSupported,
  };
}
