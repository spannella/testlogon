/**
 * WebRTC utility functions for peer connection setup.
 */

/**
 * Acquire local media (audio always, video only in video mode).
 * Returns the MediaStream on success. Throws categorized errors on failure:
 *   - NotAllowedError: permission denied
 *   - NotFoundError: no device available
 *   - NotReadableError: device in use by another app
 *   - OverconstrainedError: device cannot meet constraints
 *
 * Callers that want null-on-failure behavior should use the useMediaCapture hook instead.
 */
export async function acquireLocalMedia(mode: "audio" | "video"): Promise<MediaStream> {
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new DOMException("Media devices API not available", "NotFoundError");
  }

  const constraints: MediaStreamConstraints = {
    audio: true,
    video:
      mode === "video"
        ? { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 } }
        : false,
  };

  try {
    return await navigator.mediaDevices.getUserMedia(constraints);
  } catch (err) {
    // For OverconstrainedError on video, retry with minimal constraints
    if (
      mode === "video" &&
      err instanceof DOMException &&
      err.name === "OverconstrainedError"
    ) {
      return navigator.mediaDevices.getUserMedia({ audio: true, video: true });
    }
    throw err;
  }
}

/**
 * Acquire a screen capture stream via getDisplayMedia.
 * Returns the MediaStream on success. Throws categorized errors on failure:
 *   - NotAllowedError: user denied/cancelled the picker
 *   - NotFoundError: getDisplayMedia API not available (e.g. iOS Safari)
 *   - AbortError: browser cancelled the request
 *
 * The returned stream typically has one video track. The video track will
 * fire 'ended' when the user clicks "Stop sharing" in the browser chrome.
 * Callers must listen for this event to clean up state.
 */
export async function acquireScreenMedia(): Promise<MediaStream> {
  if (!navigator.mediaDevices?.getDisplayMedia) {
    throw new DOMException(
      "Screen sharing is not supported in this browser",
      "NotFoundError",
    );
  }

  const constraints: DisplayMediaStreamOptions = {
    video: {
      width: { ideal: 1920 },
      height: { ideal: 1080 },
      frameRate: { ideal: 15, max: 30 },
    },
    audio: false,
  };

  try {
    const stream = await navigator.mediaDevices.getDisplayMedia(constraints);
    // Set content hint for better encoding of screen content
    const videoTrack = stream.getVideoTracks()[0];
    if (videoTrack && "contentHint" in videoTrack) {
      videoTrack.contentHint = "text";
    }
    return stream;
  } catch (err) {
    if (err instanceof DOMException) {
      throw err;
    }
    throw new DOMException(
      `Screen sharing failed: ${err instanceof Error ? err.message : String(err)}`,
      "AbortError",
    );
  }
}

/**
 * Check whether the current browser supports screen sharing.
 * Used to conditionally render the screen share button.
 */
export function isScreenShareSupported(): boolean {
  return (
    typeof navigator !== "undefined" &&
    !!navigator.mediaDevices?.getDisplayMedia
  );
}

/**
 * Buffer for ICE candidates received before remote description is set.
 * Once flush() is called, subsequent add() calls return null to signal
 * the candidate should be applied immediately.
 */
export function createIceCandidateBuffer() {
  let buffer: RTCIceCandidateInit[] = [];
  let flushed = false;

  return {
    /** Returns the candidate if buffered; null if already flushed (apply immediately). */
    add(candidate: RTCIceCandidateInit): RTCIceCandidateInit | null {
      if (flushed) return null; // Signal: apply immediately
      buffer.push(candidate);
      return candidate;
    },
    /** Flush all buffered candidates to the peer connection. */
    async flush(pc: RTCPeerConnection): Promise<void> {
      flushed = true;
      const pending = buffer;
      buffer = [];
      for (const c of pending) {
        try {
          await pc.addIceCandidate(new RTCIceCandidate(c));
        } catch {
          // Best-effort: ignore candidates that fail (e.g., after close)
        }
      }
    },
    /** Whether the buffer has been flushed. */
    get isFlushed() {
      return flushed;
    },
  };
}

/**
 * Generate a 32-char hex nonce for signaling event deduplication.
 */
export function generateNonce(): string {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 32);
}

/**
 * Generate a unique event ID with a prefix.
 */
export function generateEventId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID()}`;
}
