/**
 * WebRTC utility functions for peer connection setup.
 */

/**
 * Acquire local media (audio always, video only in video mode).
 */
export async function acquireLocalMedia(mode: "audio" | "video"): Promise<MediaStream> {
  const constraints: MediaStreamConstraints = {
    audio: true,
    video:
      mode === "video"
        ? { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 } }
        : false,
  };
  return navigator.mediaDevices.getUserMedia(constraints);
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
