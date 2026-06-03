import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { SkipForward, ExternalLink } from "lucide-react";

// ─── Types (ADS-006) ─────────────────────────────────────────────

export interface AdOverlayAd {
  creative_id: string;
  format: string;
  video_url?: string | null;
  image_url?: string | null;
  cta_url?: string | null;
}

export interface AdOverlayProps {
  ad: AdOverlayAd;
  /** Seconds the viewer must wait before the Skip button appears. */
  skipAfterSeconds: number;
  /** Total duration of the ad (used for the countdown). 0 = driven by video element. */
  durationSeconds?: number;
  label?: string;
  onSkip: () => void;
  onComplete: () => void;
  onImpression?: () => void;
  onCtaClick?: (url: string) => void;
}

/**
 * Full-screen ad overlay covering the broadcast player.
 * Used for both pre-roll and mid-roll ads.
 */
export function AdOverlay({
  ad,
  skipAfterSeconds,
  durationSeconds = 0,
  label = "Advertisement",
  onSkip,
  onComplete,
  onImpression,
  onCtaClick,
}: AdOverlayProps) {
  const [elapsed, setElapsed] = useState(0);
  const impressionFired = useRef(false);

  // Fire impression once on mount.
  useEffect(() => {
    if (!impressionFired.current) {
      impressionFired.current = true;
      onImpression?.();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Tick the elapsed counter once per second.
  useEffect(() => {
    const id = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(id);
  }, []);

  // Auto-complete when the configured duration elapses (image ads / fallback).
  useEffect(() => {
    if (durationSeconds > 0 && elapsed >= durationSeconds) {
      onComplete();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [elapsed, durationSeconds]);

  const canSkip = elapsed >= skipAfterSeconds;
  const remainingToSkip = Math.max(0, skipAfterSeconds - elapsed);
  const remainingTotal = durationSeconds > 0 ? Math.max(0, durationSeconds - elapsed) : null;

  const isVideo = ad.format === "video" && !!ad.video_url;

  return (
    <div
      data-testid="broadcast-ad-overlay"
      className="absolute inset-0 z-40 flex flex-col items-center justify-center bg-black"
    >
      {/* Ad media */}
      <div className="relative flex-1 w-full flex items-center justify-center">
        {isVideo ? (
          <video
            data-testid="broadcast-ad-video"
            src={ad.video_url ?? undefined}
            className="max-h-full max-w-full"
            autoPlay
            playsInline
            onEnded={onComplete}
          />
        ) : ad.image_url ? (
          <img
            data-testid="broadcast-ad-image"
            src={ad.image_url}
            alt="Advertisement"
            className="max-h-full max-w-full object-contain"
          />
        ) : (
          <div className="text-center text-gray-300">
            <p className="text-lg font-medium">Advertisement</p>
            <p className="text-sm text-gray-500">{ad.creative_id}</p>
          </div>
        )}
      </div>

      {/* Top-left label + countdown */}
      <div className="absolute top-3 left-3 flex items-center gap-2">
        <span className="rounded bg-yellow-500/90 px-2 py-0.5 text-xs font-semibold text-black">
          {label}
        </span>
        {remainingTotal !== null && (
          <span data-testid="ad-countdown" className="text-xs text-gray-300">
            Ad ends in {remainingTotal}s
          </span>
        )}
      </div>

      {/* CTA button */}
      {ad.cta_url && (
        <Button
          data-testid="ad-cta-button"
          variant="secondary"
          size="sm"
          className="absolute bottom-16 right-3 gap-1"
          onClick={() => onCtaClick?.(ad.cta_url as string)}
        >
          Learn More <ExternalLink className="h-3 w-3" />
        </Button>
      )}

      {/* Skip button / countdown */}
      <div className="absolute bottom-3 right-3">
        {canSkip ? (
          <Button
            data-testid="ad-skip-button"
            variant="secondary"
            size="sm"
            className="gap-1"
            onClick={onSkip}
          >
            Skip <SkipForward className="h-3 w-3" />
          </Button>
        ) : (
          <span
            data-testid="ad-skip-countdown"
            className="rounded bg-black/70 px-3 py-1.5 text-xs text-gray-300"
          >
            Skip in {remainingToSkip}s
          </span>
        )}
      </div>
    </div>
  );
}

export default AdOverlay;
