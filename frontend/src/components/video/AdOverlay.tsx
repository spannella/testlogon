/**
 * AdOverlay - Ad display component for video player (VOD-018).
 *
 * Renders pre-roll, mid-roll, and overlay ad slots with countdown timer,
 * skip button, and impression tracking. In dev mode, shows placeholder
 * content since actual ad creatives are not available.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { recordAdImpression, type AdSlot } from "@/api/endpoints/ads";

interface AdOverlayProps {
  /** The ad slot to display */
  slot: AdSlot;
  /** Video ID for impression tracking */
  videoId: string;
  /** Called when the ad completes (played to the end) */
  onComplete: () => void;
  /** Called when the ad is skipped */
  onSkip: () => void;
}

export function AdOverlay({ slot, videoId, onComplete, onSkip }: AdOverlayProps) {
  const [elapsed, setElapsed] = useState(0);
  const impressionRecorded = useRef(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const canSkip = slot.skip_after_seconds > 0 && elapsed >= slot.skip_after_seconds;
  const skipCountdown = Math.max(0, slot.skip_after_seconds - elapsed);

  // Record impression when ad starts
  useEffect(() => {
    if (!impressionRecorded.current) {
      impressionRecorded.current = true;
      recordAdImpression(videoId, {
        slot_type: slot.type,
        slot_index: slot.slot_index,
        creative_id: slot.creative_id,
        event_type: "impression",
      }).catch(() => {
        // Fire-and-forget
      });
    }
  }, [videoId, slot]);

  // Countdown timer
  useEffect(() => {
    timerRef.current = setInterval(() => {
      setElapsed((prev) => {
        const next = prev + 1;
        if (next >= slot.duration_seconds) {
          // Ad completed naturally
          if (timerRef.current) clearInterval(timerRef.current);
          return next;
        }
        return next;
      });
    }, 1000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [slot.duration_seconds]);

  // Handle natural completion
  useEffect(() => {
    if (elapsed >= slot.duration_seconds) {
      recordAdImpression(videoId, {
        slot_type: slot.type,
        slot_index: slot.slot_index,
        creative_id: slot.creative_id,
        event_type: "complete",
      }).catch(() => {});
      onComplete();
    }
  }, [elapsed, slot, videoId, onComplete]);

  const handleSkip = useCallback(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    recordAdImpression(videoId, {
      slot_type: slot.type,
      slot_index: slot.slot_index,
      creative_id: slot.creative_id,
      event_type: "skip",
    }).catch(() => {});
    onSkip();
  }, [videoId, slot, onSkip]);

  // Overlay type: semi-transparent banner at bottom
  if (slot.type === "overlay") {
    return (
      <div className="absolute bottom-0 left-0 right-0 bg-black/70 text-white p-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="text-xs">
            Ad
          </Badge>
          <span className="text-sm">Sponsored content</span>
        </div>
        <Button
          size="sm"
          variant="ghost"
          className="text-white hover:text-white/80"
          onClick={handleSkip}
        >
          Close
        </Button>
      </div>
    );
  }

  // Pre-roll / Mid-roll: full-screen overlay blocking content
  return (
    <div className="absolute inset-0 bg-black flex flex-col items-center justify-center z-50">
      {/* Ad badge */}
      <Badge
        variant="secondary"
        className="absolute top-4 left-4 text-xs"
      >
        Ad
      </Badge>

      {/* Placeholder creative area */}
      <div className="flex flex-col items-center gap-4 text-white">
        <div className="w-64 h-36 bg-gray-800 rounded-lg flex items-center justify-center border border-gray-700">
          <span className="text-gray-400 text-sm">
            {slot.type === "pre_roll" ? "Pre-Roll Ad" : "Mid-Roll Ad"}
          </span>
        </div>
        <p className="text-sm text-gray-400">
          Ad {elapsed}s / {slot.duration_seconds}s
        </p>
      </div>

      {/* Skip button or countdown */}
      <div className="absolute bottom-4 right-4">
        {canSkip ? (
          <Button
            size="sm"
            variant="secondary"
            onClick={handleSkip}
          >
            Skip Ad
          </Button>
        ) : slot.skip_after_seconds > 0 ? (
          <span className="text-white text-sm bg-black/60 px-3 py-1.5 rounded">
            Skip in {skipCountdown}s
          </span>
        ) : null}
      </div>
    </div>
  );
}

export default AdOverlay;
