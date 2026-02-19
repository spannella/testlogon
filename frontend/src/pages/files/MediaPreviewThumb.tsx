import { useEffect, useMemo, useRef, useState } from "react";
import { emitFilePreviewTelemetry } from "@/api/endpoints/files";

type PreviewKind = "video" | "audio";

type MediaPreviewItem = {
  name?: string;
  path?: string;
  preview_kind?: string;
  preview_status?: "pending" | "ready" | "failed" | "unsupported";
  poster_url?: string | null;
  hover_preview_url?: string | null;
  waveform_url?: string | null;
};

const TAP_PREVIEW_MS = 2200;

function fallbackLabel(item: MediaPreviewItem): string {
  const kindLabel = item.preview_kind === "video" ? "Video" : "Audio";
  const statusLabel: Record<string, string> = {
    pending: "preview pending",
    failed: "preview unavailable",
    unsupported: "preview unsupported",
  };
  return `${kindLabel} ${statusLabel[item.preview_status || "pending"] || "preview unavailable"}`;
}

function isMediaKind(kind?: string): kind is PreviewKind {
  return kind === "video" || kind === "audio";
}

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const media = window.matchMedia(query);
    setMatches(media.matches);

    const onChange = (event: MediaQueryListEvent) => {
      setMatches(event.matches);
    };

    media.addEventListener?.("change", onChange);
    return () => media.removeEventListener?.("change", onChange);
  }, [query]);

  return matches;
}

function usePrefersReducedMotion(): boolean {
  return useMediaQuery("(prefers-reduced-motion: reduce)");
}

function useTouchDevice(): boolean {
  const coarsePointer = useMediaQuery("(pointer: coarse)");
  const noHover = useMediaQuery("(hover: none)");

  const hasTouchPoints = typeof navigator !== "undefined" && navigator.maxTouchPoints > 0;
  return coarsePointer || noHover || hasTouchPoints;
}

function supportsTapPreviewCapability(): boolean {
  if (typeof document === "undefined") return false;
  const video = document.createElement("video");
  return typeof video.play === "function";
}

export function MediaPreviewThumb({ item }: { item: MediaPreviewItem }) {
  if (!isMediaKind(item.preview_kind)) return null;

  const prefersReducedMotion = usePrefersReducedMotion();
  const isTouchDevice = useTouchDevice();
  const [showMotionPreview, setShowMotionPreview] = useState(false);
  const playStartSentRef = useRef(false);

  const isReady = item.preview_status === "ready";
  const imageSrc = item.preview_kind === "video" ? item.poster_url : item.waveform_url;
  const canAnimateClip = Boolean(
    item.preview_kind === "video" &&
    isReady &&
    item.poster_url &&
    item.hover_preview_url &&
    !prefersReducedMotion,
  );

  const canTapPreview = useMemo(
    () => isTouchDevice && canAnimateClip && supportsTapPreviewCapability(),
    [isTouchDevice, canAnimateClip],
  );
  const canHoverOrFocusPreview = !isTouchDevice && canAnimateClip;

  useEffect(() => {
    if (showMotionPreview && !playStartSentRef.current) {
      playStartSentRef.current = true;
      void emitFilePreviewTelemetry({ event: "hover_play_start", path: item.path }).catch(() => undefined);
    }
    if (!showMotionPreview) {
      playStartSentRef.current = false;
    }
    if (!showMotionPreview || !canTapPreview) return;
    const timeout = window.setTimeout(() => {
      setShowMotionPreview(false);
    }, TAP_PREVIEW_MS);
    return () => window.clearTimeout(timeout);
  }, [showMotionPreview, canTapPreview]);

  const activateMotionPreview = () => {
    if (!canHoverOrFocusPreview) return;
    setShowMotionPreview(true);
  };

  const deactivateMotionPreview = () => {
    setShowMotionPreview(false);
  };

  const handleTapPreview = () => {
    if (!canTapPreview) return;
    setShowMotionPreview((current) => !current);
  };

  if (isReady && imageSrc) {
    const alt = item.preview_kind === "video" ? "Video preview poster" : "Audio waveform preview";
    return (
      <div
        className="relative h-8 w-8 shrink-0 overflow-hidden rounded border border-border bg-muted/20"
        tabIndex={canHoverOrFocusPreview ? 0 : -1}
        onMouseEnter={activateMotionPreview}
        onMouseLeave={deactivateMotionPreview}
        onFocus={activateMotionPreview}
        onBlur={deactivateMotionPreview}
        onClick={handleTapPreview}
        aria-label={item.preview_kind === "video" ? `Video preview for ${item.name || "file"}` : undefined}
      >
        {showMotionPreview && item.preview_kind === "video" ? (
          <video
            className="h-full w-full object-cover"
            src={item.hover_preview_url || undefined}
            muted
            loop
            playsInline
            autoPlay
            preload="metadata"
            aria-label="Video hover preview"
            onError={() => {
              void emitFilePreviewTelemetry({ event: "hover_play_failure", reason: "playback_error", path: item.path }).catch(() => undefined);
              setShowMotionPreview(false);
            }}
          />
        ) : (
          <img src={imageSrc} alt={alt} className="h-full w-full object-cover" loading="lazy" />
        )}
      </div>
    );
  }

  return (
    <div className="inline-flex max-w-[170px] shrink-0 rounded border border-border bg-muted/30 px-1.5 py-0.5 text-[11px] text-muted-foreground">
      {fallbackLabel(item)}
    </div>
  );
}
