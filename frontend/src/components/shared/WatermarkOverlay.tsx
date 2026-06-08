/**
 * WatermarkOverlay (GAP-0370) — semi-transparent forensic identity overlay for
 * the VOD player.
 *
 * Absolutely positioned over the player container; `pointer-events: none` so it
 * does not interfere with player controls, and `aria-hidden` so it stays out of
 * the accessibility tree. Renders the session fingerprint and tenant ID in a
 * repeating diagonal pattern as a secondary deterrent against screen recording.
 *
 * The host container must establish a positioning context (`position: relative`)
 * for the overlay to be clipped to the player boundary.
 */

interface WatermarkOverlayProps {
  /** First ~12 characters of the playback token — per-session fingerprint. */
  sessionId: string | undefined | null;
  /** Owner/tenant ID of the video (creator identifier). */
  tenantId: string | undefined | null;
}

export function WatermarkOverlay({ sessionId, tenantId }: WatermarkOverlayProps) {
  if (!sessionId && !tenantId) return null;

  const text = [sessionId, tenantId].filter(Boolean).join(" · ");

  return (
    <div
      aria-hidden="true"
      data-testid="watermark-overlay"
      style={{
        position: "absolute",
        inset: 0,
        pointerEvents: "none",
        overflow: "hidden",
        zIndex: 10,
        userSelect: "none",
      }}
    >
      {/*
       * Faint, full-frame forensic tiling. Kept at a very low opacity so it's
       * easy to recover from a screen capture but unobtrusive to the viewer — it
       * shouldn't compete with the video itself. (WMK-006)
       */}
      <div
        data-testid="watermark-forensic"
        style={{
          position: "absolute",
          inset: 0,
          display: "flex",
          flexWrap: "wrap",
          alignContent: "space-around",
          justifyContent: "space-around",
          opacity: 0.05,
        }}
      >
        {Array.from({ length: 12 }).map((_, i) => (
          <span
            key={i}
            style={{
              color: "white",
              fontSize: "11px",
              fontFamily: "monospace",
              transform: "rotate(-25deg)",
              whiteSpace: "nowrap",
              letterSpacing: "0.05em",
            }}
          >
            {text}
          </span>
        ))}
      </div>

      {/* One clear corner mark — the visible deterrent. */}
      <div
        data-testid="watermark-corner"
        style={{
          position: "absolute",
          bottom: "8px",
          right: "10px",
          opacity: 0.3,
        }}
      >
        <span
          style={{
            color: "white",
            fontSize: "10px",
            fontFamily: "monospace",
            textShadow: "0 0 3px rgba(0,0,0,0.85)",
            letterSpacing: "0.04em",
          }}
        >
          {text}
        </span>
      </div>
    </div>
  );
}

export default WatermarkOverlay;
