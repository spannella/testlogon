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
        display: "flex",
        flexWrap: "wrap",
        alignContent: "space-around",
        justifyContent: "space-around",
        opacity: 0.18,
        userSelect: "none",
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
            textShadow: "0 0 3px rgba(0,0,0,0.7)",
            letterSpacing: "0.05em",
          }}
        >
          {text}
        </span>
      ))}
    </div>
  );
}

export default WatermarkOverlay;
