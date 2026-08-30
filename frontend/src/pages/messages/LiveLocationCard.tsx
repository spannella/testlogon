import { useEffect, useState } from "react";
import { MapPin, ExternalLink, Square } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  formatCoords,
  mapsOpenUrl,
  staticMapThumbUrl,
} from "@/lib/locationCards";
import {
  isLiveActive,
  liveRemainingLabel,
} from "@/lib/liveLocation";

export interface LiveLocationCardPayload {
  lat: number;
  lng: number;
  label?: string;
  place_name?: string;
  expires_at: number;
  stopped_at?: number | null;
}

export interface LiveLocationCardProps {
  payload: LiveLocationCardPayload;
  /** True when the viewer is the sharer -> show "Stop sharing". */
  isOwn?: boolean;
  /** Called when the sharer taps "Stop sharing". */
  onStop?: () => void;
  stopping?: boolean;
}

/**
 * FE-131: an in-chat LIVE location pin. Reuses the FE-130 keyless static-map
 * thumbnail (which naturally refreshes as lat/lng update in place on the
 * message), overlaid with a pulsing LIVE badge + a live countdown to expiry.
 * The sharer sees a "Stop sharing" button. Once expired/stopped it collapses to
 * a static "Live location ended" state showing the last-known pin. The moving-
 * pin relay requires BE-131; without it the card still renders the last-known
 * pin + badge/countdown but the pin will not move.
 */
export function LiveLocationCard({ payload, isOwn, onStop, stopping }: LiveLocationCardProps) {
  const { lat, lng, label, place_name, expires_at, stopped_at } = payload;
  const [thumbFailed, setThumbFailed] = useState(false);
  // A local 1s tick drives the countdown + the live/ended transition. nowSec is
  // passed into the pure helpers so the render stays deterministic.
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000));

  const active = isLiveActive(expires_at, stopped_at, nowSec);

  useEffect(() => {
    if (!active) return;
    const id = window.setInterval(() => setNowSec(Math.floor(Date.now() / 1000)), 1000);
    return () => window.clearInterval(id);
  }, [active]);

  const coords = formatCoords(lat, lng);
  const primary = (label ?? "").trim() || (place_name ?? "").trim() || "Live location";
  const badge = liveRemainingLabel(expires_at, stopped_at, nowSec);
  // The static-map URL is keyed by lat/lng so React remounts the <img> and the
  // thumbnail refreshes whenever the sharer's position changes on the message.
  const thumb = staticMapThumbUrl(lat, lng, { w: 320, h: 160, zoom: 15 });

  return (
    <Card
      className="w-72 max-w-full overflow-hidden"
      data-testid="live-location-card"
      data-active={active ? "true" : "false"}
    >
      <div className="relative h-32 w-full bg-muted">
        {thumbFailed ? (
          <div
            className="flex h-full w-full items-center justify-center bg-muted text-muted-foreground"
            data-testid="live-location-card-placeholder"
          >
            <MapPin className="h-8 w-8" />
          </div>
        ) : (
          <img
            key={thumb}
            src={thumb}
            alt={`Live map of ${primary}`}
            className="h-full w-full object-cover"
            loading="lazy"
            onError={() => setThumbFailed(true)}
            data-testid="live-location-card-thumb"
          />
        )}

        <div
          className="absolute left-2 top-2 flex items-center gap-1.5 rounded-full bg-black/70 px-2 py-1 text-xs font-medium text-white"
          data-testid="live-location-badge"
        >
          {active && (
            <span className="relative flex h-2 w-2" aria-hidden>
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400 opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-rose-500" />
            </span>
          )}
          <span className="tabular-nums">{badge}</span>
        </div>
      </div>

      <CardContent className="pt-3">
        <div className="flex items-start gap-2">
          <MapPin
            className={`mt-0.5 h-4 w-4 shrink-0 ${active ? "text-rose-500" : "text-muted-foreground"}`}
          />
          <div className="min-w-0 flex-1">
            <div className="line-clamp-2 text-sm font-semibold" data-testid="live-location-card-label">
              {primary}
            </div>
            <div
              className="mt-0.5 truncate text-xs text-muted-foreground tabular-nums"
              data-testid="live-location-card-sub"
            >
              {active ? coords : "Live location ended"}
            </div>
          </div>
        </div>

        <div className="mt-3 grid grid-cols-2 gap-2">
          <Button asChild size="sm" variant="outline" data-testid="live-location-card-open">
            <a href={mapsOpenUrl(lat, lng, label)} target="_blank" rel="noopener noreferrer">
              <ExternalLink className="mr-1 h-3.5 w-3.5" />
              Open in Maps
            </a>
          </Button>
          {isOwn && active ? (
            <Button
              size="sm"
              variant="destructive"
              onClick={onStop}
              disabled={stopping}
              data-testid="live-location-card-stop"
            >
              <Square className="mr-1 h-3.5 w-3.5" />
              {stopping ? "Stopping…" : "Stop sharing"}
            </Button>
          ) : (
            <div />
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export default LiveLocationCard;
