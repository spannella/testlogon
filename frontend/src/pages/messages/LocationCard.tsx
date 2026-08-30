import { useState } from "react";
import { MapPin, Navigation, ExternalLink } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  directionsUrl,
  formatCoords,
  mapsOpenUrl,
  staticMapThumbUrl,
  type LocationCardPayload,
} from "@/lib/locationCards";

export interface LocationCardProps {
  payload: LocationCardPayload;
}

/**
 * FE-130: an in-chat location pin. A keyless static-map thumbnail (OpenStreetMap
 * static service) with a red marker, falling back to a graceful pin placeholder
 * onError (no key / provider 404 => coords-only card, never a crash). Shows the
 * user label and the BE-133 reverse-geocoded place_name (or the raw coords), plus
 * "Open in Maps" + "Directions" universal links that open native maps on mobile.
 * Pure presentation -- URL/preview building lives in lib/locationCards.
 */
export function LocationCard({ payload }: LocationCardProps) {
  const { lat, lng, label, place_name } = payload;
  const [thumbFailed, setThumbFailed] = useState(false);

  const coords = formatCoords(lat, lng);
  const primary = (label ?? "").trim() || (place_name ?? "").trim() || "Shared location";
  const secondary =
    (label ?? "").trim() && (place_name ?? "").trim()
      ? (place_name as string).trim()
      : coords;

  const thumb = staticMapThumbUrl(lat, lng, { w: 320, h: 160, zoom: 15 });

  return (
    <Card className="w-72 max-w-full overflow-hidden" data-testid="location-card">
      <div className="h-32 w-full bg-muted">
        {thumbFailed ? (
          <div
            className="flex h-full w-full items-center justify-center bg-muted text-muted-foreground"
            data-testid="location-card-placeholder"
          >
            <MapPin className="h-8 w-8" />
          </div>
        ) : (
          <img
            src={thumb}
            alt={`Map of ${primary}`}
            className="h-full w-full object-cover"
            loading="lazy"
            onError={() => setThumbFailed(true)}
            data-testid="location-card-thumb"
          />
        )}
      </div>

      <CardContent className="pt-3">
        <div className="flex items-start gap-2">
          <MapPin className="mt-0.5 h-4 w-4 shrink-0 text-rose-500" />
          <div className="min-w-0 flex-1">
            <div
              className="line-clamp-2 text-sm font-semibold"
              data-testid="location-card-label"
            >
              {primary}
            </div>
            <div
              className="mt-0.5 truncate text-xs text-muted-foreground tabular-nums"
              data-testid="location-card-sub"
            >
              {secondary}
            </div>
          </div>
        </div>

        <div className="mt-3 grid grid-cols-2 gap-2">
          <Button
            asChild
            size="sm"
            variant="outline"
            data-testid="location-card-open"
          >
            <a
              href={mapsOpenUrl(lat, lng, label)}
              target="_blank"
              rel="noopener noreferrer"
            >
              <ExternalLink className="mr-1 h-3.5 w-3.5" />
              Open in Maps
            </a>
          </Button>
          <Button asChild size="sm" data-testid="location-card-directions">
            <a
              href={directionsUrl(lat, lng)}
              target="_blank"
              rel="noopener noreferrer"
            >
              <Navigation className="mr-1 h-3.5 w-3.5" />
              Directions
            </a>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default LocationCard;
