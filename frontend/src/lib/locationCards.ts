// Pure helpers for the location-in-chat card (EPIC D: FE-130). Kept
// dependency-light so payload building, coordinate validation, the maps deep
// links and previews are unit-testable without React or the network.

// The wire/payload carried on a `location` message. `label` is a user-supplied
// title ("Home", "The cafe"); `place_name` is an optional reverse-geocoded
// address from BE-133 (degrade-on-404 => absent). Coordinates are plain floats.
export interface LocationCardPayload {
  lat: number;
  lng: number;
  label?: string;
  place_name?: string;
}

/** Valid WGS84 coordinate: finite, lat in [-90,90], lng in [-180,180]. */
export function isValidLatLng(lat: unknown, lng: unknown): boolean {
  return (
    typeof lat === "number" &&
    typeof lng === "number" &&
    Number.isFinite(lat) &&
    Number.isFinite(lng) &&
    lat >= -90 &&
    lat <= 90 &&
    lng >= -180 &&
    lng <= 180
  );
}

/** e.g. "37.77490, -122.41940" -- fixed 5dp (~1.1m precision). */
export function formatCoords(lat: number, lng: number): string {
  return `${lat.toFixed(5)}, ${lng.toFixed(5)}`;
}

/**
 * A universal Google Maps "search" link. On mobile the Maps app intercepts
 * this URL and opens natively (drops a pin); on desktop it opens maps in the
 * browser. When a label is supplied it rides as the query so the pin is named,
 * with the coords appended to disambiguate.
 */
export function mapsOpenUrl(lat: number, lng: number, label?: string): string {
  const coords = `${lat},${lng}`;
  const query = label && label.trim() ? `${label.trim()} (${coords})` : coords;
  return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(query)}`;
}

/** A universal Google Maps "directions" link (destination = the pin). */
export function directionsUrl(lat: number, lng: number): string {
  return `https://www.google.com/maps/dir/?api=1&destination=${encodeURIComponent(
    `${lat},${lng}`,
  )}`;
}

/** RFC 5870 geo: URI -- lets a native geo handler take the coords directly. */
export function geoUri(lat: number, lng: number): string {
  return `geo:${lat},${lng}`;
}

export interface StaticMapOpts {
  w?: number;
  h?: number;
  zoom?: number;
}

/**
 * A keyless static-map thumbnail URL. Uses the OpenStreetMap community static
 * map service (no API key required) with a red marker on the point. The
 * renderer falls back to a pin placeholder onError so a provider outage / 404
 * never breaks the card.
 */
export function staticMapThumbUrl(
  lat: number,
  lng: number,
  opts: StaticMapOpts = {},
): string {
  const w = opts.w ?? 320;
  const h = opts.h ?? 160;
  const zoom = opts.zoom ?? 15;
  const center = `${lat},${lng}`;
  return (
    `https://staticmap.openstreetmap.de/staticmap.php` +
    `?center=${center}&zoom=${zoom}&size=${w}x${h}&markers=${center},red`
  );
}

/** Conversation-list / reply preview: "📍 Home" / "📍 Location". */
export function locationPreview(
  label?: string | null,
  placeName?: string | null,
): string {
  const name = (label ?? placeName ?? "").trim();
  return name ? `📍 ${name}` : "📍 Location";
}
