import * as React from "react";
import { MapContainer, TileLayer, Marker, useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

interface Props {
  address: string; // full address string to geocode
}

// Custom DivIcon — avoids Vite default-icon bundling issue
const PIN_ICON = L.divIcon({
  className: "",
  html: `<div style="width:14px;height:14px;border-radius:50%;background:#ef4444;border:2px solid white;box-shadow:0 1px 4px rgba(0,0,0,.4)"></div>`,
  iconSize: [14, 14],
  iconAnchor: [7, 7],
});

// Inner component that re-centres the map when coords change
function MapUpdater({ lat, lng }: { lat: number; lng: number }) {
  const map = useMap();
  React.useEffect(() => {
    map.setView([lat, lng], 15, { animate: true });
  }, [lat, lng, map]);
  return null;
}

const NOMINATIM = "https://nominatim.openstreetmap.org/search";
const DEFAULT_LAT = 40.7128;
const DEFAULT_LNG = -74.006; // New York City fallback

export function AddressMap({ address }: Props) {
  const [coords, setCoords] = React.useState<[number, number] | null>(null);
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    if (!address.trim()) {
      setCoords(null);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    fetch(
      `${NOMINATIM}?format=json&limit=1&q=${encodeURIComponent(address)}`,
      {
        headers: { "Accept-Language": "en" },
        signal: controller.signal,
      }
    )
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data) && data.length > 0) {
          setCoords([parseFloat(data[0].lat), parseFloat(data[0].lon)]);
        } else {
          setCoords(null);
        }
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
    return () => controller.abort();
  }, [address]);

  const center: [number, number] = coords ?? [DEFAULT_LAT, DEFAULT_LNG];

  return (
    <div className="relative mt-2 h-48 w-full overflow-hidden rounded-md border">
      {loading && (
        <div className="absolute inset-0 z-10 flex items-center justify-center bg-background/60 text-xs text-muted-foreground">
          Locating…
        </div>
      )}
      {!coords && !loading && (
        <div className="absolute inset-0 z-10 flex items-center justify-center bg-background/60 text-xs text-muted-foreground">
          Enter an address to see a map preview
        </div>
      )}
      <MapContainer
        center={center}
        zoom={coords ? 15 : 3}
        style={{ height: "100%", width: "100%" }}
        zoomControl={false}
        attributionControl={false}
        dragging={false}
        scrollWheelZoom={false}
        doubleClickZoom={false}
      >
        <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
        {coords && <MapUpdater lat={coords[0]} lng={coords[1]} />}
        {coords && <Marker position={coords} icon={PIN_ICON} />}
      </MapContainer>
    </div>
  );
}
