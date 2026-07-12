import * as React from "react";
import { MapContainer, TileLayer, Marker, Circle, Popup, useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

import type { ProximityResultItem } from "@/api/endpoints/crmMaps";

interface Props {
  centerLat: number;
  centerLng: number;
  radiusKm: number;
  results: ProximityResultItem[];
  /** True once a proximity search has produced a center/radius to draw. */
  searchActive: boolean;
}

// Custom DivIcons — avoids the Vite default-marker-icon bundling issue.
const CENTER_ICON = L.divIcon({
  className: "",
  html: `<div style="width:16px;height:16px;border-radius:50%;background:#2563eb;border:3px solid white;box-shadow:0 1px 5px rgba(0,0,0,.5)"></div>`,
  iconSize: [16, 16],
  iconAnchor: [8, 8],
});

const RESULT_ICON = L.divIcon({
  className: "",
  html: `<div style="width:13px;height:13px;border-radius:50%;background:#ef4444;border:2px solid white;box-shadow:0 1px 4px rgba(0,0,0,.4)"></div>`,
  iconSize: [13, 13],
  iconAnchor: [6.5, 6.5],
});

/** Re-centres the map whenever the center coords change. */
function MapUpdater({ lat, lng, zoom }: { lat: number; lng: number; zoom: number }) {
  const map = useMap();
  React.useEffect(() => {
    map.setView([lat, lng], zoom, { animate: true });
  }, [lat, lng, zoom, map]);
  return null;
}

export function CrmContactsMap({ centerLat, centerLng, radiusKm, results, searchActive }: Props) {
  const center: [number, number] = [centerLat, centerLng];
  // Roughly map radius (km) -> a sensible zoom level.
  const zoom = radiusKm <= 0 ? 5 : Math.max(3, Math.min(14, Math.round(13 - Math.log2(radiusKm))));

  return (
    <div className="relative h-[480px] w-full overflow-hidden rounded-md border">
      <MapContainer
        center={center}
        zoom={zoom}
        style={{ height: "100%", width: "100%" }}
        scrollWheelZoom
      >
        <TileLayer
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution='&copy; OpenStreetMap contributors'
        />
        <MapUpdater lat={centerLat} lng={centerLng} zoom={zoom} />

        {searchActive && (
          <>
            <Marker position={center} icon={CENTER_ICON}>
              <Popup>Search center</Popup>
            </Marker>
            <Circle
              center={center}
              radius={radiusKm * 1000}
              pathOptions={{ color: "#2563eb", fillColor: "#3b82f6", fillOpacity: 0.08 }}
            />
          </>
        )}

        {results.map((r) => (
          <Marker key={`${r.entity_type}:${r.entity_id}`} position={[r.lat, r.lng]} icon={RESULT_ICON}>
            <Popup>
              <div className="space-y-0.5 text-xs">
                <div className="font-semibold">{r.name || r.entity_id}</div>
                {r.city || r.country ? (
                  <div className="text-muted-foreground">
                    {[r.city, r.country].filter(Boolean).join(", ")}
                  </div>
                ) : null}
                <div>{r.distance_km.toFixed(2)} km away</div>
              </div>
            </Popup>
          </Marker>
        ))}
      </MapContainer>
    </div>
  );
}
