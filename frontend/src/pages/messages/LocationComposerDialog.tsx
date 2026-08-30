import { useState } from "react";
import { Crosshair, Loader2, MapPin } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { reverseGeocode } from "@/api/endpoints/messaging";
import { isValidLatLng, type LocationCardPayload } from "@/lib/locationCards";
import { LocationCard } from "./LocationCard";

interface LocationComposerDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (payload: LocationCardPayload) => void;
}

/**
 * FE-130: "Share location" composer. Offers a one-tap "Use current location"
 * (navigator.geolocation.getCurrentPosition; on deny/timeout/unsupported it
 * surfaces a hint and falls back to manual entry) plus manual lat/lng fields and
 * an optional label. On confirm it best-effort reverse-geocodes (BE-133,
 * degrade-on-404 => skip place_name) and emits a LocationCardPayload; the caller
 * POSTs via sendLocationCard which degrades-on-404 to a normal `location` message.
 */
export function LocationComposerDialog({
  open,
  onClose,
  onSubmit,
}: LocationComposerDialogProps) {
  const [latStr, setLatStr] = useState("");
  const [lngStr, setLngStr] = useState("");
  const [label, setLabel] = useState("");
  const [locating, setLocating] = useState(false);
  const [geoError, setGeoError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const lat = Number(latStr);
  const lng = Number(lngStr);
  const valid = latStr.trim() !== "" && lngStr.trim() !== "" && isValidLatLng(lat, lng);

  function reset() {
    setLatStr("");
    setLngStr("");
    setLabel("");
    setLocating(false);
    setGeoError(null);
    setSubmitting(false);
  }
  function handleClose() {
    reset();
    onClose();
  }

  function useCurrentLocation() {
    setGeoError(null);
    if (typeof navigator === "undefined" || !navigator.geolocation) {
      setGeoError("Location is not available on this device. Enter coordinates manually.");
      return;
    }
    setLocating(true);
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setLatStr(String(pos.coords.latitude));
        setLngStr(String(pos.coords.longitude));
        setLocating(false);
      },
      (err) => {
        setLocating(false);
        setGeoError(
          err.code === err.PERMISSION_DENIED
            ? "Location permission denied. Enter coordinates manually."
            : "Could not get your location. Enter coordinates manually.",
        );
      },
      { enableHighAccuracy: true, timeout: 10_000, maximumAge: 60_000 },
    );
  }

  async function handleSubmit() {
    if (!valid || submitting) return;
    setSubmitting(true);
    let placeName: string | undefined;
    try {
      placeName = await reverseGeocode(lat, lng);
    } catch {
      placeName = undefined;
    }
    const payload: LocationCardPayload = {
      lat,
      lng,
      label: label.trim() || undefined,
      place_name: placeName,
    };
    onSubmit(payload);
    reset();
  }

  return (
    <Dialog open={open} onOpenChange={(o) => (!o ? handleClose() : undefined)}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Share location</DialogTitle>
        </DialogHeader>

        <div className="space-y-3">
          <Button
            type="button"
            variant="outline"
            className="w-full justify-center gap-2"
            onClick={useCurrentLocation}
            disabled={locating}
            data-testid="location-composer-current"
          >
            {locating ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Crosshair className="h-4 w-4" />
            )}
            {locating ? "Locating…" : "Use current location"}
          </Button>

          {geoError && (
            <p className="text-xs text-amber-600" data-testid="location-composer-error">
              {geoError}
            </p>
          )}

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">Latitude</label>
              <Input
                inputMode="decimal"
                placeholder="37.7749"
                value={latStr}
                onChange={(e) => setLatStr(e.target.value)}
                aria-label="Latitude"
                data-testid="location-composer-lat"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">Longitude</label>
              <Input
                inputMode="decimal"
                placeholder="-122.4194"
                value={lngStr}
                onChange={(e) => setLngStr(e.target.value)}
                aria-label="Longitude"
                data-testid="location-composer-lng"
              />
            </div>
          </div>

          {latStr.trim() !== "" && lngStr.trim() !== "" && !valid && (
            <p className="text-xs text-red-500">
              Enter a valid coordinate (lat -90…90, lng -180…180).
            </p>
          )}

          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              Label (optional)
            </label>
            <Input
              placeholder="Home, the cafe, …"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              aria-label="Location label"
              data-testid="location-composer-label"
            />
          </div>

          {valid ? (
            <div className="flex justify-center pt-1">
              <LocationCard
                payload={{ lat, lng, label: label.trim() || undefined }}
              />
            </div>
          ) : (
            <div className="flex items-center justify-center gap-2 rounded-md border border-dashed py-6 text-sm text-muted-foreground">
              <MapPin className="h-4 w-4" />
              Set a location to preview the pin.
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose} disabled={submitting}>
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={!valid || submitting}
            data-testid="location-composer-send"
          >
            {submitting ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : null}
            Share
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default LocationComposerDialog;
