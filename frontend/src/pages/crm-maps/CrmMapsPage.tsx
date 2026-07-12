import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { MapPin, Search, RefreshCw, Crosshair } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from "@/components/ui/table";
import { ApiError } from "@/api/client";
import {
  getCrmMapFeatureFlags,
  getGeocodedAddresses,
  regeocodeAddress,
  searchProximityContacts,
  type CrmMapFeatureFlags,
  type GeocodedAddress,
  type ProximitySearchResult,
} from "@/api/endpoints/crmMaps";
import { CrmContactsMap } from "./CrmContactsMap";

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function NotEnabled({ message }: { message: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>CRM Maps not enabled</CardTitle>
        <CardDescription>{message}</CardDescription>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">
          Ask a platform operator to enable the CRM geocoding / proximity-search feature flags
          (<code>CRM_GEOCODING_ENABLED</code> and <code>CRM_PROXIMITY_SEARCH_ENABLED</code>).
        </p>
      </CardContent>
    </Card>
  );
}

// ─── Proximity search panel ──────────────────────────────────────────────────

function ProximityPanel({ flags }: { flags: CrmMapFeatureFlags }) {
  const [lat, setLat] = useState(String(flags.default_lat));
  const [lng, setLng] = useState(String(flags.default_lng));
  const [radius, setRadius] = useState(String(flags.default_radius_km));
  const [entityType, setEntityType] = useState<"address" | "party">("address");

  const [search, setSearch] = useState<ProximitySearchResult | null>(null);

  const searchMut = useMutation({
    mutationFn: () => {
      const latN = Number(lat);
      const lngN = Number(lng);
      const radN = Number(radius);
      if (!Number.isFinite(latN) || latN < -90 || latN > 90) {
        throw new ApiError(400, "Latitude must be between -90 and 90");
      }
      if (!Number.isFinite(lngN) || lngN < -180 || lngN > 180) {
        throw new ApiError(400, "Longitude must be between -180 and 180");
      }
      if (!Number.isFinite(radN) || radN <= 0 || radN > flags.max_radius_km) {
        throw new ApiError(400, `Radius must be between 0 and ${flags.max_radius_km} km`);
      }
      return searchProximityContacts({
        lat: latN,
        lng: lngN,
        radius_km: radN,
        limit: flags.max_pins,
        entity_type: entityType,
      });
    },
    onSuccess: (res) => {
      setSearch(res);
      toast.success(`Found ${res.count} nearby ${res.count === 1 ? "result" : "results"}`);
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Search failed";
      toast.error(msg);
    },
  });

  function useMyLocation() {
    if (!("geolocation" in navigator)) {
      toast.error("Geolocation is not available in this browser");
      return;
    }
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setLat(pos.coords.latitude.toFixed(6));
        setLng(pos.coords.longitude.toFixed(6));
        toast.success("Centered on your location");
      },
      () => toast.error("Could not determine your location"),
    );
  }

  const centerLat = search ? search.center_lat : Number(lat) || flags.default_lat;
  const centerLng = search ? search.center_lng : Number(lng) || flags.default_lng;
  const radiusKm = search ? search.radius_km : Number(radius) || flags.default_radius_km;

  return (
    <div className="grid gap-4 lg:grid-cols-[360px_1fr]">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Search className="h-4 w-4" /> Proximity search
          </CardTitle>
          <CardDescription>Find geocoded contacts within a radius.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label htmlFor="prox-lat">Latitude</Label>
              <Input
                id="prox-lat"
                value={lat}
                onChange={(e) => setLat(e.target.value)}
                inputMode="decimal"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="prox-lng">Longitude</Label>
              <Input
                id="prox-lng"
                value={lng}
                onChange={(e) => setLng(e.target.value)}
                inputMode="decimal"
              />
            </div>
          </div>

          <div className="space-y-1">
            <Label htmlFor="prox-radius">Radius (km)</Label>
            <Input
              id="prox-radius"
              value={radius}
              onChange={(e) => setRadius(e.target.value)}
              inputMode="decimal"
            />
            <p className="text-xs text-muted-foreground">Max {flags.max_radius_km} km</p>
          </div>

          <div className="space-y-1">
            <Label>Entity type</Label>
            <div className="flex gap-2">
              {(["address", "party"] as const).map((t) => (
                <Button
                  key={t}
                  type="button"
                  size="sm"
                  variant={entityType === t ? "default" : "outline"}
                  onClick={() => setEntityType(t)}
                  className="capitalize"
                >
                  {t}
                </Button>
              ))}
            </div>
          </div>

          <div className="flex flex-col gap-2 pt-1">
            <Button
              onClick={() => searchMut.mutate()}
              disabled={searchMut.isPending}
            >
              <Search className="mr-1.5 h-4 w-4" />
              {searchMut.isPending ? "Searching…" : "Search"}
            </Button>
            <Button type="button" variant="outline" onClick={useMyLocation}>
              <Crosshair className="mr-1.5 h-4 w-4" /> Use my location
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="space-y-4">
        <CrmContactsMap
          centerLat={centerLat}
          centerLng={centerLng}
          radiusKm={radiusKm}
          results={search?.results ?? []}
          searchActive={!!search}
        />

        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Results {search ? <Badge variant="secondary">{search.count}</Badge> : null}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!search ? (
              <p className="py-6 text-center text-sm text-muted-foreground">
                Run a search to see nearby contacts.
              </p>
            ) : search.results.length === 0 ? (
              <p className="py-6 text-center text-sm text-muted-foreground">
                No contacts found within {search.radius_km} km.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Location</TableHead>
                    <TableHead className="text-right">Distance</TableHead>
                    <TableHead>Type</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {search.results.map((r) => (
                    <TableRow key={`${r.entity_type}:${r.entity_id}`}>
                      <TableCell className="font-medium">{r.name || r.entity_id}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {[r.city, r.country].filter(Boolean).join(", ") || "—"}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">
                        {r.distance_km.toFixed(2)} km
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {r.entity_type}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─── Geocoded-addresses admin panel ──────────────────────────────────────────

function GeocodeAdminPanel() {
  const qc = useQueryClient();
  const listQuery = useQuery({
    queryKey: ["crm-maps", "geocoded-addresses"],
    queryFn: getGeocodedAddresses,
    retry: false,
  });

  const regeocodeMut = useMutation({
    mutationFn: (addressId: string) => regeocodeAddress(addressId),
    onSuccess: (res: GeocodedAddress) => {
      toast.success(`Re-geocoded (${res.lat.toFixed(4)}, ${res.lng.toFixed(4)})`);
      qc.invalidateQueries({ queryKey: ["crm-maps", "geocoded-addresses"] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Re-geocode failed";
      toast.error(msg);
    },
  });

  const addresses = listQuery.data?.addresses ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <MapPin className="h-4 w-4" /> Geocoded addresses
          {listQuery.data ? <Badge variant="secondary">{listQuery.data.count}</Badge> : null}
        </CardTitle>
        <CardDescription>
          Saved addresses with coordinates. Re-geocode to refresh stale coordinates.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {listQuery.isLoading ? (
          <p className="py-6 text-center text-sm text-muted-foreground">Loading…</p>
        ) : listQuery.isError ? (
          <p className="py-6 text-center text-sm text-destructive">
            {listQuery.error instanceof ApiError
              ? listQuery.error.detail
              : "Failed to load addresses"}
          </p>
        ) : addresses.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">
            No geocoded addresses yet.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead>Coordinates</TableHead>
                <TableHead>Geocoded</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {addresses.map((a) => (
                <TableRow key={a.address_id}>
                  <TableCell>
                    <div className="font-medium">{a.line1 || a.address_id}</div>
                    <div className="text-xs text-muted-foreground">
                      {[a.city, a.state, a.postal_code, a.country].filter(Boolean).join(", ") || "—"}
                    </div>
                  </TableCell>
                  <TableCell className="tabular-nums">
                    {a.lat.toFixed(5)}, {a.lng.toFixed(5)}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{fmt(a.geocoded_at)}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => regeocodeMut.mutate(a.address_id)}
                      disabled={
                        regeocodeMut.isPending && regeocodeMut.variables === a.address_id
                      }
                    >
                      <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
                      Re-geocode
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function CrmMapsPage() {
  const flagsQuery = useQuery({
    queryKey: ["crm-maps", "feature-flags"],
    queryFn: getCrmMapFeatureFlags,
    retry: false,
  });

  const flags = flagsQuery.data;
  const enabled = !!flags?.crm_geocoding_enabled;

  const content = useMemo(() => {
    if (flagsQuery.isLoading) {
      return (
        <p className="py-12 text-center text-sm text-muted-foreground">Loading map settings…</p>
      );
    }
    if (flagsQuery.isError) {
      const status = flagsQuery.error instanceof ApiError ? flagsQuery.error.status : 0;
      if (status === 404 || status === 503) {
        return <NotEnabled message="The CRM maps feature is not enabled on this platform." />;
      }
      return (
        <NotEnabled
          message={
            flagsQuery.error instanceof ApiError
              ? flagsQuery.error.detail
              : "Could not load CRM map settings."
          }
        />
      );
    }
    if (!flags || !enabled) {
      return (
        <NotEnabled message="Geocoding is disabled, so proximity search and the contacts map are unavailable." />
      );
    }
    return (
      <Tabs defaultValue="map" className="space-y-4">
        <TabsList>
          <TabsTrigger value="map">Map &amp; proximity</TabsTrigger>
          <TabsTrigger value="addresses">Geocoded addresses</TabsTrigger>
        </TabsList>
        <TabsContent value="map">
          <ProximityPanel flags={flags} />
        </TabsContent>
        <TabsContent value="addresses">
          <GeocodeAdminPanel />
        </TabsContent>
      </Tabs>
    );
  }, [flagsQuery.isLoading, flagsQuery.isError, flagsQuery.error, flags, enabled]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="CRM Maps"
        description="Geocode contact addresses and find nearby contacts on a map."
      />
      {content}
    </div>
  );
}
