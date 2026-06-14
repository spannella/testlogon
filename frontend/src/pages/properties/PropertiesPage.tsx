/**
 * PropertiesPage — list all properties, create a new property, navigate to detail.
 *
 * Flag-gated: if the backend returns 404 / 503 the page shows a "not enabled" state.
 * Admin/Root users can create properties; all authenticated users can list.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Building, Plus, RefreshCw, ChevronRight, Archive } from "lucide-react";

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
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

import { ApiError } from "@/api/client";
import {
  listProperties,
  createProperty,
  getPortfolioOccupancy,
  type PropertyOut,
  type PropertyIn,
  type PropertyAddress,
  type PropertyType,
} from "@/api/endpoints/property";

const PROPERTY_TYPE_LABELS: Record<PropertyType, string> = {
  single_family: "Single Family",
  multi_family: "Multi-Family",
  apartment: "Apartment",
  commercial: "Commercial",
};

const OCCUPANCY_BADGE: Record<string, { label: string; variant: "secondary" | "default" | "destructive" | "outline" }> = {
  vacant: { label: "Vacant", variant: "secondary" },
  partial: { label: "Partial", variant: "outline" },
  occupied: { label: "Occupied", variant: "default" },
};

function fmtCents(cents: number): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(cents / 100);
}

function fmtDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString();
}

// ─── Create property dialog ───────────────────────────────────────────────────

interface CreatePropertyDialogProps {
  onCreated: () => void;
}

function CreatePropertyDialog({ onCreated }: CreatePropertyDialogProps) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [propertyType, setPropertyType] = useState<PropertyType>("apartment");
  const [line1, setLine1] = useState("");
  const [line2, setLine2] = useState("");
  const [city, setCity] = useState("");
  const [region, setRegion] = useState("");
  const [postalCode, setPostalCode] = useState("");
  const [country, setCountry] = useState("US");

  const qc = useQueryClient();
  const createMut = useMutation({
    mutationFn: () => {
      const address: PropertyAddress = {
        line1: line1.trim(),
        ...(line2.trim() ? { line2: line2.trim() } : {}),
        city: city.trim(),
        region: region.trim(),
        postal_code: postalCode.trim(),
        country: country.trim(),
      };
      const body: PropertyIn = { name: name.trim(), property_type: propertyType, address };
      return createProperty(body);
    },
    onSuccess: () => {
      toast.success("Property created");
      void qc.invalidateQueries({ queryKey: ["properties"] });
      setOpen(false);
      setName(""); setLine1(""); setLine2(""); setCity(""); setRegion(""); setPostalCode("");
      onCreated();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create property"),
  });

  const canSubmit =
    name.trim().length > 0 &&
    line1.trim().length > 0 &&
    city.trim().length > 0 &&
    region.trim().length > 0 &&
    postalCode.trim().length > 0 &&
    country.trim().length > 0;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" data-testid="create-property-btn">
          <Plus className="h-4 w-4 mr-1" /> Add Property
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Add New Property</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="prop-name">Property Name</Label>
            <Input
              id="prop-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Maple House"
              data-testid="prop-name-input"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="prop-type">Property Type</Label>
            <Select value={propertyType} onValueChange={(v) => setPropertyType(v as PropertyType)}>
              <SelectTrigger id="prop-type" data-testid="prop-type-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(PROPERTY_TYPE_LABELS) as PropertyType[]).map((t) => (
                  <SelectItem key={t} value={t}>{PROPERTY_TYPE_LABELS[t]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="prop-line1">Address Line 1</Label>
            <Input id="prop-line1" value={line1} onChange={(e) => setLine1(e.target.value)} placeholder="123 Main St" />
          </div>
          <div className="space-y-1">
            <Label htmlFor="prop-line2">Address Line 2 (optional)</Label>
            <Input id="prop-line2" value={line2} onChange={(e) => setLine2(e.target.value)} placeholder="Suite 100" />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label htmlFor="prop-city">City</Label>
              <Input id="prop-city" value={city} onChange={(e) => setCity(e.target.value)} placeholder="Springfield" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="prop-region">State / Region</Label>
              <Input id="prop-region" value={region} onChange={(e) => setRegion(e.target.value)} placeholder="IL" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label htmlFor="prop-postal">Postal Code</Label>
              <Input id="prop-postal" value={postalCode} onChange={(e) => setPostalCode(e.target.value)} placeholder="62701" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="prop-country">Country</Label>
              <Input id="prop-country" value={country} onChange={(e) => setCountry(e.target.value)} placeholder="US" />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!canSubmit || createMut.isPending}
              data-testid="prop-create-submit"
            >
              {createMut.isPending ? "Creating…" : "Create"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Property card ────────────────────────────────────────────────────────────

function PropertyCard({ property }: { property: PropertyOut }) {
  const occ = OCCUPANCY_BADGE[property.occupancy_status] ?? { label: property.occupancy_status, variant: "outline" as const };
  return (
    <Link to={`/properties/${property.property_id}`} data-testid={`property-card-${property.property_id}`}>
      <Card className="hover:border-primary/60 transition-colors cursor-pointer">
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <Building className="h-5 w-5 text-muted-foreground shrink-0" />
              <CardTitle className="text-base leading-tight">{property.name}</CardTitle>
            </div>
            <div className="flex items-center gap-1 shrink-0">
              <Badge variant={occ.variant}>{occ.label}</Badge>
              {property.status === "archived" && (
                <Badge variant="secondary">
                  <Archive className="h-3 w-3 mr-1" /> Archived
                </Badge>
              )}
            </div>
          </div>
          <CardDescription className="text-xs">
            {PROPERTY_TYPE_LABELS[property.property_type as PropertyType] ?? property.property_type}
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm space-y-1">
          <p className="text-muted-foreground text-xs truncate">
            {property.address.line1}
            {property.address.line2 ? `, ${property.address.line2}` : ""}
            {", "}
            {property.address.city}, {property.address.region} {property.address.postal_code}
          </p>
          <div className="flex items-center justify-between text-xs text-muted-foreground pt-1">
            <span>{property.unit_count} unit{property.unit_count !== 1 ? "s" : ""}</span>
            <span className="flex items-center gap-1">
              Added {fmtDate(property.created_at)}
              <ChevronRight className="h-3 w-3" />
            </span>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}

// ─── Portfolio summary card ───────────────────────────────────────────────────

function PortfolioSummary() {
  const { data, isLoading } = useQuery({
    queryKey: ["properties", "portfolio-occupancy"],
    queryFn: getPortfolioOccupancy,
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  if (isLoading) {
    return (
      <div className="grid gap-3 md:grid-cols-4">
        {[...Array(4)].map((_, i) => (
          <Card key={i}>
            <CardHeader><CardTitle className="text-sm">…</CardTitle></CardHeader>
            <CardContent className="text-muted-foreground">—</CardContent>
          </Card>
        ))}
      </div>
    );
  }
  if (!data) return null;

  const pct = Math.round(data.occupancy_rate * 100);
  return (
    <div className="grid gap-3 sm:grid-cols-2 md:grid-cols-4">
      <Card>
        <CardHeader><CardTitle className="text-sm">Properties</CardTitle></CardHeader>
        <CardContent className="text-2xl font-bold">{data.property_count}</CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle className="text-sm">Total Units</CardTitle></CardHeader>
        <CardContent className="text-2xl font-bold">{data.unit_count}</CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle className="text-sm">Occupied</CardTitle></CardHeader>
        <CardContent className="text-2xl font-bold text-green-600">{data.occupied}</CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle className="text-sm">Occupancy Rate</CardTitle></CardHeader>
        <CardContent className="text-2xl font-bold">{pct}%</CardContent>
      </Card>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function PropertiesPage() {
  const [statusFilter, setStatusFilter] = useState<"active" | "archived" | "all">("active");
  const [typeFilter, setTypeFilter] = useState<PropertyType | "">("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const qc = useQueryClient();

  const listQuery = useQuery({
    queryKey: ["properties", "list", { statusFilter, typeFilter, cursor }],
    queryFn: () =>
      listProperties({
        status: statusFilter,
        property_type: typeFilter || undefined,
        cursor,
        limit: 50,
      }),
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  const notEnabled =
    listQuery.isError &&
    listQuery.error instanceof ApiError &&
    (listQuery.error.status === 404 || listQuery.error.status === 503);

  const properties = listQuery.data?.properties ?? [];

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="Properties"
        description="Manage your rental property portfolio."
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => void qc.invalidateQueries({ queryKey: ["properties"] })}
              disabled={listQuery.isFetching}
              data-testid="refresh-properties-btn"
            >
              <RefreshCw className={`h-4 w-4 ${listQuery.isFetching ? "animate-spin" : ""}`} />
            </Button>
            <CreatePropertyDialog onCreated={() => void qc.invalidateQueries({ queryKey: ["properties"] })} />
          </div>
        }
      />

      {notEnabled && (
        <Card className="border-dashed">
          <CardContent className="py-12 text-center">
            <Building className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm font-medium text-muted-foreground">
              Property management is not currently enabled on this platform.
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              Contact your administrator to enable the PROPERTY_MGMT_ENABLED feature flag.
            </p>
          </CardContent>
        </Card>
      )}

      {!notEnabled && (
        <>
          <PortfolioSummary />

          <Card>
            <CardHeader>
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div>
                  <CardTitle>Property List</CardTitle>
                  <CardDescription>Filter and browse your properties.</CardDescription>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Select
                    value={statusFilter}
                    onValueChange={(v) => { setStatusFilter(v as "active" | "archived" | "all"); setCursor(undefined); }}
                  >
                    <SelectTrigger className="w-32" data-testid="status-filter-select">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="archived">Archived</SelectItem>
                      <SelectItem value="all">All</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select
                    value={typeFilter}
                    onValueChange={(v) => { setTypeFilter(v as PropertyType | ""); setCursor(undefined); }}
                  >
                    <SelectTrigger className="w-40" data-testid="type-filter-select">
                      <SelectValue placeholder="All types" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="">All types</SelectItem>
                      {(Object.keys(PROPERTY_TYPE_LABELS) as PropertyType[]).map((t) => (
                        <SelectItem key={t} value={t}>{PROPERTY_TYPE_LABELS[t]}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {listQuery.isLoading && (
                <p className="text-sm text-muted-foreground py-8 text-center">Loading properties…</p>
              )}
              {listQuery.isError && !notEnabled && (
                <p className="text-sm text-destructive py-4">
                  Failed to load properties: {listQuery.error instanceof Error ? listQuery.error.message : "Unknown error"}
                </p>
              )}
              {!listQuery.isLoading && !listQuery.isError && properties.length === 0 && (
                <div className="py-12 text-center text-muted-foreground">
                  <Building className="h-8 w-8 mx-auto mb-2 opacity-40" />
                  <p className="text-sm">No properties found. Add your first property to get started.</p>
                </div>
              )}
              {properties.length > 0 && (
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {properties.map((p) => (
                    <PropertyCard key={p.property_id} property={p} />
                  ))}
                </div>
              )}
              {(listQuery.data?.cursor || cursor) && (
                <div className="flex gap-2 pt-4">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCursor(listQuery.data?.cursor ?? undefined)}
                    disabled={!listQuery.data?.cursor || listQuery.isFetching}
                  >
                    Next page
                  </Button>
                  {cursor && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setCursor(undefined)}
                      disabled={listQuery.isFetching}
                    >
                      First page
                    </Button>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

export { fmtCents, fmtDate };
