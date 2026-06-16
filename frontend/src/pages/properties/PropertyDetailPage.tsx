/**
 * PropertyDetailPage — shows property info, address, occupancy, and units list.
 * Allows admin/root to edit the property and manage units.
 *
 * Flag-gated: renders "not enabled" state on 404/503.
 */

import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Building,
  ArrowLeft,
  Archive,
  Pencil,
  Plus,
  Trash2,
  Home,
  DoorOpen,
} from "lucide-react";

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
  getProperty,
  updateProperty,
  archiveProperty,
  getPropertyOccupancy,
  listUnits,
  createUnit,
  updateUnit,
  deleteUnit,
  type PropertyOut,
  type PropertyAddress,
  type PropertyType,
  type PropertyUpdateIn,
  type UnitOut,
  type UnitIn,
  type UnitUpdateIn,
  type UnitOccupancyStatus,
} from "@/api/endpoints/property";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const PROPERTY_TYPE_LABELS: Record<PropertyType, string> = {
  single_family: "Single Family",
  multi_family: "Multi-Family",
  apartment: "Apartment",
  commercial: "Commercial",
};

const UNIT_STATUS_LABELS: Record<UnitOccupancyStatus, string> = {
  vacant: "Vacant",
  occupied: "Occupied",
  turnover: "Turnover",
  unavailable: "Unavailable",
};

const UNIT_STATUS_VARIANT: Record<UnitOccupancyStatus, "secondary" | "default" | "destructive" | "outline"> = {
  vacant: "secondary",
  occupied: "default",
  turnover: "outline",
  unavailable: "destructive",
};

function fmtCents(cents: number): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(cents / 100);
}

function fmtDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString();
}

// ─── Edit property dialog ─────────────────────────────────────────────────────

function EditPropertyDialog({
  property,
  onUpdated,
}: {
  property: PropertyOut;
  onUpdated: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(property.name);
  const [propertyType, setPropertyType] = useState<PropertyType>(property.property_type as PropertyType);
  const [line1, setLine1] = useState(property.address.line1);
  const [line2, setLine2] = useState(property.address.line2 ?? "");
  const [city, setCity] = useState(property.address.city);
  const [region, setRegion] = useState(property.address.region);
  const [postalCode, setPostalCode] = useState(property.address.postal_code);
  const [country, setCountry] = useState(property.address.country);

  const qc = useQueryClient();
  const updateMut = useMutation({
    mutationFn: () => {
      const address: PropertyAddress = {
        line1: line1.trim(),
        ...(line2.trim() ? { line2: line2.trim() } : {}),
        city: city.trim(),
        region: region.trim(),
        postal_code: postalCode.trim(),
        country: country.trim(),
      };
      const body: PropertyUpdateIn = {
        ...(name.trim() !== property.name ? { name: name.trim() } : {}),
        ...(propertyType !== property.property_type ? { property_type: propertyType } : {}),
        address,
      };
      return updateProperty(property.property_id, body);
    },
    onSuccess: () => {
      toast.success("Property updated");
      void qc.invalidateQueries({ queryKey: ["property", property.property_id] });
      setOpen(false);
      onUpdated();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to update property"),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" data-testid="edit-property-btn">
          <Pencil className="h-4 w-4 mr-1" /> Edit
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Edit Property</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="edit-prop-name">Property Name</Label>
            <Input id="edit-prop-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="edit-prop-type">Property Type</Label>
            <Select value={propertyType} onValueChange={(v) => setPropertyType(v as PropertyType)}>
              <SelectTrigger id="edit-prop-type">
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
            <Label htmlFor="edit-line1">Address Line 1</Label>
            <Input id="edit-line1" value={line1} onChange={(e) => setLine1(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="edit-line2">Address Line 2</Label>
            <Input id="edit-line2" value={line2} onChange={(e) => setLine2(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label htmlFor="edit-city">City</Label>
              <Input id="edit-city" value={city} onChange={(e) => setCity(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="edit-region">State / Region</Label>
              <Input id="edit-region" value={region} onChange={(e) => setRegion(e.target.value)} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label htmlFor="edit-postal">Postal Code</Label>
              <Input id="edit-postal" value={postalCode} onChange={(e) => setPostalCode(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="edit-country">Country</Label>
              <Input id="edit-country" value={country} onChange={(e) => setCountry(e.target.value)} />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={() => updateMut.mutate()} disabled={updateMut.isPending}>
              {updateMut.isPending ? "Saving…" : "Save"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Add unit dialog ──────────────────────────────────────────────────────────

function AddUnitDialog({
  propertyId,
  onAdded,
}: {
  propertyId: string;
  onAdded: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [bedrooms, setBedrooms] = useState("1");
  const [bathrooms, setBathrooms] = useState("1");
  const [sqft, setSqft] = useState("");
  const [rentCents, setRentCents] = useState("");
  const [status, setStatus] = useState<UnitOccupancyStatus>("vacant");

  const qc = useQueryClient();
  const createMut = useMutation({
    mutationFn: () => {
      const body: UnitIn = {
        label: label.trim(),
        bedrooms: parseInt(bedrooms, 10) || 0,
        bathrooms: parseFloat(bathrooms) || 0,
        square_footage: parseInt(sqft, 10) || 0,
        market_rent_cents: Math.round(parseFloat(rentCents) * 100) || 0,
        occupancy_status: status,
      };
      return createUnit(propertyId, body);
    },
    onSuccess: () => {
      toast.success("Unit added");
      void qc.invalidateQueries({ queryKey: ["property", propertyId] });
      void qc.invalidateQueries({ queryKey: ["units", propertyId] });
      setOpen(false);
      setLabel(""); setBedrooms("1"); setBathrooms("1"); setSqft(""); setRentCents("");
      onAdded();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to add unit"),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" data-testid="add-unit-btn">
          <Plus className="h-4 w-4 mr-1" /> Add Unit
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Add Unit</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="unit-label">Label</Label>
            <Input
              id="unit-label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Apt 1A"
              data-testid="unit-label-input"
            />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label htmlFor="unit-beds">Bedrooms</Label>
              <Input
                id="unit-beds"
                type="number"
                min="0"
                value={bedrooms}
                onChange={(e) => setBedrooms(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="unit-baths">Bathrooms</Label>
              <Input
                id="unit-baths"
                type="number"
                min="0"
                step="0.5"
                value={bathrooms}
                onChange={(e) => setBathrooms(e.target.value)}
              />
            </div>
          </div>
          <div className="space-y-1">
            <Label htmlFor="unit-sqft">Square Footage</Label>
            <Input
              id="unit-sqft"
              type="number"
              min="0"
              value={sqft}
              onChange={(e) => setSqft(e.target.value)}
              placeholder="850"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="unit-rent">Market Rent ($/month)</Label>
            <Input
              id="unit-rent"
              type="number"
              min="0"
              step="0.01"
              value={rentCents}
              onChange={(e) => setRentCents(e.target.value)}
              placeholder="1500.00"
              data-testid="unit-rent-input"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="unit-status">Occupancy Status</Label>
            <Select value={status} onValueChange={(v) => setStatus(v as UnitOccupancyStatus)}>
              <SelectTrigger id="unit-status" data-testid="unit-status-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(UNIT_STATUS_LABELS) as UnitOccupancyStatus[]).map((s) => (
                  <SelectItem key={s} value={s}>{UNIT_STATUS_LABELS[s]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!label.trim() || createMut.isPending}
              data-testid="unit-create-submit"
            >
              {createMut.isPending ? "Adding…" : "Add Unit"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Edit unit dialog ─────────────────────────────────────────────────────────

function EditUnitDialog({
  unit,
  propertyId,
  onUpdated,
}: {
  unit: UnitOut;
  propertyId: string;
  onUpdated: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState(unit.label);
  const [bedrooms, setBedrooms] = useState(String(unit.bedrooms));
  const [bathrooms, setBathrooms] = useState(String(unit.bathrooms));
  const [sqft, setSqft] = useState(String(unit.square_footage));
  const [rentDollars, setRentDollars] = useState((unit.market_rent_cents / 100).toFixed(2));
  const [status, setStatus] = useState<UnitOccupancyStatus>(unit.occupancy_status);

  const qc = useQueryClient();
  const updateMut = useMutation({
    mutationFn: () => {
      const body: UnitUpdateIn = {
        label: label.trim() || undefined,
        bedrooms: parseInt(bedrooms, 10) || undefined,
        bathrooms: parseFloat(bathrooms) || undefined,
        square_footage: parseInt(sqft, 10) || undefined,
        market_rent_cents: Math.round(parseFloat(rentDollars) * 100) || undefined,
        occupancy_status: status,
      };
      return updateUnit(propertyId, unit.unit_id, body);
    },
    onSuccess: () => {
      toast.success("Unit updated");
      void qc.invalidateQueries({ queryKey: ["units", propertyId] });
      void qc.invalidateQueries({ queryKey: ["property", propertyId] });
      setOpen(false);
      onUpdated();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to update unit"),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="icon" className="h-7 w-7" data-testid={`edit-unit-${unit.unit_id}`}>
          <Pencil className="h-3 w-3" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Edit Unit — {unit.label}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor={`eu-label-${unit.unit_id}`}>Label</Label>
            <Input id={`eu-label-${unit.unit_id}`} value={label} onChange={(e) => setLabel(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label>Bedrooms</Label>
              <Input type="number" min="0" value={bedrooms} onChange={(e) => setBedrooms(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label>Bathrooms</Label>
              <Input type="number" min="0" step="0.5" value={bathrooms} onChange={(e) => setBathrooms(e.target.value)} />
            </div>
          </div>
          <div className="space-y-1">
            <Label>Square Footage</Label>
            <Input type="number" min="0" value={sqft} onChange={(e) => setSqft(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label>Market Rent ($/month)</Label>
            <Input type="number" min="0" step="0.01" value={rentDollars} onChange={(e) => setRentDollars(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label>Occupancy Status</Label>
            <Select value={status} onValueChange={(v) => setStatus(v as UnitOccupancyStatus)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {(Object.keys(UNIT_STATUS_LABELS) as UnitOccupancyStatus[]).map((s) => (
                  <SelectItem key={s} value={s}>{UNIT_STATUS_LABELS[s]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={() => updateMut.mutate()} disabled={updateMut.isPending}>
              {updateMut.isPending ? "Saving…" : "Save"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Unit row ─────────────────────────────────────────────────────────────────

function UnitRow({
  unit,
  propertyId,
  onChanged,
}: {
  unit: UnitOut;
  propertyId: string;
  onChanged: () => void;
}) {
  const qc = useQueryClient();
  const deleteMut = useMutation({
    mutationFn: () => deleteUnit(propertyId, unit.unit_id),
    onSuccess: () => {
      toast.success(`Unit "${unit.label}" deleted`);
      void qc.invalidateQueries({ queryKey: ["units", propertyId] });
      void qc.invalidateQueries({ queryKey: ["property", propertyId] });
      onChanged();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to delete unit"),
  });

  const variant = UNIT_STATUS_VARIANT[unit.occupancy_status];

  return (
    <div
      className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-md border p-3 text-sm"
      data-testid={`unit-row-${unit.unit_id}`}
    >
      <div className="flex items-center gap-3">
        <DoorOpen className="h-4 w-4 text-muted-foreground shrink-0" />
        <div>
          <div className="font-medium">{unit.label}</div>
          <div className="text-xs text-muted-foreground">
            {unit.bedrooms}bd / {unit.bathrooms}ba · {unit.square_footage.toLocaleString()} sqft
          </div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2 sm:gap-3">
        <span className="text-sm font-medium">{fmtCents(unit.market_rent_cents)}/mo</span>
        <Badge variant={variant}>{UNIT_STATUS_LABELS[unit.occupancy_status]}</Badge>
        <div className="flex items-center gap-1">
          <EditUnitDialog unit={unit} propertyId={propertyId} onUpdated={onChanged} />
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7 text-destructive hover:text-destructive"
            onClick={() => {
              if (window.confirm(`Delete unit "${unit.label}"?`)) {
                deleteMut.mutate();
              }
            }}
            disabled={deleteMut.isPending}
            data-testid={`delete-unit-${unit.unit_id}`}
          >
            <Trash2 className="h-3 w-3" />
          </Button>
        </div>
      </div>
    </div>
  );
}

// ─── Occupancy summary ────────────────────────────────────────────────────────

function OccupancySummary({ propertyId }: { propertyId: string }) {
  const { data } = useQuery({
    queryKey: ["property-occupancy", propertyId],
    queryFn: () => getPropertyOccupancy(propertyId),
    retry: false,
  });
  if (!data || data.total === 0) return null;
  const pct = Math.round(data.occupancy_rate * 100);
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
      <div className="rounded-md border p-3 text-center">
        <div className="text-lg font-bold text-green-600">{data.occupied}</div>
        <div className="text-xs text-muted-foreground">Occupied</div>
      </div>
      <div className="rounded-md border p-3 text-center">
        <div className="text-lg font-bold">{data.vacant}</div>
        <div className="text-xs text-muted-foreground">Vacant</div>
      </div>
      <div className="rounded-md border p-3 text-center">
        <div className="text-lg font-bold text-amber-600">{data.turnover}</div>
        <div className="text-xs text-muted-foreground">Turnover</div>
      </div>
      <div className="rounded-md border p-3 text-center">
        <div className="text-lg font-bold">{pct}%</div>
        <div className="text-xs text-muted-foreground">Occupancy Rate</div>
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function PropertyDetailPage() {
  const { propertyId } = useParams<{ propertyId: string }>();
  const qc = useQueryClient();

  const propQuery = useQuery({
    queryKey: ["property", propertyId],
    queryFn: () => getProperty(propertyId!),
    enabled: !!propertyId,
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  const unitsQuery = useQuery({
    queryKey: ["units", propertyId],
    queryFn: () => listUnits(propertyId!),
    enabled: !!propertyId && !propQuery.isError,
    retry: false,
  });

  const archiveMut = useMutation({
    mutationFn: () => archiveProperty(propertyId!),
    onSuccess: () => {
      toast.success("Property archived");
      void qc.invalidateQueries({ queryKey: ["property", propertyId] });
      void qc.invalidateQueries({ queryKey: ["properties"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to archive property"),
  });

  const notEnabled =
    propQuery.isError &&
    propQuery.error instanceof ApiError &&
    (propQuery.error.status === 404 || propQuery.error.status === 503);

  const property = propQuery.data;
  const units = unitsQuery.data ?? [];

  if (propQuery.isLoading) {
    return (
      <div className="p-4 md:p-6 lg:p-8">
        <p className="text-sm text-muted-foreground">Loading property…</p>
      </div>
    );
  }

  if (notEnabled) {
    return (
      <div className="p-4 md:p-6 lg:p-8 space-y-4">
        <Link to="/properties">
          <Button variant="outline" size="sm"><ArrowLeft className="h-4 w-4 mr-1" /> Back</Button>
        </Link>
        <Card className="border-dashed">
          <CardContent className="py-12 text-center">
            <Building className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">
              Property management is not currently enabled.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!property) {
    return (
      <div className="p-4 md:p-6 lg:p-8 space-y-4">
        <Link to="/properties">
          <Button variant="outline" size="sm"><ArrowLeft className="h-4 w-4 mr-1" /> Back</Button>
        </Link>
        <p className="text-sm text-destructive">Property not found.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <div className="flex items-center gap-2">
        <Link to="/properties">
          <Button variant="outline" size="sm" data-testid="back-to-properties-btn">
            <ArrowLeft className="h-4 w-4 mr-1" /> Properties
          </Button>
        </Link>
      </div>

      <PageHeader
        title={property.name}
        description={`${PROPERTY_TYPE_LABELS[property.property_type as PropertyType] ?? property.property_type} · ${property.unit_count} unit${property.unit_count !== 1 ? "s" : ""}`}
        actions={
          <div className="flex items-center gap-2">
            <EditPropertyDialog
              property={property}
              onUpdated={() => void qc.invalidateQueries({ queryKey: ["property", propertyId] })}
            />
            {property.status === "active" && (
              <Button
                variant="outline"
                size="sm"
                className="text-amber-600 border-amber-300"
                onClick={() => {
                  if (window.confirm("Archive this property?")) {
                    archiveMut.mutate();
                  }
                }}
                disabled={archiveMut.isPending}
                data-testid="archive-property-btn"
              >
                <Archive className="h-4 w-4 mr-1" /> Archive
              </Button>
            )}
          </div>
        }
      />

      {/* Status badges */}
      <div className="flex flex-wrap items-center gap-2">
        <Badge
          variant={
            property.occupancy_status === "occupied"
              ? "default"
              : property.occupancy_status === "partial"
              ? "outline"
              : "secondary"
          }
        >
          {property.occupancy_status.charAt(0).toUpperCase() + property.occupancy_status.slice(1)}
        </Badge>
        {property.status === "archived" && (
          <Badge variant="secondary">
            <Archive className="h-3 w-3 mr-1" /> Archived
          </Badge>
        )}
        {property.color_tags.map((tag) => (
          <Badge key={tag} variant="outline">{tag}</Badge>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left: Address + info */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Home className="h-4 w-4" /> Address
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm space-y-1">
            <p>{property.address.line1}</p>
            {property.address.line2 && <p>{property.address.line2}</p>}
            <p>
              {property.address.city}, {property.address.region} {property.address.postal_code}
            </p>
            <p className="text-muted-foreground">{property.address.country}</p>
            <div className="pt-3 text-xs text-muted-foreground space-y-1 border-t mt-3">
              <p>Created: {fmtDate(property.created_at)}</p>
              <p>Updated: {fmtDate(property.updated_at)}</p>
              <p className="truncate">ID: {property.property_id}</p>
            </div>
          </CardContent>
        </Card>

        {/* Right: Occupancy + Units */}
        <div className="lg:col-span-2 space-y-4">
          <OccupancySummary propertyId={property.property_id} />

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base">Units</CardTitle>
                  <CardDescription>{units.length} unit{units.length !== 1 ? "s" : ""} in this property</CardDescription>
                </div>
                <AddUnitDialog
                  propertyId={property.property_id}
                  onAdded={() => void unitsQuery.refetch()}
                />
              </div>
            </CardHeader>
            <CardContent>
              {unitsQuery.isLoading && (
                <p className="text-sm text-muted-foreground py-4 text-center">Loading units…</p>
              )}
              {!unitsQuery.isLoading && units.length === 0 && (
                <div className="py-8 text-center text-muted-foreground">
                  <DoorOpen className="h-7 w-7 mx-auto mb-2 opacity-40" />
                  <p className="text-sm">No units yet. Add a unit to get started.</p>
                </div>
              )}
              {units.length > 0 && (
                <div className="space-y-2">
                  {units.map((unit) => (
                    <UnitRow
                      key={unit.unit_id}
                      unit={unit}
                      propertyId={property.property_id}
                      onChanged={() => void unitsQuery.refetch()}
                    />
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
