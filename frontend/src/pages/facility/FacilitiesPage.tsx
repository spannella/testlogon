import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Building2, Plus, MapPin, Archive, RefreshCw } from "lucide-react";

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
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";

import {
  archiveFacility,
  createFacility,
  createFacilityLocation,
  getFacility,
  listFacilities,
  listFacilityLocations,
  type FacilityIn,
  type FacilityLocationIn,
  type FacilityStatus,
  type FacilityType,
  type LocationType,
} from "@/api/endpoints/facility";
import {
  FeatureDisabledCard,
  formatTs,
  isFeatureDisabled,
  retryUnlessDisabled,
  statusBadgeClass,
} from "./facilityUtils";

const FACILITY_TYPES: FacilityType[] = ["warehouse", "retail", "virtual", "drop_ship"];
const LOCATION_TYPES: LocationType[] = [
  "bulk",
  "bin",
  "aisle",
  "shelf",
  "staging",
  "receiving",
  "shipping",
];

export default function FacilitiesPage() {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<FacilityStatus>("active");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

  const listQuery = useQuery({
    queryKey: ["facilities", "list", statusFilter],
    queryFn: () => listFacilities({ status: statusFilter, limit: 100 }),
    retry: retryUnlessDisabled,
  });

  const disabled = isFeatureDisabled(listQuery.error);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Facilities"
        description="Warehouses, retail locations, and storage zones (OFBiz FAC-005)"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => void listQuery.refetch()}
              disabled={listQuery.isFetching}
            >
              <RefreshCw className="mr-1 h-4 w-4" />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)} disabled={disabled}>
              <Plus className="mr-1 h-4 w-4" />
              New facility
            </Button>
          </div>
        }
      />

      {disabled ? (
        <FeatureDisabledCard />
      ) : (
        <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between gap-3 space-y-0">
              <div>
                <CardTitle>All facilities</CardTitle>
                <CardDescription>Select a facility to view its locations</CardDescription>
              </div>
              <Select
                value={statusFilter}
                onValueChange={(v) => setStatusFilter(v as FacilityStatus)}
              >
                <SelectTrigger className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="active">Active</SelectItem>
                  <SelectItem value="archived">Archived</SelectItem>
                </SelectContent>
              </Select>
            </CardHeader>
            <CardContent>
              {listQuery.isLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-10 w-full" />
                  ))}
                </div>
              ) : (listQuery.data?.facilities ?? []).length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-12 text-center text-muted-foreground">
                  <Building2 className="h-8 w-8" />
                  <p className="text-sm">No {statusFilter} facilities yet.</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(listQuery.data?.facilities ?? []).map((f) => (
                      <TableRow
                        key={f.facility_id}
                        className="cursor-pointer"
                        data-state={selectedId === f.facility_id ? "selected" : undefined}
                        onClick={() => setSelectedId(f.facility_id)}
                      >
                        <TableCell className="font-medium">{f.name}</TableCell>
                        <TableCell className="capitalize text-muted-foreground">
                          {f.facility_type.replace(/_/g, " ")}
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary" className={statusBadgeClass(f.status)}>
                            {f.status}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <FacilityDetail
            facilityId={selectedId}
            onArchived={() => {
              setSelectedId(null);
              void qc.invalidateQueries({ queryKey: ["facilities", "list"] });
            }}
          />
        </div>
      )}

      <CreateFacilityDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(id) => {
          setSelectedId(id);
          void qc.invalidateQueries({ queryKey: ["facilities", "list"] });
        }}
      />
    </div>
  );
}

// ─── Detail panel: facility info + locations ─────────────────────────────────

function FacilityDetail({
  facilityId,
  onArchived,
}: {
  facilityId: string | null;
  onArchived: () => void;
}) {
  const [locOpen, setLocOpen] = useState(false);

  const facQuery = useQuery({
    queryKey: ["facilities", "detail", facilityId],
    queryFn: () => getFacility(facilityId!),
    enabled: !!facilityId,
    retry: retryUnlessDisabled,
  });

  const locQuery = useQuery({
    queryKey: ["facilities", "locations", facilityId],
    queryFn: () => listFacilityLocations(facilityId!),
    enabled: !!facilityId,
    retry: retryUnlessDisabled,
  });

  const archiveMut = useMutation({
    mutationFn: () => archiveFacility(facilityId!),
    onSuccess: () => {
      toast.success("Facility archived");
      onArchived();
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to archive"),
  });

  if (!facilityId) {
    return (
      <Card>
        <CardContent className="flex h-full flex-col items-center justify-center gap-2 py-16 text-center text-muted-foreground">
          <Building2 className="h-8 w-8" />
          <p className="text-sm">Select a facility to view details.</p>
        </CardContent>
      </Card>
    );
  }

  const fac = facQuery.data;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle>{fac?.name ?? "Facility"}</CardTitle>
            <CardDescription className="capitalize">
              {fac ? fac.facility_type.replace(/_/g, " ") : "Loading…"}
            </CardDescription>
          </div>
          {fac?.status === "active" && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => archiveMut.mutate()}
              disabled={archiveMut.isPending}
            >
              <Archive className="mr-1 h-4 w-4" />
              Archive
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {facQuery.isLoading ? (
          <Skeleton className="h-20 w-full" />
        ) : fac ? (
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">Status</dt>
            <dd>
              <Badge variant="secondary" className={statusBadgeClass(fac.status)}>
                {fac.status}
              </Badge>
            </dd>
            <dt className="text-muted-foreground">Description</dt>
            <dd>{fac.description || "—"}</dd>
            <dt className="text-muted-foreground">Created</dt>
            <dd>{formatTs(fac.created_at)}</dd>
            <dt className="text-muted-foreground">Updated</dt>
            <dd>{formatTs(fac.updated_at)}</dd>
          </dl>
        ) : null}

        <div className="flex items-center justify-between border-t pt-4">
          <h3 className="flex items-center gap-2 text-sm font-medium">
            <MapPin className="h-4 w-4" /> Locations
          </h3>
          <Button size="sm" variant="outline" onClick={() => setLocOpen(true)}>
            <Plus className="mr-1 h-4 w-4" />
            Add
          </Button>
        </div>

        {locQuery.isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : (locQuery.data?.locations ?? []).length === 0 ? (
          <p className="py-4 text-center text-sm text-muted-foreground">
            No locations defined.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(locQuery.data?.locations ?? []).map((l) => (
                <TableRow key={l.location_id}>
                  <TableCell className="font-medium">{l.name}</TableCell>
                  <TableCell className="capitalize text-muted-foreground">
                    {l.location_type}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>

      <CreateLocationDialog
        facilityId={facilityId}
        open={locOpen}
        onOpenChange={setLocOpen}
        onCreated={() => void locQuery.refetch()}
      />
    </Card>
  );
}

// ─── Create facility dialog ──────────────────────────────────────────────────

function CreateFacilityDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onCreated: (id: string) => void;
}) {
  const [name, setName] = useState("");
  const [facilityType, setFacilityType] = useState<FacilityType>("warehouse");
  const [description, setDescription] = useState("");

  const mut = useMutation({
    mutationFn: () => {
      const body: FacilityIn = {
        name: name.trim(),
        facility_type: facilityType,
        description: description.trim() || null,
      };
      return createFacility(body);
    },
    onSuccess: (rec) => {
      toast.success("Facility created");
      setName("");
      setDescription("");
      setFacilityType("warehouse");
      onOpenChange(false);
      onCreated(rec.facility_id);
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to create facility"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New facility</DialogTitle>
          <DialogDescription>Create a warehouse or fulfillment location.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="fac-name">Name</Label>
            <Input
              id="fac-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Main Warehouse"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="fac-type">Type</Label>
            <Select value={facilityType} onValueChange={(v) => setFacilityType(v as FacilityType)}>
              <SelectTrigger id="fac-type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FACILITY_TYPES.map((t) => (
                  <SelectItem key={t} value={t} className="capitalize">
                    {t.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="fac-desc">Description</Label>
            <Textarea
              id="fac-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional notes"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => mut.mutate()} disabled={!name.trim() || mut.isPending}>
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Create location dialog ──────────────────────────────────────────────────

function CreateLocationDialog({
  facilityId,
  open,
  onOpenChange,
  onCreated,
}: {
  facilityId: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [locationType, setLocationType] = useState<LocationType>("bulk");

  const mut = useMutation({
    mutationFn: () => {
      const body: FacilityLocationIn = {
        name: name.trim(),
        location_type: locationType,
      };
      return createFacilityLocation(facilityId, body);
    },
    onSuccess: () => {
      toast.success("Location added");
      setName("");
      setLocationType("bulk");
      onOpenChange(false);
      onCreated();
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to add location"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add location</DialogTitle>
          <DialogDescription>Add a storage zone, bin, or staging area.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="loc-name">Name</Label>
            <Input
              id="loc-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Aisle A-1"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="loc-type">Type</Label>
            <Select value={locationType} onValueChange={(v) => setLocationType(v as LocationType)}>
              <SelectTrigger id="loc-type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LOCATION_TYPES.map((t) => (
                  <SelectItem key={t} value={t} className="capitalize">
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => mut.mutate()} disabled={!name.trim() || mut.isPending}>
            Add
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
