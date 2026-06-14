/**
 * Hotel Setup — Room Types Manager page (HTL-005)
 *
 * Route: hotels/:hotelId/room-types
 * Lists room types for a specific hotel, create/edit/archive room types.
 */

import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { BedDouble, Plus, Users, DollarSign, ArrowLeft } from "lucide-react";

import { ApiError } from "@/api/client";
import {
  listRoomTypes,
  createRoomType,
  updateRoomType,
  archiveRoomType,
  type RoomTypeOut,
  type RoomTypeIn,
  type RoomTypeUpdateIn,
  type BedType,
} from "@/api/endpoints/hotelSetup";
import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const BED_TYPES: BedType[] = ["single", "twin", "double", "queen", "king", "suite"];

function centsToDisplay(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

const defaultForm = (): RoomTypeIn => ({
  name: "",
  description: "",
  base_occupancy_adults: 2,
  base_occupancy_children: 0,
  max_occupancy: 2,
  bed_type: "double",
  size_sqft: 0,
  base_nightly_rate_cents: 10000,
  photo_urls: [],
});

export default function RoomTypesPage() {
  const { hotelId } = useParams<{ hotelId: string }>();
  const qc = useQueryClient();

  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<RoomTypeIn>(defaultForm());

  const [editTarget, setEditTarget] = useState<RoomTypeOut | null>(null);
  const [editForm, setEditForm] = useState<RoomTypeUpdateIn>({});

  const [showArchiveId, setShowArchiveId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<"active" | "all">("active");

  // ── queries ──────────────────────────────────────────────────────
  const roomTypesQuery = useQuery({
    queryKey: ["hotels", hotelId, "room-types", statusFilter],
    queryFn: () => listRoomTypes(hotelId!, { status: statusFilter }),
    enabled: !!hotelId,
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  // ── mutations ────────────────────────────────────────────────────
  const createMut = useMutation({
    mutationFn: () => createRoomType(hotelId!, form),
    onSuccess: (rt) => {
      toast.success(`Room type "${rt.name}" created`);
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "room-types"] });
      setShowCreate(false);
      setForm(defaultForm());
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Create failed"),
  });

  const updateMut = useMutation({
    mutationFn: () => updateRoomType(hotelId!, editTarget!.room_type_id, editForm),
    onSuccess: () => {
      toast.success("Room type updated");
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "room-types"] });
      setEditTarget(null);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Update failed"),
  });

  const archiveMut = useMutation({
    mutationFn: (id: string) => archiveRoomType(hotelId!, id),
    onSuccess: () => {
      toast.success("Room type archived");
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "room-types"] });
      setShowArchiveId(null);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Archive failed"),
  });

  // ── feature-disabled guard ────────────────────────────────────────
  if (
    roomTypesQuery.error instanceof ApiError &&
    (roomTypesQuery.error.status === 404 || roomTypesQuery.error.status === 503)
  ) {
    return (
      <div className="p-6">
        <EmptyState
          icon={<BedDouble className="h-8 w-8" />}
          title="Hotel PMS not enabled"
          description="HOTEL_PMS_ENABLED is off — contact your administrator."
        />
      </div>
    );
  }

  const roomTypes = roomTypesQuery.data?.room_types ?? [];

  function startEdit(rt: RoomTypeOut) {
    setEditForm({
      name: rt.name,
      description: rt.description,
      base_occupancy_adults: rt.base_occupancy_adults,
      base_occupancy_children: rt.base_occupancy_children,
      max_occupancy: rt.max_occupancy,
      bed_type: rt.bed_type,
      size_sqft: rt.size_sqft,
      base_nightly_rate_cents: rt.base_nightly_rate_cents,
    });
    setEditTarget(rt);
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Room Types"
        description={`Hotel ID: ${hotelId}`}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" asChild>
              <Link to={`/hotels/setup/${hotelId}`}>
                <ArrowLeft className="h-3 w-3 mr-1" />
                Hotel
              </Link>
            </Button>
            <Select
              value={statusFilter}
              onValueChange={(v) => setStatusFilter(v as "active" | "all")}
            >
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="all">All</SelectItem>
              </SelectContent>
            </Select>
            <Button onClick={() => setShowCreate(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Add Room Type
            </Button>
          </div>
        }
      />

      {roomTypesQuery.isLoading && (
        <p className="text-sm text-muted-foreground">Loading room types…</p>
      )}
      {!roomTypesQuery.isLoading && roomTypes.length === 0 && (
        <EmptyState
          icon={<BedDouble className="h-8 w-8" />}
          title="No room types yet"
          description="Create your first room type to start adding rooms."
          action={{ label: "Add Room Type", onClick: () => setShowCreate(true) }}
        />
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {roomTypes.map((rt) => (
          <Card key={rt.room_type_id} className="hover:shadow-md transition-shadow">
            <CardHeader className="pb-2">
              <div className="flex items-start justify-between gap-2">
                <CardTitle className="text-base">{rt.name}</CardTitle>
                <Badge variant={rt.status === "active" ? "default" : "secondary"}>
                  {rt.status}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground capitalize">{rt.bed_type} bed</p>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              {rt.description && (
                <p className="text-muted-foreground line-clamp-2">{rt.description}</p>
              )}
              <div className="flex items-center gap-3">
                <span className="flex items-center gap-1">
                  <Users className="h-3.5 w-3.5" />
                  {rt.base_occupancy_adults} adults
                  {rt.base_occupancy_children > 0 ? ` + ${rt.base_occupancy_children} children` : ""}
                  {" "}(max {rt.max_occupancy})
                </span>
              </div>
              <div className="flex items-center gap-1 text-green-700 dark:text-green-400 font-medium">
                <DollarSign className="h-3.5 w-3.5" />
                {centsToDisplay(rt.base_nightly_rate_cents)} / night
              </div>
              {rt.size_sqft > 0 && (
                <p className="text-xs text-muted-foreground">{rt.size_sqft} sq ft</p>
              )}
              <div className="flex gap-2 pt-1">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => startEdit(rt)}
                  disabled={rt.status !== "active"}
                >
                  Edit
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  asChild
                >
                  <Link to={`/hotels/${hotelId}/rooms?room_type_id=${rt.room_type_id}`}>
                    Rooms
                  </Link>
                </Button>
                {rt.status === "active" && (
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => setShowArchiveId(rt.room_type_id)}
                  >
                    Archive
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Create Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create Room Type</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <Label>Name *</Label>
              <Input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Deluxe King Room"
              />
            </div>
            <div className="space-y-1">
              <Label>Description</Label>
              <Textarea
                value={form.description ?? ""}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                rows={2}
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>Bed Type *</Label>
                <Select
                  value={form.bed_type}
                  onValueChange={(v) => setForm({ ...form, bed_type: v as BedType })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {BED_TYPES.map((b) => (
                      <SelectItem key={b} value={b} className="capitalize">
                        {b}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>Size (sq ft)</Label>
                <Input
                  type="number"
                  min={0}
                  value={form.size_sqft ?? 0}
                  onChange={(e) => setForm({ ...form, size_sqft: Number(e.target.value) })}
                />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="space-y-1">
                <Label>Adults *</Label>
                <Input
                  type="number"
                  min={0}
                  value={form.base_occupancy_adults}
                  onChange={(e) =>
                    setForm({ ...form, base_occupancy_adults: Number(e.target.value) })
                  }
                />
              </div>
              <div className="space-y-1">
                <Label>Children</Label>
                <Input
                  type="number"
                  min={0}
                  value={form.base_occupancy_children ?? 0}
                  onChange={(e) =>
                    setForm({ ...form, base_occupancy_children: Number(e.target.value) })
                  }
                />
              </div>
              <div className="space-y-1">
                <Label>Max *</Label>
                <Input
                  type="number"
                  min={1}
                  value={form.max_occupancy}
                  onChange={(e) =>
                    setForm({ ...form, max_occupancy: Number(e.target.value) })
                  }
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label>Base Nightly Rate ($ per night) *</Label>
              <Input
                type="number"
                min={0}
                step={0.01}
                value={(form.base_nightly_rate_cents / 100).toFixed(2)}
                onChange={(e) =>
                  setForm({
                    ...form,
                    base_nightly_rate_cents: Math.round(Number(e.target.value) * 100),
                  })
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button
              disabled={!form.name.trim() || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              {createMut.isPending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={!!editTarget} onOpenChange={(o) => !o && setEditTarget(null)}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Room Type</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <Label>Name</Label>
              <Input
                value={editForm.name ?? ""}
                onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label>Description</Label>
              <Textarea
                value={editForm.description ?? ""}
                onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                rows={2}
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>Bed Type</Label>
                <Select
                  value={editForm.bed_type ?? "double"}
                  onValueChange={(v) => setEditForm({ ...editForm, bed_type: v as BedType })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {BED_TYPES.map((b) => (
                      <SelectItem key={b} value={b} className="capitalize">
                        {b}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>Size (sq ft)</Label>
                <Input
                  type="number"
                  min={0}
                  value={editForm.size_sqft ?? 0}
                  onChange={(e) => setEditForm({ ...editForm, size_sqft: Number(e.target.value) })}
                />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="space-y-1">
                <Label>Adults</Label>
                <Input
                  type="number"
                  min={0}
                  value={editForm.base_occupancy_adults ?? 0}
                  onChange={(e) =>
                    setEditForm({ ...editForm, base_occupancy_adults: Number(e.target.value) })
                  }
                />
              </div>
              <div className="space-y-1">
                <Label>Children</Label>
                <Input
                  type="number"
                  min={0}
                  value={editForm.base_occupancy_children ?? 0}
                  onChange={(e) =>
                    setEditForm({
                      ...editForm,
                      base_occupancy_children: Number(e.target.value),
                    })
                  }
                />
              </div>
              <div className="space-y-1">
                <Label>Max Occ.</Label>
                <Input
                  type="number"
                  min={1}
                  value={editForm.max_occupancy ?? 1}
                  onChange={(e) =>
                    setEditForm({ ...editForm, max_occupancy: Number(e.target.value) })
                  }
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label>Base Nightly Rate ($)</Label>
              <Input
                type="number"
                min={0}
                step={0.01}
                value={((editForm.base_nightly_rate_cents ?? 0) / 100).toFixed(2)}
                onChange={(e) =>
                  setEditForm({
                    ...editForm,
                    base_nightly_rate_cents: Math.round(Number(e.target.value) * 100),
                  })
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditTarget(null)}>
              Cancel
            </Button>
            <Button disabled={updateMut.isPending} onClick={() => updateMut.mutate()}>
              {updateMut.isPending ? "Saving…" : "Save Changes"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Archive Confirm */}
      <Dialog open={!!showArchiveId} onOpenChange={(o) => !o && setShowArchiveId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Archive Room Type?</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            This room type will be archived and hidden from active room allocations.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowArchiveId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={archiveMut.isPending}
              onClick={() => showArchiveId && archiveMut.mutate(showArchiveId)}
            >
              {archiveMut.isPending ? "Archiving…" : "Archive"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
