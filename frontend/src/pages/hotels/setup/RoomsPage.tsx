/**
 * Hotel Setup — Rooms inventory page (HTL-006)
 *
 * Route: hotels/:hotelId/rooms
 * Lists rooms for a specific hotel, create/edit/delete rooms, set housekeeping status.
 */

import { useState } from "react";
import { useParams, Link, useSearchParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Hotel, Plus, ArrowLeft } from "lucide-react";

import { ApiError } from "@/api/client";
import {
  listRooms,
  createRoom,
  updateRoom,
  deleteRoom,
  setRoomHousekeepingStatus,
  listRoomTypes,
  type RoomOut,
  type RoomIn,
  type RoomUpdateIn,
} from "@/api/endpoints/hotelSetup";
import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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

type HkStatus = "clean" | "dirty" | "inspected" | "out_of_service";
type RoomStatus = "available" | "out_of_service";

const HK_BADGE: Record<HkStatus, string> = {
  clean: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  dirty: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
  inspected: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  out_of_service: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300",
};

export default function RoomsPage() {
  const { hotelId } = useParams<{ hotelId: string }>();
  const [searchParams] = useSearchParams();
  const qc = useQueryClient();

  const roomTypeFilter = searchParams.get("room_type_id") ?? undefined;

  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<RoomIn>({
    room_type_id: roomTypeFilter ?? "",
    room_number: "",
    floor: 1,
    status: "available",
  });

  const [editTarget, setEditTarget] = useState<RoomOut | null>(null);
  const [editForm, setEditForm] = useState<RoomUpdateIn>({});
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [hkTarget, setHkTarget] = useState<RoomOut | null>(null);
  const [hkStatus, setHkStatus] = useState<HkStatus>("clean");

  // ── queries ──────────────────────────────────────────────────────
  const roomsQuery = useQuery({
    queryKey: ["hotels", hotelId, "rooms", roomTypeFilter],
    queryFn: () =>
      listRooms(hotelId!, { room_type_id: roomTypeFilter }),
    enabled: !!hotelId,
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  const roomTypesQuery = useQuery({
    queryKey: ["hotels", hotelId, "room-types", "active"],
    queryFn: () => listRoomTypes(hotelId!, { status: "active" }),
    enabled: !!hotelId && (showCreate || !!editTarget),
    retry: false,
  });

  // ── mutations ────────────────────────────────────────────────────
  const createMut = useMutation({
    mutationFn: () => createRoom(hotelId!, form),
    onSuccess: (room) => {
      toast.success(`Room ${room.room_number} created`);
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "rooms"] });
      setShowCreate(false);
      setForm({ room_type_id: roomTypeFilter ?? "", room_number: "", floor: 1, status: "available" });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Create failed"),
  });

  const updateMut = useMutation({
    mutationFn: () => updateRoom(hotelId!, editTarget!.room_id, editForm),
    onSuccess: () => {
      toast.success("Room updated");
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "rooms"] });
      setEditTarget(null);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Update failed"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteRoom(hotelId!, id),
    onSuccess: () => {
      toast.success("Room deleted");
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "rooms"] });
      setDeleteTarget(null);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Delete failed"),
  });

  const hkMut = useMutation({
    mutationFn: () => setRoomHousekeepingStatus(hotelId!, hkTarget!.room_id, hkStatus),
    onSuccess: () => {
      toast.success("Housekeeping status updated");
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "rooms"] });
      setHkTarget(null);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Update failed"),
  });

  // ── feature-disabled guard ────────────────────────────────────────
  if (
    roomsQuery.error instanceof ApiError &&
    (roomsQuery.error.status === 404 || roomsQuery.error.status === 503)
  ) {
    return (
      <div className="p-6">
        <EmptyState
          icon={<Hotel className="h-8 w-8" />}
          title="Hotel PMS not enabled"
          description="HOTEL_PMS_ENABLED is off — contact your administrator."
        />
      </div>
    );
  }

  const rooms = roomsQuery.data?.rooms ?? [];
  const roomTypes = roomTypesQuery.data?.room_types ?? [];
  const roomTypeMap = Object.fromEntries(roomTypes.map((rt) => [rt.room_type_id, rt.name]));

  function startEdit(room: RoomOut) {
    setEditForm({
      room_type_id: room.room_type_id,
      room_number: room.room_number,
      floor: room.floor,
      status: room.status,
    });
    setEditTarget(room);
  }

  function startHkUpdate(room: RoomOut) {
    setHkStatus(room.housekeeping_status);
    setHkTarget(room);
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Rooms"
        description={`Hotel ID: ${hotelId}${roomTypeFilter ? ` · filtered by room type` : ""}`}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" asChild>
              <Link to={`/hotels/${hotelId}/room-types`}>
                <ArrowLeft className="h-3 w-3 mr-1" />
                Room Types
              </Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to={`/hotels/${hotelId}/housekeeping`}>
                HK Board
              </Link>
            </Button>
            <Button onClick={() => setShowCreate(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Add Room
            </Button>
          </div>
        }
      />

      {roomsQuery.isLoading && (
        <p className="text-sm text-muted-foreground">Loading rooms…</p>
      )}
      {!roomsQuery.isLoading && rooms.length === 0 && (
        <EmptyState
          icon={<Hotel className="h-8 w-8" />}
          title="No rooms yet"
          description="Add individual rooms to this hotel."
          action={{ label: "Add Room", onClick: () => setShowCreate(true) }}
        />
      )}

      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b text-xs text-muted-foreground uppercase">
              <th className="py-2 px-3 text-left">Room</th>
              <th className="py-2 px-3 text-left">Floor</th>
              <th className="py-2 px-3 text-left">Type</th>
              <th className="py-2 px-3 text-left">Status</th>
              <th className="py-2 px-3 text-left">Housekeeping</th>
              <th className="py-2 px-3 text-left">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rooms.map((room) => (
              <tr key={room.room_id} className="border-b hover:bg-muted/30">
                <td className="py-2 px-3 font-medium">{room.room_number}</td>
                <td className="py-2 px-3">{room.floor}</td>
                <td className="py-2 px-3 text-muted-foreground">
                  {roomTypeMap[room.room_type_id] ?? room.room_type_id.slice(0, 8) + "…"}
                </td>
                <td className="py-2 px-3">
                  <Badge variant={room.status === "available" ? "default" : "secondary"}>
                    {room.status}
                  </Badge>
                </td>
                <td className="py-2 px-3">
                  <span
                    className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${HK_BADGE[room.housekeeping_status]}`}
                  >
                    {room.housekeeping_status}
                  </span>
                </td>
                <td className="py-2 px-3">
                  <div className="flex gap-1">
                    <Button size="sm" variant="outline" onClick={() => startEdit(room)}>
                      Edit
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => startHkUpdate(room)}>
                      HK Status
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => setDeleteTarget(room.room_id)}
                    >
                      Delete
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Create Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Room</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <Label>Room Type *</Label>
              <Select
                value={form.room_type_id}
                onValueChange={(v) => setForm({ ...form, room_type_id: v })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select room type…" />
                </SelectTrigger>
                <SelectContent>
                  {roomTypes.map((rt) => (
                    <SelectItem key={rt.room_type_id} value={rt.room_type_id}>
                      {rt.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>Room Number *</Label>
                <Input
                  value={form.room_number}
                  onChange={(e) => setForm({ ...form, room_number: e.target.value })}
                  placeholder="101"
                />
              </div>
              <div className="space-y-1">
                <Label>Floor *</Label>
                <Input
                  type="number"
                  value={form.floor}
                  onChange={(e) => setForm({ ...form, floor: Number(e.target.value) })}
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label>Status</Label>
              <Select
                value={form.status ?? "available"}
                onValueChange={(v) => setForm({ ...form, status: v as RoomStatus })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="available">Available</SelectItem>
                  <SelectItem value="out_of_service">Out of Service</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button
              disabled={!form.room_type_id || !form.room_number.trim() || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              {createMut.isPending ? "Creating…" : "Create Room"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={!!editTarget} onOpenChange={(o) => !o && setEditTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Room {editTarget?.room_number}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <Label>Room Type</Label>
              <Select
                value={editForm.room_type_id ?? ""}
                onValueChange={(v) => setEditForm({ ...editForm, room_type_id: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {roomTypes.map((rt) => (
                    <SelectItem key={rt.room_type_id} value={rt.room_type_id}>
                      {rt.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>Room Number</Label>
                <Input
                  value={editForm.room_number ?? ""}
                  onChange={(e) => setEditForm({ ...editForm, room_number: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label>Floor</Label>
                <Input
                  type="number"
                  value={editForm.floor ?? 1}
                  onChange={(e) => setEditForm({ ...editForm, floor: Number(e.target.value) })}
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label>Status</Label>
              <Select
                value={editForm.status ?? "available"}
                onValueChange={(v) => setEditForm({ ...editForm, status: v as RoomStatus })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="available">Available</SelectItem>
                  <SelectItem value="out_of_service">Out of Service</SelectItem>
                </SelectContent>
              </Select>
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

      {/* Housekeeping Status Dialog */}
      <Dialog open={!!hkTarget} onOpenChange={(o) => !o && setHkTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Update Housekeeping — Room {hkTarget?.room_number}</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <Label>Housekeeping Status</Label>
            <Select value={hkStatus} onValueChange={(v) => setHkStatus(v as HkStatus)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="clean">Clean</SelectItem>
                <SelectItem value="dirty">Dirty</SelectItem>
                <SelectItem value="inspected">Inspected</SelectItem>
                <SelectItem value="out_of_service">Out of Service</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setHkTarget(null)}>
              Cancel
            </Button>
            <Button disabled={hkMut.isPending} onClick={() => hkMut.mutate()}>
              {hkMut.isPending ? "Updating…" : "Update Status"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirm */}
      <Dialog open={!!deleteTarget} onOpenChange={(o) => !o && setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Room?</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            This permanently removes the room. This action cannot be undone.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={deleteMut.isPending}
              onClick={() => deleteTarget && deleteMut.mutate(deleteTarget)}
            >
              {deleteMut.isPending ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
