/**
 * Manage In-House Reservation Page (HTL-023).
 *
 * Route: hotels/front-desk/manage/:reservationId
 * Admin-only: change room assignment or perform a room-move for a checked-in guest.
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF) -> 404.
 */

import { useState } from "react";
import { useParams, useNavigate, useLocation } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  BedDouble,
  AlertCircle,
  Loader2,
  ChevronLeft,
  ArrowLeftRight,
  Plus,
  X,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  changeRoom,
  roomMove,
  type FrontDeskRow,
  type AssignRoomIn,
  type RoomMoveIn,
} from "@/api/endpoints/hotelFrontDesk";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function centsToCurrency(cents: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 0,
  }).format(cents / 100);
}

function RoomIdList({
  roomIds,
  onChange,
}: {
  roomIds: string[];
  onChange: (ids: string[]) => void;
}) {
  const [newId, setNewId] = useState("");
  function add() {
    const t = newId.trim();
    if (!t || roomIds.includes(t)) return;
    onChange([...roomIds, t]);
    setNewId("");
  }
  function remove(id: string) {
    onChange(roomIds.filter((r) => r !== id));
  }
  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <Input
          placeholder="Room ID"
          value={newId}
          onChange={(e) => setNewId(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") { e.preventDefault(); add(); }
          }}
        />
        <Button type="button" variant="outline" size="icon" onClick={add} disabled={!newId.trim()}>
          <Plus className="h-4 w-4" />
        </Button>
      </div>
      {roomIds.map((id) => (
        <div
          key={id}
          className="flex items-center justify-between px-3 py-1.5 rounded border bg-muted/40 text-sm"
        >
          <BedDouble className="h-3.5 w-3.5 text-muted-foreground mr-2" />
          <span className="flex-1 font-mono">{id}</span>
          <button type="button" onClick={() => remove(id)} className="text-muted-foreground hover:text-destructive">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ManageReservationPage() {
  const { reservationId } = useParams<{ reservationId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const qc = useQueryClient();

  const stateRow = (location.state as { row?: FrontDeskRow; hotelId?: string } | null)?.row;
  const stateHotelId = (location.state as { row?: FrontDeskRow; hotelId?: string } | null)?.hotelId;
  const hotelId = stateHotelId ?? stateRow?.hotel_id ?? "hotel_demo";
  const row = stateRow;

  // Change-room state
  const [newRoomIds, setNewRoomIds] = useState<string[]>(row?.assigned_room_ids ?? []);

  // Room-move state
  const [fromRoom, setFromRoom] = useState(row?.assigned_room_ids[0] ?? "");
  const [toRoom, setToRoom] = useState("");

  const changeRoomMut = useMutation({
    mutationFn: () => {
      if (!reservationId || !row) throw new Error("Missing reservation");
      const body: AssignRoomIn = { assigned_room_ids: newRoomIds, version: row.occupancy_adults };
      return changeRoom(hotelId, reservationId, body);
    },
    onSuccess: () => {
      toast.success("Room assignment updated");
      void qc.invalidateQueries({ queryKey: ["hotel-frontdesk"] });
      navigate("/hotels/front-desk");
    },
    onError: (err: unknown) =>
      toast.error(err instanceof ApiError ? err.detail : "Change room failed"),
  });

  const roomMoveMut = useMutation({
    mutationFn: () => {
      if (!reservationId || !row) throw new Error("Missing reservation");
      const body: RoomMoveIn = { from_room_id: fromRoom.trim(), to_room_id: toRoom.trim(), version: row.occupancy_adults };
      return roomMove(hotelId, reservationId, body);
    },
    onSuccess: () => {
      toast.success(`Guest moved from ${fromRoom} to ${toRoom}`);
      void qc.invalidateQueries({ queryKey: ["hotel-frontdesk"] });
      navigate("/hotels/front-desk");
    },
    onError: (err: unknown) =>
      toast.error(err instanceof ApiError ? err.detail : "Room move failed"),
  });

  if (!row) {
    return (
      <div className="container mx-auto max-w-lg py-12 px-4 text-center">
        <AlertCircle className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
        <h2 className="font-semibold text-lg">Reservation not found</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Navigate from the Front Desk dashboard to manage a reservation.
        </p>
        <Button className="mt-4" onClick={() => navigate("/hotels/front-desk")}>
          Back to Front Desk
        </Button>
      </div>
    );
  }

  return (
    <div className="container mx-auto max-w-lg py-8 px-4 space-y-6">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="icon" onClick={() => navigate("/hotels/front-desk")}>
          <ChevronLeft className="h-5 w-5" />
        </Button>
        <PageHeader
          title="Manage Reservation"
          description="Change room assignment or move a checked-in guest"
        />
      </div>

      {/* Summary */}
      <Card>
        <CardContent className="pt-4 space-y-1.5 text-sm">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Guest</span>
            <span className="font-medium">{row.guest_name}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Stay</span>
            <span>{row.checkin} → {row.checkout}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Current rooms</span>
            <span>
              {row.assigned_room_ids.length > 0
                ? row.assigned_room_ids.join(", ")
                : "None assigned"}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Status</span>
            <Badge className="bg-green-100 text-green-800 text-xs">{row.status}</Badge>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Total</span>
            <span>{centsToCurrency(row.total_cents)}</span>
          </div>
        </CardContent>
      </Card>

      {/* Actions */}
      <Tabs defaultValue="change-room">
        <TabsList className="w-full">
          <TabsTrigger value="change-room" className="flex-1">
            <BedDouble className="h-4 w-4 mr-1.5" />
            Change Rooms
          </TabsTrigger>
          <TabsTrigger value="room-move" className="flex-1">
            <ArrowLeftRight className="h-4 w-4 mr-1.5" />
            Room Move
          </TabsTrigger>
        </TabsList>

        {/* Change rooms tab */}
        <TabsContent value="change-room">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Update Room Assignment</CardTitle>
              <CardDescription>
                Replace the current room set with a new one. Freed rooms will be
                flipped to clean; new rooms will be flipped to dirty.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <RoomIdList roomIds={newRoomIds} onChange={setNewRoomIds} />
              <Separator />
              <Button
                className="w-full"
                disabled={newRoomIds.length === 0 || changeRoomMut.isPending}
                onClick={() => changeRoomMut.mutate()}
              >
                {changeRoomMut.isPending && (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                )}
                Update Assignment
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Room-move tab */}
        <TabsContent value="room-move">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Move Guest to Another Room</CardTitle>
              <CardDescription>
                Swap exactly one room from the current assignment. The old room
                will be flipped to clean; the new room to dirty.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label>From Room *</Label>
                <Input
                  placeholder="Current room ID"
                  value={fromRoom}
                  onChange={(e) => setFromRoom(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label>To Room *</Label>
                <Input
                  placeholder="New room ID"
                  value={toRoom}
                  onChange={(e) => setToRoom(e.target.value)}
                />
              </div>
              <Separator />
              <Button
                className="w-full"
                disabled={!fromRoom.trim() || !toRoom.trim() || roomMoveMut.isPending}
                onClick={() => roomMoveMut.mutate()}
              >
                {roomMoveMut.isPending && (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                )}
                <ArrowLeftRight className="h-4 w-4 mr-2" />
                Move Guest
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
