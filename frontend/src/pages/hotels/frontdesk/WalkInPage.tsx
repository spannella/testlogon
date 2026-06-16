/**
 * Hotel Walk-In Booking Page (HTL-023).
 *
 * Route: hotels/front-desk/walk-in
 * Admin-only: creates a walk-in reservation and immediately checks it in.
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF) -> 404.
 */

import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  BedDouble,
  Loader2,
  ChevronLeft,
  Plus,
  X,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  postWalkIn,
  type WalkInBookingIn,
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
import { Separator } from "@/components/ui/separator";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function todayIso(): string {
  return new Date().toISOString().slice(0, 10);
}

function tomorrowIso(): string {
  const d = new Date();
  d.setDate(d.getDate() + 1);
  return d.toISOString().slice(0, 10);
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
    const trimmed = newId.trim();
    if (!trimmed || roomIds.includes(trimmed)) return;
    onChange([...roomIds, trimmed]);
    setNewId("");
  }

  function remove(id: string) {
    onChange(roomIds.filter((r) => r !== id));
  }

  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <Input
          placeholder="Room ID (e.g. 204)"
          value={newId}
          onChange={(e) => setNewId(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <Button
          type="button"
          variant="outline"
          size="icon"
          onClick={add}
          disabled={!newId.trim()}
        >
          <Plus className="h-4 w-4" />
        </Button>
      </div>
      {roomIds.length > 0 && (
        <ul className="space-y-1">
          {roomIds.map((id) => (
            <li
              key={id}
              className="flex items-center justify-between px-3 py-1.5 rounded border bg-muted/40 text-sm"
            >
              <BedDouble className="h-3.5 w-3.5 text-muted-foreground mr-2" />
              <span className="flex-1 font-mono">{id}</span>
              <button
                type="button"
                className="text-muted-foreground hover:text-destructive"
                onClick={() => remove(id)}
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function WalkInPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const qc = useQueryClient();

  const stateHotelId =
    (location.state as { hotelId?: string } | null)?.hotelId ?? "hotel_demo";

  const [guestName, setGuestName] = useState("");
  const [roomTypeId, setRoomTypeId] = useState("");
  const [checkin, setCheckin] = useState(todayIso());
  const [checkout, setCheckout] = useState(tomorrowIso());
  const [adults, setAdults] = useState(1);
  const [children, setChildren] = useState(0);
  const [assignedRoomIds, setAssignedRoomIds] = useState<string[]>([]);
  const [totalCents, setTotalCents] = useState<string>("");

  const walkInMut = useMutation({
    mutationFn: () => {
      const body: WalkInBookingIn = {
        room_type_id: roomTypeId.trim(),
        checkin,
        checkout,
        occupancy_adults: adults,
        occupancy_children: children,
        guest_name: guestName.trim(),
        assigned_room_ids: assignedRoomIds.length > 0 ? assignedRoomIds : null,
        total_cents: totalCents ? parseInt(totalCents, 10) * 100 : null,
      };
      return postWalkIn(stateHotelId, body);
    },
    onSuccess: (res) => {
      toast.success(
        `Walk-in checked in: ${res.reservation.guest_name} → Room ${res.reservation.assigned_room_ids.join(", ") || "(unassigned)"}`,
      );
      void qc.invalidateQueries({ queryKey: ["hotel-frontdesk"] });
      navigate("/hotels/front-desk");
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError && err.status === 404) {
        toast.error("Hotel PMS is not enabled.");
      } else {
        toast.error(
          err instanceof ApiError ? err.detail : "Walk-in booking failed",
        );
      }
    },
  });

  const canSubmit =
    guestName.trim() &&
    roomTypeId.trim() &&
    checkin &&
    checkout &&
    checkin < checkout &&
    adults >= 1;

  return (
    <div className="container mx-auto max-w-lg py-8 px-4 space-y-6">
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => navigate("/hotels/front-desk")}
        >
          <ChevronLeft className="h-5 w-5" />
        </Button>
        <PageHeader
          title="Walk-In Booking"
          description="Create a reservation and check in immediately"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Guest Details</CardTitle>
          <CardDescription>
            Complete the form to create and check in a walk-in guest.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Guest name */}
          <div className="space-y-1.5">
            <Label htmlFor="guest-name">Guest Name *</Label>
            <Input
              id="guest-name"
              placeholder="Full name"
              value={guestName}
              onChange={(e) => setGuestName(e.target.value)}
            />
          </div>

          {/* Room type */}
          <div className="space-y-1.5">
            <Label htmlFor="room-type">Room Type ID *</Label>
            <Input
              id="room-type"
              placeholder="e.g. rt_standard"
              value={roomTypeId}
              onChange={(e) => setRoomTypeId(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Enter the room type identifier from Hotel Setup.
            </p>
          </div>

          <Separator />

          {/* Dates */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="checkin">Check-In *</Label>
              <Input
                id="checkin"
                type="date"
                value={checkin}
                onChange={(e) => setCheckin(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="checkout">Check-Out *</Label>
              <Input
                id="checkout"
                type="date"
                value={checkout}
                onChange={(e) => setCheckout(e.target.value)}
              />
            </div>
          </div>
          {checkin >= checkout && (
            <p className="text-xs text-destructive">
              Check-out must be after check-in.
            </p>
          )}

          {/* Occupancy */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="adults">Adults *</Label>
              <Input
                id="adults"
                type="number"
                min={1}
                value={adults}
                onChange={(e) => setAdults(Math.max(1, parseInt(e.target.value || "1", 10)))}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="children">Children</Label>
              <Input
                id="children"
                type="number"
                min={0}
                value={children}
                onChange={(e) => setChildren(Math.max(0, parseInt(e.target.value || "0", 10)))}
              />
            </div>
          </div>

          <Separator />

          {/* Total (optional) */}
          <div className="space-y-1.5">
            <Label htmlFor="total">Agreed Total (USD, optional)</Label>
            <div className="relative">
              <span className="absolute inset-y-0 left-3 flex items-center text-muted-foreground text-sm">
                $
              </span>
              <Input
                id="total"
                type="number"
                min={0}
                className="pl-6"
                placeholder="0"
                value={totalCents}
                onChange={(e) => setTotalCents(e.target.value)}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Leave blank to use the computed rate plan price.
            </p>
          </div>

          {/* Room assignment */}
          <Separator />
          <div className="space-y-2">
            <Label>Assign Room(s)</Label>
            <p className="text-xs text-muted-foreground">
              Enter the physical room number(s) to assign at check-in.
            </p>
            <RoomIdList roomIds={assignedRoomIds} onChange={setAssignedRoomIds} />
          </div>

          <Separator />

          <Button
            className="w-full"
            disabled={!canSubmit || walkInMut.isPending}
            onClick={() => walkInMut.mutate()}
          >
            {walkInMut.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
            ) : (
              <BedDouble className="h-4 w-4 mr-2" />
            )}
            Create & Check In
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
