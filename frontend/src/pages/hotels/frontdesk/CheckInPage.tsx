/**
 * Hotel Check-In Flow Page (HTL-024).
 *
 * Route: hotels/front-desk/check-in/:reservationId
 * Admin-only: assigns room IDs and transitions the reservation to checked_in.
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF) -> 404.
 */

import { useState } from "react";
import { useParams, useNavigate, useLocation } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  LogIn,
  AlertCircle,
  Loader2,
  ChevronLeft,
  BedDouble,
  X,
  Plus,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  frontDeskCheckIn,
  getFrontDeskArrivals,
  type FrontDeskRow,
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
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function centsToCurrency(cents: number, currency = "usd"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 0,
  }).format(cents / 100);
}

function ReservationSummary({ row }: { row: FrontDeskRow }) {
  return (
    <div className="space-y-1 text-sm">
      <div className="flex justify-between">
        <span className="text-muted-foreground">Guest</span>
        <span className="font-medium">{row.guest_name}</span>
      </div>
      <div className="flex justify-between">
        <span className="text-muted-foreground">Reservation ID</span>
        <span className="font-mono text-xs">{row.reservation_id}</span>
      </div>
      <div className="flex justify-between">
        <span className="text-muted-foreground">Check-in / out</span>
        <span>
          {row.checkin} → {row.checkout} ({row.nights} night
          {row.nights !== 1 ? "s" : ""})
        </span>
      </div>
      <div className="flex justify-between">
        <span className="text-muted-foreground">Occupancy</span>
        <span>
          {row.occupancy_adults} adult{row.occupancy_adults !== 1 ? "s" : ""}
          {row.occupancy_children > 0
            ? `, ${row.occupancy_children} child${row.occupancy_children !== 1 ? "ren" : ""}`
            : ""}
        </span>
      </div>
      <div className="flex justify-between">
        <span className="text-muted-foreground">Total</span>
        <span>{centsToCurrency(row.total_cents)}</span>
      </div>
      <div className="flex justify-between">
        <span className="text-muted-foreground">Status</span>
        <Badge
          variant="secondary"
          className="bg-blue-100 text-blue-800 text-xs"
        >
          {row.status}
        </Badge>
      </div>
    </div>
  );
}

// ─── Room ID input list ───────────────────────────────────────────────────────

function RoomIdList({
  roomIds,
  onChange,
  requiredCount,
}: {
  roomIds: string[];
  onChange: (ids: string[]) => void;
  requiredCount: number;
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
    <div className="space-y-3">
      <div className="flex gap-2">
        <Input
          placeholder="Room ID (e.g. 101)"
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
      {roomIds.length > 0 ? (
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
      ) : (
        <p className="text-xs text-muted-foreground">
          No rooms assigned yet. Add {requiredCount} room
          {requiredCount !== 1 ? "s" : ""} to proceed.
        </p>
      )}
      {requiredCount > 0 && (
        <p className="text-xs text-muted-foreground">
          {roomIds.length} / {requiredCount} room{requiredCount !== 1 ? "s" : ""} assigned
        </p>
      )}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function CheckInPage() {
  const { reservationId } = useParams<{ reservationId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const qc = useQueryClient();

  // Row may be passed via Link state from the dashboard
  const stateRow = (location.state as { row?: FrontDeskRow; hotelId?: string } | null)?.row;
  const stateHotelId = (location.state as { row?: FrontDeskRow; hotelId?: string } | null)?.hotelId;

  const hotelId = stateHotelId ?? stateRow?.hotel_id ?? "hotel_demo";

  const [roomIds, setRoomIds] = useState<string[]>(
    stateRow?.assigned_room_ids ?? [],
  );
  const [reason, setReason] = useState("");

  // If no row passed via state, try to find it from arrivals
  const arrivalsQ = useQuery({
    queryKey: ["hotel-frontdesk", "arrivals", hotelId],
    queryFn: () => getFrontDeskArrivals(hotelId, { limit: 200 }),
    enabled: !stateRow,
    retry: false,
  });

  const row: FrontDeskRow | undefined =
    stateRow ??
    arrivalsQ.data?.rows.find((r) => r.reservation_id === reservationId);

  const isDisabled =
    arrivalsQ.error instanceof ApiError && arrivalsQ.error.status === 404;

  const checkInMut = useMutation({
    mutationFn: () => {
      if (!reservationId) throw new Error("No reservation ID");
      return frontDeskCheckIn(hotelId, reservationId, {
        assigned_room_ids: roomIds,
        reason: reason.trim() || undefined,
      });
    },
    onSuccess: () => {
      toast.success("Guest checked in successfully");
      void qc.invalidateQueries({ queryKey: ["hotel-frontdesk"] });
      navigate("/hotels/front-desk");
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError ? err.detail : "Check-in failed",
      ),
  });

  if (isDisabled) {
    return (
      <div className="container mx-auto max-w-xl py-12 px-4 text-center">
        <AlertCircle className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
        <h2 className="font-semibold text-lg">Hotel PMS Not Enabled</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Enable <code className="font-mono text-xs">HOTEL_PMS_ENABLED</code> to
          use the front desk.
        </p>
      </div>
    );
  }

  return (
    <div className="container mx-auto max-w-xl py-8 px-4 space-y-6">
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => navigate("/hotels/front-desk")}
        >
          <ChevronLeft className="h-5 w-5" />
        </Button>
        <PageHeader
          title="Check In Guest"
          description="Assign room(s) and complete the check-in"
        />
      </div>

      {arrivalsQ.isLoading && !stateRow && (
        <div className="flex items-center justify-center py-10">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      )}

      {!row && !arrivalsQ.isLoading && (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            <AlertCircle className="h-8 w-8 mx-auto mb-2" />
            Reservation not found or already processed.
          </CardContent>
        </Card>
      )}

      {row && (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Reservation Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <ReservationSummary row={row} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Assign Rooms</CardTitle>
              <CardDescription>
                Enter the physical room number(s) the guest will occupy.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <RoomIdList
                roomIds={roomIds}
                onChange={setRoomIds}
                requiredCount={row?.occupancy_adults ?? 1}
              />

              <Separator />

              <div className="space-y-1.5">
                <Label htmlFor="reason">Notes (optional)</Label>
                <Input
                  id="reason"
                  placeholder="Early check-in, VIP, special request…"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </div>

              <Button
                className="w-full"
                disabled={
                  roomIds.length === 0 || checkInMut.isPending
                }
                onClick={() => checkInMut.mutate()}
              >
                {checkInMut.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : (
                  <LogIn className="h-4 w-4 mr-2" />
                )}
                Confirm Check-In
              </Button>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
