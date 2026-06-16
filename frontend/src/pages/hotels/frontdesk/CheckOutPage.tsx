/**
 * Hotel Check-Out Flow Page (HTL-024).
 *
 * Route: hotels/front-desk/check-out/:reservationId
 * Admin-only: transitions a checked-in reservation to checked_out.
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF) -> 404.
 */

import { useState } from "react";
import { useParams, useNavigate, useLocation } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  LogOut,
  AlertCircle,
  Loader2,
  ChevronLeft,
  CalendarRange,
  Users,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  frontDeskCheckOut,
  getFrontDeskDepartures,
  type FrontDeskRow,
} from "@/api/endpoints/hotelFrontDesk";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
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
    <div className="space-y-2 text-sm">
      <div className="flex justify-between">
        <span className="text-muted-foreground">Guest</span>
        <span className="font-medium">{row.guest_name}</span>
      </div>
      <div className="flex justify-between">
        <span className="text-muted-foreground">Reservation</span>
        <span className="font-mono text-xs">{row.reservation_id}</span>
      </div>
      <div className="flex justify-between">
        <span className="text-muted-foreground">Stay</span>
        <span className="flex items-center gap-1">
          <CalendarRange className="h-3.5 w-3.5 text-muted-foreground" />
          {row.checkin} → {row.checkout} ({row.nights}n)
        </span>
      </div>
      <div className="flex justify-between">
        <span className="text-muted-foreground">Rooms</span>
        <span className="flex items-center gap-1">
          <Users className="h-3.5 w-3.5 text-muted-foreground" />
          {row.assigned_room_ids.length > 0
            ? row.assigned_room_ids.join(", ")
            : "—"}
        </span>
      </div>
      <div className="flex justify-between">
        <span className="text-muted-foreground">Total charged</span>
        <span className="font-semibold">{centsToCurrency(row.total_cents)}</span>
      </div>
      <div className="flex justify-between">
        <span className="text-muted-foreground">Status</span>
        <Badge className="bg-green-100 text-green-800 text-xs">{row.status}</Badge>
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function CheckOutPage() {
  const { reservationId } = useParams<{ reservationId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const qc = useQueryClient();

  const stateRow = (location.state as { row?: FrontDeskRow; hotelId?: string } | null)?.row;
  const stateHotelId = (location.state as { row?: FrontDeskRow; hotelId?: string } | null)?.hotelId;
  const hotelId = stateHotelId ?? stateRow?.hotel_id ?? "hotel_demo";

  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);

  // Fetch departures to find row if not passed via state
  const departuresQ = useQuery({
    queryKey: ["hotel-frontdesk", "departures", hotelId],
    queryFn: () => getFrontDeskDepartures(hotelId, { limit: 200 }),
    enabled: !stateRow,
    retry: false,
  });

  const isDisabled =
    departuresQ.error instanceof ApiError && departuresQ.error.status === 404;

  const row: FrontDeskRow | undefined =
    stateRow ??
    departuresQ.data?.rows.find((r) => r.reservation_id === reservationId);

  const checkOutMut = useMutation({
    mutationFn: () => {
      if (!reservationId) throw new Error("No reservation ID");
      return frontDeskCheckOut(hotelId, reservationId, reason.trim() || undefined);
    },
    onSuccess: () => {
      toast.success("Guest checked out successfully");
      void qc.invalidateQueries({ queryKey: ["hotel-frontdesk"] });
      navigate("/hotels/front-desk");
    },
    onError: (err: unknown) =>
      toast.error(err instanceof ApiError ? err.detail : "Check-out failed"),
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
          title="Check Out Guest"
          description="Confirm departure and release the room"
        />
      </div>

      {departuresQ.isLoading && !stateRow && (
        <div className="flex items-center justify-center py-10">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      )}

      {!row && !departuresQ.isLoading && (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            <AlertCircle className="h-8 w-8 mx-auto mb-2" />
            Reservation not found or already checked out.
          </CardContent>
        </Card>
      )}

      {row && (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Stay Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <ReservationSummary row={row} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Confirm Check-Out</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Checking out <strong>{row.guest_name}</strong> will release
                {row.assigned_room_ids.length > 0
                  ? ` room${row.assigned_room_ids.length > 1 ? "s" : ""} ${row.assigned_room_ids.join(", ")} `
                  : " the assigned room(s) "}
                for housekeeping and mark the reservation as checked-out.
              </p>

              <div className="space-y-1.5">
                <Label htmlFor="reason">Departure notes (optional)</Label>
                <Input
                  id="reason"
                  placeholder="Early departure, damage reported…"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </div>

              <Separator />

              <div className="flex items-start gap-2">
                <input
                  id="confirm-chk"
                  type="checkbox"
                  className="mt-0.5"
                  checked={confirmed}
                  onChange={(e) => setConfirmed(e.target.checked)}
                />
                <label htmlFor="confirm-chk" className="text-sm">
                  I confirm that the guest has vacated the room and all charges
                  have been settled.
                </label>
              </div>

              <Button
                className="w-full"
                variant="default"
                disabled={!confirmed || checkOutMut.isPending}
                onClick={() => checkOutMut.mutate()}
              >
                {checkOutMut.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : (
                  <LogOut className="h-4 w-4 mr-2" />
                )}
                Complete Check-Out
              </Button>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
