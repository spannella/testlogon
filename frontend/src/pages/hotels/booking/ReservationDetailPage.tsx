/**
 * Reservation Detail Page — deep-link target after booking.
 *
 * Route: hotels/reservations/:hotelId/:reservationId
 * Redirects (replace) to the reservations list with the detail view preloaded.
 * Actually renders the detail inline using the same data.
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF).
 */

import { useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ChevronLeft,
  ReceiptText,
  AlertCircle,
  Loader2,
  Clock,
  CheckCircle2,
  XCircle,
  LogIn,
  LogOut,
  RefreshCw,
  CalendarRange,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  getReservation,
  getReservationHistory,
  cancelReservation,
  noShowReservation,
  type StayReservationOut,
  type ReservationStatus,
  type ReservationHistoryEntry,
} from "@/api/endpoints/hotelBooking";

import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function centsToCurrency(cents: number, currency = "usd"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function fmtDate(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function nightsLabel(n: number): string {
  return `${n} night${n === 1 ? "" : "s"}`;
}

const STATUS_LABELS: Record<ReservationStatus, string> = {
  confirmed: "Confirmed",
  checked_in: "Checked In",
  checked_out: "Checked Out",
  cancelled: "Cancelled",
  no_show: "No Show",
};

const STATUS_VARIANTS: Record<
  ReservationStatus,
  "default" | "secondary" | "destructive" | "outline"
> = {
  confirmed: "default",
  checked_in: "default",
  checked_out: "secondary",
  cancelled: "destructive",
  no_show: "destructive",
};

function StatusBadge({ status }: { status: ReservationStatus }) {
  return <Badge variant={STATUS_VARIANTS[status]}>{STATUS_LABELS[status]}</Badge>;
}

function StatusIcon({ status }: { status: ReservationStatus }) {
  switch (status) {
    case "confirmed":
      return <Clock className="h-4 w-4 text-blue-500" />;
    case "checked_in":
      return <LogIn className="h-4 w-4 text-green-500" />;
    case "checked_out":
      return <LogOut className="h-4 w-4 text-gray-500" />;
    case "cancelled":
      return <XCircle className="h-4 w-4 text-red-500" />;
    case "no_show":
      return <AlertCircle className="h-4 w-4 text-orange-500" />;
    default:
      return <CheckCircle2 className="h-4 w-4" />;
  }
}

function InfoCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border p-3 space-y-0.5">
      <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        {label}
      </div>
      <div className="text-sm font-medium break-all">{value}</div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function ReservationDetailPage() {
  const { hotelId = "", reservationId = "" } = useParams<{
    hotelId: string;
    reservationId: string;
  }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [actionDialog, setActionDialog] = useState<"cancel" | "no_show" | null>(null);
  const [actionReason, setActionReason] = useState("");
  const [showHistory, setShowHistory] = useState(false);

  const detailQuery = useQuery({
    queryKey: ["hotel-reservation-detail", hotelId, reservationId],
    queryFn: () => getReservation(hotelId, reservationId),
    enabled: !!hotelId && !!reservationId,
    retry: (count, err) => {
      if (err instanceof ApiError && (err as ApiError).status === 404) return false;
      return count < 2;
    },
  });

  const historyQuery = useQuery({
    queryKey: ["hotel-reservation-history", hotelId, reservationId],
    queryFn: () => getReservationHistory(hotelId, reservationId),
    enabled: !!hotelId && !!reservationId && showHistory,
  });

  const history: ReservationHistoryEntry[] = historyQuery.data?.history ?? [];

  const cancelMut = useMutation({
    mutationFn: () => cancelReservation(hotelId, reservationId, actionReason),
    onSuccess: () => {
      toast.success("Reservation cancelled.");
      setActionDialog(null);
      qc.invalidateQueries({ queryKey: ["hotel-reservation-detail"] });
      qc.invalidateQueries({ queryKey: ["hotel-reservations"] });
    },
    onError: (err: unknown) => {
      toast.error(err instanceof ApiError ? (err as ApiError).detail : "Cancel failed");
    },
  });

  const noShowMut = useMutation({
    mutationFn: () => noShowReservation(hotelId, reservationId, actionReason),
    onSuccess: () => {
      toast.success("Marked as no-show.");
      setActionDialog(null);
      qc.invalidateQueries({ queryKey: ["hotel-reservation-detail"] });
      qc.invalidateQueries({ queryKey: ["hotel-reservations"] });
    },
    onError: (err: unknown) => {
      toast.error(err instanceof ApiError ? (err as ApiError).detail : "No-show marking failed");
    },
  });

  const actionPending = cancelMut.isPending || noShowMut.isPending;

  // ── Loading ────────────────────────────────────────────────────────────────
  if (detailQuery.isLoading) {
    return (
      <div className="p-6 flex items-center gap-3 text-muted-foreground">
        <Loader2 className="h-6 w-6 animate-spin" /> Loading reservation…
      </div>
    );
  }

  // ── Error / disabled ───────────────────────────────────────────────────────
  if (
    detailQuery.isError ||
    !detailQuery.data
  ) {
    const is404 =
      detailQuery.error instanceof ApiError &&
      (detailQuery.error as ApiError).status === 404;
    return (
      <div className="p-6 space-y-4">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate("/hotels/reservations")}
        >
          <ChevronLeft className="h-4 w-4 mr-1" /> Back
        </Button>
        <EmptyState
          icon={<AlertCircle className="h-10 w-10 text-muted-foreground" />}
          title={is404 ? "Reservation Not Found" : "Failed to Load"}
          description={
            is404
              ? "This reservation does not exist or Hotel PMS is not enabled."
              : "Could not load reservation details. Please try again."
          }
        />
      </div>
    );
  }

  const reservation: StayReservationOut = detailQuery.data;
  const canCancel = reservation.status === "confirmed";
  const canNoShow = reservation.status === "confirmed";

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate("/hotels/reservations")}
        >
          <ChevronLeft className="h-4 w-4 mr-1" /> All Reservations
        </Button>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <StatusIcon status={reservation.status} />
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              <ReceiptText className="h-5 w-5" />
              {reservation.reservation_id}
            </h1>
            <p className="text-sm text-muted-foreground">
              Hotel: {reservation.hotel_id}
            </p>
          </div>
        </div>
        <StatusBadge status={reservation.status} />
      </div>

      {/* Details grid */}
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <InfoCard label="Guest / Party" value={reservation.guest_party_id} />
        <InfoCard label="Room Type" value={reservation.room_type_id} />
        <InfoCard label="Rooms" value={String(reservation.rooms)} />
        <InfoCard
          label="Stay"
          value={`${reservation.checkin} → ${reservation.checkout}`}
        />
        <InfoCard label="Duration" value={nightsLabel(reservation.nights)} />
        <InfoCard
          label="Guests"
          value={`${reservation.adults} adult${reservation.adults !== 1 ? "s" : ""}${reservation.children > 0 ? `, ${reservation.children} child${reservation.children !== 1 ? "ren" : ""}` : ""}`}
        />
        <InfoCard
          label="Total"
          value={centsToCurrency(reservation.total_cents, reservation.currency)}
        />
        <InfoCard
          label="Deposit"
          value={centsToCurrency(reservation.deposit_cents, reservation.currency)}
        />
        <InfoCard label="Currency" value={reservation.currency.toUpperCase()} />
        <InfoCard
          label="Assigned Rooms"
          value={
            reservation.assigned_room_ids.length > 0
              ? reservation.assigned_room_ids.join(", ")
              : "Not yet assigned"
          }
        />
        <InfoCard label="Version" value={String(reservation.version)} />
        <InfoCard label="Hold ID" value={reservation.hold_id} />
        <InfoCard label="Created" value={fmtDate(reservation.created_at)} />
        <InfoCard label="Last Updated" value={fmtDate(reservation.updated_at)} />
      </div>

      {/* Actions */}
      <div className="flex flex-wrap gap-2">
        {canCancel && (
          <Button
            variant="destructive"
            size="sm"
            onClick={() => {
              setActionReason("");
              setActionDialog("cancel");
            }}
          >
            <XCircle className="h-4 w-4 mr-1" /> Cancel Reservation
          </Button>
        )}
        {canNoShow && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setActionReason("");
              setActionDialog("no_show");
            }}
          >
            <AlertCircle className="h-4 w-4 mr-1" /> Mark No-Show
          </Button>
        )}
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowHistory((h) => !h)}
        >
          <RefreshCw className="h-4 w-4 mr-1" />
          {showHistory ? "Hide" : "Show"} History
        </Button>
        <Link to="/hotels/book">
          <Button variant="outline" size="sm">
            <CalendarRange className="h-4 w-4 mr-1" /> New Booking
          </Button>
        </Link>
      </div>

      {/* History */}
      {showHistory && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Reservation History</CardTitle>
          </CardHeader>
          <CardContent>
            {historyQuery.isLoading ? (
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading…
              </div>
            ) : history.length === 0 ? (
              <p className="text-sm text-muted-foreground">No history events.</p>
            ) : (
              <div className="space-y-2">
                {history.map((evt) => (
                  <div
                    key={evt.event_id}
                    className="flex items-start gap-3 text-sm border-l-2 border-muted pl-3"
                  >
                    <div className="min-w-0 flex-1">
                      <span className="font-medium">
                        {evt.from_status ? `${evt.from_status} → ` : ""}
                        {evt.to_status}
                      </span>
                      {evt.reason && (
                        <span className="text-muted-foreground ml-2">
                          "{evt.reason}"
                        </span>
                      )}
                      <div className="text-xs text-muted-foreground">
                        {fmtDate(evt.ts)} · by {evt.actor}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Action confirmation dialog */}
      <Dialog
        open={!!actionDialog}
        onOpenChange={(open) => !open && setActionDialog(null)}
      >
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>
              {actionDialog === "cancel" ? "Cancel Reservation" : "Mark as No-Show"}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <p className="text-sm text-muted-foreground">
              {actionDialog === "cancel"
                ? "This will cancel the reservation and release the held inventory. This cannot be undone."
                : "Mark this reservation as a no-show. A no-show fee may apply per the cancellation policy."}
            </p>
            <div className="grid gap-1.5">
              <Label>Reason (optional)</Label>
              <Input
                placeholder="e.g. Guest request, weather, etc."
                value={actionReason}
                onChange={(e) => setActionReason(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setActionDialog(null)}>
              Back
            </Button>
            <Button
              variant="destructive"
              disabled={actionPending}
              onClick={() => {
                if (actionDialog === "cancel") cancelMut.mutate();
                else noShowMut.mutate();
              }}
            >
              {actionPending ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" /> Processing…
                </>
              ) : actionDialog === "cancel" ? (
                "Confirm Cancel"
              ) : (
                "Confirm No-Show"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
