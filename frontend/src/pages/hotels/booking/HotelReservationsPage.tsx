/**
 * Hotel Reservations List + Detail page (HTL-018, HTL-019).
 *
 * Route: hotels/reservations
 * Lists all reservations for a selected hotel. Click a reservation to see
 * full detail, history, and available lifecycle actions (cancel, no-show).
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF).
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ReceiptText,
  CalendarRange,
  ChevronRight,
  ChevronLeft,
  AlertCircle,
  Loader2,
  Clock,
  CheckCircle2,
  XCircle,
  LogIn,
  LogOut,
  RefreshCw,
  Building2,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  listHotelsForBooking,
  listReservations,
  getReservation,
  getReservationHistory,
  cancelReservation,
  noShowReservation,
  type StayReservationOut,
  type ReservationStatus,
  type HotelOut,
  type ReservationHistoryEntry,
} from "@/api/endpoints/hotelBooking";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
  return (
    <Badge variant={STATUS_VARIANTS[status]}>{STATUS_LABELS[status]}</Badge>
  );
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

export default function HotelReservationsPage() {
  const qc = useQueryClient();
  const [selectedHotelId, setSelectedHotelId] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<ReservationStatus | "">("");
  const [checkinFrom, setCheckinFrom] = useState("");
  const [checkinTo, setCheckinTo] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const [selectedReservationId, setSelectedReservationId] = useState<string | null>(null);
  const [actionDialog, setActionDialog] = useState<"cancel" | "no_show" | null>(null);
  const [actionReason, setActionReason] = useState("");
  const [showHistory, setShowHistory] = useState(false);

  // Hotels for picker
  const hotelsQuery = useQuery({
    queryKey: ["hotels-for-booking"],
    queryFn: () => listHotelsForBooking({ status: "active", limit: 100 }),
    retry: (count, err) => {
      if (err instanceof ApiError && (err as ApiError).status === 404) return false;
      return count < 2;
    },
  });

  const featureDisabled =
    hotelsQuery.error instanceof ApiError &&
    ((hotelsQuery.error as ApiError).status === 404 ||
      (hotelsQuery.error as ApiError).status === 503);

  const hotels: HotelOut[] = hotelsQuery.data?.items ?? [];

  // Reservations list
  const listQuery = useQuery({
    queryKey: [
      "hotel-reservations",
      selectedHotelId,
      statusFilter,
      checkinFrom,
      checkinTo,
      cursor,
    ],
    queryFn: () =>
      listReservations(selectedHotelId, {
        status: (statusFilter as ReservationStatus) || undefined,
        checkin_from: checkinFrom || undefined,
        checkin_to: checkinTo || undefined,
        cursor,
        limit: 20,
      }),
    enabled: !!selectedHotelId,
  });

  const reservations: StayReservationOut[] = listQuery.data?.reservations ?? [];
  const nextCursor: string | null = listQuery.data?.cursor ?? null;

  // Reservation detail
  const detailQuery = useQuery({
    queryKey: ["hotel-reservation-detail", selectedHotelId, selectedReservationId],
    queryFn: () => getReservation(selectedHotelId, selectedReservationId!),
    enabled: !!selectedHotelId && !!selectedReservationId,
  });

  const reservation: StayReservationOut | undefined = detailQuery.data;

  // Reservation history
  const historyQuery = useQuery({
    queryKey: ["hotel-reservation-history", selectedHotelId, selectedReservationId],
    queryFn: () => getReservationHistory(selectedHotelId, selectedReservationId!),
    enabled: !!selectedHotelId && !!selectedReservationId && showHistory,
  });

  const history: ReservationHistoryEntry[] = historyQuery.data?.history ?? [];

  // Cancel mutation
  const cancelMut = useMutation({
    mutationFn: () =>
      cancelReservation(selectedHotelId, selectedReservationId!, actionReason),
    onSuccess: () => {
      toast.success("Reservation cancelled.");
      setActionDialog(null);
      setActionReason("");
      qc.invalidateQueries({ queryKey: ["hotel-reservations"] });
      qc.invalidateQueries({ queryKey: ["hotel-reservation-detail"] });
    },
    onError: (err: unknown) => {
      toast.error(
        err instanceof ApiError ? (err as ApiError).detail : "Cancel failed",
      );
    },
  });

  // No-show mutation
  const noShowMut = useMutation({
    mutationFn: () =>
      noShowReservation(selectedHotelId, selectedReservationId!, actionReason),
    onSuccess: () => {
      toast.success("Reservation marked as no-show.");
      setActionDialog(null);
      setActionReason("");
      qc.invalidateQueries({ queryKey: ["hotel-reservations"] });
      qc.invalidateQueries({ queryKey: ["hotel-reservation-detail"] });
    },
    onError: (err: unknown) => {
      toast.error(
        err instanceof ApiError
          ? (err as ApiError).detail
          : "No-show marking failed",
      );
    },
  });

  const handleAction = () => {
    if (actionDialog === "cancel") cancelMut.mutate();
    else if (actionDialog === "no_show") noShowMut.mutate();
  };

  const actionPending = cancelMut.isPending || noShowMut.isPending;

  // ── Feature disabled ───────────────────────────────────────────────────────
  if (featureDisabled) {
    return (
      <div className="p-6 space-y-4">
        <PageHeader
          title="Reservations"
          description="Manage guest reservations and check-in/check-out lifecycle."
        />
        <EmptyState
          icon={<AlertCircle className="h-10 w-10 text-muted-foreground" />}
          title="Hotel PMS Not Enabled"
          description="The Hotel PMS feature is not enabled on this platform. Contact your administrator to enable HOTEL_PMS_ENABLED."
        />
      </div>
    );
  }

  // ── Detail view ────────────────────────────────────────────────────────────
  if (selectedReservationId && reservation) {
    const canCancel = reservation.status === "confirmed";
    const canNoShow = reservation.status === "confirmed";

    return (
      <div className="p-6 space-y-6">
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSelectedReservationId(null);
              setShowHistory(false);
            }}
          >
            <ChevronLeft className="h-4 w-4 mr-1" /> Back to List
          </Button>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <StatusIcon status={reservation.status} />
          <div>
            <h1 className="text-xl font-bold">{reservation.reservation_id}</h1>
            <p className="text-sm text-muted-foreground">
              Hotel: {reservation.hotel_id}
            </p>
          </div>
          <div className="ml-auto">
            <StatusBadge status={reservation.status} />
          </div>
        </div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <InfoCard label="Guest / Party" value={reservation.guest_party_id} />
          <InfoCard label="Room Type" value={reservation.room_type_id} />
          <InfoCard label="Rooms" value={String(reservation.rooms)} />
          <InfoCard
            label="Dates"
            value={`${reservation.checkin} → ${reservation.checkout}`}
          />
          <InfoCard label="Nights" value={nightsLabel(reservation.nights)} />
          <InfoCard
            label="Guests"
            value={`${reservation.adults} adult${reservation.adults !== 1 ? "s" : ""}${
              reservation.children > 0
                ? `, ${reservation.children} child${reservation.children !== 1 ? "ren" : ""}`
                : ""
            }`}
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
          <InfoCard label="Created" value={fmtDate(reservation.created_at)} />
          <InfoCard label="Updated" value={fmtDate(reservation.updated_at)} />
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
                  <Loader2 className="h-4 w-4 animate-spin" /> Loading history…
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

        {/* Action Dialog */}
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
                  ? "Are you sure you want to cancel this reservation? This will release the held inventory."
                  : "Mark this reservation as a no-show? A no-show fee may apply per the cancellation policy."}
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
                onClick={handleAction}
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

  // ── List view ──────────────────────────────────────────────────────────────
  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="Reservations"
        description="Browse and manage guest reservations for your hotels."
      />

      {/* Filters */}
      <Card>
        <CardContent className="pt-4 space-y-4">
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="grid gap-1.5">
              <Label>
                <Building2 className="h-4 w-4 inline mr-1" />
                Hotel
              </Label>
              {hotelsQuery.isLoading ? (
                <div className="flex items-center gap-2 text-muted-foreground text-sm">
                  <Loader2 className="h-4 w-4 animate-spin" /> Loading…
                </div>
              ) : (
                <Select
                  value={selectedHotelId}
                  onValueChange={(v) => {
                    setSelectedHotelId(v);
                    setCursor(undefined);
                    setSelectedReservationId(null);
                  }}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select a hotel…" />
                  </SelectTrigger>
                  <SelectContent>
                    {hotels.map((h) => (
                      <SelectItem key={h.hotel_id} value={h.hotel_id}>
                        {h.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>

            <div className="grid gap-1.5">
              <Label>Status</Label>
              <Select
                value={statusFilter}
                onValueChange={(v) => {
                  setStatusFilter(v as ReservationStatus | "");
                  setCursor(undefined);
                }}
              >
                <SelectTrigger>
                  <SelectValue placeholder="All statuses" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">All Statuses</SelectItem>
                  <SelectItem value="confirmed">Confirmed</SelectItem>
                  <SelectItem value="checked_in">Checked In</SelectItem>
                  <SelectItem value="checked_out">Checked Out</SelectItem>
                  <SelectItem value="cancelled">Cancelled</SelectItem>
                  <SelectItem value="no_show">No Show</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="grid gap-1.5">
              <Label>Check-in From</Label>
              <Input
                type="date"
                value={checkinFrom}
                onChange={(e) => {
                  setCheckinFrom(e.target.value);
                  setCursor(undefined);
                }}
              />
            </div>

            <div className="grid gap-1.5">
              <Label>Check-in To</Label>
              <Input
                type="date"
                value={checkinTo}
                onChange={(e) => {
                  setCheckinTo(e.target.value);
                  setCursor(undefined);
                }}
              />
            </div>
          </div>

          <div className="flex items-center justify-between">
            <Link to="/hotels/book">
              <Button size="sm">
                <CalendarRange className="h-4 w-4 mr-1" /> New Booking
              </Button>
            </Link>
            {(statusFilter || checkinFrom || checkinTo) && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setStatusFilter("");
                  setCheckinFrom("");
                  setCheckinTo("");
                  setCursor(undefined);
                }}
              >
                Clear Filters
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* List */}
      {!selectedHotelId ? (
        <EmptyState
          icon={<Building2 className="h-8 w-8 text-muted-foreground" />}
          title="Select a Hotel"
          description="Choose a hotel above to view its reservations."
        />
      ) : listQuery.isLoading ? (
        <div className="flex items-center gap-2 text-muted-foreground py-8 justify-center">
          <Loader2 className="h-6 w-6 animate-spin" /> Loading reservations…
        </div>
      ) : listQuery.isError ? (
        <EmptyState
          icon={<AlertCircle className="h-8 w-8 text-muted-foreground" />}
          title="Failed to Load"
          description="Could not load reservations. Please try again."
        />
      ) : reservations.length === 0 ? (
        <EmptyState
          icon={<ReceiptText className="h-8 w-8 text-muted-foreground" />}
          title="No Reservations"
          description="No reservations match the selected filters."
        />
      ) : (
        <div className="space-y-3">
          {reservations.map((res) => (
            <ReservationRow
              key={res.reservation_id}
              reservation={res}
              onSelect={() => setSelectedReservationId(res.reservation_id)}
            />
          ))}

          {/* Pagination */}
          <div className="flex items-center justify-between pt-2">
            <Button
              variant="outline"
              size="sm"
              disabled={!cursor}
              onClick={() => setCursor(undefined)}
            >
              <ChevronLeft className="h-4 w-4 mr-1" /> First Page
            </Button>
            {nextCursor && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCursor(nextCursor)}
              >
                Next Page <ChevronRight className="h-4 w-4 ml-1" />
              </Button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Reservation row card ─────────────────────────────────────────────────────

function ReservationRow({
  reservation,
  onSelect,
}: {
  reservation: StayReservationOut;
  onSelect: () => void;
}) {
  const STATUS_ICONS: Record<ReservationStatus, JSX.Element> = {
    confirmed: <Clock className="h-4 w-4 text-blue-500" />,
    checked_in: <LogIn className="h-4 w-4 text-green-500" />,
    checked_out: <LogOut className="h-4 w-4 text-gray-500" />,
    cancelled: <XCircle className="h-4 w-4 text-red-500" />,
    no_show: <AlertCircle className="h-4 w-4 text-orange-500" />,
  };

  return (
    <button className="w-full text-left" onClick={onSelect}>
      <Card className="hover:bg-muted/40 transition-colors cursor-pointer">
        <CardContent className="pt-4">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              {STATUS_ICONS[reservation.status] ?? <CheckCircle2 className="h-4 w-4" />}
              <div>
                <div className="font-medium text-sm">{reservation.reservation_id}</div>
                <div className="text-xs text-muted-foreground">
                  Guest: {reservation.guest_party_id}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Badge variant={STATUS_VARIANTS[reservation.status]}>
                {STATUS_LABELS[reservation.status]}
              </Badge>
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            </div>
          </div>
          <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-2 text-sm">
            <div>
              <span className="text-muted-foreground text-xs">Check-in</span>
              <div>{reservation.checkin}</div>
            </div>
            <div>
              <span className="text-muted-foreground text-xs">Check-out</span>
              <div>{reservation.checkout}</div>
            </div>
            <div>
              <span className="text-muted-foreground text-xs">Nights</span>
              <div>{nightsLabel(reservation.nights)}</div>
            </div>
            <div>
              <span className="text-muted-foreground text-xs">Total</span>
              <div className="font-semibold">
                {centsToCurrency(reservation.total_cents, reservation.currency)}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </button>
  );
}
