/**
 * AvailabilityCalendarPage — Hotel per-date room inventory calendar (HTL-012).
 *
 * Admin page: shows room availability per date per room-type for a hotel.
 * Admins can adjust total_rooms, overbooking allowance, and min/max
 * availability directly from the calendar view.
 *
 * Feature-gated by HOTEL_PMS_ENABLED (default OFF): returns HTTP 404 when
 * the flag is off; handled as a "not enabled" state with no retry.
 */

import { useState, useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  CalendarRange,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  getAvailabilityCalendar,
  setTotalRooms as apiSetTotalRooms,
  setOverbooking as apiSetOverbooking,
  setMinMax,
  type AvailabilityDayOut,
} from "@/api/endpoints/hotelInventory";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function startOfMonth(y: number, m: number): string {
  return `${y}-${String(m).padStart(2, "0")}-01`;
}

function endOfMonth(y: number, m: number): string {
  const last = new Date(Date.UTC(y, m, 0)); // m is 1-based; Date.UTC(y, m, 0) = last day of m
  return last.toISOString().slice(0, 10);
}

function daysInMonth(y: number, m: number): number {
  return new Date(Date.UTC(y, m, 0)).getUTCDate();
}

function formatMonthYear(y: number, m: number): string {
  return new Date(Date.UTC(y, m - 1, 1)).toLocaleString("default", {
    month: "long",
    year: "numeric",
    timeZone: "UTC",
  });
}

function availColor(avail: number, total: number): string {
  if (total === 0) return "bg-muted text-muted-foreground";
  const pct = avail / total;
  if (avail <= 0) return "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300";
  if (pct <= 0.25) return "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300";
  if (pct <= 0.5) return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300";
  return "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300";
}

// ─── Edit dialog ───────────────────────────────────────────────────────────────

interface EditDialogProps {
  open: boolean;
  onClose: () => void;
  hotelId: string;
  roomTypeId: string;
  date: string;
  current: AvailabilityDayOut | null;
  onSaved: () => void;
}

function EditDialog({
  open,
  onClose,
  hotelId,
  roomTypeId,
  date,
  current,
  onSaved,
}: EditDialogProps) {
  const [totalRooms, setTotalRooms] = useState(String(current?.total_rooms ?? 0));
  const [overbooking, setOverbooking] = useState(String(current?.overbooking_allowance ?? 0));
  const [minAvail, setMinAvail] = useState(String(current?.min_availability ?? 0));
  const [maxAvail, setMaxAvail] = useState(
    current?.max_availability != null ? String(current.max_availability) : "",
  );

  // Reset state when dialog opens with new data
  const openKey = `${open}-${date}`;
  useMemo(() => {
    if (open) {
      setTotalRooms(String(current?.total_rooms ?? 0));
      setOverbooking(String(current?.overbooking_allowance ?? 0));
      setMinAvail(String(current?.min_availability ?? 0));
      setMaxAvail(
        current?.max_availability != null ? String(current.max_availability) : "",
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openKey]);

  const totalMut = useMutation({
    mutationFn: () =>
      apiSetTotalRooms(hotelId, roomTypeId, {
        hotel_id: hotelId,
        room_type_id: roomTypeId,
        start_date: date,
        end_date: date,
        total_rooms: Number(totalRooms),
      }),
    onSuccess: () => {
      toast.success("Total rooms updated");
      onSaved();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to update total rooms"),
  });

  const obMut = useMutation({
    mutationFn: () =>
      apiSetOverbooking(hotelId, roomTypeId, {
        hotel_id: hotelId,
        room_type_id: roomTypeId,
        start_date: date,
        end_date: date,
        allowance: Number(overbooking),
      }),
    onSuccess: () => {
      toast.success("Overbooking allowance updated");
      onSaved();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to update overbooking"),
  });

  const mmMut = useMutation({
    mutationFn: () => {
      const body: {
        hotel_id: string;
        room_type_id: string;
        start_date: string;
        end_date: string;
        min_availability?: number;
        max_availability?: number;
      } = {
        hotel_id: hotelId,
        room_type_id: roomTypeId,
        start_date: date,
        end_date: date,
        min_availability: Number(minAvail),
      };
      if (maxAvail.trim() !== "") body["max_availability"] = Number(maxAvail);
      return setMinMax(hotelId, roomTypeId, body);
    },
    onSuccess: () => {
      toast.success("Min/max updated");
      onSaved();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to update min/max"),
  });

  const isPending = totalMut.isPending || obMut.isPending || mmMut.isPending;

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>
            Adjust Inventory — {date}
          </DialogTitle>
        </DialogHeader>

        {current && (
          <div className="mb-4 grid grid-cols-3 gap-2 rounded-lg border p-3 text-sm">
            <div className="text-center">
              <p className="text-xs text-muted-foreground">Available</p>
              <p className="font-semibold">{current.available}</p>
            </div>
            <div className="text-center">
              <p className="text-xs text-muted-foreground">Booked</p>
              <p className="font-semibold">{current.booked}</p>
            </div>
            <div className="text-center">
              <p className="text-xs text-muted-foreground">Held</p>
              <p className="font-semibold">{current.held}</p>
            </div>
          </div>
        )}

        <div className="space-y-4">
          {/* Total rooms */}
          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1">
              <Label htmlFor="edit-total">Total Rooms</Label>
              <Input
                id="edit-total"
                type="number"
                min={0}
                value={totalRooms}
                onChange={(e) => setTotalRooms(e.target.value)}
                disabled={isPending}
              />
            </div>
            <Button
              size="sm"
              onClick={() => totalMut.mutate()}
              disabled={isPending || Number(totalRooms) < 0}
            >
              Save
            </Button>
          </div>

          {/* Overbooking allowance */}
          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1">
              <Label htmlFor="edit-ob">Overbooking Allowance</Label>
              <Input
                id="edit-ob"
                type="number"
                min={0}
                value={overbooking}
                onChange={(e) => setOverbooking(e.target.value)}
                disabled={isPending}
              />
            </div>
            <Button
              size="sm"
              onClick={() => obMut.mutate()}
              disabled={isPending || Number(overbooking) < 0}
            >
              Save
            </Button>
          </div>

          {/* Min / max */}
          <div className="space-y-2">
            <p className="text-sm font-medium">Min / Max Availability</p>
            <div className="flex gap-2">
              <div className="flex-1 space-y-1">
                <Label htmlFor="edit-min" className="text-xs">Min</Label>
                <Input
                  id="edit-min"
                  type="number"
                  min={0}
                  value={minAvail}
                  onChange={(e) => setMinAvail(e.target.value)}
                  disabled={isPending}
                />
              </div>
              <div className="flex-1 space-y-1">
                <Label htmlFor="edit-max" className="text-xs">Max (blank = none)</Label>
                <Input
                  id="edit-max"
                  type="number"
                  min={0}
                  value={maxAvail}
                  onChange={(e) => setMaxAvail(e.target.value)}
                  disabled={isPending}
                />
              </div>
            </div>
            <Button
              size="sm"
              className="w-full"
              onClick={() => mmMut.mutate()}
              disabled={isPending}
            >
              Save Min/Max
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export default function AvailabilityCalendarPage() {
  const qc = useQueryClient();

  const today = new Date();
  const [year, setYear] = useState(today.getFullYear());
  const [month, setMonth] = useState(today.getMonth() + 1);

  const [hotelId, setHotelId] = useState("hotel_1");
  const [pendingHotelId, setPendingHotelId] = useState("hotel_1");

  const startDate = startOfMonth(year, month);
  const endDate = endOfMonth(year, month);

  const calQuery = useQuery({
    queryKey: ["hotel-availability-calendar", hotelId, startDate, endDate],
    queryFn: () => getAvailabilityCalendar(hotelId, startDate, endDate),
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 403)) return false;
      return count < 2;
    },
  });

  const roomTypes = Object.keys(calQuery.data?.room_types ?? {});

  // Build a lookup: room_type_id → date → row
  const dayLookup = useMemo(() => {
    const result: Record<string, Record<string, AvailabilityDayOut>> = {};
    const rts = calQuery.data?.room_types ?? {};
    for (const [rt, days] of Object.entries(rts)) {
      result[rt] = {};
      for (const day of days) {
        result[rt]![day.date] = day;
      }
    }
    return result;
  }, [calQuery.data]);

  // Build array of all dates in the month
  const numDays = daysInMonth(year, month);
  const monthDates = Array.from({ length: numDays }, (_, i) =>
    `${year}-${String(month).padStart(2, "0")}-${String(i + 1).padStart(2, "0")}`,
  );

  const [editCell, setEditCell] = useState<{
    roomTypeId: string;
    date: string;
  } | null>(null);

  function prevMonth() {
    if (month === 1) {
      setYear((y) => y - 1);
      setMonth(12);
    } else {
      setMonth((m) => m - 1);
    }
  }

  function nextMonth() {
    if (month === 12) {
      setYear((y) => y + 1);
      setMonth(1);
    } else {
      setMonth((m) => m + 1);
    }
  }

  // Feature not enabled
  if (calQuery.isError && calQuery.error instanceof ApiError && calQuery.error.status === 404) {
    return (
      <div className="space-y-6 p-4 md:p-6 lg:p-8">
        <PageHeader
          title="Availability Calendar"
          description="Per-date room inventory by room type."
        />
        <Card>
          <CardContent className="flex flex-col items-center gap-4 py-16 text-center">
            <CalendarRange className="h-12 w-12 text-muted-foreground" />
            <p className="text-lg font-medium">Hotel PMS not enabled</p>
            <p className="text-sm text-muted-foreground max-w-sm">
              The Hotel PMS feature is currently disabled. Enable it via the
              HOTEL_PMS_ENABLED environment variable to manage room availability.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const editDay =
    editCell
      ? dayLookup[editCell.roomTypeId]?.[editCell.date] ?? null
      : null;

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="Availability Calendar"
        description="Per-date room inventory by room type. Click a cell to adjust."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => void calQuery.refetch()}
            disabled={calQuery.isFetching}
          >
            <RefreshCw className={`h-4 w-4 mr-1 ${calQuery.isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        }
      />

      {/* Hotel selector */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Hotel</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <Input
              placeholder="Hotel ID (e.g. hotel_1)"
              value={pendingHotelId}
              onChange={(e) => setPendingHotelId(e.target.value)}
              className="max-w-xs"
            />
            <Button
              onClick={() => {
                setHotelId(pendingHotelId.trim());
                void qc.invalidateQueries({ queryKey: ["hotel-availability-calendar"] });
              }}
              disabled={!pendingHotelId.trim()}
            >
              Load
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Legend */}
      <div className="flex flex-wrap gap-3 text-xs">
        <span className="flex items-center gap-1">
          <span className="inline-block h-3 w-3 rounded bg-green-100 border border-green-200" />
          Good availability
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-3 w-3 rounded bg-yellow-100 border border-yellow-200" />
          50% or less
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-3 w-3 rounded bg-orange-100 border border-orange-200" />
          25% or less
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-3 w-3 rounded bg-red-100 border border-red-200" />
          Sold out / over
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-3 w-3 rounded bg-muted border" />
          No inventory seeded
        </span>
      </div>

      {/* Month navigation */}
      <div className="flex items-center gap-3">
        <Button variant="outline" size="icon" onClick={prevMonth}>
          <ChevronLeft className="h-4 w-4" />
        </Button>
        <span className="text-lg font-semibold min-w-[180px] text-center">
          {formatMonthYear(year, month)}
        </span>
        <Button variant="outline" size="icon" onClick={nextMonth}>
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>

      {/* Calendar grid */}
      <div className="rounded-lg border overflow-x-auto">
        {calQuery.isPending ? (
          <div className="p-6 space-y-3">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : calQuery.isError ? (
          <div className="p-8 text-center text-muted-foreground">
            <p>Failed to load calendar: {(calQuery.error as Error).message}</p>
            <Button
              variant="outline"
              size="sm"
              className="mt-3"
              onClick={() => void calQuery.refetch()}
            >
              Retry
            </Button>
          </div>
        ) : roomTypes.length === 0 ? (
          <div className="flex flex-col items-center gap-3 py-16 text-center">
            <CalendarRange className="h-10 w-10 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              No availability data for hotel <strong>{hotelId}</strong> in{" "}
              {formatMonthYear(year, month)}.
            </p>
            <p className="text-xs text-muted-foreground">
              Seed inventory using the per-room-type set-total-rooms endpoint.
            </p>
          </div>
        ) : (
          <table className="min-w-full text-xs">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="sticky left-0 bg-muted/80 px-3 py-2 text-left font-medium min-w-[140px]">
                  Room Type
                </th>
                {monthDates.map((d) => (
                  <th
                    key={d}
                    className="px-1 py-2 text-center font-medium min-w-[40px]"
                    title={d}
                  >
                    {d.slice(8)} {/* DD */}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {roomTypes.map((rt) => (
                <tr key={rt} className="border-b last:border-b-0 hover:bg-muted/20">
                  <td className="sticky left-0 bg-background px-3 py-2 font-mono text-[11px] font-medium truncate max-w-[140px]">
                    {rt}
                  </td>
                  {monthDates.map((d) => {
                    const row = dayLookup[rt]?.[d];
                    if (!row) {
                      return (
                        <td key={d} className="px-1 py-1 text-center">
                          <button
                            className="w-9 h-8 rounded text-[10px] bg-muted text-muted-foreground hover:ring-2 hover:ring-primary/40 transition-all"
                            onClick={() => setEditCell({ roomTypeId: rt, date: d })}
                            title={`${rt} / ${d} — no data seeded`}
                          >
                            —
                          </button>
                        </td>
                      );
                    }
                    return (
                      <td key={d} className="px-1 py-1 text-center">
                        <button
                          className={`w-9 h-8 rounded text-[10px] font-semibold hover:ring-2 hover:ring-primary/40 transition-all ${availColor(row.available, row.total_rooms)}`}
                          onClick={() => setEditCell({ roomTypeId: rt, date: d })}
                          title={`${rt} / ${d}\nAvail: ${row.available} / ${row.total_rooms}\nBooked: ${row.booked} | Held: ${row.held}\nOverbook: ${row.overbooking_allowance}`}
                        >
                          {row.available}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Stats summary */}
      {!calQuery.isPending && !calQuery.isError && roomTypes.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {(() => {
            const allDays = Object.values(calQuery.data?.room_types ?? {}).flat();
            const totalDays = allDays.length;
            const soldOut = allDays.filter((d) => d.available <= 0).length;
            const lowAvail = allDays.filter(
              (d) => d.available > 0 && d.total_rooms > 0 && d.available / d.total_rooms <= 0.25,
            ).length;
            const totalRooms = allDays.reduce((s, d) => s + d.total_rooms, 0);
            const totalBooked = allDays.reduce((s, d) => s + d.booked, 0);
            return (
              <>
                <Card>
                  <CardHeader className="pb-1 pt-3 px-4">
                    <CardDescription className="text-xs">Room-night slots</CardDescription>
                  </CardHeader>
                  <CardContent className="px-4 pb-3">
                    <p className="text-2xl font-bold">{totalDays}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-1 pt-3 px-4">
                    <CardDescription className="text-xs">Sold out nights</CardDescription>
                  </CardHeader>
                  <CardContent className="px-4 pb-3">
                    <p className="text-2xl font-bold text-red-600">{soldOut}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-1 pt-3 px-4">
                    <CardDescription className="text-xs">Low avail. nights (&le;25%)</CardDescription>
                  </CardHeader>
                  <CardContent className="px-4 pb-3">
                    <p className="text-2xl font-bold text-orange-600">{lowAvail}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-1 pt-3 px-4">
                    <CardDescription className="text-xs">Total booked room-nights</CardDescription>
                  </CardHeader>
                  <CardContent className="px-4 pb-3">
                    <p className="text-2xl font-bold">{totalBooked}</p>
                    <p className="text-xs text-muted-foreground">of {totalRooms} room-nights</p>
                  </CardContent>
                </Card>
              </>
            );
          })()}
        </div>
      )}

      {/* Edit dialog */}
      {editCell && (
        <EditDialog
          open={!!editCell}
          onClose={() => setEditCell(null)}
          hotelId={hotelId}
          roomTypeId={editCell.roomTypeId}
          date={editCell.date}
          current={editDay}
          onSaved={() => {
            void calQuery.refetch();
            setEditCell(null);
          }}
        />
      )}
    </div>
  );
}
