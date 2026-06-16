/**
 * Hotel Front-Desk Dashboard (HTL-022..024).
 *
 * Route: hotels/front-desk
 * Shows today's arrivals, departures, in-house guests, and a live occupancy
 * snapshot for a selected hotel.
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF) -> backend returns 404.
 * The page renders a clear "not enabled" state when it receives a 404/503.
 *
 * Admin-only write actions (check-in, check-out, walk-in) are conditionally
 * rendered based on the user's role.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  LogIn,
  LogOut,
  BedDouble,
  RefreshCw,
  AlertCircle,
  Users,
  CalendarRange,
  Building2,
  TrendingUp,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  getFrontDeskArrivals,
  getFrontDeskDepartures,
  getFrontDeskInHouse,
  getFrontDeskOccupancy,
  type FrontDeskRow,
  type OccupancySnapshotOut,
} from "@/api/endpoints/hotelFrontDesk";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function centsToCurrency(cents: number, currency = "usd"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }).format(cents / 100);
}

function pct(rate: number): string {
  return `${Math.round(rate * 100)}%`;
}

function todayIso(): string {
  return new Date().toISOString().slice(0, 10);
}

// ─── Status badge ─────────────────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  confirmed: "bg-blue-100 text-blue-800",
  checked_in: "bg-green-100 text-green-800",
  checked_out: "bg-gray-100 text-gray-700",
  cancelled: "bg-red-100 text-red-800",
  no_show: "bg-yellow-100 text-yellow-800",
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_COLORS[status] ?? "bg-gray-100 text-gray-700";
  const label = status.replace("_", " ");
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {label}
    </span>
  );
}

// ─── Occupancy card ───────────────────────────────────────────────────────────

function OccupancyCard({
  snap,
  isLoading,
  isError,
}: {
  snap: OccupancySnapshotOut | undefined;
  isLoading: boolean;
  isError: boolean;
}) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <Skeleton key={i} className="h-24 rounded-lg" />
        ))}
      </div>
    );
  }
  if (isError || !snap) {
    return (
      <div className="text-sm text-muted-foreground">
        Occupancy data unavailable.
      </div>
    );
  }

  const stats = [
    {
      label: "Occupancy Rate",
      value: pct(snap.occupancy_rate),
      sub: `${snap.rooms_occupied} / ${snap.rooms_total} rooms`,
      icon: <TrendingUp className="h-5 w-5 text-muted-foreground" />,
    },
    {
      label: "Available",
      value: String(snap.rooms_available),
      sub: "rooms free tonight",
      icon: <BedDouble className="h-5 w-5 text-muted-foreground" />,
    },
    {
      label: "Arrivals Today",
      value: String(snap.arrivals_count),
      sub: `${snap.date}`,
      icon: <LogIn className="h-5 w-5 text-muted-foreground" />,
    },
    {
      label: "Departures Today",
      value: String(snap.departures_count),
      sub: `${snap.in_house_count} in-house`,
      icon: <LogOut className="h-5 w-5 text-muted-foreground" />,
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
      {stats.map((s) => (
        <Card key={s.label}>
          <CardContent className="pt-4 pb-4">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs text-muted-foreground">{s.label}</p>
                <p className="text-2xl font-bold mt-1">{s.value}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{s.sub}</p>
              </div>
              {s.icon}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Reservation list item ────────────────────────────────────────────────────

function ReservationRow({
  row,
  hotelId,
  showActions,
  actionLabel,
  actionPath,
}: {
  row: FrontDeskRow;
  hotelId: string;
  showActions: boolean;
  actionLabel: string;
  actionPath: string;
}) {
  return (
    <div className="flex items-center justify-between py-3 border-b last:border-0">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium text-sm">{row.guest_name}</span>
          <StatusBadge status={row.status} />
          {row.assigned_room_ids.length > 0 && (
            <span className="text-xs text-muted-foreground">
              Room: {row.assigned_room_ids.join(", ")}
            </span>
          )}
        </div>
        <div className="text-xs text-muted-foreground mt-0.5 flex gap-3 flex-wrap">
          <span>
            <CalendarRange className="inline h-3 w-3 mr-0.5" />
            {row.checkin} – {row.checkout} ({row.nights}n)
          </span>
          <span>
            <Users className="inline h-3 w-3 mr-0.5" />
            {row.occupancy_adults}A
            {row.occupancy_children > 0 && ` + ${row.occupancy_children}C`}
          </span>
          <span>{centsToCurrency(row.total_cents)}</span>
        </div>
      </div>
      {showActions && (
        <Link
          to={actionPath}
          state={{ row, hotelId }}
          className="ml-3 shrink-0"
        >
          <Button size="sm" variant="outline">
            {actionLabel}
          </Button>
        </Link>
      )}
    </div>
  );
}

// ─── Feature-disabled notice ──────────────────────────────────────────────────

function NotEnabled() {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
      <AlertCircle className="h-10 w-10 text-muted-foreground" />
      <h2 className="text-lg font-semibold">Hotel PMS Not Enabled</h2>
      <p className="text-sm text-muted-foreground max-w-md">
        The Hotel Property Management System is disabled on this platform.
        Contact your administrator to enable{" "}
        <code className="font-mono text-xs">HOTEL_PMS_ENABLED</code>.
      </p>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

/** Hardcoded placeholder hotel list. In a real deployment the hotel picker
 *  would load from /ui/hotels; we keep this simple since the front-desk agent
 *  only owns the front-desk cluster. */
const DEMO_HOTELS = [{ hotel_id: "hotel_demo", name: "Demo Hotel" }];

export default function FrontDeskDashboard() {
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const [hotelId, setHotelId] = useState<string>(DEMO_HOTELS[0]?.hotel_id ?? "hotel_demo");
  const [tab, setTab] = useState<"arrivals" | "departures" | "inhouse">(
    "arrivals",
  );
  const today = todayIso();

  const qc = useQueryClient();

  const occupancyQ = useQuery({
    queryKey: ["hotel-frontdesk", "occupancy", hotelId, today],
    queryFn: () => getFrontDeskOccupancy(hotelId, { date: today }),
    retry: false,
  });

  const arrivalsQ = useQuery({
    queryKey: ["hotel-frontdesk", "arrivals", hotelId, today],
    queryFn: () => getFrontDeskArrivals(hotelId, { date: today, limit: 50 }),
    retry: false,
    enabled: tab === "arrivals",
  });

  const departuresQ = useQuery({
    queryKey: ["hotel-frontdesk", "departures", hotelId, today],
    queryFn: () => getFrontDeskDepartures(hotelId, { date: today, limit: 50 }),
    retry: false,
    enabled: tab === "departures",
  });

  const inHouseQ = useQuery({
    queryKey: ["hotel-frontdesk", "in-house", hotelId],
    queryFn: () => getFrontDeskInHouse(hotelId, { limit: 50 }),
    retry: false,
    enabled: tab === "inhouse",
  });

  // Detect 404 = feature disabled
  const isDisabled =
    (occupancyQ.error instanceof ApiError && occupancyQ.error.status === 404) ||
    (arrivalsQ.error instanceof ApiError && arrivalsQ.error.status === 404);

  if (isDisabled) {
    return (
      <div className="container mx-auto max-w-5xl py-8 px-4">
        <PageHeader
          title="Front Desk"
          description="Check-in, check-out and in-house management"
        />
        <NotEnabled />
      </div>
    );
  }

  function refresh() {
    void qc.invalidateQueries({ queryKey: ["hotel-frontdesk"] });
  }

  const activeQ =
    tab === "arrivals" ? arrivalsQ : tab === "departures" ? departuresQ : inHouseQ;
  const rows: FrontDeskRow[] = activeQ.data?.rows ?? [];

  return (
    <div className="container mx-auto max-w-5xl py-8 px-4 space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <PageHeader
          title="Front Desk"
          description="Live arrivals, departures and in-house management"
        />
        <div className="flex items-center gap-2">
          <Select value={hotelId} onValueChange={setHotelId}>
            <SelectTrigger className="w-48">
              <SelectValue placeholder="Select hotel" />
            </SelectTrigger>
            <SelectContent>
              {DEMO_HOTELS.map((h) => (
                <SelectItem key={h.hotel_id} value={h.hotel_id}>
                  {h.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="icon" onClick={refresh}>
            <RefreshCw className="h-4 w-4" />
          </Button>
          {isAdmin && (
            <Link to="/hotels/front-desk/walk-in" state={{ hotelId }}>
              <Button size="sm">
                <BedDouble className="h-4 w-4 mr-1.5" />
                Walk-in
              </Button>
            </Link>
          )}
        </div>
      </div>

      {/* Occupancy snapshot */}
      <section>
        <h2 className="text-sm font-semibold text-muted-foreground mb-3 uppercase tracking-wide">
          Today&rsquo;s Occupancy — {today}
        </h2>
        <OccupancyCard
          snap={occupancyQ.data}
          isLoading={occupancyQ.isLoading}
          isError={occupancyQ.isError}
        />
      </section>

      <Separator />

      {/* Arrival / Departure / In-house tabs */}
      <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)}>
        <TabsList>
          <TabsTrigger value="arrivals">
            <LogIn className="h-4 w-4 mr-1.5" />
            Arrivals
            {arrivalsQ.data?.count != null && (
              <Badge variant="secondary" className="ml-1.5">
                {arrivalsQ.data.count}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="departures">
            <LogOut className="h-4 w-4 mr-1.5" />
            Departures
            {departuresQ.data?.count != null && (
              <Badge variant="secondary" className="ml-1.5">
                {departuresQ.data.count}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="inhouse">
            <Users className="h-4 w-4 mr-1.5" />
            In-house
            {inHouseQ.data?.count != null && (
              <Badge variant="secondary" className="ml-1.5">
                {inHouseQ.data.count}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        {(["arrivals", "departures", "inhouse"] as const).map((t) => (
          <TabsContent key={t} value={t}>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base">
                  {t === "arrivals"
                    ? "Expected Arrivals"
                    : t === "departures"
                    ? "Expected Departures"
                    : "In-House Guests"}
                </CardTitle>
                <CardDescription>
                  {t === "arrivals"
                    ? "Confirmed reservations checking in today"
                    : t === "departures"
                    ? "Checked-in guests departing today"
                    : "All currently checked-in reservations"}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {activeQ.isLoading && (
                  <div className="space-y-3">
                    {[...Array(5)].map((_, i) => (
                      <Skeleton key={i} className="h-14 rounded-lg" />
                    ))}
                  </div>
                )}
                {activeQ.isError && (
                  <div className="flex items-center gap-2 text-sm text-destructive py-4">
                    <AlertCircle className="h-4 w-4" />
                    Failed to load data — {String(activeQ.error)}
                  </div>
                )}
                {!activeQ.isLoading && !activeQ.isError && rows.length === 0 && (
                  <EmptyState
                    icon={<Building2 className="h-8 w-8" />}
                    title="No reservations"
                    description={
                      t === "arrivals"
                        ? "No arrivals expected today."
                        : t === "departures"
                        ? "No departures expected today."
                        : "No guests are currently checked in."
                    }
                  />
                )}
                {!activeQ.isLoading &&
                  rows.map((row) => (
                    <ReservationRow
                      key={row.reservation_id}
                      row={row}
                      hotelId={hotelId}
                      showActions={isAdmin}
                      actionLabel={
                        t === "arrivals"
                          ? "Check In"
                          : t === "departures"
                          ? "Check Out"
                          : "Manage"
                      }
                      actionPath={
                        t === "arrivals"
                          ? `/hotels/front-desk/check-in/${row.reservation_id}`
                          : t === "departures"
                          ? `/hotels/front-desk/check-out/${row.reservation_id}`
                          : `/hotels/front-desk/manage/${row.reservation_id}`
                      }
                    />
                  ))}
              </CardContent>
            </Card>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
