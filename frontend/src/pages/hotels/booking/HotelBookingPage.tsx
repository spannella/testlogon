/**
 * Hotel Booking Page — Stay search + reservation creation (HTL-017, HTL-018).
 *
 * Route: hotels/book
 * Flow: pick hotel (or city) + dates + guests -> available room types + prices
 *       -> select room type -> confirm reservation.
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF).
 * When disabled (backend 404) shows a clear "not enabled" empty state.
 */

import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  BedDouble,
  Search,
  CalendarRange,
  Users,
  ChevronRight,
  AlertCircle,
  Loader2,
  MapPin,
  Building2,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  searchStays,
  listHotelsForBooking,
  createReservation,
  type StayRoomTypeResult,
  type StaySearchResult,
  type HotelOut,
} from "@/api/endpoints/hotelBooking";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { Badge } from "@/components/ui/badge";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function centsToCurrency(cents: number, currency = "usd"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function todayStr(): string {
  return new Date().toISOString().split("T")[0]!;
}

function tomorrowStr(): string {
  const d = new Date();
  d.setDate(d.getDate() + 1);
  return d.toISOString().split("T")[0]!;
}

function nightsLabel(n: number): string {
  return `${n} night${n === 1 ? "" : "s"}`;
}

// ─── Search form state ────────────────────────────────────────────────────────

interface SearchForm {
  hotelId: string;
  city: string;
  checkin: string;
  checkout: string;
  adults: number;
  children: number;
  rooms: number;
}

const defaultForm = (): SearchForm => ({
  hotelId: "",
  city: "",
  checkin: todayStr(),
  checkout: tomorrowStr(),
  adults: 1,
  children: 0,
  rooms: 1,
});

// ─── Main component ───────────────────────────────────────────────────────────

export default function HotelBookingPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [form, setForm] = useState<SearchForm>(defaultForm);
  const [searchTarget, setSearchTarget] = useState<"hotel" | "city">("hotel");
  const [searchResult, setSearchResult] = useState<StaySearchResult | null>(null);
  const [selectedRoom, setSelectedRoom] = useState<StayRoomTypeResult | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [guestPartyId, setGuestPartyId] = useState("");
  const [depositCents, setDepositCents] = useState(0);

  // Load hotels for the picker
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
    (hotelsQuery.error.status === 404 || hotelsQuery.error.status === 503);

  const hotels: HotelOut[] = hotelsQuery.data?.items ?? [];

  // Stay search mutation
  const searchMut = useMutation({
    mutationFn: () =>
      searchStays({
        hotel_id: searchTarget === "hotel" && form.hotelId ? form.hotelId : undefined,
        city: searchTarget === "city" && form.city ? form.city : undefined,
        checkin: form.checkin,
        checkout: form.checkout,
        adults: form.adults,
        children: form.children,
        rooms: form.rooms,
      }),
    onSuccess: (data) => {
      setSearchResult(data);
      if (data.result_count === 0) {
        toast.info("No available room types found for these dates.");
      }
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        toast.error((err as ApiError).detail || "Search failed");
      }
    },
  });

  // Create reservation mutation
  const createMut = useMutation({
    mutationFn: () => {
      if (!selectedRoom) throw new Error("No room selected");
      return createReservation(selectedRoom.hotel_id, {
        hotel_id: selectedRoom.hotel_id,
        guest_party_id: guestPartyId.trim() || "walk-in",
        room_type_id: selectedRoom.room_type_id,
        checkin: searchResult!.checkin,
        checkout: searchResult!.checkout,
        adults: searchResult!.adults,
        children: searchResult!.children,
        rooms: searchResult!.rooms,
        deposit_cents: depositCents,
      });
    },
    onSuccess: (data) => {
      toast.success("Reservation created successfully!");
      setConfirmOpen(false);
      qc.invalidateQueries({ queryKey: ["hotel-reservations"] });
      navigate(`/hotels/reservations/${data.hotel_id}/${data.reservation_id}`);
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        if ((err as ApiError).status === 409) {
          toast.error("No rooms available for this selection. Please try different dates.");
        } else {
          toast.error((err as ApiError).detail || "Failed to create reservation");
        }
      }
    },
  });

  const handleSearch = useCallback(() => {
    if (searchTarget === "hotel" && !form.hotelId) {
      toast.error("Please select a hotel");
      return;
    }
    if (searchTarget === "city" && !form.city.trim()) {
      toast.error("Please enter a city");
      return;
    }
    if (!form.checkin || !form.checkout) {
      toast.error("Please set check-in and check-out dates");
      return;
    }
    setSearchResult(null);
    searchMut.mutate();
  }, [form, searchTarget, searchMut]);

  const handleSelectRoom = (room: StayRoomTypeResult) => {
    setSelectedRoom(room);
    setGuestPartyId("");
    setDepositCents(0);
    setConfirmOpen(true);
  };

  // ── Feature disabled state ─────────────────────────────────────────────────
  if (featureDisabled) {
    return (
      <div className="p-6 space-y-4">
        <PageHeader
          title="Hotel Booking"
          description="Search available stays and create reservations."
        />
        <EmptyState
          icon={<AlertCircle className="h-10 w-10 text-muted-foreground" />}
          title="Hotel Booking Not Enabled"
          description="The Hotel PMS feature is not enabled on this platform. Contact your administrator to enable HOTEL_PMS_ENABLED."
        />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="Hotel Booking"
        description="Search available rooms and create guest reservations."
      />

      {/* ── Search Form ──────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5" />
            Find Available Rooms
          </CardTitle>
          <CardDescription>
            Search by hotel or city, pick your dates and guest count.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Hotel vs City toggle */}
          <div className="flex gap-2">
            <Button
              variant={searchTarget === "hotel" ? "default" : "outline"}
              size="sm"
              onClick={() => setSearchTarget("hotel")}
            >
              <Building2 className="h-4 w-4 mr-1" /> By Hotel
            </Button>
            <Button
              variant={searchTarget === "city" ? "default" : "outline"}
              size="sm"
              onClick={() => setSearchTarget("city")}
            >
              <MapPin className="h-4 w-4 mr-1" /> By City
            </Button>
          </div>

          {searchTarget === "hotel" ? (
            <div className="grid gap-1.5">
              <Label>Hotel</Label>
              {hotelsQuery.isLoading ? (
                <div className="flex items-center gap-2 text-muted-foreground text-sm">
                  <Loader2 className="h-4 w-4 animate-spin" /> Loading hotels…
                </div>
              ) : (
                <Select
                  value={form.hotelId}
                  onValueChange={(v) => setForm((f) => ({ ...f, hotelId: v }))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select a hotel…" />
                  </SelectTrigger>
                  <SelectContent>
                    {hotels.map((h) => (
                      <SelectItem key={h.hotel_id} value={h.hotel_id}>
                        {h.name} — {h.address.city}, {h.address.country}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
          ) : (
            <div className="grid gap-1.5">
              <Label>City</Label>
              <Input
                placeholder="e.g. Paris"
                value={form.city}
                onChange={(e) => setForm((f) => ({ ...f, city: e.target.value }))}
              />
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-1.5">
              <Label htmlFor="checkin">
                <CalendarRange className="h-4 w-4 inline mr-1" />
                Check-in
              </Label>
              <Input
                id="checkin"
                type="date"
                value={form.checkin}
                min={todayStr()}
                onChange={(e) => setForm((f) => ({ ...f, checkin: e.target.value }))}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="checkout">
                <CalendarRange className="h-4 w-4 inline mr-1" />
                Check-out
              </Label>
              <Input
                id="checkout"
                type="date"
                value={form.checkout}
                min={form.checkin || todayStr()}
                onChange={(e) => setForm((f) => ({ ...f, checkout: e.target.value }))}
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div className="grid gap-1.5">
              <Label htmlFor="adults">
                <Users className="h-4 w-4 inline mr-1" />
                Adults
              </Label>
              <Input
                id="adults"
                type="number"
                min={1}
                value={form.adults}
                onChange={(e) =>
                  setForm((f) => ({ ...f, adults: Math.max(1, Number(e.target.value)) }))
                }
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="children">Children</Label>
              <Input
                id="children"
                type="number"
                min={0}
                value={form.children}
                onChange={(e) =>
                  setForm((f) => ({ ...f, children: Math.max(0, Number(e.target.value)) }))
                }
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="rooms">Rooms</Label>
              <Input
                id="rooms"
                type="number"
                min={1}
                value={form.rooms}
                onChange={(e) =>
                  setForm((f) => ({ ...f, rooms: Math.max(1, Number(e.target.value)) }))
                }
              />
            </div>
          </div>

          <Button
            onClick={handleSearch}
            disabled={searchMut.isPending}
            className="w-full sm:w-auto"
          >
            {searchMut.isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" /> Searching…
              </>
            ) : (
              <>
                <Search className="h-4 w-4 mr-2" /> Search Availability
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* ── Search Results ───────────────────────────────────────── */}
      {searchResult && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">
              Available Rooms — {searchResult.checkin} to {searchResult.checkout} ({nightsLabel(searchResult.nights)})
            </h2>
            <Badge variant="secondary">
              {searchResult.result_count} room type{searchResult.result_count !== 1 ? "s" : ""}
            </Badge>
          </div>

          {searchResult.results.length === 0 ? (
            <EmptyState
              icon={<BedDouble className="h-8 w-8 text-muted-foreground" />}
              title="No Available Rooms"
              description="No room types are available for the selected dates and guest count. Try different dates or fewer rooms."
            />
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {searchResult.results.map((room) => (
                <RoomTypeCard
                  key={`${room.hotel_id}-${room.room_type_id}`}
                  room={room}
                  nights={searchResult.nights}
                  onSelect={handleSelectRoom}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Confirm Reservation Dialog ──────────────────────────── */}
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Confirm Reservation</DialogTitle>
          </DialogHeader>
          {selectedRoom && searchResult && (
            <div className="space-y-4 py-2">
              <div className="rounded-lg border p-3 space-y-1 text-sm">
                <div className="font-medium">{selectedRoom.name}</div>
                <div className="text-muted-foreground">
                  {searchResult.checkin} to {searchResult.checkout} ({nightsLabel(searchResult.nights)})
                </div>
                <div className="text-muted-foreground">
                  {searchResult.adults} adult{searchResult.adults !== 1 ? "s" : ""}
                  {searchResult.children > 0
                    ? `, ${searchResult.children} child${searchResult.children !== 1 ? "ren" : ""}`
                    : ""}
                  {" · "}
                  {searchResult.rooms} room{searchResult.rooms !== 1 ? "s" : ""}
                </div>
                <div className="font-semibold text-base">
                  {centsToCurrency(selectedRoom.total_cents, selectedRoom.currency)} total
                </div>
              </div>

              <div className="grid gap-1.5">
                <Label htmlFor="guest-id">Guest / Party ID</Label>
                <Input
                  id="guest-id"
                  placeholder="e.g. user_sub or walk-in"
                  value={guestPartyId}
                  onChange={(e) => setGuestPartyId(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Enter a user sub, CRM party ID, or leave blank for walk-in.
                </p>
              </div>

              <div className="grid gap-1.5">
                <Label htmlFor="deposit">Deposit Amount</Label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-sm">
                    {selectedRoom.currency.toUpperCase()}
                  </span>
                  <Input
                    id="deposit"
                    type="number"
                    min={0}
                    max={selectedRoom.total_cents / 100}
                    step={0.01}
                    className="pl-12"
                    value={(depositCents / 100).toFixed(2)}
                    onChange={(e) =>
                      setDepositCents(Math.round(Number(e.target.value) * 100))
                    }
                  />
                </div>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => createMut.mutate()} disabled={createMut.isPending}>
              {createMut.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" /> Booking…
                </>
              ) : (
                "Confirm Booking"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Room type result card ────────────────────────────────────────────────────

function RoomTypeCard({
  room,
  nights,
  onSelect,
}: {
  room: StayRoomTypeResult;
  nights: number;
  onSelect: (r: StayRoomTypeResult) => void;
}) {
  const perNightAvg = nights > 0 ? Math.round(room.total_cents / nights) : room.total_cents;
  return (
    <Card className="flex flex-col">
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <BedDouble className="h-4 w-4 shrink-0 text-muted-foreground" />
          {room.name}
        </CardTitle>
        <CardDescription className="text-xs">
          {room.min_remaining} room{room.min_remaining !== 1 ? "s" : ""} left · {room.rooms} requested
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col flex-1 gap-3">
        <div>
          <div className="text-2xl font-bold">
            {centsToCurrency(room.total_cents, room.currency)}
          </div>
          <div className="text-xs text-muted-foreground">
            {centsToCurrency(perNightAvg, room.currency)}/night avg · {nightsLabel(nights)}
          </div>
        </div>

        {room.per_night && room.per_night.length > 0 && (
          <div className="rounded border divide-y text-xs max-h-28 overflow-y-auto">
            {room.per_night.slice(0, 7).map((nl, i) => (
              <div key={i} className="flex justify-between px-2 py-1">
                <span className="text-muted-foreground">{nl.date}</span>
                <span className="font-medium">
                  {centsToCurrency(nl.amount_cents, room.currency)}
                </span>
              </div>
            ))}
            {room.per_night.length > 7 && (
              <div className="px-2 py-1 text-muted-foreground">
                +{room.per_night.length - 7} more nights…
              </div>
            )}
          </div>
        )}

        <Button className="mt-auto w-full" onClick={() => onSelect(room)}>
          Book This Room <ChevronRight className="h-4 w-4 ml-1" />
        </Button>
      </CardContent>
    </Card>
  );
}
