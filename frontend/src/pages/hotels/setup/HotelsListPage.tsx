/**
 * Hotel Setup — Hotels List page (HTL-001)
 *
 * Route: hotels/setup
 * Lists all hotels for the authenticated user with create form inline.
 * Feature-gated: shows "not enabled" state when backend returns 404.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Hotel, Plus, MapPin, Phone } from "lucide-react";

import { ApiError } from "@/api/client";
import {
  listHotels,
  createHotel,
  type HotelIn,
  type HotelAddress,
} from "@/api/endpoints/hotelSetup";
import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

function starLabel(n: number) {
  return "★".repeat(n) + "☆".repeat(5 - n);
}

const emptyAddress = (): HotelAddress => ({
  line1: "",
  city: "",
  region: "",
  postal_code: "",
  country: "",
});

export default function HotelsListPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [statusFilter, setStatusFilter] = useState<"" | "active" | "archived">("");

  // ── form state ───────────────────────────────────────────────────
  const [form, setForm] = useState<HotelIn>({
    name: "",
    description: "",
    star_rating: 3,
    address: emptyAddress(),
    check_in_time: "15:00",
    check_out_time: "11:00",
    policies: { cancellation_text: "", pet_policy: "", smoking: false, children: true },
    contact: { phone: "", email: "", website: "" },
    photo_urls: [],
  });

  // ── queries ───────────────────────────────────────────────────────
  const hotelsQuery = useQuery({
    queryKey: ["hotels", "list", statusFilter],
    queryFn: () => listHotels({ status: statusFilter || undefined }),
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  const createMut = useMutation({
    mutationFn: () => createHotel(form),
    onSuccess: (hotel) => {
      toast.success(`Hotel "${hotel.name}" created`);
      qc.invalidateQueries({ queryKey: ["hotels", "list"] });
      setShowCreate(false);
      setForm({ ...form, name: "", description: "" });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create hotel"),
  });

  // ── feature-disabled guard ────────────────────────────────────────
  if (
    hotelsQuery.error instanceof ApiError &&
    (hotelsQuery.error.status === 404 || hotelsQuery.error.status === 503)
  ) {
    return (
      <div className="p-6">
        <EmptyState
          icon={<Hotel className="h-8 w-8" />}
          title="Hotel PMS not enabled"
          description="The Hotel PMS feature is currently disabled. Contact your administrator to enable HOTEL_PMS_ENABLED."
        />
      </div>
    );
  }

  const hotels = hotelsQuery.data?.items ?? [];

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Hotels"
        description="Manage your hotel properties"
        actions={
          <div className="flex items-center gap-2">
            <Select
              value={statusFilter}
              onValueChange={(v) => setStatusFilter(v as "" | "active" | "archived")}
            >
              <SelectTrigger className="w-36">
                <SelectValue placeholder="All statuses" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All statuses</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="archived">Archived</SelectItem>
              </SelectContent>
            </Select>
            <Button onClick={() => setShowCreate(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Add Hotel
            </Button>
          </div>
        }
      />

      {hotelsQuery.isLoading && (
        <div className="text-sm text-muted-foreground">Loading hotels…</div>
      )}

      {!hotelsQuery.isLoading && hotels.length === 0 && (
        <EmptyState
          icon={<Hotel className="h-8 w-8" />}
          title="No hotels yet"
          description="Create your first hotel property to get started."
          action={{ label: "Add Hotel", onClick: () => setShowCreate(true) }}
        />
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {hotels.map((h) => (
          <Card key={h.hotel_id} className="hover:shadow-md transition-shadow">
            <CardHeader className="pb-2">
              <div className="flex items-start justify-between gap-2">
                <CardTitle className="text-base leading-tight">
                  <Link
                    to={`/hotels/setup/${h.hotel_id}`}
                    className="hover:underline text-foreground"
                  >
                    {h.name}
                  </Link>
                </CardTitle>
                <Badge variant={h.status === "active" ? "default" : "secondary"}>
                  {h.status}
                </Badge>
              </div>
              <div className="text-xs text-amber-500">{starLabel(h.star_rating)}</div>
            </CardHeader>
            <CardContent className="space-y-1 text-sm text-muted-foreground">
              {h.description && (
                <p className="line-clamp-2 text-foreground/80">{h.description}</p>
              )}
              <div className="flex items-center gap-1">
                <MapPin className="h-3 w-3" />
                <span>{h.address.city}, {h.address.country}</span>
              </div>
              {h.contact.phone && (
                <div className="flex items-center gap-1">
                  <Phone className="h-3 w-3" />
                  <span>{h.contact.phone}</span>
                </div>
              )}
              <div className="pt-1 text-xs">
                Check-in {h.check_in_time} · Check-out {h.check_out_time}
              </div>
              <div className="flex gap-2 pt-2">
                <Button size="sm" variant="outline" asChild>
                  <Link to={`/hotels/setup/${h.hotel_id}`}>View</Link>
                </Button>
                <Button size="sm" variant="outline" asChild>
                  <Link to={`/hotels/${h.hotel_id}/room-types`}>Room Types</Link>
                </Button>
                <Button size="sm" variant="outline" asChild>
                  <Link to={`/hotels/${h.hotel_id}/housekeeping`}>HK Board</Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Create Hotel Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create Hotel</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <Label>Hotel Name *</Label>
              <Input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Grand Palace Hotel"
              />
            </div>
            <div className="space-y-1">
              <Label>Description</Label>
              <Textarea
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                rows={3}
              />
            </div>
            <div className="space-y-1">
              <Label>Star Rating</Label>
              <Select
                value={String(form.star_rating)}
                onValueChange={(v) => setForm({ ...form, star_rating: Number(v) })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {[1, 2, 3, 4, 5].map((n) => (
                    <SelectItem key={n} value={String(n)}>
                      {n} Star{n > 1 ? "s" : ""}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="rounded border p-3 space-y-3">
              <p className="text-sm font-medium">Address</p>
              <div className="space-y-1">
                <Label>Street Line 1 *</Label>
                <Input
                  value={form.address.line1}
                  onChange={(e) =>
                    setForm({ ...form, address: { ...form.address, line1: e.target.value } })
                  }
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <Label>City *</Label>
                  <Input
                    value={form.address.city}
                    onChange={(e) =>
                      setForm({ ...form, address: { ...form.address, city: e.target.value } })
                    }
                  />
                </div>
                <div className="space-y-1">
                  <Label>Region/State *</Label>
                  <Input
                    value={form.address.region}
                    onChange={(e) =>
                      setForm({ ...form, address: { ...form.address, region: e.target.value } })
                    }
                  />
                </div>
                <div className="space-y-1">
                  <Label>Postal Code *</Label>
                  <Input
                    value={form.address.postal_code}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        address: { ...form.address, postal_code: e.target.value },
                      })
                    }
                  />
                </div>
                <div className="space-y-1">
                  <Label>Country *</Label>
                  <Input
                    value={form.address.country}
                    onChange={(e) =>
                      setForm({ ...form, address: { ...form.address, country: e.target.value } })
                    }
                    placeholder="US"
                  />
                </div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>Check-in Time</Label>
                <Input
                  value={form.check_in_time}
                  onChange={(e) => setForm({ ...form, check_in_time: e.target.value })}
                  placeholder="15:00"
                />
              </div>
              <div className="space-y-1">
                <Label>Check-out Time</Label>
                <Input
                  value={form.check_out_time}
                  onChange={(e) => setForm({ ...form, check_out_time: e.target.value })}
                  placeholder="11:00"
                />
              </div>
            </div>
            <div className="rounded border p-3 space-y-3">
              <p className="text-sm font-medium">Contact</p>
              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <Label>Phone</Label>
                  <Input
                    value={form.contact?.phone ?? ""}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        contact: { ...form.contact, phone: e.target.value },
                      })
                    }
                  />
                </div>
                <div className="space-y-1">
                  <Label>Email</Label>
                  <Input
                    value={form.contact?.email ?? ""}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        contact: { ...form.contact, email: e.target.value },
                      })
                    }
                  />
                </div>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button
              disabled={!form.name.trim() || !form.address.city || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              {createMut.isPending ? "Creating…" : "Create Hotel"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
