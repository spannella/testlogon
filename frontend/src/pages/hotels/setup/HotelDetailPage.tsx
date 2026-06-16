/**
 * Hotel Setup — Hotel Detail / Edit page (HTL-001)
 *
 * Route: hotels/setup/:hotelId
 * Shows hotel details, allows editing, manages attached amenities,
 * and links to room-types / housekeeping sub-pages.
 */

import { useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Hotel,
  BedDouble,
  Wrench,
  Star,
  MapPin,
  Phone,
  Globe,
  Mail,
  Plus,
  X,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  getHotel,
  updateHotel,
  archiveHotel,
  listAmenities,
  listHotelAmenities,
  attachAmenity,
  detachAmenity,
  getCancellationPolicy,
  upsertCancellationPolicy,
  type HotelUpdateIn,
  type AmenityOut,
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

function centsToDisplay(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function HotelDetailPage() {
  const { hotelId } = useParams<{ hotelId: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [editing, setEditing] = useState(false);
  const [editForm, setEditForm] = useState<HotelUpdateIn>({});
  const [showAmenityDialog, setShowAmenityDialog] = useState(false);
  const [selectedAmenityId, setSelectedAmenityId] = useState("");
  const [showArchiveConfirm, setShowArchiveConfirm] = useState(false);

  // cancellation policy form state
  const [editPolicy, setEditPolicy] = useState(false);
  const [policyForm, setPolicyForm] = useState({
    free_until_days_before: 0,
    penalty_pct: 0,
    penalty_fixed_cents: 0,
    no_show_fee_cents: 0,
  });

  const hotelQuery = useQuery({
    queryKey: ["hotels", "detail", hotelId],
    queryFn: () => getHotel(hotelId!),
    enabled: !!hotelId,
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  const amenitiesQuery = useQuery({
    queryKey: ["hotels", hotelId, "amenities"],
    queryFn: () => listHotelAmenities(hotelId!),
    enabled: !!hotelId,
    retry: false,
  });

  const allAmenitiesQuery = useQuery({
    queryKey: ["hotels", "amenities-dict"],
    queryFn: () => listAmenities(),
    enabled: showAmenityDialog,
    retry: false,
  });

  const cancellationQuery = useQuery({
    queryKey: ["hotels", hotelId, "cancellation-policy"],
    queryFn: () => getCancellationPolicy(hotelId!),
    enabled: !!hotelId,
    retry: (count, err) => {
      if (err instanceof ApiError && err.status === 404) return false;
      return count < 2;
    },
  });

  const updateMut = useMutation({
    mutationFn: () => updateHotel(hotelId!, editForm),
    onSuccess: () => {
      toast.success("Hotel updated");
      qc.invalidateQueries({ queryKey: ["hotels", "detail", hotelId] });
      qc.invalidateQueries({ queryKey: ["hotels", "list"] });
      setEditing(false);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Update failed"),
  });

  const archiveMut = useMutation({
    mutationFn: () => archiveHotel(hotelId!),
    onSuccess: () => {
      toast.success("Hotel archived");
      navigate("/hotels/setup");
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Archive failed"),
  });

  const attachMut = useMutation({
    mutationFn: () => attachAmenity("hotel", hotelId!, selectedAmenityId),
    onSuccess: () => {
      toast.success("Amenity attached");
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "amenities"] });
      setShowAmenityDialog(false);
      setSelectedAmenityId("");
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Attach failed"),
  });

  const detachMut = useMutation({
    mutationFn: (amenityId: string) => detachAmenity("hotel", hotelId!, amenityId),
    onSuccess: () => {
      toast.success("Amenity removed");
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "amenities"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Detach failed"),
  });

  const policyMut = useMutation({
    mutationFn: () => upsertCancellationPolicy(hotelId!, policyForm),
    onSuccess: () => {
      toast.success("Cancellation policy saved");
      qc.invalidateQueries({ queryKey: ["hotels", hotelId, "cancellation-policy"] });
      setEditPolicy(false);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Save failed"),
  });

  if (
    hotelQuery.error instanceof ApiError &&
    (hotelQuery.error.status === 404 || hotelQuery.error.status === 503)
  ) {
    return (
      <div className="p-6">
        <EmptyState
          icon={<Hotel className="h-8 w-8" />}
          title="Hotel not found or PMS not enabled"
          description="This hotel may have been archived or the Hotel PMS feature is disabled."
          action={{ label: "Back to Hotels", onClick: () => navigate("/hotels/setup") }}
        />
      </div>
    );
  }

  const hotel = hotelQuery.data;
  if (!hotel) {
    return <div className="p-6 text-sm text-muted-foreground">Loading…</div>;
  }

  const hotelAmenities = amenitiesQuery.data ?? [];
  const attachedIds = new Set(hotelAmenities.map((a) => a.amenity_id));
  const availableAmenities = (allAmenitiesQuery.data ?? []).filter(
    (a: AmenityOut) => !attachedIds.has(a.amenity_id),
  );

  function startEditing() {
    setEditForm({
      name: hotel!.name,
      description: hotel!.description,
      star_rating: hotel!.star_rating,
      address: { ...hotel!.address },
      check_in_time: hotel!.check_in_time,
      check_out_time: hotel!.check_out_time,
      policies: { ...hotel!.policies },
      contact: { ...hotel!.contact },
    });
    setEditing(true);
  }

  function startEditPolicy() {
    const p = cancellationQuery.data;
    setPolicyForm({
      free_until_days_before: p?.free_until_days_before ?? 0,
      penalty_pct: p?.penalty_pct ?? 0,
      penalty_fixed_cents: p?.penalty_fixed_cents ?? 0,
      no_show_fee_cents: p?.no_show_fee_cents ?? 0,
    });
    setEditPolicy(true);
  }

  const canc = cancellationQuery.data;

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title={hotel.name}
        description={`Hotel ID: ${hotel.hotel_id}`}
        actions={
          <div className="flex items-center gap-2">
            <Badge variant={hotel.status === "active" ? "default" : "secondary"}>
              {hotel.status}
            </Badge>
            <Button variant="outline" size="sm" asChild>
              <Link to="/hotels/setup">← Hotels</Link>
            </Button>
            <Button size="sm" onClick={startEditing}>
              Edit Hotel
            </Button>
            {hotel.status === "active" && (
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setShowArchiveConfirm(true)}
              >
                Archive
              </Button>
            )}
          </div>
        }
      />

      {/* Navigation cards */}
      <div className="grid gap-4 sm:grid-cols-3">
        <Link to={`/hotels/${hotel.hotel_id}/room-types`}>
          <Card className="hover:shadow-md transition-shadow cursor-pointer">
            <CardContent className="flex items-center gap-3 p-4">
              <BedDouble className="h-6 w-6 text-blue-500" />
              <div>
                <p className="font-medium">Room Types</p>
                <p className="text-xs text-muted-foreground">Manage room categories</p>
              </div>
            </CardContent>
          </Card>
        </Link>
        <Link to={`/hotels/${hotel.hotel_id}/rooms`}>
          <Card className="hover:shadow-md transition-shadow cursor-pointer">
            <CardContent className="flex items-center gap-3 p-4">
              <Hotel className="h-6 w-6 text-green-500" />
              <div>
                <p className="font-medium">Rooms</p>
                <p className="text-xs text-muted-foreground">Individual room inventory</p>
              </div>
            </CardContent>
          </Card>
        </Link>
        <Link to={`/hotels/${hotel.hotel_id}/housekeeping`}>
          <Card className="hover:shadow-md transition-shadow cursor-pointer">
            <CardContent className="flex items-center gap-3 p-4">
              <Wrench className="h-6 w-6 text-orange-500" />
              <div>
                <p className="font-medium">Housekeeping</p>
                <p className="text-xs text-muted-foreground">Status board & tasks</p>
              </div>
            </CardContent>
          </Card>
        </Link>
      </div>

      {/* Hotel Info */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Hotel Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex items-center gap-2">
              <Star className="h-4 w-4 text-amber-500" />
              <span>{hotel.star_rating}-Star Hotel</span>
            </div>
            {hotel.description && <p className="text-muted-foreground">{hotel.description}</p>}
            <div className="flex items-start gap-2">
              <MapPin className="h-4 w-4 mt-0.5 text-muted-foreground" />
              <div>
                <p>{hotel.address.line1}</p>
                {hotel.address.line2 && <p>{hotel.address.line2}</p>}
                <p>{hotel.address.city}, {hotel.address.region} {hotel.address.postal_code}</p>
                <p>{hotel.address.country}</p>
              </div>
            </div>
            {hotel.contact.phone && (
              <div className="flex items-center gap-2">
                <Phone className="h-4 w-4 text-muted-foreground" />
                <span>{hotel.contact.phone}</span>
              </div>
            )}
            {hotel.contact.email && (
              <div className="flex items-center gap-2">
                <Mail className="h-4 w-4 text-muted-foreground" />
                <span>{hotel.contact.email}</span>
              </div>
            )}
            {hotel.contact.website && (
              <div className="flex items-center gap-2">
                <Globe className="h-4 w-4 text-muted-foreground" />
                <a
                  href={hotel.contact.website}
                  className="text-primary underline"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {hotel.contact.website}
                </a>
              </div>
            )}
            <div className="rounded bg-muted p-2 text-xs space-y-1">
              <p>Check-in: {hotel.check_in_time}</p>
              <p>Check-out: {hotel.check_out_time}</p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Policies</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {hotel.policies.cancellation_text && (
              <div>
                <p className="font-medium text-xs text-muted-foreground uppercase">Cancellation</p>
                <p>{hotel.policies.cancellation_text}</p>
              </div>
            )}
            <div className="flex gap-4">
              <div>
                <p className="font-medium text-xs text-muted-foreground uppercase">Pets</p>
                <p>{hotel.policies.pet_policy || "Not specified"}</p>
              </div>
              <div>
                <p className="font-medium text-xs text-muted-foreground uppercase">Smoking</p>
                <p>{hotel.policies.smoking ? "Allowed" : "Not allowed"}</p>
              </div>
              <div>
                <p className="font-medium text-xs text-muted-foreground uppercase">Children</p>
                <p>{hotel.policies.children ? "Welcome" : "Not allowed"}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Amenities */}
        <Card>
          <CardHeader className="flex-row items-center justify-between pb-2">
            <CardTitle className="text-base">Amenities</CardTitle>
            <Button size="sm" variant="outline" onClick={() => setShowAmenityDialog(true)}>
              <Plus className="h-3 w-3 mr-1" />
              Add
            </Button>
          </CardHeader>
          <CardContent>
            {amenitiesQuery.isLoading && (
              <p className="text-sm text-muted-foreground">Loading…</p>
            )}
            {hotelAmenities.length === 0 && !amenitiesQuery.isLoading && (
              <p className="text-sm text-muted-foreground">No amenities attached yet.</p>
            )}
            <div className="flex flex-wrap gap-2">
              {hotelAmenities.map((a) => (
                <Badge key={a.amenity_id} variant="secondary" className="flex items-center gap-1">
                  {a.icon && <span>{a.icon}</span>}
                  {a.name}
                  <button
                    onClick={() => detachMut.mutate(a.amenity_id)}
                    className="ml-1 hover:text-destructive"
                    title="Remove amenity"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Cancellation Policy */}
        <Card>
          <CardHeader className="flex-row items-center justify-between pb-2">
            <CardTitle className="text-base">Cancellation Policy</CardTitle>
            <Button size="sm" variant="outline" onClick={startEditPolicy}>
              {canc ? "Edit" : "Set"}
            </Button>
          </CardHeader>
          <CardContent className="text-sm">
            {cancellationQuery.isLoading && (
              <p className="text-muted-foreground">Loading…</p>
            )}
            {!cancellationQuery.isLoading && !canc && (
              <p className="text-muted-foreground">No cancellation policy set.</p>
            )}
            {canc && (
              <div className="space-y-1">
                <p>Free cancellation until <strong>{canc.free_until_days_before}</strong> day(s) before</p>
                <p>Penalty: <strong>{canc.penalty_pct}%</strong> or <strong>{centsToDisplay(canc.penalty_fixed_cents)}</strong> fixed</p>
                <p>No-show fee: <strong>{centsToDisplay(canc.no_show_fee_cents)}</strong></p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Edit Hotel Dialog */}
      <Dialog open={editing} onOpenChange={setEditing}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Hotel</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <Label>Name</Label>
              <Input
                value={editForm.name ?? ""}
                onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label>Description</Label>
              <Textarea
                value={editForm.description ?? ""}
                onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                rows={3}
              />
            </div>
            <div className="space-y-1">
              <Label>Star Rating</Label>
              <Select
                value={String(editForm.star_rating ?? 3)}
                onValueChange={(v) => setEditForm({ ...editForm, star_rating: Number(v) })}
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
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>Check-in Time</Label>
                <Input
                  value={editForm.check_in_time ?? ""}
                  onChange={(e) => setEditForm({ ...editForm, check_in_time: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label>Check-out Time</Label>
                <Input
                  value={editForm.check_out_time ?? ""}
                  onChange={(e) => setEditForm({ ...editForm, check_out_time: e.target.value })}
                />
              </div>
            </div>
            <div className="rounded border p-3 space-y-2">
              <p className="text-sm font-medium">Contact</p>
              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <Label>Phone</Label>
                  <Input
                    value={editForm.contact?.phone ?? ""}
                    onChange={(e) =>
                      setEditForm({
                        ...editForm,
                        contact: { ...editForm.contact, phone: e.target.value },
                      })
                    }
                  />
                </div>
                <div className="space-y-1">
                  <Label>Email</Label>
                  <Input
                    value={editForm.contact?.email ?? ""}
                    onChange={(e) =>
                      setEditForm({
                        ...editForm,
                        contact: { ...editForm.contact, email: e.target.value },
                      })
                    }
                  />
                </div>
                <div className="space-y-1 col-span-2">
                  <Label>Website</Label>
                  <Input
                    value={editForm.contact?.website ?? ""}
                    onChange={(e) =>
                      setEditForm({
                        ...editForm,
                        contact: { ...editForm.contact, website: e.target.value },
                      })
                    }
                  />
                </div>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditing(false)}>
              Cancel
            </Button>
            <Button disabled={updateMut.isPending} onClick={() => updateMut.mutate()}>
              {updateMut.isPending ? "Saving…" : "Save Changes"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Amenity Dialog */}
      <Dialog open={showAmenityDialog} onOpenChange={setShowAmenityDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Amenity</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            {allAmenitiesQuery.isLoading && (
              <p className="text-sm text-muted-foreground">Loading amenities…</p>
            )}
            {availableAmenities.length === 0 && !allAmenitiesQuery.isLoading && (
              <p className="text-sm text-muted-foreground">All amenities already attached.</p>
            )}
            <Select value={selectedAmenityId} onValueChange={setSelectedAmenityId}>
              <SelectTrigger>
                <SelectValue placeholder="Select amenity…" />
              </SelectTrigger>
              <SelectContent>
                {availableAmenities.map((a: AmenityOut) => (
                  <SelectItem key={a.amenity_id} value={a.amenity_id}>
                    {a.icon ? `${a.icon} ` : ""}{a.name} ({a.category})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAmenityDialog(false)}>
              Cancel
            </Button>
            <Button
              disabled={!selectedAmenityId || attachMut.isPending}
              onClick={() => attachMut.mutate()}
            >
              {attachMut.isPending ? "Attaching…" : "Attach"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Cancellation Policy Dialog */}
      <Dialog open={editPolicy} onOpenChange={setEditPolicy}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Cancellation Policy</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <Label>Free cancellation until N days before arrival</Label>
              <Input
                type="number"
                min={0}
                value={policyForm.free_until_days_before}
                onChange={(e) =>
                  setPolicyForm({ ...policyForm, free_until_days_before: Number(e.target.value) })
                }
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label>Penalty % (0–100)</Label>
                <Input
                  type="number"
                  min={0}
                  max={100}
                  value={policyForm.penalty_pct}
                  onChange={(e) =>
                    setPolicyForm({ ...policyForm, penalty_pct: Number(e.target.value) })
                  }
                />
              </div>
              <div className="space-y-1">
                <Label>Penalty Fixed ($)</Label>
                <Input
                  type="number"
                  min={0}
                  step={0.01}
                  value={(policyForm.penalty_fixed_cents / 100).toFixed(2)}
                  onChange={(e) =>
                    setPolicyForm({
                      ...policyForm,
                      penalty_fixed_cents: Math.round(Number(e.target.value) * 100),
                    })
                  }
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label>No-show Fee ($)</Label>
              <Input
                type="number"
                min={0}
                step={0.01}
                value={(policyForm.no_show_fee_cents / 100).toFixed(2)}
                onChange={(e) =>
                  setPolicyForm({
                    ...policyForm,
                    no_show_fee_cents: Math.round(Number(e.target.value) * 100),
                  })
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditPolicy(false)}>
              Cancel
            </Button>
            <Button disabled={policyMut.isPending} onClick={() => policyMut.mutate()}>
              {policyMut.isPending ? "Saving…" : "Save Policy"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Archive Confirm */}
      <Dialog open={showArchiveConfirm} onOpenChange={setShowArchiveConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Archive Hotel?</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            This will soft-archive the hotel. It can be unarchived later. Room data is preserved.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowArchiveConfirm(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={archiveMut.isPending}
              onClick={() => archiveMut.mutate()}
            >
              {archiveMut.isPending ? "Archiving…" : "Archive"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
