/**
 * Hotel Setup — Amenities dictionary management (HTL-002)
 *
 * Route: hotels/setup/amenities
 * Global amenity dictionary — create and browse amenities to attach to hotels.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Star as StarIcon } from "lucide-react";

import { ApiError } from "@/api/client";
import {
  listAmenities,
  createAmenity,
  type AmenityOut,
  type AmenityIn,
  type AmenityCategory,
} from "@/api/endpoints/hotelSetup";
import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
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

const CATEGORIES: AmenityCategory[] = [
  "connectivity",
  "wellness",
  "parking",
  "dining",
  "family",
  "accessibility",
  "general",
];

const CATEGORY_COLOR: Record<string, string> = {
  connectivity: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  wellness: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
  parking: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
  dining: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
  family: "bg-pink-100 text-pink-800 dark:bg-pink-900 dark:text-pink-200",
  accessibility: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  general: "bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-200",
};

export default function AmenitiesPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState<"all" | AmenityCategory>("all");
  const [form, setForm] = useState<AmenityIn>({
    name: "",
    category: "general",
    icon: "",
  });

  const amenitiesQuery = useQuery({
    queryKey: ["hotels", "amenities-dict", categoryFilter],
    queryFn: () => listAmenities(categoryFilter === "all" ? undefined : categoryFilter),
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  const createMut = useMutation({
    mutationFn: () =>
      createAmenity({
        name: form.name,
        category: form.category,
        icon: form.icon || undefined,
      }),
    onSuccess: (a) => {
      toast.success(`Amenity "${a.name}" created`);
      qc.invalidateQueries({ queryKey: ["hotels", "amenities-dict"] });
      setShowCreate(false);
      setForm({ name: "", category: "general", icon: "" });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Create failed"),
  });

  if (
    amenitiesQuery.error instanceof ApiError &&
    (amenitiesQuery.error.status === 404 || amenitiesQuery.error.status === 503)
  ) {
    return (
      <div className="p-6">
        <EmptyState
          icon={<StarIcon className="h-8 w-8" />}
          title="Hotel PMS not enabled"
          description="HOTEL_PMS_ENABLED is off — contact your administrator."
        />
      </div>
    );
  }

  const amenities = (amenitiesQuery.data ?? []) as AmenityOut[];

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Amenities Dictionary"
        description="Global list of amenities that can be attached to hotels and room types"
        actions={
          <div className="flex items-center gap-2">
            <Select
              value={categoryFilter}
              onValueChange={(v) => setCategoryFilter(v as "all" | AmenityCategory)}
            >
              <SelectTrigger className="w-40">
                <SelectValue placeholder="All categories" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All categories</SelectItem>
                {CATEGORIES.map((c) => (
                  <SelectItem key={c} value={c} className="capitalize">
                    {c}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button onClick={() => setShowCreate(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Add Amenity
            </Button>
          </div>
        }
      />

      {amenitiesQuery.isLoading && (
        <p className="text-sm text-muted-foreground">Loading…</p>
      )}

      {!amenitiesQuery.isLoading && amenities.length === 0 && (
        <EmptyState
          icon={<StarIcon className="h-8 w-8" />}
          title="No amenities yet"
          description="Add amenities to the global dictionary, then attach them to hotels."
          action={{ label: "Add Amenity", onClick: () => setShowCreate(true) }}
        />
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {amenities.map((a) => (
          <Card key={a.amenity_id} className="hover:shadow-sm transition-shadow">
            <CardContent className="p-4 flex items-center gap-3">
              {a.icon && <span className="text-2xl">{a.icon}</span>}
              <div className="flex-1 min-w-0">
                <p className="font-medium text-sm truncate">{a.name}</p>
                <span
                  className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${CATEGORY_COLOR[a.category] ?? CATEGORY_COLOR.general}`}
                >
                  {a.category}
                </span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Create Amenity Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Amenity</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <Label>Name *</Label>
              <Input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="WiFi, Pool, Gym…"
              />
            </div>
            <div className="space-y-1">
              <Label>Category *</Label>
              <Select
                value={form.category}
                onValueChange={(v) => setForm({ ...form, category: v as AmenityCategory })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CATEGORIES.map((c) => (
                    <SelectItem key={c} value={c} className="capitalize">
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Icon (emoji, optional)</Label>
              <Input
                value={form.icon ?? ""}
                onChange={(e) => setForm({ ...form, icon: e.target.value })}
                placeholder="🏊 💪 📶"
                maxLength={4}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button
              disabled={!form.name.trim() || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              {createMut.isPending ? "Creating…" : "Create Amenity"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
