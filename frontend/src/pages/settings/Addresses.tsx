import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Plus, Pencil, Trash2, Star } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { EmptyState } from "@/components/shared/EmptyState";
import {
  getAddresses,
  createAddress,
  updateAddress,
  deleteAddress,
  setPrimaryAddress,
} from "@/api/endpoints/profile";
import type { Address, AddressIn } from "@/api/types";

// ─── Schema ──────────────────────────────────────────────────────

const addressSchema = z.object({
  name: z.string().optional(),
  label: z.string().optional(),
  line1: z.string().min(1, "Address line 1 is required"),
  line2: z.string().optional(),
  city: z.string().optional(),
  state: z.string().optional(),
  postal_code: z.string().optional(),
  country: z.string().optional(),
  notes: z.string().optional(),
});

type AddressFormValues = z.infer<typeof addressSchema>;

// ─── Component ───────────────────────────────────────────────────

export function Addresses() {
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<Address | null>(null);
  const [deleting, setDeleting] = React.useState<Address | null>(null);

  const addressesQuery = useQuery({
    queryKey: ["addresses"],
    queryFn: getAddresses,
  });

  const form = useForm<AddressFormValues>({
    resolver: zodResolver(addressSchema),
    defaultValues: {
      name: "",
      label: "",
      line1: "",
      line2: "",
      city: "",
      state: "",
      postal_code: "",
      country: "",
      notes: "",
    },
  });

  const openAdd = () => {
    setEditing(null);
    form.reset({
      name: "",
      label: "",
      line1: "",
      line2: "",
      city: "",
      state: "",
      postal_code: "",
      country: "",
      notes: "",
    });
    setDialogOpen(true);
  };

  const openEdit = (addr: Address) => {
    setEditing(addr);
    form.reset({
      name: addr.name ?? "",
      label: addr.label ?? "",
      line1: addr.line1 ?? "",
      line2: addr.line2 ?? "",
      city: addr.city ?? "",
      state: addr.state ?? "",
      postal_code: addr.postal_code ?? "",
      country: addr.country ?? "",
      notes: addr.notes ?? "",
    });
    setDialogOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: (values: AddressFormValues) => {
      const body: AddressIn = { ...values };
      if (editing) {
        return updateAddress(editing.address_id, body);
      }
      return createAddress(body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["addresses"] });
      setDialogOpen(false);
      toast.success(editing ? "Address updated" : "Address added");
    },
    onError: () => {
      toast.error("Failed to save address");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (addressId: string) => deleteAddress(addressId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["addresses"] });
      setDeleting(null);
      toast.success("Address deleted");
    },
    onError: () => {
      toast.error("Failed to delete address");
    },
  });

  const setPrimaryMutation = useMutation({
    mutationFn: (addressId: string) => setPrimaryAddress(addressId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["addresses"] });
      toast.success("Primary address updated");
    },
    onError: () => {
      toast.error("Failed to set primary address");
    },
  });

  const addresses: Address[] = Array.isArray(addressesQuery.data)
    ? addressesQuery.data
    : [];

  if (addressesQuery.isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-24 w-full rounded-xl" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {addresses.length} address{addresses.length !== 1 ? "es" : ""} saved
        </p>
        <Button variant="outline" size="sm" onClick={openAdd}>
          <Plus className="mr-1 h-3.5 w-3.5" />
          Add Address
        </Button>
      </div>

      {addresses.length === 0 ? (
        <EmptyState
          icon={<Star className="h-6 w-6" />}
          title="No addresses"
          description="Add your first address to get started"
          className="py-12"
        />
      ) : (
        <div className="space-y-3">
          {addresses.map((addr) => (
            <Card key={addr.address_id}>
              <CardContent className="flex items-start gap-4 p-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    {addr.name && (
                      <span className="text-sm font-semibold">{addr.name}</span>
                    )}
                    {addr.label && (
                      <Badge variant="outline" className="text-[10px]">
                        {addr.label}
                      </Badge>
                    )}
                    {addr.is_primary_mailing && (
                      <Badge variant="secondary" className="text-[10px]">
                        Primary
                      </Badge>
                    )}
                  </div>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {[addr.line1, addr.line2].filter(Boolean).join(", ")}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {[addr.city, addr.state, addr.postal_code, addr.country]
                      .filter(Boolean)
                      .join(", ")}
                  </p>
                  {addr.notes && (
                    <p className="mt-1 text-xs text-muted-foreground italic">{addr.notes}</p>
                  )}
                </div>
                <div className="flex shrink-0 gap-1">
                  {!addr.is_primary_mailing && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      title="Set as primary"
                      onClick={() => setPrimaryMutation.mutate(addr.address_id)}
                      disabled={setPrimaryMutation.isPending}
                    >
                      <Star className="h-3.5 w-3.5" />
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={() => openEdit(addr)}
                  >
                    <Pencil className="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-destructive"
                    onClick={() => setDeleting(addr)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Add / Edit dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editing ? "Edit Address" : "Add Address"}</DialogTitle>
          </DialogHeader>
          <form
            onSubmit={form.handleSubmit((values) => saveMutation.mutate(values))}
            className="space-y-4 py-2"
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="addr-name">Name</Label>
                <Input id="addr-name" placeholder="e.g. Home" {...form.register("name")} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="addr-label">Label</Label>
                <Input id="addr-label" placeholder="e.g. shipping" {...form.register("label")} />
              </div>
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="addr-line1">Address Line 1 *</Label>
                <Input id="addr-line1" {...form.register("line1")} />
                {form.formState.errors.line1 && (
                  <p className="text-xs text-destructive">{form.formState.errors.line1.message}</p>
                )}
              </div>
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="addr-line2">Address Line 2</Label>
                <Input id="addr-line2" {...form.register("line2")} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="addr-city">City</Label>
                <Input id="addr-city" {...form.register("city")} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="addr-state">State / Province</Label>
                <Input id="addr-state" {...form.register("state")} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="addr-postal">Postal Code</Label>
                <Input id="addr-postal" {...form.register("postal_code")} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="addr-country">Country</Label>
                <Input id="addr-country" {...form.register("country")} />
              </div>
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="addr-notes">Notes</Label>
                <Input id="addr-notes" {...form.register("notes")} />
              </div>
            </div>
            <DialogFooter>
              <Button type="submit" disabled={saveMutation.isPending}>
                {saveMutation.isPending ? "Saving..." : editing ? "Update" : "Add"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(open) => { if (!open) setDeleting(null); }}
        title="Delete Address"
        description={`Are you sure you want to delete "${deleting?.name ?? deleting?.line1 ?? "this address"}"?`}
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => {
          if (deleting) deleteMutation.mutate(deleting.address_id);
        }}
        loading={deleteMutation.isPending}
      />
    </div>
  );
}
