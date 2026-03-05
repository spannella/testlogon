import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Plus, Pencil, Trash2, Star, CheckCircle, XCircle, AlertCircle } from "lucide-react";
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
import { AddressMap } from "@/components/shared/AddressMap";

// ─── Error boundary (contains map crashes) ───────────────────────

class MapErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: boolean }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { error: false };
  }
  static getDerivedStateFromError() {
    return { error: true };
  }
  render() {
    if (this.state.error) {
      return (
        <div className="mt-2 flex h-48 items-center justify-center rounded-md border text-xs text-muted-foreground">
          Map preview unavailable
        </div>
      );
    }
    return this.props.children;
  }
}
import {
  getAddresses,
  createAddress,
  updateAddress,
  deleteAddress,
  setPrimaryAddress,
  validateAddress,
} from "@/api/endpoints/profile";
import type { Address, AddressIn, AddressValidateResp } from "@/api/types";

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
  const [validationResult, setValidationResult] = React.useState<AddressValidateResp | null>(null);
  const [validationError, setValidationError] = React.useState<string | null>(null);

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

  // Debounced address string for map preview
  const [debouncedAddress, setDebouncedAddress] = React.useState("");
  const watchedLine1 = form.watch("line1");
  const watchedCity = form.watch("city");
  const watchedState = form.watch("state");
  const watchedPostal = form.watch("postal_code");
  const watchedCountry = form.watch("country");
  React.useEffect(() => {
    const parts = [watchedLine1, watchedCity, watchedState, watchedPostal, watchedCountry].filter(Boolean);
    const full = parts.join(", ");
    const t = setTimeout(() => setDebouncedAddress(full), 600);
    return () => clearTimeout(t);
  }, [watchedLine1, watchedCity, watchedState, watchedPostal, watchedCountry]);

  const openAdd = () => {
    setEditing(null);
    setValidationResult(null);
    setValidationError(null);
    setDebouncedAddress("");
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
    setValidationResult(null);
    setValidationError(null);
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

  const validateMutation = useMutation({
    mutationFn: () =>
      validateAddress({
        line1: form.getValues("line1"),
        line2: form.getValues("line2"),
        city: form.getValues("city"),
        state: form.getValues("state"),
        postal_code: form.getValues("postal_code"),
        country: form.getValues("country"),
      }),
    onSuccess: (data) => setValidationResult(data),
    onError: () => setValidationError("Validation service unavailable"),
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
        <DialogContent className="max-h-[90vh] overflow-y-auto">
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
                <Input id="addr-country" placeholder="e.g. US" {...form.register("country")} />
              </div>
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="addr-notes">Notes</Label>
                <Input id="addr-notes" {...form.register("notes")} />
              </div>
            </div>

            {/* Map preview */}
            <MapErrorBoundary>
              <AddressMap address={debouncedAddress} />
            </MapErrorBoundary>

            {/* UPS Validation */}
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  setValidationError(null);
                  setValidationResult(null);
                  validateMutation.mutate();
                }}
                disabled={validateMutation.isPending || !form.getValues("line1")}
              >
                {validateMutation.isPending ? "Validating…" : "Validate Address (UPS)"}
              </Button>
              {validationResult && (
                validationResult.valid ? (
                  <span className="flex items-center gap-1 text-sm text-green-600">
                    <CheckCircle className="h-4 w-4" /> Valid address
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-sm text-destructive">
                    <XCircle className="h-4 w-4" /> Address not found
                  </span>
                )
              )}
              {validationError && (
                <span className="flex items-center gap-1 text-sm text-amber-600">
                  <AlertCircle className="h-4 w-4" />{validationError}
                </span>
              )}
            </div>

            {/* Suggestions */}
            {validationResult?.candidates && validationResult.candidates.length > 0 && (
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">Suggested correction — click to apply:</p>
                {validationResult.candidates.map((c, i) => (
                  <button
                    key={i}
                    type="button"
                    className="w-full rounded border px-3 py-2 text-left text-xs hover:bg-muted"
                    onClick={() => {
                      form.setValue("line1", c.line1);
                      form.setValue("line2", c.line2 ?? "");
                      form.setValue("city", c.city);
                      form.setValue("state", c.state);
                      form.setValue("postal_code", c.postal_code);
                      form.setValue("country", c.country);
                      setValidationResult(null);
                    }}
                  >
                    {[c.line1, c.line2, c.city, c.state, c.postal_code, c.country].filter(Boolean).join(", ")}
                  </button>
                ))}
              </div>
            )}

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
