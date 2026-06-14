/**
 * TenantsPage — Property Tenant Directory (TEN-004)
 * Route: /property/tenants
 *
 * Feature flag: PROPERTY_TENANTS_ENABLED (backend default false → 404)
 * When the flag is off the backend returns 404 "Property tenants are not enabled".
 * This page detects that case and shows a clean "feature not enabled" banner.
 */

import { useState, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { PlusCircle, Users } from "lucide-react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { ApiError } from "@/api/client";
import {
  listPropertyTenants,
  createPropertyTenant,
  type PropertyTenantOut,
} from "@/api/endpoints/propertyTenants";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isFeatureDisabled(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404 && /not enabled/i.test(error.detail ?? "");
}

function fmtDate(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

function statusColor(status: string): "default" | "secondary" | "destructive" | "outline" {
  if (status === "active") return "default";
  if (status === "past") return "secondary";
  return "outline"; // prospect
}

// ─── New-Tenant form schema ───────────────────────────────────────────────────

const newTenantSchema = z.object({
  display_name: z.string().min(1, "Name is required"),
  email: z
    .string()
    .email("Invalid email")
    .optional()
    .or(z.literal("")),
  phone: z.string().optional().or(z.literal("")),
});

type NewTenantForm = z.infer<typeof newTenantSchema>;

// ─── Debounce hook ────────────────────────────────────────────────────────────

function useDebounce(value: string, delay = 300): string {
  const [debounced, setDebounced] = useState(value);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const update = useCallback(
    (v: string) => {
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => setDebounced(v), delay);
    },
    [delay],
  );

  // keep in sync
  update(value);

  return debounced;
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function TenantsPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [searchRaw, setSearchRaw] = useState("");
  const [filterStatus, setFilterStatus] = useState<"" | "prospect" | "active" | "past">("");
  const [showNew, setShowNew] = useState(false);

  const debouncedQ = useDebounce(searchRaw);

  const {
    data,
    isLoading,
    isError,
    error,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery({
    queryKey: ["propertyTenants", "list", { status: filterStatus, q: debouncedQ }],
    queryFn: ({ pageParam }: { pageParam: string | undefined }) =>
      listPropertyTenants({
        status: filterStatus || undefined,
        q: debouncedQ || undefined,
        cursor: pageParam,
        limit: 50,
      }),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    initialPageParam: undefined as string | undefined,
    retry: false,
  });

  const tenants: PropertyTenantOut[] = data?.pages.flatMap((p) => p.tenants) ?? [];

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<NewTenantForm>({ resolver: zodResolver(newTenantSchema) });

  const createMut = useMutation({
    mutationFn: (vals: NewTenantForm) =>
      createPropertyTenant({
        display_name: vals.display_name,
        email: vals.email || null,
        phone: vals.phone || null,
      }),
    onSuccess: () => {
      toast.success("Tenant created");
      setShowNew(false);
      reset();
      void queryClient.invalidateQueries({ queryKey: ["propertyTenants", "list"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create tenant"),
  });

  const onSubmit = handleSubmit((vals) => createMut.mutate(vals));

  // ─── Feature-disabled state ─────────────────────────────────────────────────

  if (isError && isFeatureDisabled(error)) {
    return (
      <div className="max-w-6xl mx-auto p-4 sm:p-6">
        <PageHeader title="Tenants" description="Manage your property tenants" />
        <Card className="mt-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-muted-foreground">
              <Users className="h-5 w-5" />
              Feature Not Enabled
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Property tenant management is not available on this server.
              Set <code className="font-mono">PROPERTY_TENANTS_ENABLED=1</code> in the backend
              environment and restart to enable this feature.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="max-w-6xl mx-auto p-4 sm:p-6 space-y-6">
      <PageHeader
        title="Tenants"
        description="Manage your property tenants"
        actions={
          <Button onClick={() => setShowNew(true)}>
            <PlusCircle className="h-4 w-4 mr-2" />
            New Tenant
          </Button>
        }
      />

      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <Input
          placeholder="Search by name or email…"
          value={searchRaw}
          onChange={(e) => setSearchRaw(e.target.value)}
          className="sm:max-w-xs"
        />
        <Select
          value={filterStatus}
          onValueChange={(v) => setFilterStatus(v as typeof filterStatus)}
        >
          <SelectTrigger className="sm:w-40">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="">All</SelectItem>
            <SelectItem value="prospect">Prospect</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="past">Past</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Email</TableHead>
              <TableHead>Phone</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Active Unit</TableHead>
              <TableHead>Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <TableRow key={i}>
                  {Array.from({ length: 6 }).map((__, j) => (
                    <TableCell key={j}>
                      <Skeleton className="h-4 w-full" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : tenants.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                  {isError
                    ? "Failed to load tenants."
                    : "No tenants yet. Create your first tenant to get started."}
                </TableCell>
              </TableRow>
            ) : (
              tenants.map((t) => (
                <TableRow
                  key={t.tenant_id}
                  className="cursor-pointer hover:bg-muted/50"
                  onClick={() => navigate(`/property/tenants/${t.tenant_id}`)}
                >
                  <TableCell className="font-medium">{t.display_name}</TableCell>
                  <TableCell className="text-muted-foreground">{t.email ?? "—"}</TableCell>
                  <TableCell className="text-muted-foreground">{t.phone ?? "—"}</TableCell>
                  <TableCell>
                    <Badge variant={statusColor(t.status)}>
                      {t.status.charAt(0).toUpperCase() + t.status.slice(1)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {t.active_unit_id ?? "—"}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{fmtDate(t.created_at)}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>

      {/* Load more */}
      {hasNextPage && (
        <div className="flex justify-center">
          <Button
            variant="outline"
            onClick={() => void fetchNextPage()}
            disabled={isFetchingNextPage}
          >
            {isFetchingNextPage ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}

      {/* New-Tenant dialog */}
      <Dialog open={showNew} onOpenChange={setShowNew}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>New Tenant</DialogTitle>
          </DialogHeader>
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="display_name">Full name *</Label>
              <Input id="display_name" {...register("display_name")} />
              {errors.display_name && (
                <p className="text-xs text-destructive">{errors.display_name.message}</p>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" {...register("email")} />
              {errors.email && (
                <p className="text-xs text-destructive">{errors.email.message}</p>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="phone">Phone</Label>
              <Input id="phone" type="tel" {...register("phone")} />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowNew(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSubmitting || createMut.isPending}>
                {createMut.isPending ? "Creating…" : "Create tenant"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
