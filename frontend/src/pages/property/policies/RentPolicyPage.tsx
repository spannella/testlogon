/**
 * PMD-001 — Rent Policy page.
 *
 * Route: /property/policies
 *
 * Shows the current rent policy for the authenticated user (landlord).
 * Admins/root see an inline edit form and the full audit log.
 *
 * Flag-gated: PROPERTY_DASHBOARD_ENABLED (default OFF).
 * When the flag is off every backend call returns 404;
 * the page renders a "not enabled" message.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Settings, Loader2, AlertCircle, Clock } from "lucide-react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";

import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import { ApiError } from "@/api/client";
import {
  getRentPolicy,
  updateRentPolicy,
  getRentPolicyAudit,
} from "@/api/endpoints/propertyDashboard";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

// ─── Feature-not-enabled guard ────────────────────────────────────────────────

function FeatureDisabled() {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4 text-muted-foreground">
      <AlertCircle className="h-10 w-10" />
      <p className="text-lg font-medium">Property Dashboard is not enabled</p>
      <p className="text-sm">
        Enable <code>PROPERTY_DASHBOARD_ENABLED</code> to use this feature.
      </p>
    </div>
  );
}

// ─── Edit form schema ─────────────────────────────────────────────────────────

const policySchema = z.object({
  rent_due_day: z.coerce.number().int().min(1, "Min 1").max(28, "Max 28"),
  late_fee_cents: z.coerce.number().int().min(0, "Min 0"),
  grace_period_days: z.coerce.number().int().min(0, "Min 0"),
  currency: z
    .string()
    .length(3, "Must be 3 letters")
    .regex(/^[a-zA-Z]+$/, "Letters only"),
});

type PolicyFormValues = z.infer<typeof policySchema>;

// ─── Main component ───────────────────────────────────────────────────────────

export default function RentPolicyPage() {
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const canEdit = role === "admin" || role === "root";

  const [editing, setEditing] = useState(false);
  const [auditCursor, setAuditCursor] = useState<string | undefined>(undefined);

  const queryClient = useQueryClient();

  // ── Queries ───────────────────────────────────────────────────────────────

  const notEnabledOpts = {
    retry: (count: number, err: unknown) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  };

  const policyQuery = useQuery({
    queryKey: ["property", "rent-policy"],
    queryFn: getRentPolicy,
    ...notEnabledOpts,
  });

  const auditQuery = useQuery({
    queryKey: ["property", "rent-policy-audit", auditCursor],
    queryFn: () => getRentPolicyAudit({ limit: 20, cursor: auditCursor }),
    enabled: canEdit,
    ...notEnabledOpts,
  });

  // ── Form ──────────────────────────────────────────────────────────────────

  const policy = policyQuery.data;

  const form = useForm<PolicyFormValues>({
    resolver: zodResolver(policySchema),
    values: policy
      ? {
          rent_due_day: policy.rent_due_day,
          late_fee_cents: policy.late_fee_cents,
          grace_period_days: policy.grace_period_days,
          currency: policy.currency,
        }
      : {
          rent_due_day: 1,
          late_fee_cents: 0,
          grace_period_days: 0,
          currency: "usd",
        },
  });

  const saveMut = useMutation({
    mutationFn: (vals: PolicyFormValues) =>
      updateRentPolicy({
        rent_due_day: vals.rent_due_day,
        late_fee_cents: vals.late_fee_cents,
        grace_period_days: vals.grace_period_days,
        currency: vals.currency.toLowerCase(),
      }),
    onSuccess: () => {
      toast.success("Rent policy updated");
      void queryClient.invalidateQueries({ queryKey: ["property", "rent-policy"] });
      void queryClient.invalidateQueries({ queryKey: ["property", "rent-policy-audit"] });
      setEditing(false);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to save policy"),
  });

  // ── Flag-off check ────────────────────────────────────────────────────────

  const isDisabled =
    policyQuery.isError &&
    policyQuery.error instanceof ApiError &&
    (policyQuery.error.status === 404 || policyQuery.error.status === 503);

  if (isDisabled) return <FeatureDisabled />;

  return (
    <div className="p-6 space-y-6 max-w-3xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Rent Policy</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Per-landlord defaults inherited by leases at creation time
          </p>
        </div>
        {canEdit && !editing && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setEditing(true)}
            className="gap-2"
          >
            <Settings className="h-4 w-4" />
            Edit Policy
          </Button>
        )}
      </div>

      {/* Policy card */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <CardTitle>Current Policy</CardTitle>
            {policy?.is_default && (
              <Badge variant="secondary">Platform Default</Badge>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {policyQuery.isLoading && (
            <div className="space-y-3">
              {[1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-6 w-full" />)}
            </div>
          )}

          {policyQuery.isError && !isDisabled && (
            <p className="text-sm text-destructive">Failed to load policy</p>
          )}

          {policy && !editing && (
            <dl className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {[
                { label: "Rent Due Day", value: `Day ${policy.rent_due_day}` },
                { label: "Grace Period", value: `${policy.grace_period_days} days` },
                { label: "Late Fee", value: formatCents(policy.late_fee_cents) },
                { label: "Currency", value: policy.currency.toUpperCase() },
              ].map(({ label, value }) => (
                <div key={label} className="rounded-lg border p-3">
                  <dt className="text-xs text-muted-foreground mb-1">{label}</dt>
                  <dd className="text-base font-semibold">{value}</dd>
                </div>
              ))}
            </dl>
          )}

          {policy && editing && (
            <form
              onSubmit={form.handleSubmit((vals) => saveMut.mutate(vals))}
              className="space-y-4"
            >
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <Label htmlFor="rent_due_day">Rent Due Day (1–28)</Label>
                  <Input
                    id="rent_due_day"
                    type="number"
                    min={1}
                    max={28}
                    {...form.register("rent_due_day")}
                  />
                  {form.formState.errors.rent_due_day && (
                    <p className="text-xs text-destructive">
                      {form.formState.errors.rent_due_day.message}
                    </p>
                  )}
                </div>

                <div className="space-y-1">
                  <Label htmlFor="grace_period_days">Grace Period (days)</Label>
                  <Input
                    id="grace_period_days"
                    type="number"
                    min={0}
                    {...form.register("grace_period_days")}
                  />
                  {form.formState.errors.grace_period_days && (
                    <p className="text-xs text-destructive">
                      {form.formState.errors.grace_period_days.message}
                    </p>
                  )}
                </div>

                <div className="space-y-1">
                  <Label htmlFor="late_fee_cents">Late Fee (cents)</Label>
                  <Input
                    id="late_fee_cents"
                    type="number"
                    min={0}
                    {...form.register("late_fee_cents")}
                  />
                  {form.formState.errors.late_fee_cents && (
                    <p className="text-xs text-destructive">
                      {form.formState.errors.late_fee_cents.message}
                    </p>
                  )}
                </div>

                <div className="space-y-1">
                  <Label htmlFor="currency">Currency (ISO-4217)</Label>
                  <Input
                    id="currency"
                    maxLength={3}
                    placeholder="usd"
                    {...form.register("currency")}
                  />
                  {form.formState.errors.currency && (
                    <p className="text-xs text-destructive">
                      {form.formState.errors.currency.message}
                    </p>
                  )}
                </div>
              </div>

              <div className="flex gap-2 pt-2">
                <Button type="submit" disabled={saveMut.isPending} size="sm">
                  {saveMut.isPending && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
                  Save
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => { setEditing(false); form.reset(); }}
                >
                  Cancel
                </Button>
              </div>
            </form>
          )}

          {policy && !policy.is_default && (
            <p className="text-xs text-muted-foreground mt-4">
              Last updated {fmtTs(policy.updated_at)}
              {policy.updated_by ? ` by ${policy.updated_by}` : ""}
            </p>
          )}
        </CardContent>
      </Card>

      {/* Audit log (admin/root only) */}
      {canEdit && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-muted-foreground" />
              <CardTitle>Change History</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            {auditQuery.isLoading && (
              <div className="space-y-2">
                {[1, 2, 3].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
              </div>
            )}

            {auditQuery.isError && (
              <p className="text-sm text-muted-foreground py-4 text-center">
                Failed to load audit log
              </p>
            )}

            {!auditQuery.isLoading && !auditQuery.isError &&
              (auditQuery.data?.entries.length ?? 0) === 0 && (
              <p className="text-sm text-muted-foreground py-6 text-center">
                No changes recorded yet
              </p>
            )}

            {(auditQuery.data?.entries.length ?? 0) > 0 && (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Changed At</TableHead>
                      <TableHead>Actor</TableHead>
                      <TableHead>Due Day</TableHead>
                      <TableHead>Late Fee</TableHead>
                      <TableHead>Grace</TableHead>
                      <TableHead>Currency</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {auditQuery.data!.entries.map((entry, idx) => (
                      <TableRow key={idx}>
                        <TableCell className="text-sm">{fmtTs(entry.created_at)}</TableCell>
                        <TableCell className="text-sm font-mono text-xs">
                          {entry.actor_sub}
                        </TableCell>
                        <TableCell className="text-sm">
                          {(entry.after as Record<string, unknown>).rent_due_day as number ?? "—"}
                        </TableCell>
                        <TableCell className="text-sm">
                          {(entry.after as Record<string, unknown>).late_fee_cents != null
                            ? formatCents((entry.after as Record<string, unknown>).late_fee_cents as number)
                            : "—"}
                        </TableCell>
                        <TableCell className="text-sm">
                          {(entry.after as Record<string, unknown>).grace_period_days as number ?? "—"}d
                        </TableCell>
                        <TableCell className="text-sm uppercase">
                          {String((entry.after as Record<string, unknown>).currency ?? "—")}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>

                {/* Pagination */}
                <div className="flex justify-between items-center mt-4">
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={!auditCursor}
                    onClick={() => setAuditCursor(undefined)}
                  >
                    First page
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={!auditQuery.data?.cursor}
                    onClick={() => setAuditCursor(auditQuery.data?.cursor ?? undefined)}
                  >
                    Next page
                  </Button>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
