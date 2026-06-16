/**
 * LeaseDetailPage — Full lease view with property/unit + tenant + term + rent info,
 * inline editing, and lifecycle status transitions (LSE-004).
 * Route: /property/leases/:leaseId
 */

import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, AlertTriangle, Edit2, Check, X } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { ApiError } from "@/api/client";
import {
  getLease,
  patchLease,
  transitionLeaseStatus,
  type LeaseOut,
  type LeaseStatus,
  type LateFeeType,
} from "@/api/endpoints/leases";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(ts: number | null): string {
  if (!ts) return "Open-ended";
  return new Date(ts * 1000).toLocaleDateString();
}

function fmtDatetime(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

function fmtCents(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function dollarsToCents(str: string): number {
  return Math.round(parseFloat(str) * 100);
}

const STATUS_COLORS: Record<LeaseStatus, string> = {
  draft: "bg-gray-100 text-gray-700",
  upcoming: "bg-blue-100 text-blue-700",
  active: "bg-green-100 text-green-700",
  ended: "bg-red-100 text-red-700",
};

function StatusBadge({ status }: { status: string }) {
  const cls =
    STATUS_COLORS[status as LeaseStatus] ?? "bg-gray-100 text-gray-700";
  return (
    <Badge className={cls} variant="outline">
      {status}
    </Badge>
  );
}

const NEXT_STATUSES: Record<string, string[]> = {
  draft: ["upcoming", "active"],
  upcoming: ["active", "ended"],
  active: ["ended"],
  ended: [],
};

function isFeatureDisabled(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.status === 404 || error.status === 503) &&
    /not enabled/i.test(error.detail ?? "")
  );
}

// ─── Editable field ───────────────────────────────────────────────────────────

interface EditableFieldProps {
  label: string;
  value: string;
  onSave: (value: string) => Promise<void>;
  inputType?: string;
  min?: string;
  max?: string;
  renderDisplay?: (v: string) => string;
}

function EditableField({
  label,
  value,
  onSave,
  inputType = "text",
  min,
  max,
  renderDisplay,
}: EditableFieldProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const [saving, setSaving] = useState(false);

  async function save() {
    if (draft === value) { setEditing(false); return; }
    setSaving(true);
    try {
      await onSave(draft);
      setEditing(false);
    } finally {
      setSaving(false);
    }
  }

  function cancel() {
    setDraft(value);
    setEditing(false);
  }

  return (
    <div className="space-y-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      {editing ? (
        <div className="flex items-center gap-2">
          <Input
            type={inputType}
            value={draft}
            min={min}
            max={max}
            onChange={(e) => setDraft(e.target.value)}
            className="h-8 text-sm"
            autoFocus
          />
          <Button
            size="sm"
            variant="ghost"
            onClick={save}
            disabled={saving}
            className="h-8 w-8 p-0"
          >
            <Check className="w-3 h-3" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={cancel}
            disabled={saving}
            className="h-8 w-8 p-0"
          >
            <X className="w-3 h-3" />
          </Button>
        </div>
      ) : (
        <div className="flex items-center gap-2 group">
          <span className="text-sm">
            {renderDisplay ? renderDisplay(value) : value}
          </span>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => { setDraft(value); setEditing(true); }}
            className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
          >
            <Edit2 className="w-3 h-3" />
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function LeaseDetailPage() {
  const { leaseId } = useParams<{ leaseId: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [transitioning, setTransitioning] = useState(false);

  const query = useQuery({
    queryKey: ["leases", "detail", leaseId],
    queryFn: () => getLease(leaseId!),
    enabled: Boolean(leaseId),
    retry: (failCount, error) => {
      if (isFeatureDisabled(error)) return false;
      return failCount < 2;
    },
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["leases"] });
  };

  const { mutateAsync: patch } = useMutation({
    mutationFn: (body: Parameters<typeof patchLease>[1]) =>
      patchLease(leaseId!, body),
    onSuccess: () => {
      toast.success("Lease updated");
      invalidate();
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.detail : "Update failed");
    },
  });

  const { mutate: transition } = useMutation({
    mutationFn: (status: string) => {
      setTransitioning(true);
      return transitionLeaseStatus(leaseId!, status);
    },
    onSuccess: (updated) => {
      toast.success(`Lease moved to "${updated.status}"`);
      invalidate();
    },
    onError: (err) => {
      toast.error(
        err instanceof ApiError ? err.detail : "Status transition failed"
      );
    },
    onSettled: () => setTransitioning(false),
  });

  // Feature disabled
  if (isFeatureDisabled(query.error)) {
    return (
      <div className="p-6 space-y-4">
        <Button variant="ghost" size="sm" onClick={() => navigate(-1)}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Back
        </Button>
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center gap-3 py-12 text-center text-muted-foreground">
              <AlertTriangle className="w-10 h-10" />
              <p className="font-medium">Lease management is not enabled</p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (query.isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (query.isError || !query.data) {
    return (
      <div className="p-6 space-y-4">
        <Button variant="ghost" size="sm" onClick={() => navigate(-1)}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Back
        </Button>
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-destructive">Lease not found.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const lease: LeaseOut = query.data;
  const nextStatuses = NEXT_STATUSES[lease.status] ?? [];
  const daysUntilExpiry = lease.end_date
    ? Math.round((lease.end_date - Date.now() / 1000) / 86400)
    : null;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate("/property/leases")}
        >
          <ArrowLeft className="w-4 h-4 mr-1" /> Leases
        </Button>
      </div>

      <PageHeader
        title={lease.lease_number}
        description={`Lease for unit ${lease.unit_id}`}
        actions={
          <div className="flex items-center gap-2">
            <StatusBadge status={lease.status} />
            {nextStatuses.map((s) => (
              <Button
                key={s}
                size="sm"
                variant="outline"
                disabled={transitioning}
                onClick={() => transition(s)}
              >
                Move to: {s}
              </Button>
            ))}
          </div>
        }
      />

      {/* Expiry warning */}
      {daysUntilExpiry !== null &&
        daysUntilExpiry >= 0 &&
        daysUntilExpiry <= 60 &&
        lease.status === "active" && (
          <div className="flex items-center gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-950/20 dark:border-amber-800 dark:text-amber-200">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            This lease expires in{" "}
            <strong>{daysUntilExpiry} day{daysUntilExpiry === 1 ? "" : "s"}</strong>{" "}
            ({fmtDate(lease.end_date)})
          </div>
        )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Property / Unit / Tenant */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Property &amp; Tenant</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-muted-foreground">Tenant ID</p>
                <p className="text-sm font-mono">{lease.tenant_id}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Property ID</p>
                <p className="text-sm font-mono">{lease.property_id}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Unit ID</p>
                <p className="text-sm font-mono">{lease.unit_id}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Lease #</p>
                <p className="text-sm font-mono">{lease.lease_number}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Term */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Lease Term</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-muted-foreground">Start Date</p>
                <p className="text-sm">{fmtDate(lease.start_date)}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">End Date</p>
                <p className="text-sm">{fmtDate(lease.end_date)}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Status</p>
                <StatusBadge status={lease.status} />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">
                  Renewal Notice Days
                </p>
                <p className="text-sm">{lease.renewal_notice_days} days</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Rent & fees (editable) */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Rent &amp; Fees</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <EditableField
              label="Monthly Rent"
              value={String(lease.monthly_rent_cents / 100)}
              inputType="number"
              min="0"
              renderDisplay={(v) =>
                fmtCents(Math.round(parseFloat(v) * 100), lease.currency) +
                " /mo"
              }
              onSave={async (v) => {
                await patch({
                  monthly_rent_cents: dollarsToCents(v),
                });
              }}
            />
            <EditableField
              label="Security Deposit"
              value={String(lease.security_deposit_cents / 100)}
              inputType="number"
              min="0"
              renderDisplay={(v) =>
                fmtCents(Math.round(parseFloat(v) * 100), lease.currency)
              }
              onSave={async (v) => {
                await patch({
                  security_deposit_cents: dollarsToCents(v),
                });
              }}
            />
            <EditableField
              label="Rent Due Day"
              value={String(lease.rent_due_day)}
              inputType="number"
              min="1"
              max="28"
              renderDisplay={(v) => `Day ${v} of month`}
              onSave={async (v) => {
                await patch({ rent_due_day: parseInt(v) });
              }}
            />
            <Separator />
            <div>
              <p className="text-xs text-muted-foreground mb-1">Late Fee</p>
              <LateFeeEditor lease={lease} onPatch={patch} />
            </div>
          </CardContent>
        </Card>

        {/* Notes */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Notes</CardTitle>
          </CardHeader>
          <CardContent>
            <NotesEditor lease={lease} onPatch={patch} />
          </CardContent>
        </Card>
      </div>

      {/* Metadata */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex flex-wrap gap-6 text-xs text-muted-foreground">
            <span>Created: {fmtDatetime(lease.created_at)}</span>
            <span>Updated: {fmtDatetime(lease.updated_at)}</span>
            <span>Currency: {lease.currency.toUpperCase()}</span>
            {lease.renewal_notified_at && (
              <span>
                Renewal notice sent: {fmtDatetime(lease.renewal_notified_at)}
              </span>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Late fee editor ──────────────────────────────────────────────────────────

interface LateFeeEditorProps {
  lease: LeaseOut;
  onPatch: (body: Parameters<typeof patchLease>[1]) => Promise<LeaseOut>;
}

function LateFeeEditor({ lease, onPatch }: LateFeeEditorProps) {
  const [editing, setEditing] = useState(false);
  const [feeType, setFeeType] = useState<LateFeeType>(lease.late_fee_type);
  const [feeCents, setFeeCents] = useState(
    String(lease.late_fee_cents / 100)
  );
  const [feeBps, setFeeBps] = useState(String(lease.late_fee_percent_bps));
  const [graceDays, setGraceDays] = useState(
    String(lease.late_fee_grace_days)
  );
  const [saving, setSaving] = useState(false);

  async function save() {
    setSaving(true);
    try {
      await onPatch({
        late_fee_type: feeType,
        late_fee_cents:
          feeType === "flat" ? Math.round(parseFloat(feeCents) * 100) : 0,
        late_fee_percent_bps:
          feeType === "percent" ? parseInt(feeBps) : 0,
        late_fee_grace_days: parseInt(graceDays) || 0,
      });
      setEditing(false);
    } catch {
      // error handled by parent mutation
    } finally {
      setSaving(false);
    }
  }

  if (!editing) {
    return (
      <div className="flex items-start gap-2 group">
        <div className="text-sm">
          {lease.late_fee_type === "none" && "None"}
          {lease.late_fee_type === "flat" &&
            `Flat ${fmtCents(lease.late_fee_cents, lease.currency)} after ${lease.late_fee_grace_days} grace day(s)`}
          {lease.late_fee_type === "percent" &&
            `${(lease.late_fee_percent_bps / 100).toFixed(2)}% after ${lease.late_fee_grace_days} grace day(s)`}
        </div>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setEditing(true)}
          className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
        >
          <Edit2 className="w-3 h-3" />
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-2 border rounded-md p-3">
      <div className="space-y-1">
        <Label className="text-xs">Type</Label>
        <Select
          value={feeType}
          onValueChange={(v) => setFeeType(v as LateFeeType)}
        >
          <SelectTrigger className="h-8 text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="none">None</SelectItem>
            <SelectItem value="flat">Flat amount</SelectItem>
            <SelectItem value="percent">Percentage</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {feeType === "flat" && (
        <div className="space-y-1">
          <Label className="text-xs">Amount ($)</Label>
          <Input
            type="number"
            min="0"
            step="0.01"
            value={feeCents}
            onChange={(e) => setFeeCents(e.target.value)}
            className="h-8 text-sm"
          />
        </div>
      )}

      {feeType === "percent" && (
        <div className="space-y-1">
          <Label className="text-xs">Basis Points (500 = 5%)</Label>
          <Input
            type="number"
            min="1"
            max="10000"
            value={feeBps}
            onChange={(e) => setFeeBps(e.target.value)}
            className="h-8 text-sm"
          />
        </div>
      )}

      {feeType !== "none" && (
        <div className="space-y-1">
          <Label className="text-xs">Grace Days</Label>
          <Input
            type="number"
            min="0"
            value={graceDays}
            onChange={(e) => setGraceDays(e.target.value)}
            className="h-8 text-sm"
          />
        </div>
      )}

      <div className="flex items-center gap-2 pt-1">
        <Button
          size="sm"
          onClick={save}
          disabled={saving}
          className="h-7 text-xs"
        >
          Save
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setEditing(false)}
          className="h-7 text-xs"
        >
          Cancel
        </Button>
      </div>
    </div>
  );
}

// ─── Notes editor ─────────────────────────────────────────────────────────────

interface NotesEditorProps {
  lease: LeaseOut;
  onPatch: (body: Parameters<typeof patchLease>[1]) => Promise<LeaseOut>;
}

function NotesEditor({ lease, onPatch }: NotesEditorProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(lease.notes ?? "");
  const [saving, setSaving] = useState(false);

  async function save() {
    setSaving(true);
    try {
      await onPatch({ notes: draft });
      setEditing(false);
    } catch {
      // handled upstream
    } finally {
      setSaving(false);
    }
  }

  if (!editing) {
    return (
      <div className="group space-y-1">
        <p className="text-sm text-muted-foreground whitespace-pre-wrap min-h-[3rem]">
          {lease.notes || <em>No notes</em>}
        </p>
        <Button
          size="sm"
          variant="outline"
          onClick={() => { setDraft(lease.notes ?? ""); setEditing(true); }}
          className="opacity-0 group-hover:opacity-100 transition-opacity h-7 text-xs"
        >
          <Edit2 className="w-3 h-3 mr-1" /> Edit notes
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <Textarea
        rows={4}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        autoFocus
      />
      <div className="flex items-center gap-2">
        <Button size="sm" onClick={save} disabled={saving} className="h-7 text-xs">
          Save
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setEditing(false)}
          className="h-7 text-xs"
        >
          Cancel
        </Button>
      </div>
    </div>
  );
}
