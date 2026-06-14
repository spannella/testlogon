/**
 * LeaseCreateDialog — React Hook Form + Zod creation dialog for leases (LSE-004)
 */

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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

import { ApiError } from "@/api/client";
import { createLease, type LeaseOut } from "@/api/endpoints/leases";

// ─── Zod schema ───────────────────────────────────────────────────────────────

const leaseSchema = z
  .object({
    tenant_id: z.string().min(1, "Tenant ID is required"),
    property_id: z.string().min(1, "Property ID is required"),
    unit_id: z.string().min(1, "Unit ID is required"),
    start_date_str: z.string().min(1, "Start date is required"),
    end_date_str: z.string().optional(),
    monthly_rent_str: z
      .string()
      .min(1, "Monthly rent is required")
      .regex(/^\d+(\.\d{1,2})?$/, "Enter a valid amount"),
    security_deposit_str: z.string().optional(),
    rent_due_day: z
      .number({ coerce: true })
      .int()
      .min(1)
      .max(28, "Must be 1–28"),
    late_fee_type: z.enum(["none", "flat", "percent"]),
    late_fee_cents_str: z.string().optional(),
    late_fee_bps_str: z.string().optional(),
    late_fee_grace_days: z.number({ coerce: true }).int().min(0).default(0),
    currency: z.string().min(1).default("usd"),
    notes: z.string().optional(),
    renewal_notice_days: z
      .number({ coerce: true })
      .int()
      .min(1)
      .max(365)
      .default(30),
    force_draft: z.boolean().default(false),
  })
  .superRefine((data, ctx) => {
    if (data.late_fee_type === "flat") {
      const v = parseFloat(data.late_fee_cents_str ?? "0");
      if (!v || v <= 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["late_fee_cents_str"],
          message: "Enter a flat late fee amount",
        });
      }
    }
    if (data.late_fee_type === "percent") {
      const v = parseFloat(data.late_fee_bps_str ?? "0");
      if (!v || v <= 0 || v > 10000) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["late_fee_bps_str"],
          message: "Enter basis points 1–10000 (e.g. 500 = 5%)",
        });
      }
    }
    if (data.end_date_str) {
      const start = new Date(data.start_date_str).getTime();
      const end = new Date(data.end_date_str).getTime();
      if (end <= start) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["end_date_str"],
          message: "End date must be after start date",
        });
      }
    }
  });

type FormValues = z.infer<typeof leaseSchema>;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function toUnixTs(dateStr: string): number {
  return Math.floor(new Date(dateStr).getTime() / 1000);
}

function dollarsToCents(str: string): number {
  return Math.round(parseFloat(str) * 100);
}

// ─── Component ────────────────────────────────────────────────────────────────

interface LeaseCreateDialogProps {
  open: boolean;
  onClose: () => void;
  onCreated: (lease: LeaseOut) => void;
}

export function LeaseCreateDialog({
  open,
  onClose,
  onCreated,
}: LeaseCreateDialogProps) {
  const {
    register,
    handleSubmit,
    watch,
    setValue,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({
    resolver: zodResolver(leaseSchema),
    defaultValues: {
      late_fee_type: "none",
      rent_due_day: 1,
      late_fee_grace_days: 0,
      renewal_notice_days: 30,
      currency: "usd",
      force_draft: false,
    },
  });

  const lateFeeType = watch("late_fee_type");

  const mutation = useMutation({
    mutationFn: (values: FormValues) => {
      const body = {
        tenant_id: values.tenant_id,
        property_id: values.property_id,
        unit_id: values.unit_id,
        start_date: toUnixTs(values.start_date_str),
        end_date: values.end_date_str
          ? toUnixTs(values.end_date_str)
          : undefined,
        monthly_rent_cents: dollarsToCents(values.monthly_rent_str),
        security_deposit_cents: values.security_deposit_str
          ? dollarsToCents(values.security_deposit_str)
          : 0,
        rent_due_day: values.rent_due_day,
        late_fee_type: values.late_fee_type,
        late_fee_cents:
          values.late_fee_type === "flat" && values.late_fee_cents_str
            ? dollarsToCents(values.late_fee_cents_str)
            : 0,
        late_fee_percent_bps:
          values.late_fee_type === "percent" && values.late_fee_bps_str
            ? parseInt(values.late_fee_bps_str)
            : 0,
        late_fee_grace_days: values.late_fee_grace_days,
        currency: values.currency || "usd",
        notes: values.notes ?? "",
        renewal_notice_days: values.renewal_notice_days,
        force_draft: values.force_draft,
      };
      return createLease(body);
    },
    onSuccess: (lease) => {
      toast.success(`Lease ${lease.lease_number} created`);
      reset();
      onCreated(lease);
    },
    onError: (err) => {
      const msg =
        err instanceof ApiError ? err.detail : "Failed to create lease";
      toast.error(msg);
    },
  });

  function handleClose() {
    reset();
    onClose();
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !v && handleClose()}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>New Lease</DialogTitle>
        </DialogHeader>

        <form
          onSubmit={handleSubmit((v) => mutation.mutate(v))}
          className="space-y-4"
        >
          {/* Tenant / Property / Unit IDs */}
          <div className="grid grid-cols-1 gap-3">
            <div className="space-y-1">
              <Label htmlFor="tenant_id">Tenant ID *</Label>
              <Input
                id="tenant_id"
                placeholder="e.g. ten_abc123"
                {...register("tenant_id")}
              />
              {errors.tenant_id && (
                <p className="text-xs text-destructive">
                  {errors.tenant_id.message}
                </p>
              )}
            </div>

            <div className="space-y-1">
              <Label htmlFor="property_id">Property ID *</Label>
              <Input
                id="property_id"
                placeholder="e.g. prop_abc123"
                {...register("property_id")}
              />
              {errors.property_id && (
                <p className="text-xs text-destructive">
                  {errors.property_id.message}
                </p>
              )}
            </div>

            <div className="space-y-1">
              <Label htmlFor="unit_id">Unit ID *</Label>
              <Input
                id="unit_id"
                placeholder="e.g. unt_abc123"
                {...register("unit_id")}
              />
              {errors.unit_id && (
                <p className="text-xs text-destructive">
                  {errors.unit_id.message}
                </p>
              )}
            </div>
          </div>

          {/* Dates */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="start_date_str">Start Date *</Label>
              <Input type="date" id="start_date_str" {...register("start_date_str")} />
              {errors.start_date_str && (
                <p className="text-xs text-destructive">
                  {errors.start_date_str.message}
                </p>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="end_date_str">
                End Date <span className="text-muted-foreground">(optional)</span>
              </Label>
              <Input type="date" id="end_date_str" {...register("end_date_str")} />
              {errors.end_date_str && (
                <p className="text-xs text-destructive">
                  {errors.end_date_str.message}
                </p>
              )}
            </div>
          </div>

          {/* Rent fields */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="monthly_rent_str">Monthly Rent ($) *</Label>
              <Input
                id="monthly_rent_str"
                type="number"
                min="0"
                step="0.01"
                placeholder="1500.00"
                {...register("monthly_rent_str")}
              />
              {errors.monthly_rent_str && (
                <p className="text-xs text-destructive">
                  {errors.monthly_rent_str.message}
                </p>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="security_deposit_str">
                Security Deposit ($){" "}
                <span className="text-muted-foreground">(optional)</span>
              </Label>
              <Input
                id="security_deposit_str"
                type="number"
                min="0"
                step="0.01"
                placeholder="0.00"
                {...register("security_deposit_str")}
              />
            </div>
          </div>

          {/* Due day + currency */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="rent_due_day">Rent Due Day (1–28) *</Label>
              <Input
                id="rent_due_day"
                type="number"
                min="1"
                max="28"
                {...register("rent_due_day", { valueAsNumber: true })}
              />
              {errors.rent_due_day && (
                <p className="text-xs text-destructive">
                  {errors.rent_due_day.message}
                </p>
              )}
            </div>
            <div className="space-y-1">
              <Label htmlFor="currency">Currency</Label>
              <Input id="currency" defaultValue="usd" {...register("currency")} />
            </div>
          </div>

          {/* Late fee */}
          <div className="space-y-2">
            <Label>Late Fee</Label>
            <Select
              value={lateFeeType}
              onValueChange={(v) =>
                setValue("late_fee_type", v as "none" | "flat" | "percent", {
                  shouldValidate: true,
                })
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None</SelectItem>
                <SelectItem value="flat">Flat amount</SelectItem>
                <SelectItem value="percent">Percentage (basis points)</SelectItem>
              </SelectContent>
            </Select>

            {lateFeeType === "flat" && (
              <div className="space-y-1">
                <Label htmlFor="late_fee_cents_str">Late Fee Amount ($)</Label>
                <Input
                  id="late_fee_cents_str"
                  type="number"
                  min="0"
                  step="0.01"
                  placeholder="50.00"
                  {...register("late_fee_cents_str")}
                />
                {errors.late_fee_cents_str && (
                  <p className="text-xs text-destructive">
                    {errors.late_fee_cents_str.message}
                  </p>
                )}
              </div>
            )}

            {lateFeeType === "percent" && (
              <div className="space-y-1">
                <Label htmlFor="late_fee_bps_str">
                  Late Fee Basis Points (500 = 5%)
                </Label>
                <Input
                  id="late_fee_bps_str"
                  type="number"
                  min="1"
                  max="10000"
                  placeholder="500"
                  {...register("late_fee_bps_str")}
                />
                {errors.late_fee_bps_str && (
                  <p className="text-xs text-destructive">
                    {errors.late_fee_bps_str.message}
                  </p>
                )}
              </div>
            )}

            {lateFeeType !== "none" && (
              <div className="space-y-1">
                <Label htmlFor="late_fee_grace_days">Grace Days</Label>
                <Input
                  id="late_fee_grace_days"
                  type="number"
                  min="0"
                  defaultValue={0}
                  {...register("late_fee_grace_days", { valueAsNumber: true })}
                />
              </div>
            )}
          </div>

          {/* Renewal notice days */}
          <div className="space-y-1">
            <Label htmlFor="renewal_notice_days">
              Renewal Notice Days (1–365)
            </Label>
            <Input
              id="renewal_notice_days"
              type="number"
              min="1"
              max="365"
              defaultValue={30}
              {...register("renewal_notice_days", { valueAsNumber: true })}
            />
          </div>

          {/* Notes */}
          <div className="space-y-1">
            <Label htmlFor="notes">Notes</Label>
            <Textarea id="notes" rows={3} {...register("notes")} />
          </div>

          {/* Force draft */}
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="force_draft"
              {...register("force_draft")}
              className="h-4 w-4 rounded border-border"
            />
            <Label htmlFor="force_draft" className="cursor-pointer">
              Save as Draft (pre-signing)
            </Label>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={handleClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={isSubmitting || mutation.isPending}>
              {mutation.isPending ? "Creating…" : "Create Lease"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
