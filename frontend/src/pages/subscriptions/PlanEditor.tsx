import { useEffect } from "react";
import { useForm, useFieldArray } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Trash2, Loader2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAuthStore } from "@/stores/authStore";
import { createPlan, updatePlan } from "@/api/endpoints/subscriptions";
import type { SubscriptionPlan } from "@/api/types";

// ─── Validation ─────────────────────────────────────────────────

const planSchema = z
  .object({
    name: z.string().min(2, "Name must be at least 2 characters").max(128),
    description: z.string().max(1000).optional().or(z.literal("")),
    price_dollars: z
      .number({ invalid_type_error: "Price is required" })
      .positive("Price must be greater than 0"),
    interval: z.enum(["month", "year"]),
    annual_price_dollars: z.number().positive().optional().nullable(),
    currency: z.string().min(3).max(10),
    asset_paths: z.array(z.object({ value: z.string() })),
  })
  .refine(
    (d) => d.interval !== "month" || !d.annual_price_dollars || d.annual_price_dollars > 0,
    { path: ["annual_price_dollars"], message: "Annual price must be positive" },
  );

type PlanFormValues = z.infer<typeof planSchema>;

// ─── Props ──────────────────────────────────────────────────────

interface PlanEditorProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  plan?: SubscriptionPlan | null;
}

// ─── Component ──────────────────────────────────────────────────

export function PlanEditor({ open, onOpenChange, plan }: PlanEditorProps) {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();
  const isEdit = !!plan;

  const {
    register,
    handleSubmit,
    control,
    reset,
    watch,
    setValue,
    formState: { errors },
  } = useForm<PlanFormValues>({
    resolver: zodResolver(planSchema),
    defaultValues: {
      name: "",
      description: "",
      price_dollars: undefined as unknown as number,
      interval: "month",
      annual_price_dollars: null,
      currency: "usd",
      asset_paths: [],
    },
  });

  const { fields, append, remove } = useFieldArray({
    control,
    name: "asset_paths",
  });

  const interval = watch("interval");

  // Reset form when plan changes or dialog opens
  useEffect(() => {
    if (open) {
      if (plan) {
        reset({
          name: plan.name,
          description: plan.description ?? "",
          price_dollars: plan.price_cents / 100,
          interval: plan.interval as "month" | "year",
          annual_price_dollars: plan.annual_price_cents
            ? plan.annual_price_cents / 100
            : null,
          currency: plan.currency || "usd",
          asset_paths: (plan.assets ?? []).map((a) => ({ value: a.path ?? "" })),
        });
      } else {
        reset({
          name: "",
          description: "",
          price_dollars: undefined as unknown as number,
          interval: "month",
          annual_price_dollars: null,
          currency: "usd",
          asset_paths: [],
        });
      }
    }
  }, [open, plan, reset]);

  const createMut = useMutation({
    mutationFn: (body: Parameters<typeof createPlan>[1]) =>
      createPlan(userId!, body),
    onSuccess: () => {
      toast.success("Plan created");
      queryClient.invalidateQueries({ queryKey: ["creator-plans", userId] });
      queryClient.invalidateQueries({ queryKey: ["plans", userId] });
      onOpenChange(false);
    },
    onError: () => toast.error("Failed to create plan"),
  });

  const updateMut = useMutation({
    mutationFn: (body: Parameters<typeof updatePlan>[1]) =>
      updatePlan(plan!.plan_id, body),
    onSuccess: () => {
      toast.success("Plan updated");
      queryClient.invalidateQueries({ queryKey: ["creator-plans", userId] });
      queryClient.invalidateQueries({ queryKey: ["plans", userId] });
      onOpenChange(false);
    },
    onError: () => toast.error("Failed to update plan"),
  });

  const isPending = createMut.isPending || updateMut.isPending;

  const onSubmit = (values: PlanFormValues) => {
    const body = {
      name: values.name,
      description: values.description || undefined,
      price_cents: Math.round(values.price_dollars * 100),
      interval: values.interval as "month" | "year",
      annual_price_cents:
        values.interval === "month" && values.annual_price_dollars
          ? Math.round(values.annual_price_dollars * 100)
          : undefined,
      currency: values.currency,
      asset_paths: values.asset_paths
        .map((a) => a.value)
        .filter(Boolean),
    };

    if (isEdit) {
      updateMut.mutate(body);
    } else {
      createMut.mutate(body);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit Plan" : "Create Plan"}</DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          {/* Name */}
          <div className="space-y-1">
            <Label htmlFor="plan-name">Name</Label>
            <Input
              id="plan-name"
              placeholder="e.g. Pro Tier"
              {...register("name")}
            />
            {errors.name && (
              <p className="text-xs text-destructive">{errors.name.message}</p>
            )}
          </div>

          {/* Description */}
          <div className="space-y-1">
            <Label htmlFor="plan-desc">Description</Label>
            <Textarea
              id="plan-desc"
              placeholder="Describe what subscribers get..."
              rows={3}
              {...register("description")}
            />
            {errors.description && (
              <p className="text-xs text-destructive">
                {errors.description.message}
              </p>
            )}
          </div>

          {/* Interval */}
          <div className="space-y-1">
            <Label>Billing Interval</Label>
            <Select
              value={interval}
              onValueChange={(v) => setValue("interval", v as "month" | "year")}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="month">Monthly</SelectItem>
                <SelectItem value="year">Yearly</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Price */}
          <div className="space-y-1">
            <Label htmlFor="plan-price">Price (dollars)</Label>
            <Input
              id="plan-price"
              type="number"
              step="0.01"
              min="0.01"
              placeholder="9.99"
              {...register("price_dollars", { valueAsNumber: true })}
            />
            {errors.price_dollars && (
              <p className="text-xs text-destructive">
                {errors.price_dollars.message}
              </p>
            )}
          </div>

          {/* Annual price — only for monthly plans */}
          {interval === "month" && (
            <div className="space-y-1">
              <Label htmlFor="plan-annual">Annual Price (dollars, optional)</Label>
              <Input
                id="plan-annual"
                type="number"
                step="0.01"
                min="0.01"
                placeholder="99.99"
                {...register("annual_price_dollars", { valueAsNumber: true })}
              />
              {errors.annual_price_dollars && (
                <p className="text-xs text-destructive">
                  {errors.annual_price_dollars.message}
                </p>
              )}
            </div>
          )}

          {/* Currency */}
          <div className="space-y-1">
            <Label>Currency</Label>
            <Select
              value={watch("currency")}
              onValueChange={(v) => setValue("currency", v)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="usd">USD</SelectItem>
                <SelectItem value="eur">EUR</SelectItem>
                <SelectItem value="gbp">GBP</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Asset paths */}
          <div className="space-y-2">
            <Label>Asset Paths</Label>
            {fields.map((field, idx) => (
              <div key={field.id} className="flex items-center gap-2">
                <Input
                  placeholder="/path/to/file"
                  {...register(`asset_paths.${idx}.value`)}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  onClick={() => remove(idx)}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            ))}
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => append({ value: "" })}
            >
              <Plus className="mr-1 h-3 w-3" /> Add asset path
            </Button>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={isPending}>
              {isPending && <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />}
              {isEdit ? "Save" : "Create"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
