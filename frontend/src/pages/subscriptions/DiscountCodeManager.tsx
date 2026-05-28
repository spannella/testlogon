import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
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
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuthStore } from "@/stores/authStore";
import {
  createDiscount,
  listDiscounts,
  disableDiscount,
} from "@/api/endpoints/subscriptions";
import type { DiscountCode } from "@/api/types";

// ─── Validation ─────────────────────────────────────────────────

const discountSchema = z
  .object({
    code: z.string().min(3, "Code must be at least 3 characters").max(32),
    percent_off: z
      .number({ invalid_type_error: "Required" })
      .int("Must be an integer")
      .min(1, "Min 1%")
      .max(100, "Max 100%"),
    duration: z.enum(["once", "forever", "repeating"]),
    duration_months: z.number().int().min(1).max(36).optional().nullable(),
  })
  .refine(
    (d) =>
      d.duration !== "repeating" ||
      (d.duration_months != null && d.duration_months > 0),
    {
      message: "Duration months is required for repeating discounts",
      path: ["duration_months"],
    },
  );

type DiscountFormValues = z.infer<typeof discountSchema>;

// ─── Component ──────────────────────────────────────────────────

export function DiscountCodeManager() {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);

  const { data: codes, isLoading } = useQuery({
    queryKey: ["creator-discounts", userId],
    queryFn: () => listDiscounts(userId!),
    enabled: !!userId,
  });

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    reset,
    formState: { errors },
  } = useForm<DiscountFormValues>({
    resolver: zodResolver(discountSchema),
    defaultValues: {
      code: "",
      percent_off: undefined as unknown as number,
      duration: "once",
      duration_months: null,
    },
  });

  const duration = watch("duration");

  const createMut = useMutation({
    mutationFn: (body: DiscountFormValues) =>
      createDiscount(userId!, {
        code: body.code.toUpperCase(),
        percent_off: body.percent_off,
        duration: body.duration,
        duration_months: body.duration === "repeating" ? body.duration_months! : undefined,
        active: true,
      }),
    onSuccess: () => {
      toast.success("Discount code created");
      queryClient.invalidateQueries({ queryKey: ["creator-discounts", userId] });
      reset();
      setShowForm(false);
    },
    onError: () => toast.error("Failed to create discount code"),
  });

  const disableMut = useMutation({
    mutationFn: (code: string) => disableDiscount(userId!, code),
    onSuccess: () => {
      toast.success("Discount code disabled");
      queryClient.invalidateQueries({ queryKey: ["creator-discounts", userId] });
    },
    onError: () => toast.error("Failed to disable discount code"),
  });

  const onSubmit = (values: DiscountFormValues) => {
    createMut.mutate(values);
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-48" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Create button / form */}
      {!showForm ? (
        <Button onClick={() => setShowForm(true)}>
          <Plus className="mr-1.5 h-4 w-4" /> Create Code
        </Button>
      ) : (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">New Discount Code</CardTitle>
          </CardHeader>
          <CardContent>
            <form
              onSubmit={handleSubmit(onSubmit)}
              className="grid gap-4 sm:grid-cols-2"
            >
              <div className="space-y-1">
                <Label htmlFor="dc-code">Code</Label>
                <Input
                  id="dc-code"
                  placeholder="e.g. SAVE20"
                  {...register("code")}
                  onBlur={(e) =>
                    setValue("code", e.target.value.toUpperCase())
                  }
                />
                {errors.code && (
                  <p className="text-xs text-destructive">
                    {errors.code.message}
                  </p>
                )}
              </div>

              <div className="space-y-1">
                <Label htmlFor="dc-pct">Percent Off</Label>
                <Input
                  id="dc-pct"
                  type="number"
                  min={1}
                  max={100}
                  placeholder="20"
                  {...register("percent_off", { valueAsNumber: true })}
                />
                {errors.percent_off && (
                  <p className="text-xs text-destructive">
                    {errors.percent_off.message}
                  </p>
                )}
              </div>

              <div className="space-y-1">
                <Label>Duration</Label>
                <Select
                  value={duration}
                  onValueChange={(v) =>
                    setValue(
                      "duration",
                      v as "once" | "forever" | "repeating",
                    )
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="once">Once</SelectItem>
                    <SelectItem value="forever">Forever</SelectItem>
                    <SelectItem value="repeating">Repeating</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {duration === "repeating" && (
                <div className="space-y-1">
                  <Label htmlFor="dc-months">Duration Months</Label>
                  <Input
                    id="dc-months"
                    type="number"
                    min={1}
                    max={36}
                    placeholder="3"
                    {...register("duration_months", { valueAsNumber: true })}
                  />
                  {errors.duration_months && (
                    <p className="text-xs text-destructive">
                      {errors.duration_months.message}
                    </p>
                  )}
                </div>
              )}

              <div className="sm:col-span-2 flex gap-2">
                <Button type="submit" disabled={createMut.isPending}>
                  {createMut.isPending && (
                    <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
                  )}
                  Create
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    reset();
                    setShowForm(false);
                  }}
                >
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Codes table */}
      {(!codes || codes.length === 0) ? (
        <EmptyState
          icon={<Plus className="h-8 w-8" />}
          title="No discount codes yet"
          description="Create one to start promotions."
        />
      ) : (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Code</TableHead>
                <TableHead>% Off</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {codes.map((dc: DiscountCode) => (
                <TableRow key={dc.code}>
                  <TableCell className="font-mono font-semibold">
                    {dc.code}
                  </TableCell>
                  <TableCell>{dc.percent_off}%</TableCell>
                  <TableCell>
                    {dc.duration}
                    {dc.duration === "repeating" && dc.duration_months
                      ? ` (${dc.duration_months} mo)`
                      : ""}
                  </TableCell>
                  <TableCell>
                    {dc.active ? (
                      <Badge variant="default" className="bg-green-600 hover:bg-green-700">Active</Badge>
                    ) : (
                      <Badge variant="destructive">Disabled</Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    {dc.active && (
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="outline" size="sm">
                            Disable
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Disable Discount Code</AlertDialogTitle>
                            <AlertDialogDescription>
                              Are you sure you want to disable the code{" "}
                              <span className="font-mono font-semibold">
                                {dc.code}
                              </span>
                              ? This cannot be undone.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() => disableMut.mutate(dc.code)}
                            >
                              Disable
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
