import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Layers, Plus, Pencil, Archive, RefreshCw } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageHeader } from "@/components/shared/PageHeader";
import { useAuthStore } from "@/stores/authStore";
import {
  listPlans,
  archivePlan,
  updatePlan,
} from "@/api/endpoints/subscriptions";
import type { SubscriptionPlan } from "@/api/types";
import { PlanEditor } from "./PlanEditor";
import { DiscountCodeManager } from "./DiscountCodeManager";
import { PlanBrowser } from "./PlanBrowser";

// ─── Helpers ──────────────────────────────────────────────────

function formatPrice(cents: number, currency: string): string {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: currency || "USD",
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

// ─── Component ──────────────────────────────────────────────────

export default function TierManager() {
  const userId = useAuthStore((s) => s.userId);
  const queryClient = useQueryClient();
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingPlan, setEditingPlan] = useState<SubscriptionPlan | null>(null);

  const { data: plans, isLoading } = useQuery({
    queryKey: ["creator-plans", userId],
    queryFn: () => listPlans(userId!),
    enabled: !!userId,
  });

  const archiveMut = useMutation({
    mutationFn: (planId: string) => archivePlan(planId),
    onSuccess: () => {
      toast.success("Plan archived");
      queryClient.invalidateQueries({ queryKey: ["creator-plans", userId] });
      queryClient.invalidateQueries({ queryKey: ["plans", userId] });
    },
    onError: () => toast.error("Failed to archive plan"),
  });

  const reactivateMut = useMutation({
    mutationFn: (planId: string) => updatePlan(planId, { status: "active" }),
    onSuccess: () => {
      toast.success("Plan reactivated");
      queryClient.invalidateQueries({ queryKey: ["creator-plans", userId] });
      queryClient.invalidateQueries({ queryKey: ["plans", userId] });
    },
    onError: () => toast.error("Failed to reactivate plan"),
  });

  const openCreate = () => {
    setEditingPlan(null);
    setEditorOpen(true);
  };

  const openEdit = (plan: SubscriptionPlan) => {
    setEditingPlan(plan);
    setEditorOpen(true);
  };

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Subscription Tiers"
        description="Manage your subscription plans and discount codes"
        actions={
          <div className="flex items-center gap-2">
            <Layers className="h-5 w-5 text-muted-foreground" />
          </div>
        }
      />

      <Tabs defaultValue="plans">
        <TabsList>
          <TabsTrigger value="plans">Plans</TabsTrigger>
          <TabsTrigger value="discounts">Discount Codes</TabsTrigger>
          <TabsTrigger value="preview">Preview</TabsTrigger>
        </TabsList>

        {/* ── Plans Tab ────────────────────────────────────────── */}
        <TabsContent value="plans" className="mt-4 space-y-4">
          <div className="flex justify-end">
            <Button onClick={openCreate}>
              <Plus className="mr-1.5 h-4 w-4" /> Create Plan
            </Button>
          </div>

          {isLoading && (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-64 w-full rounded-xl" />
              ))}
            </div>
          )}

          {!isLoading && (!plans || plans.length === 0) && (
            <EmptyState
              icon={<Layers className="h-8 w-8" />}
              title="No subscription tiers yet"
              description="Create your first tier to start earning."
            />
          )}

          {!isLoading && plans && plans.length > 0 && (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {plans.map((plan: SubscriptionPlan) => (
                <Card
                  key={plan.plan_id}
                  className={
                    plan.status === "archived" ? "opacity-70" : ""
                  }
                >
                  <CardHeader className="pb-2">
                    <div className="flex items-center gap-2">
                      <CardTitle className="text-lg truncate">
                        {plan.name}
                      </CardTitle>
                      {plan.status === "active" ? (
                        <Badge
                          variant="default"
                          className="bg-green-600 hover:bg-green-700"
                        >
                          Active
                        </Badge>
                      ) : (
                        <Badge variant="secondary">Archived</Badge>
                      )}
                    </div>
                  </CardHeader>

                  <CardContent className="space-y-2">
                    {/* Price */}
                    <div>
                      <span className="text-2xl font-bold">
                        {formatPrice(plan.price_cents, plan.currency)}
                      </span>
                      <span className="text-sm text-muted-foreground">
                        {" "}
                        / {plan.interval}
                      </span>
                    </div>

                    {plan.annual_price_cents != null &&
                      plan.interval === "month" && (
                        <p className="text-xs text-muted-foreground">
                          or{" "}
                          {formatPrice(
                            plan.annual_price_cents,
                            plan.currency,
                          )}{" "}
                          / year
                          {plan.price_cents > 0 && (
                            <span className="ml-1 text-green-600">
                              (save{" "}
                              {Math.round(
                                (1 -
                                  plan.annual_price_cents /
                                    (plan.price_cents * 12)) *
                                  100,
                              )}
                              %)
                            </span>
                          )}
                        </p>
                      )}

                    {/* Description */}
                    {plan.description && (
                      <p className="text-sm text-muted-foreground line-clamp-2">
                        {plan.description}
                      </p>
                    )}

                    {/* Assets */}
                    {plan.assets && plan.assets.length > 0 && (
                      <ul className="text-xs text-muted-foreground space-y-0.5">
                        {plan.assets.slice(0, 3).map((a, i) => (
                          <li key={i}>
                            - {a.name || a.path}
                          </li>
                        ))}
                        {plan.assets.length > 3 && (
                          <li>+ {plan.assets.length - 3} more</li>
                        )}
                      </ul>
                    )}
                  </CardContent>

                  <CardFooter className="gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openEdit(plan)}
                    >
                      <Pencil className="mr-1 h-3 w-3" /> Edit
                    </Button>

                    {plan.status === "active" && (
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="outline" size="sm">
                            <Archive className="mr-1 h-3 w-3" /> Archive
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>
                              Archive Plan
                            </AlertDialogTitle>
                            <AlertDialogDescription>
                              Are you sure you want to archive "
                              {plan.name}"? New subscribers will not be
                              able to select it. Existing subscribers
                              keep their subscription.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() =>
                                archiveMut.mutate(plan.plan_id)
                              }
                            >
                              Archive
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    )}

                    {plan.status === "archived" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          reactivateMut.mutate(plan.plan_id)
                        }
                        disabled={reactivateMut.isPending}
                      >
                        <RefreshCw className="mr-1 h-3 w-3" /> Reactivate
                      </Button>
                    )}
                  </CardFooter>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Discount Codes Tab ───────────────────────────────── */}
        <TabsContent value="discounts" className="mt-4">
          <DiscountCodeManager />
        </TabsContent>

        {/* ── Preview Tab ──────────────────────────────────────── */}
        <TabsContent value="preview" className="mt-4">
          {userId ? (
            <PlanBrowser creatorId={userId} />
          ) : (
            <p className="text-sm text-muted-foreground">
              Not authenticated.
            </p>
          )}
        </TabsContent>
      </Tabs>

      {/* Plan Editor Dialog */}
      <PlanEditor
        open={editorOpen}
        onOpenChange={setEditorOpen}
        plan={editingPlan}
      />
    </div>
  );
}
