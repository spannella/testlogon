import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Check,
  ChevronDown,
  ChevronUp,
  Eye,
  Layers,
  MoreVertical,
  Plus,
} from "lucide-react";
import {
  archiveSubscriptionTier,
  createSubscriptionTier,
  deleteSubscriptionTier,
  getSubscriptionTierAnalytics,
  listSubscriptionTiers,
  previewSubscriptionTiers,
  reorderSubscriptionTiers,
  unarchiveSubscriptionTier,
  updateSubscriptionTier,
} from "@/api/endpoints/adminSubscriptionTiers";
import type {
  SubscriptionTierCreate,
  SubscriptionTierOut,
  SubscriptionTierPreviewItem,
} from "@/api/types";
import { ApiError } from "@/api/client";
import SubscriptionTierDialog from "./SubscriptionTierDialog";
import SubscriptionTierPreviewDialog from "./SubscriptionTierPreviewDialog";

function formatCurrency(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function TierCard({
  tier,
  onEdit,
  onArchive,
  onDelete,
  onMoveUp,
  onMoveDown,
  canMoveUp,
  canMoveDown,
}: {
  tier: SubscriptionTierOut;
  onEdit: () => void;
  onArchive: () => void;
  onDelete: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
  canMoveUp: boolean;
  canMoveDown: boolean;
}) {
  return (
    <Card
      data-testid="tier-card"
      className={tier.status === "archived" ? "opacity-60" : ""}
    >
      <CardHeader className="flex flex-row items-start justify-between gap-2">
        <div>
          <CardTitle>{tier.name}</CardTitle>
          <p className="text-sm text-muted-foreground">
            {formatCurrency(tier.price_cents)} / {tier.billing_cycle}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={tier.status === "active" ? "default" : "secondary"}>
            {tier.status}
          </Badge>
          <div className="flex flex-col">
            <button
              type="button"
              aria-label="Move tier up"
              disabled={!canMoveUp}
              onClick={onMoveUp}
              className="disabled:opacity-30"
            >
              <ChevronUp className="h-4 w-4" />
            </button>
            <button
              type="button"
              aria-label="Move tier down"
              disabled={!canMoveDown}
              onClick={onMoveDown}
              className="disabled:opacity-30"
            >
              <ChevronDown className="h-4 w-4" />
            </button>
          </div>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" aria-label="Tier actions">
                <MoreVertical className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem onClick={onEdit}>Edit</DropdownMenuItem>
              <DropdownMenuItem onClick={onArchive}>
                {tier.status === "active" ? "Archive" : "Unarchive"}
              </DropdownMenuItem>
              {tier.subscriber_count === 0 && (
                <DropdownMenuItem onClick={onDelete} className="text-red-600">
                  Delete
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </CardHeader>
      <CardContent>
        {tier.description && <p className="text-sm">{tier.description}</p>}
        <ul className="mt-2 space-y-1">
          {tier.benefits.map((b, idx) => (
            <li key={`${b}-${idx}`} className="flex items-center gap-2 text-sm">
              <Check className="h-4 w-4 text-green-500" />
              {b}
            </li>
          ))}
        </ul>
        <div className="mt-4 flex gap-4 text-sm text-muted-foreground">
          <span>{tier.subscriber_count} subscribers</span>
          <span>Access: {tier.access_level}</span>
        </div>
      </CardContent>
    </Card>
  );
}

export default function SubscriptionTierManagerPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [editTier, setEditTier] = useState<SubscriptionTierOut | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [previewTiers, setPreviewTiers] = useState<SubscriptionTierPreviewItem[]>([]);

  const tiersQ = useQuery({
    queryKey: ["admin-subscription-tiers", "list"],
    queryFn: () => listSubscriptionTiers(true),
    staleTime: 30_000,
  });

  const analyticsQ = useQuery({
    queryKey: ["admin-subscription-tiers", "analytics"],
    queryFn: () => getSubscriptionTierAnalytics(),
    staleTime: 60_000,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["admin-subscription-tiers"] });
  };

  const createMut = useMutation({
    mutationFn: createSubscriptionTier,
    onSuccess: () => {
      toast.success("Tier created");
      setShowCreate(false);
      invalidate();
    },
    onError: (e: unknown) => toast.error(e instanceof ApiError ? e.detail : "Create failed"),
  });

  const updateMut = useMutation({
    mutationFn: ({ tierId, data }: { tierId: string; data: SubscriptionTierCreate }) =>
      updateSubscriptionTier(tierId, data),
    onSuccess: () => {
      toast.success("Tier updated");
      setEditTier(null);
      invalidate();
    },
    onError: (e: unknown) => toast.error(e instanceof ApiError ? e.detail : "Update failed"),
  });

  const archiveMut = useMutation({
    mutationFn: ({ tierId, archived }: { tierId: string; archived: boolean }) =>
      archived ? unarchiveSubscriptionTier(tierId) : archiveSubscriptionTier(tierId),
    onSuccess: () => invalidate(),
    onError: (e: unknown) => toast.error(e instanceof ApiError ? e.detail : "Action failed"),
  });

  const deleteMut = useMutation({
    mutationFn: (tierId: string) => deleteSubscriptionTier(tierId),
    onSuccess: () => {
      toast.success("Tier deleted");
      invalidate();
    },
    onError: (e: unknown) => toast.error(e instanceof ApiError ? e.detail : "Delete failed"),
  });

  const reorderMut = useMutation({
    mutationFn: (tierIds: string[]) => reorderSubscriptionTiers(tierIds),
    onSuccess: () => invalidate(),
    onError: (e: unknown) => toast.error(e instanceof ApiError ? e.detail : "Reorder failed"),
  });

  const handleSave = (data: SubscriptionTierCreate) => {
    if (editTier) {
      updateMut.mutate({ tierId: editTier.tier_id, data });
    } else {
      createMut.mutate(data);
    }
  };

  const openPreview = async () => {
    try {
      const res = await previewSubscriptionTiers();
      setPreviewTiers(res.tiers);
      setShowPreview(true);
    } catch (e) {
      toast.error(e instanceof ApiError ? e.detail : "Preview failed");
    }
  };

  const tiers = tiersQ.data ?? [];

  const move = (index: number, dir: -1 | 1) => {
    const next = [...tiers];
    const target = index + dir;
    if (target < 0 || target >= next.length) return;
    [next[index], next[target]] = [next[target]!, next[index]!];
    reorderMut.mutate(next.map((t) => t.tier_id));
  };

  const analytics = analyticsQ.data;

  return (
    <div className="space-y-6 p-4">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-bold">
          <Layers className="h-6 w-6" /> Subscription Tiers
        </h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={openPreview}>
            <Eye className="mr-2 h-4 w-4" /> Preview
          </Button>
          <Button
            onClick={() => {
              setEditTier(null);
              setShowCreate(true);
            }}
          >
            <Plus className="mr-2 h-4 w-4" /> Create Tier
          </Button>
        </div>
      </div>

      {tiersQ.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading tiers…</p>
      ) : tiers.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            No subscription tiers yet. Create your first tier to get started.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {tiers.map((tier, index) => (
            <TierCard
              key={tier.tier_id}
              tier={tier}
              onEdit={() => {
                setShowCreate(false);
                setEditTier(tier);
              }}
              onArchive={() =>
                archiveMut.mutate({
                  tierId: tier.tier_id,
                  archived: tier.status === "archived",
                })
              }
              onDelete={() => deleteMut.mutate(tier.tier_id)}
              onMoveUp={() => move(index, -1)}
              onMoveDown={() => move(index, 1)}
              canMoveUp={index > 0}
              canMoveDown={index < tiers.length - 1}
            />
          ))}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Tier Analytics</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="rounded border p-4">
              <p className="text-sm text-muted-foreground">Total Subscribers</p>
              <p className="text-2xl font-bold">{analytics?.total_subscribers ?? 0}</p>
            </div>
            <div className="rounded border p-4">
              <p className="text-sm text-muted-foreground">Total Revenue</p>
              <p className="text-2xl font-bold">
                {formatCurrency(analytics?.total_revenue_cents ?? 0)}
              </p>
            </div>
          </div>
          {analytics && analytics.tiers.length > 0 && (
            <div className="space-y-2">
              {analytics.tiers.map((row) => {
                const max = Math.max(
                  1,
                  ...analytics.tiers.map((r) => r.subscriber_count),
                );
                const pct = Math.round((row.subscriber_count / max) * 100);
                return (
                  <div key={row.tier_id} className="space-y-1">
                    <div className="flex justify-between text-sm">
                      <span>{row.name}</span>
                      <span className="text-muted-foreground">
                        {row.subscriber_count} subs · {formatCurrency(row.revenue_cents)}
                      </span>
                    </div>
                    <div className="h-2 w-full rounded bg-muted">
                      <div
                        className="h-2 rounded bg-primary"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      <SubscriptionTierDialog
        open={showCreate || !!editTier}
        tier={editTier}
        onSave={handleSave}
        onCancel={() => {
          setShowCreate(false);
          setEditTier(null);
        }}
        saving={createMut.isPending || updateMut.isPending}
      />

      <SubscriptionTierPreviewDialog
        open={showPreview}
        tiers={previewTiers}
        onClose={() => setShowPreview(false)}
      />
    </div>
  );
}
