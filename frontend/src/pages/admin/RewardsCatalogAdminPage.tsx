import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Gift, Plus, Star } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogFooter,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { canAccessGeneralAdminControls } from "@/lib/adminCapabilities";
import type { RewardKind } from "@/api/endpoints/rewards";
import {
  listAdminRewardsCatalog,
  createAdminRewardsCatalogItem,
  updateAdminRewardsCatalogItem,
  deleteAdminRewardsCatalogItem,
  type AdminCatalogItem,
  type AdminCatalogInput,
} from "@/api/endpoints/adminRewards";
import {
  validateCatalogItem,
  emptyDraft,
  formatPoints,
  formatCents,
} from "@/lib/rewardsCatalogAdmin";
import { remainingStock, sortCatalog } from "@/lib/rewards";

function is404(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

// ─── Create / Edit form dialog ───────────────────────────────────

function CatalogItemDialog({
  open,
  item,
  onSave,
  onCancel,
  saving,
}: {
  open: boolean;
  item: AdminCatalogItem | null; // null = create mode
  onSave: (data: AdminCatalogInput) => void;
  onCancel: () => void;
  saving?: boolean;
}) {
  const [draft, setDraft] = useState<AdminCatalogInput>(emptyDraft());

  useEffect(() => {
    if (open) {
      setDraft(
        item
          ? {
              name: item.name,
              description: item.description,
              cost_points: item.cost_points,
              value_cents: item.value_cents,
              kind: item.kind,
              active: item.active,
              stock_limit: item.stock_limit ?? null,
              featured: item.featured ?? false,
              sort_order: item.sort_order ?? 0,
            }
          : emptyDraft(),
      );
    }
  }, [open, item]);

  const { ok, errors } = validateCatalogItem(draft);

  const set = <K extends keyof AdminCatalogInput>(k: K, v: AdminCatalogInput[K]) =>
    setDraft((prev) => ({ ...prev, [k]: v }));

  const intFromInput = (raw: string): number => {
    const n = parseInt(raw, 10);
    return Number.isNaN(n) ? 0 : n;
  };

  return (
    <Dialog open={open} onOpenChange={(o) => (!o ? onCancel() : undefined)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{item ? "Edit reward" : "Create reward"}</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="rc-name">Name</Label>
            <Input
              id="rc-name"
              value={draft.name}
              onChange={(e) => set("name", e.target.value)}
              placeholder="$5 cash credit"
            />
            {errors.name && <p className="text-sm text-destructive">{errors.name}</p>}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="rc-desc">Description</Label>
            <Textarea
              id="rc-desc"
              value={draft.description}
              onChange={(e) => set("description", e.target.value)}
              placeholder="Redeem points for a credit to your USD cash wallet."
              rows={3}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="rc-cost">Cost (points)</Label>
              <Input
                id="rc-cost"
                type="number"
                inputMode="numeric"
                min={1}
                step={1}
                value={draft.cost_points === 0 ? "" : String(draft.cost_points)}
                onChange={(e) => set("cost_points", intFromInput(e.target.value))}
              />
              {errors.cost_points && (
                <p className="text-sm text-destructive">{errors.cost_points}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="rc-value">Value (cents)</Label>
              <Input
                id="rc-value"
                type="number"
                inputMode="numeric"
                min={0}
                step={1}
                value={draft.value_cents === 0 ? "" : String(draft.value_cents)}
                onChange={(e) => set("value_cents", intFromInput(e.target.value))}
              />
              {errors.value_cents && (
                <p className="text-sm text-destructive">{errors.value_cents}</p>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 items-start gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="rc-kind">Kind</Label>
              <Select
                value={draft.kind}
                onValueChange={(v) => set("kind", v as RewardKind)}
              >
                <SelectTrigger id="rc-kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="cash">Cash</SelectItem>
                  <SelectItem value="perk">Perk</SelectItem>
                </SelectContent>
              </Select>
              {errors.kind && <p className="text-sm text-destructive">{errors.kind}</p>}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="rc-active">Active</Label>
              <div className="flex h-10 items-center gap-2">
                <Switch
                  id="rc-active"
                  checked={draft.active}
                  onCheckedChange={(v) => set("active", v)}
                />
                <span className="text-sm text-muted-foreground">
                  {draft.active ? "Visible to users" : "Hidden from users"}
                </span>
              </div>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rc-stock">Stock limit</Label>
            <Input
              id="rc-stock"
              type="number"
              inputMode="numeric"
              min={0}
              step={1}
              placeholder="Blank = unlimited"
              value={
                draft.stock_limit === null || draft.stock_limit === undefined
                  ? ""
                  : String(draft.stock_limit)
              }
              onChange={(e) =>
                set(
                  "stock_limit",
                  e.target.value.trim() === "" ? null : intFromInput(e.target.value),
                )
              }
            />
            <p className="text-xs text-muted-foreground">
              Leave blank for unlimited inventory.
            </p>
            {errors.stock_limit && (
              <p className="text-sm text-destructive">{errors.stock_limit}</p>
            )}
          </div>

          <div className="grid grid-cols-2 items-start gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="rc-sort">Sort order</Label>
              <Input
                id="rc-sort"
                type="number"
                inputMode="numeric"
                min={0}
                step={1}
                value={draft.sort_order ? String(draft.sort_order) : ""}
                onChange={(e) => set("sort_order", intFromInput(e.target.value))}
                placeholder="0"
              />
              <p className="text-xs text-muted-foreground">
                Lower shows first (after featured).
              </p>
              {errors.sort_order && (
                <p className="text-sm text-destructive">{errors.sort_order}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="rc-featured">Featured</Label>
              <div className="flex h-10 items-center gap-2">
                <Switch
                  id="rc-featured"
                  checked={!!draft.featured}
                  onCheckedChange={(v) => set("featured", v)}
                />
                <span className="text-sm text-muted-foreground">
                  {draft.featured ? "Shown first with a badge" : "Not featured"}
                </span>
              </div>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onCancel} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={() => onSave(draft)} disabled={!ok || saving}>
            {saving ? "Saving…" : item ? "Save changes" : "Create reward"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Page ────────────────────────────────────────────────────────

export default function RewardsCatalogAdminPage() {
  const queryClient = useQueryClient();
  const accessToken = useAuthStore((s) => s.accessToken);
  const canAccess = canAccessGeneralAdminControls(accessToken);

  const [showCreate, setShowCreate] = useState(false);
  const [editItem, setEditItem] = useState<AdminCatalogItem | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<AdminCatalogItem | null>(null);

  const catalogQ = useQuery({
    queryKey: ["admin", "rewards", "catalog"],
    queryFn: listAdminRewardsCatalog,
    retry: false,
    enabled: canAccess,
  });

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["admin", "rewards", "catalog"] });

  const createMut = useMutation({
    mutationFn: (data: AdminCatalogInput) => createAdminRewardsCatalogItem(data),
    onSuccess: () => {
      toast.success("Reward created");
      setShowCreate(false);
      invalidate();
    },
    onError: (e: unknown) =>
      toast.error(e instanceof ApiError ? e.detail : "Create failed"),
  });

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: AdminCatalogInput }) =>
      updateAdminRewardsCatalogItem(id, data),
    onSuccess: () => {
      toast.success("Reward updated");
      setEditItem(null);
      invalidate();
    },
    onError: (e: unknown) =>
      toast.error(e instanceof ApiError ? e.detail : "Update failed"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteAdminRewardsCatalogItem(id),
    onSuccess: () => {
      toast.success("Reward deleted");
      setDeleteTarget(null);
      invalidate();
    },
    onError: (e: unknown) =>
      toast.error(e instanceof ApiError ? e.detail : "Delete failed"),
  });

  const toggleActive = (item: AdminCatalogItem) =>
    updateMut.mutate({
      id: item.id,
      data: {
        name: item.name,
        description: item.description,
        cost_points: item.cost_points,
        value_cents: item.value_cents,
        kind: item.kind,
        active: !item.active,
        stock_limit: item.stock_limit ?? null,
        featured: item.featured ?? false,
        sort_order: item.sort_order ?? 0,
      },
    });

  const handleSave = (data: AdminCatalogInput) => {
    if (editItem) updateMut.mutate({ id: editItem.id, data });
    else createMut.mutate(data);
  };

  const items = useMemo(
    () => sortCatalog(catalogQ.data?.rewards ?? []),
    [catalogQ.data],
  );
  const notAvailable = is404(catalogQ.error);

  if (!canAccess) {
    return (
      <div className="mx-auto w-full max-w-5xl p-4 sm:p-6">
        <PageHeader title="Rewards Catalog" />
        <p className="text-muted-foreground">
          You do not have permission to manage the rewards catalog.
        </p>
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Rewards Catalog"
        description="Manage the redeemable rewards users see on their Rewards page. Deactivated rewards are hidden from users."
        actions={
          <Button
            onClick={() => {
              setEditItem(null);
              setShowCreate(true);
            }}
          >
            <Plus className="mr-2 h-4 w-4" /> Create reward
          </Button>
        }
      />

      {catalogQ.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading catalog…</p>
      ) : notAvailable ? (
        <div className="rounded-lg border border-dashed p-8 text-center">
          <Gift className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">
            The rewards catalog admin API is not available yet. This surface will
            populate once the backend endpoints ship.
          </p>
        </div>
      ) : catalogQ.isError ? (
        <div className="rounded-lg border border-dashed p-8 text-center">
          <p className="text-sm text-muted-foreground">
            Could not load the rewards catalog. Please try again.
          </p>
        </div>
      ) : items.length === 0 ? (
        <div className="rounded-lg border border-dashed p-8 text-center">
          <Gift className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">
            No rewards in the catalog yet. Create the first redeemable reward.
          </p>
        </div>
      ) : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead className="text-right">Order</TableHead>
                <TableHead>Cost</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead className="text-right">Stock</TableHead>
                <TableHead className="text-right">Redeemed</TableHead>
                <TableHead>Active</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((item) => (
                <TableRow key={item.id} className={item.active ? "" : "opacity-60"}>
                  <TableCell>
                    <div className="flex items-center gap-1.5">
                      <span className="font-medium">{item.name}</span>
                      {item.featured ? (
                        <Badge className="gap-1 px-1.5 py-0">
                          <Star className="h-3 w-3 fill-current" /> Featured
                        </Badge>
                      ) : null}
                    </div>
                    {item.description && (
                      <div className="text-xs text-muted-foreground line-clamp-2">
                        {item.description}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">
                    {item.sort_order ?? 0}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    {formatPoints(item.cost_points)}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    {formatCents(item.value_cents)}
                  </TableCell>
                  <TableCell>
                    <Badge variant={item.kind === "cash" ? "default" : "secondary"}>
                      {item.kind}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">
                    {item.stock_limit === null || item.stock_limit === undefined ? (
                      <span className="text-muted-foreground">∞</span>
                    ) : (
                      <span className={remainingStock(item) === 0 ? "text-destructive" : ""}>
                        {remainingStock(item)}/{item.stock_limit}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">
                    {item.redeemed_count ?? 0}
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={item.active}
                      onCheckedChange={() => toggleActive(item)}
                      disabled={updateMut.isPending}
                      aria-label={`Toggle ${item.name} active`}
                    />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setShowCreate(false);
                          setEditItem(item);
                        }}
                      >
                        Edit
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive"
                        onClick={() => setDeleteTarget(item)}
                      >
                        Delete
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <CatalogItemDialog
        open={showCreate || !!editItem}
        item={editItem}
        onSave={handleSave}
        onCancel={() => {
          setShowCreate(false);
          setEditItem(null);
        }}
        saving={createMut.isPending || updateMut.isPending}
      />

      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(o) => (!o ? setDeleteTarget(null) : undefined)}
        title="Delete reward?"
        description={
          deleteTarget
            ? `"${deleteTarget.name}" will be removed from the catalog. This cannot be undone.`
            : undefined
        }
        variant="danger"
        confirmLabel="Delete"
        loading={deleteMut.isPending}
        onConfirm={() => deleteTarget && deleteMut.mutate(deleteTarget.id)}
      />
    </div>
  );
}
