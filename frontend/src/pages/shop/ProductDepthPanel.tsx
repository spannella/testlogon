/**
 * ProductDepthPanel (PRD-015)
 *
 * Embeddable panel that renders product depth management for a single catalog
 * item.  Tabs: Features | Variants | Bundle | Associations.
 *
 * The panel is intentionally self-contained so it can be:
 *  - Embedded directly in ItemEditor.tsx
 *  - Rendered standalone via CatalogDepthPage (shop/admin/CatalogDepthPage.tsx)
 *
 * Feature-gated: all depth endpoints return 501 when product_depth_enabled is
 * off on the backend.  Each section handles 501/404 with a friendly empty
 * state so the flag toggle doesn't break the UI.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Link2, Package, Plus, Shapes, Trash2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import { ApiError } from "@/api/client";
import {
  addAssociation,
  addItemFeatureValue,
  createItemFeatureCategory,
  createItemVariant,
  deleteItemFeatureCategory,
  deleteItemVariant,
  expandBundle,
  formatCents,
  formatDeltaCents,
  getItemProductFeatures,
  listAssociations,
  listItemVariants,
  removeAssociation,
} from "@/api/endpoints/productDepth";
import type {
  ProductAssoc,
  ProductFeatureCategoryOut,
  ProductFeatureValueOut,
} from "@/api/types";

const ASSOC_TYPES = ["substitute", "complement", "upgrade", "manufacture_source"] as const;
type AssocType = (typeof ASSOC_TYPES)[number];

// ─────────────────────────────────────────────────────────────────────────────
// Public component
// ─────────────────────────────────────────────────────────────────────────────

export interface ProductDepthPanelProps {
  itemId: string;
  itemName?: string;
}

export function ProductDepthPanel({ itemId, itemName }: ProductDepthPanelProps) {
  return (
    <div className="space-y-2">
      {itemName && (
        <p className="text-sm font-medium text-muted-foreground">
          Item: <span className="font-mono">{itemId}</span> — {itemName}
        </p>
      )}
      <Tabs defaultValue="features">
        <TabsList className="flex-wrap">
          <TabsTrigger value="features">
            <Shapes className="mr-1.5 h-3.5 w-3.5" /> Features
          </TabsTrigger>
          <TabsTrigger value="variants">
            <Package className="mr-1.5 h-3.5 w-3.5" /> Variants
          </TabsTrigger>
          <TabsTrigger value="bundle">
            <Package className="mr-1.5 h-3.5 w-3.5" /> Bundle
          </TabsTrigger>
          <TabsTrigger value="associations">
            <Link2 className="mr-1.5 h-3.5 w-3.5" /> Associations
          </TabsTrigger>
        </TabsList>

        <TabsContent value="features" className="mt-3">
          <FeaturesTab itemId={itemId} />
        </TabsContent>
        <TabsContent value="variants" className="mt-3">
          <VariantsTab itemId={itemId} />
        </TabsContent>
        <TabsContent value="bundle" className="mt-3">
          <BundleTab itemId={itemId} />
        </TabsContent>
        <TabsContent value="associations" className="mt-3">
          <AssociationsTab itemId={itemId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Features tab
// ─────────────────────────────────────────────────────────────────────────────

function FeaturesTab({ itemId }: { itemId: string }) {
  const qc = useQueryClient();
  const [newCatName, setNewCatName] = useState("");
  const [addingValueFor, setAddingValueFor] = useState<string | null>(null);
  const [newValue, setNewValue] = useState("");
  const [newDelta, setNewDelta] = useState("0");

  const featQuery = useQuery({
    queryKey: ["productDepth", "itemFeatures", itemId],
    queryFn: () => getItemProductFeatures(itemId),
    retry: false,
  });

  const err = featQuery.error as ApiError | undefined;
  const flagOff = err?.status === 501 || err?.status === 404;

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["productDepth", "itemFeatures", itemId] });

  const addCatMut = useMutation({
    mutationFn: () => createItemFeatureCategory(itemId, newCatName.trim()),
    onSuccess: () => {
      toast.success("Feature category created");
      setNewCatName("");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to create category"),
  });

  const delCatMut = useMutation({
    mutationFn: (fcId: string) => deleteItemFeatureCategory(itemId, fcId),
    onSuccess: () => {
      toast.success("Feature category deleted");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to delete category"),
  });

  const addValMut = useMutation({
    mutationFn: ({ fcId, value, delta }: { fcId: string; value: string; delta: number }) =>
      addItemFeatureValue(itemId, fcId, value, delta),
    onSuccess: () => {
      toast.success("Feature value added");
      setAddingValueFor(null);
      setNewValue("");
      setNewDelta("0");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to add value"),
  });

  if (flagOff) {
    return <FlagOffNotice feature="product_depth_enabled" />;
  }

  const categories: ProductFeatureCategoryOut[] = featQuery.data?.feature_categories ?? [];
  const values: ProductFeatureValueOut[] = featQuery.data?.values ?? [];

  const valuesFor = (fcId: string) => values.filter((v) => v.feature_category_id === fcId);

  return (
    <div className="space-y-4">
      {featQuery.isLoading ? (
        <Skeleton className="h-24 w-full" />
      ) : categories.length === 0 ? (
        <p className="text-sm text-muted-foreground">No feature categories yet.</p>
      ) : (
        categories.map((fc) => (
          <Card key={fc.feature_category_id}>
            <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{fc.name}</CardTitle>
              <Button
                size="icon"
                variant="ghost"
                className="h-6 w-6 text-destructive"
                title="Delete category"
                onClick={() => delCatMut.mutate(fc.feature_category_id)}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex flex-wrap gap-1.5">
                {valuesFor(fc.feature_category_id).map((v) => (
                  <Badge key={v.feature_value_id} variant="secondary">
                    {v.value}
                    {v.price_delta_cents !== 0 && (
                      <span className="ml-1 text-xs text-muted-foreground">
                        ({formatDeltaCents(v.price_delta_cents)})
                      </span>
                    )}
                  </Badge>
                ))}
              </div>
              {addingValueFor === fc.feature_category_id ? (
                <div className="flex flex-wrap items-end gap-2">
                  <div className="flex-1 space-y-1">
                    <Label className="text-xs">Value</Label>
                    <Input
                      value={newValue}
                      onChange={(e) => setNewValue(e.target.value)}
                      placeholder='e.g. "Red"'
                      className="h-8 text-sm"
                    />
                  </div>
                  <div className="w-28 space-y-1">
                    <Label className="text-xs">Price delta (¢)</Label>
                    <Input
                      type="number"
                      value={newDelta}
                      onChange={(e) => setNewDelta(e.target.value)}
                      className="h-8 text-sm"
                    />
                  </div>
                  <Button
                    size="sm"
                    disabled={!newValue.trim() || addValMut.isPending}
                    onClick={() =>
                      addValMut.mutate({
                        fcId: fc.feature_category_id,
                        value: newValue.trim(),
                        delta: parseInt(newDelta || "0", 10) || 0,
                      })
                    }
                  >
                    Add
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setAddingValueFor(null)}
                  >
                    Cancel
                  </Button>
                </div>
              ) : (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs"
                  onClick={() => setAddingValueFor(fc.feature_category_id)}
                >
                  <Plus className="mr-1 h-3 w-3" /> Add value
                </Button>
              )}
            </CardContent>
          </Card>
        ))
      )}

      <div className="flex items-end gap-2 pt-1">
        <div className="flex-1 space-y-1">
          <Label className="text-xs">New feature category</Label>
          <Input
            value={newCatName}
            onChange={(e) => setNewCatName(e.target.value)}
            placeholder='e.g. "Color", "Size"'
            className="h-8 text-sm"
          />
        </div>
        <Button
          size="sm"
          disabled={!newCatName.trim() || addCatMut.isPending}
          onClick={() => addCatMut.mutate()}
        >
          <Plus className="mr-1 h-3.5 w-3.5" /> Add category
        </Button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Variants tab
// ─────────────────────────────────────────────────────────────────────────────

function VariantsTab({ itemId }: { itemId: string }) {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [selection, setSelection] = useState<Record<string, string>>({});
  const [sku, setSku] = useState("");

  const variantsQuery = useQuery({
    queryKey: ["productDepth", "itemVariants", itemId],
    queryFn: () => listItemVariants(itemId),
    retry: false,
  });

  const featQuery = useQuery({
    queryKey: ["productDepth", "itemFeatures", itemId],
    queryFn: () => getItemProductFeatures(itemId),
    retry: false,
  });

  const err = variantsQuery.error as ApiError | undefined;
  const flagOff = err?.status === 501 || err?.status === 404;

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["productDepth", "itemVariants", itemId] });

  const createMut = useMutation({
    mutationFn: () => createItemVariant(itemId, selection, sku.trim() || undefined),
    onSuccess: () => {
      toast.success("Variant created");
      setShowCreate(false);
      setSelection({});
      setSku("");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to create variant"),
  });

  const deleteMut = useMutation({
    mutationFn: (variantId: string) => deleteItemVariant(itemId, variantId),
    onSuccess: () => {
      toast.success("Variant deleted");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to delete variant"),
  });

  if (flagOff) {
    return <FlagOffNotice feature="product_depth_enabled" />;
  }

  const categories = featQuery.data?.feature_categories ?? [];
  const values = featQuery.data?.values ?? [];
  const variants = variantsQuery.data?.variants ?? [];

  const labelForFv = (fcId: string, fvId: string) => {
    const fc = categories.find((c) => c.feature_category_id === fcId);
    const fv = values.find((v) => v.feature_value_id === fvId);
    return fv ? `${fc?.name ?? fcId}: ${fv.value}` : fvId;
  };

  const allSelected = categories.length > 0 && categories.every((c) => selection[c.feature_category_id]);

  /** Generate all combinations and create one variant per combo. */
  const generateAllMut = useMutation({
    mutationFn: async () => {
      if (categories.length === 0) return;
      const axes = categories.map((c) => ({
        id: c.feature_category_id,
        vals: values.filter((v) => v.feature_category_id === c.feature_category_id),
      }));
      const combos: Record<string, string>[] = [{}];
      for (const axis of axes) {
        const next: Record<string, string>[] = [];
        for (const combo of combos) {
          for (const val of axis.vals) {
            next.push({ ...combo, [axis.id]: val.feature_value_id });
          }
        }
        combos.splice(0, combos.length, ...next);
      }
      for (const combo of combos) {
        await createItemVariant(itemId, combo);
      }
    },
    onSuccess: () => {
      toast.success("All combinations generated");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to generate variants"),
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          {variants.length} variant{variants.length !== 1 ? "s" : ""}
        </p>
        <div className="flex gap-2">
          {categories.length > 0 && (
            <Button
              size="sm"
              variant="outline"
              disabled={generateAllMut.isPending}
              onClick={() => generateAllMut.mutate()}
            >
              Generate all
            </Button>
          )}
          <Button size="sm" disabled={categories.length === 0} onClick={() => setShowCreate(!showCreate)}>
            <Plus className="mr-1 h-3.5 w-3.5" /> New variant
          </Button>
        </div>
      </div>

      {showCreate && (
        <Card>
          <CardContent className="space-y-3 pt-4">
            {categories.map((c) => (
              <div key={c.feature_category_id} className="space-y-1">
                <Label className="text-xs">{c.name}</Label>
                <Select
                  value={selection[c.feature_category_id] ?? ""}
                  onValueChange={(v) =>
                    setSelection((p) => ({ ...p, [c.feature_category_id]: v }))
                  }
                >
                  <SelectTrigger className="h-8 text-sm">
                    <SelectValue placeholder={`Choose ${c.name}`} />
                  </SelectTrigger>
                  <SelectContent>
                    {values
                      .filter((v) => v.feature_category_id === c.feature_category_id)
                      .map((v) => (
                        <SelectItem key={v.feature_value_id} value={v.feature_value_id}>
                          {v.value} ({formatDeltaCents(v.price_delta_cents)})
                        </SelectItem>
                      ))}
                  </SelectContent>
                </Select>
              </div>
            ))}
            <div className="space-y-1">
              <Label className="text-xs">SKU override (optional)</Label>
              <Input
                value={sku}
                onChange={(e) => setSku(e.target.value)}
                placeholder="auto-generated if blank"
                className="h-8 text-sm"
              />
            </div>
            <div className="flex gap-2">
              <Button
                size="sm"
                disabled={!allSelected || createMut.isPending}
                onClick={() => createMut.mutate()}
              >
                Create
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {variantsQuery.isLoading ? (
        <Skeleton className="h-16 w-full" />
      ) : variants.length === 0 ? (
        <p className="text-sm text-muted-foreground">No variants yet.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>SKU</TableHead>
              <TableHead>Combination</TableHead>
              <TableHead className="text-right">Delta</TableHead>
              <TableHead className="text-right">Effective</TableHead>
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {variants.map((v) => (
              <TableRow key={v.variant_id}>
                <TableCell className="font-mono text-xs">{v.sku}</TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(v.feature_values).map(([fcId, fvId]) => (
                      <Badge key={fcId} variant="secondary" className="font-normal text-xs">
                        {labelForFv(fcId, fvId)}
                      </Badge>
                    ))}
                  </div>
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {formatDeltaCents(v.price_delta_cents)}
                </TableCell>
                <TableCell className="text-right tabular-nums font-medium">
                  {formatCents(v.effective_price_cents)}
                </TableCell>
                <TableCell>
                  <Button
                    size="icon"
                    variant="ghost"
                    className="h-7 w-7 text-destructive"
                    title="Delete variant"
                    onClick={() => deleteMut.mutate(v.variant_id)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Bundle tab
// ─────────────────────────────────────────────────────────────────────────────

function BundleTab({ itemId }: { itemId: string }) {
  const [qty, setQty] = useState("1");

  const expandQuery = useQuery({
    queryKey: ["productDepth", "bundleExpand", itemId, qty],
    queryFn: () => expandBundle(itemId, Math.max(1, parseInt(qty, 10) || 1)),
    retry: false,
    enabled: true,
  });

  const err = expandQuery.error as ApiError | undefined;
  const flagOff = err?.status === 501 || err?.status === 404;

  if (flagOff) {
    return <FlagOffNotice feature="product_depth_enabled" />;
  }

  const data = expandQuery.data;

  return (
    <div className="space-y-3">
      <div className="flex items-end gap-2">
        <div className="w-24 space-y-1">
          <Label className="text-xs">Quantity</Label>
          <Input
            type="number"
            min="1"
            value={qty}
            onChange={(e) => setQty(e.target.value)}
            className="h-8 text-sm"
          />
        </div>
      </div>

      {expandQuery.isLoading ? (
        <Skeleton className="h-24 w-full" />
      ) : !data ? (
        <p className="text-sm text-muted-foreground">
          No bundle data. This item may not be a bundle/kit, or the feature flag
          is off.
        </p>
      ) : (
        <div className="space-y-2">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Component</TableHead>
                <TableHead className="text-right">Unit price</TableHead>
                <TableHead className="text-right">Qty</TableHead>
                <TableHead className="text-right">Line total</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.lines.map((line) => (
                <TableRow key={line.item_id}>
                  <TableCell>
                    <span className="font-medium">{line.name}</span>
                    <span className="ml-1.5 font-mono text-xs text-muted-foreground">
                      {line.item_id}
                    </span>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">
                    {formatCents(line.price_cents)}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{line.qty}</TableCell>
                  <TableCell className="text-right tabular-nums font-medium">
                    {formatCents(line.line_total_cents)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <p className="text-right text-sm font-semibold">
            Bundle total: {formatCents(data.bundle_price_cents)}
          </p>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Associations tab
// ─────────────────────────────────────────────────────────────────────────────

function AssociationsTab({ itemId }: { itemId: string }) {
  const qc = useQueryClient();
  const [assocType, setAssocType] = useState<AssocType>("substitute");
  const [toItemId, setToItemId] = useState("");
  const [filterType, setFilterType] = useState<AssocType | "">("");

  const assocsQuery = useQuery({
    queryKey: ["productDepth", "associations", itemId, filterType],
    queryFn: () => listAssociations(itemId, filterType || undefined),
    retry: false,
  });

  const err = assocsQuery.error as ApiError | undefined;
  const flagOff = err?.status === 501 || err?.status === 404;

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["productDepth", "associations", itemId] });

  const addMut = useMutation({
    mutationFn: () => addAssociation(itemId, assocType, toItemId.trim()),
    onSuccess: () => {
      toast.success("Association added");
      setToItemId("");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to add association"),
  });

  const removeMut = useMutation({
    mutationFn: ({ toId, type }: { toId: string; type: string }) =>
      removeAssociation(itemId, toId, type),
    onSuccess: () => {
      toast.success("Association removed");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to remove association"),
  });

  if (flagOff) {
    return <FlagOffNotice feature="product_depth_enabled" />;
  }

  const assocs: ProductAssoc[] = assocsQuery.data?.associations ?? [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-2">
        <div className="w-40 space-y-1">
          <Label className="text-xs">Filter by type</Label>
          <Select value={filterType} onValueChange={(v) => setFilterType(v as AssocType | "")}>
            <SelectTrigger className="h-8 text-sm">
              <SelectValue placeholder="All" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="">All</SelectItem>
              {ASSOC_TYPES.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {assocsQuery.isLoading ? (
        <Skeleton className="h-16 w-full" />
      ) : assocs.length === 0 ? (
        <p className="text-sm text-muted-foreground">No associations.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Type</TableHead>
              <TableHead>To item</TableHead>
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {assocs.map((a) => (
              <TableRow key={a.assoc_id}>
                <TableCell>
                  <Badge variant="outline">{a.assoc_type}</Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">{a.to_item_id}</TableCell>
                <TableCell>
                  <Button
                    size="icon"
                    variant="ghost"
                    className="h-7 w-7 text-destructive"
                    title="Remove"
                    onClick={() =>
                      removeMut.mutate({ toId: a.to_item_id, type: a.assoc_type })
                    }
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <div className="flex flex-wrap items-end gap-2 pt-1">
        <div className="w-40 space-y-1">
          <Label className="text-xs">Assoc type</Label>
          <Select value={assocType} onValueChange={(v) => setAssocType(v as AssocType)}>
            <SelectTrigger className="h-8 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {ASSOC_TYPES.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex-1 space-y-1">
          <Label className="text-xs">Target item ID</Label>
          <Input
            value={toItemId}
            onChange={(e) => setToItemId(e.target.value)}
            placeholder="item_…"
            className="h-8 text-sm"
          />
        </div>
        <Button
          size="sm"
          disabled={!toItemId.trim() || addMut.isPending}
          onClick={() => addMut.mutate()}
        >
          <Plus className="mr-1 h-3.5 w-3.5" /> Add
        </Button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

function FlagOffNotice({ feature }: { feature: string }) {
  return (
    <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
      The <code className="mx-1 font-mono">{feature}</code> feature flag is off.
      Enable it on the backend to manage this section.
    </div>
  );
}
