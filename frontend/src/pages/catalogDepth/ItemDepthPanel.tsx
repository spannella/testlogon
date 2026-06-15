import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Boxes, DollarSign, Layers, Plus, Tags, Trash2 } from "lucide-react";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import { ApiError } from "@/api/client";
import {
  addBundleComponent,
  addPriceComponent,
  attachFeatureCategory,
  createVariant,
  deleteVariant,
  detachFeatureCategory,
  getProductType,
  listBundleComponents,
  listFeatureCategories,
  listItemFeatures,
  listPriceComponents,
  listVariants,
  removeBundleComponent,
  setProductType,
  formatCents,
  formatDeltaCents,
  type FeatureCategory,
  type PriceType,
  type ProductType,
} from "@/api/endpoints/productDepth";

const PRODUCT_TYPES: ProductType[] = [
  "standalone",
  "virtual",
  "variant",
  "bundle",
  "kit",
  "digital",
];

const PRICE_TYPES: PriceType[] = [
  "LIST",
  "DEFAULT",
  "PROMO",
  "COMPETITIVE",
  "MINIMUM",
  "AVERAGE_COST",
];

export function ItemDepthPanel({
  itemId,
  itemName,
}: {
  itemId: string;
  itemName: string;
}) {
  const qc = useQueryClient();

  const typeQuery = useQuery({
    queryKey: ["catalogDepth", "productType", itemId],
    queryFn: () => getProductType(itemId),
    retry: false,
  });

  const typeErr = typeQuery.error as ApiError | undefined;
  const flagOff = typeErr?.status === 404;

  const setTypeMut = useMutation({
    mutationFn: (pt: ProductType) => setProductType(itemId, pt),
    onSuccess: () => {
      toast.success("Product type updated");
      qc.invalidateQueries({ queryKey: ["catalogDepth", "productType", itemId] });
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to set product type"),
  });

  const productType = typeQuery.data?.product_type ?? "standalone";

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Layers className="h-4 w-4" /> {itemName || "Item"}
          </CardTitle>
          <CardDescription className="font-mono text-xs">{itemId}</CardDescription>
        </CardHeader>
        <CardContent>
          {flagOff ? (
            <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
              Product depth is not enabled on this platform. Enable the
              <code className="mx-1 font-mono">product_depth</code> feature flag
              to manage product types, variants, and price components.
            </div>
          ) : typeQuery.isLoading ? (
            <Skeleton className="h-10 w-48" />
          ) : (
            <div className="flex flex-wrap items-center gap-3">
              <Label className="text-sm">Product type</Label>
              <Select
                value={productType}
                onValueChange={(v) => setTypeMut.mutate(v as ProductType)}
              >
                <SelectTrigger className="w-44">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PRODUCT_TYPES.map((pt) => (
                    <SelectItem key={pt} value={pt}>
                      {pt}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Badge variant="secondary">{productType}</Badge>
            </div>
          )}
        </CardContent>
      </Card>

      {!flagOff && (
        <>
          <FeaturesSection itemId={itemId} />
          {productType === "virtual" && <VariantsSection itemId={itemId} />}
          {(productType === "bundle" || productType === "kit") && (
            <BundleComponentsSection itemId={itemId} />
          )}
          <PriceComponentsSection itemId={itemId} />
        </>
      )}
    </div>
  );
}

// ─── Attached features ───────────────────────────────────────────────────────

function FeaturesSection({ itemId }: { itemId: string }) {
  const qc = useQueryClient();
  const [attachId, setAttachId] = useState<string>("");

  const featuresQuery = useQuery({
    queryKey: ["catalogDepth", "itemFeatures", itemId],
    queryFn: async () => (await listItemFeatures(itemId)).features,
    retry: false,
  });

  const allFcQuery = useQuery({
    queryKey: ["catalogDepth", "featureCategories"],
    queryFn: async () => (await listFeatureCategories(true)).feature_categories,
    retry: false,
  });

  const attached = featuresQuery.data ?? [];
  const attachedIds = useMemo(
    () => new Set(attached.map((f) => f.feature_category_id)),
    [attached],
  );
  const available = (allFcQuery.data ?? []).filter(
    (f) => !attachedIds.has(f.feature_category_id),
  );

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["catalogDepth", "itemFeatures", itemId] });

  const attachMut = useMutation({
    mutationFn: () => attachFeatureCategory(itemId, attachId),
    onSuccess: () => {
      toast.success("Feature category attached");
      setAttachId("");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to attach"),
  });

  const detachMut = useMutation({
    mutationFn: (fcId: string) => detachFeatureCategory(itemId, fcId),
    onSuccess: () => {
      toast.success("Feature category detached");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to detach"),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Tags className="h-4 w-4" /> Feature Axes
        </CardTitle>
        <CardDescription>
          Attach feature categories to enable variant generation.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {featuresQuery.isLoading ? (
          <Skeleton className="h-10 w-full" />
        ) : attached.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No feature axes attached.
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {attached.map((fc: FeatureCategory) => (
              <Badge
                key={fc.feature_category_id}
                variant="outline"
                className="gap-1.5 py-1 pl-2.5 pr-1"
              >
                {fc.name}
                <span className="text-muted-foreground">
                  ({(fc.values ?? []).length})
                </span>
                <button
                  type="button"
                  className="ml-0.5 rounded-sm p-0.5 hover:bg-muted"
                  title="Detach"
                  onClick={() => detachMut.mutate(fc.feature_category_id)}
                >
                  <Trash2 className="h-3 w-3" />
                </button>
              </Badge>
            ))}
          </div>
        )}

        <div className="flex items-end gap-2">
          <div className="flex-1 space-y-1">
            <Label className="text-xs">Attach feature category</Label>
            <Select value={attachId} onValueChange={setAttachId}>
              <SelectTrigger>
                <SelectValue placeholder="Select a feature category" />
              </SelectTrigger>
              <SelectContent>
                {available.length === 0 ? (
                  <div className="px-2 py-1.5 text-sm text-muted-foreground">
                    No more available
                  </div>
                ) : (
                  available.map((fc) => (
                    <SelectItem
                      key={fc.feature_category_id}
                      value={fc.feature_category_id}
                    >
                      {fc.name}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
          </div>
          <Button
            variant="outline"
            disabled={!attachId || attachMut.isPending}
            onClick={() => attachMut.mutate()}
          >
            <Plus className="mr-1 h-4 w-4" /> Attach
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Variants ────────────────────────────────────────────────────────────────

function VariantsSection({ itemId }: { itemId: string }) {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [selection, setSelection] = useState<Record<string, string>>({});
  const [sku, setSku] = useState("");

  const variantsQuery = useQuery({
    queryKey: ["catalogDepth", "variants", itemId],
    queryFn: async () => (await listVariants(itemId)).variants,
    retry: false,
  });

  const featuresQuery = useQuery({
    queryKey: ["catalogDepth", "itemFeatures", itemId],
    queryFn: async () => (await listItemFeatures(itemId)).features,
    retry: false,
  });

  const axes = featuresQuery.data ?? [];

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["catalogDepth", "variants", itemId] });

  const createMut = useMutation({
    mutationFn: () =>
      createVariant(itemId, {
        feature_values: selection,
        sku_override: sku.trim() || undefined,
      }),
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
    mutationFn: (variantId: string) => deleteVariant(itemId, variantId),
    onSuccess: () => {
      toast.success("Variant deleted");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to delete variant"),
  });

  const allAxesSelected =
    axes.length > 0 && axes.every((a) => selection[a.feature_category_id]);

  const labelForFv = (fcId: string, fvId: string): string => {
    const fc = axes.find((a) => a.feature_category_id === fcId);
    const fv = (fc?.values ?? []).find((v) => v.feature_value_id === fvId);
    return fv ? `${fc?.name}: ${fv.name}` : `${fcId}: ${fvId}`;
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <Layers className="h-4 w-4" /> Variants
          </CardTitle>
          <CardDescription>
            Concrete sellable combinations of the attached feature axes.
          </CardDescription>
        </div>
        <Button
          size="sm"
          disabled={axes.length === 0}
          onClick={() => setShowCreate(true)}
        >
          <Plus className="mr-1 h-4 w-4" /> New Variant
        </Button>
      </CardHeader>
      <CardContent>
        {axes.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Attach at least one feature axis before creating variants.
          </p>
        ) : variantsQuery.isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : !variantsQuery.data || variantsQuery.data.length === 0 ? (
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
              {variantsQuery.data.map((v) => (
                <TableRow key={v.variant_id}>
                  <TableCell className="font-mono text-xs">{v.sku}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(v.feature_values).map(([fcId, fvId]) => (
                        <Badge
                          key={fcId}
                          variant="secondary"
                          className="font-normal"
                        >
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
      </CardContent>

      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Variant</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            {axes.map((axis) => (
              <div key={axis.feature_category_id} className="space-y-1.5">
                <Label className="text-xs">{axis.name}</Label>
                <Select
                  value={selection[axis.feature_category_id] ?? ""}
                  onValueChange={(v) =>
                    setSelection((p) => ({ ...p, [axis.feature_category_id]: v }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder={`Choose ${axis.name}`} />
                  </SelectTrigger>
                  <SelectContent>
                    {(axis.values ?? []).map((val) => (
                      <SelectItem
                        key={val.feature_value_id}
                        value={val.feature_value_id}
                      >
                        {val.name} ({formatDeltaCents(val.price_delta_cents)})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            ))}
            <div className="space-y-1.5">
              <Label htmlFor="variant-sku" className="text-xs">
                SKU override (optional)
              </Label>
              <Input
                id="variant-sku"
                value={sku}
                onChange={(e) => setSku(e.target.value)}
                placeholder="auto-generated if blank"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button
              disabled={!allAxesSelected || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

// ─── Bundle components ───────────────────────────────────────────────────────

function BundleComponentsSection({ itemId }: { itemId: string }) {
  const qc = useQueryClient();
  const [componentId, setComponentId] = useState("");
  const [quantity, setQuantity] = useState("1");

  const componentsQuery = useQuery({
    queryKey: ["catalogDepth", "bundleComponents", itemId],
    queryFn: () => listBundleComponents(itemId),
    retry: false,
  });

  const err = componentsQuery.error as ApiError | undefined;
  const flagOff = err?.status === 404;

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["catalogDepth", "bundleComponents", itemId] });

  const addMut = useMutation({
    mutationFn: () => {
      const qty = Math.max(1, Math.round(parseInt(quantity || "1", 10) || 1));
      return addBundleComponent(itemId, {
        component_item_id: componentId.trim(),
        quantity: qty,
      });
    },
    onSuccess: () => {
      toast.success("Component added");
      setComponentId("");
      setQuantity("1");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to add component"),
  });

  const removeMut = useMutation({
    mutationFn: (cid: string) => removeBundleComponent(itemId, cid),
    onSuccess: () => {
      toast.success("Component removed");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to remove component"),
  });

  const components = componentsQuery.data?.components ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Boxes className="h-4 w-4" /> Bundle Components
        </CardTitle>
        <CardDescription>
          The items included in this bundle/kit and their quantities.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {flagOff ? (
          <p className="text-sm text-muted-foreground">
            Bundle composition is not enabled on this platform.
          </p>
        ) : componentsQuery.isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : components.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No components yet. Add component items below.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>SKU</TableHead>
                <TableHead className="text-right">Qty</TableHead>
                <TableHead className="text-right">Price</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {components.map((c) => (
                <TableRow key={c.component_item_id}>
                  <TableCell>{c.component_name}</TableCell>
                  <TableCell className="font-mono text-xs">{c.component_sku}</TableCell>
                  <TableCell className="text-right tabular-nums">{c.quantity}</TableCell>
                  <TableCell className="text-right tabular-nums">
                    {formatCents(c.component_price_cents)}
                  </TableCell>
                  <TableCell>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-7 w-7 text-destructive"
                      title="Remove component"
                      disabled={removeMut.isPending}
                      onClick={() => removeMut.mutate(c.component_item_id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        {!flagOff && (
          <div className="flex flex-wrap items-end gap-2">
            <div className="flex-1 space-y-1">
              <Label htmlFor="bundle-component-id" className="text-xs">
                Component item ID
              </Label>
              <Input
                id="bundle-component-id"
                value={componentId}
                placeholder="item_…"
                onChange={(e) => setComponentId(e.target.value)}
              />
            </div>
            <div className="w-24 space-y-1">
              <Label htmlFor="bundle-component-qty" className="text-xs">
                Qty
              </Label>
              <Input
                id="bundle-component-qty"
                type="number"
                min="1"
                step="1"
                value={quantity}
                onChange={(e) => setQuantity(e.target.value)}
              />
            </div>
            <Button
              variant="outline"
              disabled={!componentId.trim() || addMut.isPending}
              onClick={() => addMut.mutate()}
            >
              <Plus className="mr-1 h-4 w-4" /> Add
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Price components ────────────────────────────────────────────────────────

function PriceComponentsSection({ itemId }: { itemId: string }) {
  const qc = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);
  const [priceType, setPriceType] = useState<PriceType>("DEFAULT");
  const [amount, setAmount] = useState("");
  const [effectiveAt, setEffectiveAt] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  const componentsQuery = useQuery({
    queryKey: ["catalogDepth", "priceComponents", itemId],
    queryFn: async () => (await listPriceComponents(itemId)).components,
    retry: false,
  });

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["catalogDepth", "priceComponents", itemId] });

  const toEpoch = (local: string): number => {
    if (!local) return Math.floor(Date.now() / 1000);
    const ms = new Date(local).getTime();
    return Number.isFinite(ms) ? Math.floor(ms / 1000) : Math.floor(Date.now() / 1000);
  };

  const addMut = useMutation({
    mutationFn: () => {
      const cents = Math.round(parseFloat(amount || "0") * 100);
      return addPriceComponent(itemId, {
        price_type: priceType,
        amount_cents: Number.isFinite(cents) ? cents : 0,
        currency: "USD",
        effective_at: toEpoch(effectiveAt),
        expires_at: expiresAt ? toEpoch(expiresAt) : null,
      });
    },
    onSuccess: () => {
      toast.success("Price component added");
      setShowAdd(false);
      setAmount("");
      setEffectiveAt("");
      setExpiresAt("");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to add price component"),
  });

  const fmtTs = (ts?: number | null) =>
    ts == null ? "—" : new Date(ts * 1000).toLocaleString();

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <DollarSign className="h-4 w-4" /> Price Components
          </CardTitle>
          <CardDescription>
            Time-bounded prices by type (LIST, PROMO, etc.).
          </CardDescription>
        </div>
        <Button size="sm" onClick={() => setShowAdd(true)}>
          <Plus className="mr-1 h-4 w-4" /> Add
        </Button>
      </CardHeader>
      <CardContent>
        {componentsQuery.isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : !componentsQuery.data || componentsQuery.data.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No price components. The item falls back to its scalar price.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead className="text-right">Amount</TableHead>
                <TableHead>Effective</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {componentsQuery.data.map((c) => (
                <TableRow key={c.price_component_id}>
                  <TableCell>
                    <Badge variant="outline">{c.price_type}</Badge>
                  </TableCell>
                  <TableCell className="text-right tabular-nums font-medium">
                    {formatCents(c.amount_cents, c.currency)}
                  </TableCell>
                  <TableCell className="text-xs">{fmtTs(c.effective_at)}</TableCell>
                  <TableCell className="text-xs">{fmtTs(c.expires_at)}</TableCell>
                  <TableCell>
                    {c.is_active ? (
                      <Badge>active</Badge>
                    ) : (
                      <Badge variant="secondary">inactive</Badge>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>

      <Dialog open={showAdd} onOpenChange={setShowAdd}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Price Component</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label className="text-xs">Price type</Label>
              <Select
                value={priceType}
                onValueChange={(v) => setPriceType(v as PriceType)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PRICE_TYPES.map((pt) => (
                    <SelectItem key={pt} value={pt}>
                      {pt}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pc-amount" className="text-xs">
                Amount (USD)
              </Label>
              <Input
                id="pc-amount"
                type="number"
                min="0"
                step="0.01"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="0.00"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pc-eff" className="text-xs">
                Effective at
              </Label>
              <Input
                id="pc-eff"
                type="datetime-local"
                value={effectiveAt}
                onChange={(e) => setEffectiveAt(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="pc-exp" className="text-xs">
                Expires at (optional)
              </Label>
              <Input
                id="pc-exp"
                type="datetime-local"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAdd(false)}>
              Cancel
            </Button>
            <Button disabled={!amount || addMut.isPending} onClick={() => addMut.mutate()}>
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
