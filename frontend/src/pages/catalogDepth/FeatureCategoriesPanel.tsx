import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Tags, Trash2 } from "lucide-react";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
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
  addFeatureValue,
  createFeatureCategory,
  deleteFeatureCategory,
  deleteFeatureValue,
  listFeatureCategories,
  formatDeltaCents,
  type FeatureCategory,
} from "@/api/endpoints/productDepth";

/**
 * Manage reusable feature axes (e.g. Color, Size) and their values
 * (e.g. Red +$0.00, XL +$2.00). These axes are attached to virtual products
 * to generate variants (see ItemDepthPanel).
 */
export function FeatureCategoriesPanel() {
  const qc = useQueryClient();
  const [showNew, setShowNew] = useState(false);
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");

  const query = useQuery({
    queryKey: ["catalogDepth", "featureCategories"],
    queryFn: async () => (await listFeatureCategories(true)).feature_categories,
    staleTime: 20_000,
    retry: false,
  });

  const err = query.error as ApiError | undefined;
  const flagOff = err?.status === 404;

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["catalogDepth", "featureCategories"] });

  const createMut = useMutation({
    mutationFn: () =>
      createFeatureCategory({ name: name.trim(), description: desc.trim() || null }),
    onSuccess: () => {
      toast.success("Feature category created");
      setShowNew(false);
      setName("");
      setDesc("");
      invalidate();
    },
    onError: (e: ApiError) =>
      toast.error(e.detail || "Failed to create feature category"),
  });

  const deleteMut = useMutation({
    mutationFn: (fcId: string) => deleteFeatureCategory(fcId),
    onSuccess: () => {
      toast.success("Feature category deleted");
      invalidate();
    },
    onError: (e: ApiError) =>
      toast.error(e.detail || "Failed to delete feature category"),
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <Tags className="h-4 w-4" /> Feature Categories
          </CardTitle>
          <CardDescription>
            Define feature axes (Color, Size) and their values with price deltas.
          </CardDescription>
        </div>
        <Button size="sm" onClick={() => setShowNew(true)} disabled={flagOff}>
          <Plus className="mr-1 h-4 w-4" /> New
        </Button>
      </CardHeader>
      <CardContent>
        {query.isLoading ? (
          <div className="space-y-2">
            {[0, 1].map((i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : flagOff ? (
          <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
            Product depth is not enabled on this platform. Ask an operator to
            enable the <code className="font-mono">product_depth</code> feature
            flag to manage feature categories and variants.
          </div>
        ) : err ? (
          <div className="rounded-md border border-dashed p-8 text-center text-sm text-destructive">
            {err.detail}
          </div>
        ) : !query.data || query.data.length === 0 ? (
          <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
            No feature categories yet. Create one (e.g. &ldquo;Color&rdquo;) to
            start building product variants.
          </div>
        ) : (
          <div className="space-y-4">
            {query.data.map((fc) => (
              <FeatureCategoryCard
                key={fc.feature_category_id}
                fc={fc}
                onDelete={() => deleteMut.mutate(fc.feature_category_id)}
                onChanged={invalidate}
              />
            ))}
          </div>
        )}
      </CardContent>

      <Dialog open={showNew} onOpenChange={setShowNew}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Feature Category</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="fc-name">Name</Label>
              <Input
                id="fc-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Color"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="fc-desc">Description</Label>
              <Textarea
                id="fc-desc"
                value={desc}
                onChange={(e) => setDesc(e.target.value)}
                placeholder="Optional"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowNew(false)}>
              Cancel
            </Button>
            <Button
              disabled={!name.trim() || createMut.isPending}
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

function FeatureCategoryCard({
  fc,
  onDelete,
  onChanged,
}: {
  fc: FeatureCategory;
  onDelete: () => void;
  onChanged: () => void;
}) {
  const [valName, setValName] = useState("");
  const [valDelta, setValDelta] = useState("");

  const addMut = useMutation({
    mutationFn: () => {
      const cents = Math.round(parseFloat(valDelta || "0") * 100);
      return addFeatureValue(fc.feature_category_id, {
        name: valName.trim(),
        price_delta_cents: Number.isFinite(cents) ? cents : 0,
      });
    },
    onSuccess: () => {
      toast.success("Value added");
      setValName("");
      setValDelta("");
      onChanged();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to add value"),
  });

  const delValMut = useMutation({
    mutationFn: (fvId: string) => deleteFeatureValue(fc.feature_category_id, fvId),
    onSuccess: () => {
      toast.success("Value removed");
      onChanged();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to remove value"),
  });

  const values = fc.values ?? [];

  return (
    <div className="rounded-lg border p-4">
      <div className="mb-3 flex items-start justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-medium">{fc.name}</span>
            <Badge variant="secondary">{values.length} values</Badge>
          </div>
          {fc.description && (
            <p className="mt-0.5 text-xs text-muted-foreground">{fc.description}</p>
          )}
        </div>
        <Button
          size="icon"
          variant="ghost"
          className="h-8 w-8 text-destructive"
          title="Delete feature category"
          onClick={onDelete}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>

      {values.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Value</TableHead>
              <TableHead className="text-right">Price Delta</TableHead>
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {values.map((v) => (
              <TableRow key={v.feature_value_id}>
                <TableCell>{v.name}</TableCell>
                <TableCell className="text-right tabular-nums">
                  {formatDeltaCents(v.price_delta_cents)}
                </TableCell>
                <TableCell>
                  <Button
                    size="icon"
                    variant="ghost"
                    className="h-7 w-7 text-destructive"
                    title="Remove value"
                    onClick={() => delValMut.mutate(v.feature_value_id)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <div className="mt-3 flex flex-wrap items-end gap-2">
        <div className="flex-1 space-y-1">
          <Label className="text-xs">Value name</Label>
          <Input
            value={valName}
            onChange={(e) => setValName(e.target.value)}
            placeholder="e.g. Red"
          />
        </div>
        <div className="w-32 space-y-1">
          <Label className="text-xs">Delta (USD)</Label>
          <Input
            type="number"
            step="0.01"
            value={valDelta}
            onChange={(e) => setValDelta(e.target.value)}
            placeholder="0.00"
          />
        </div>
        <Button
          variant="outline"
          disabled={!valName.trim() || addMut.isPending}
          onClick={() => addMut.mutate()}
        >
          <Plus className="mr-1 h-4 w-4" /> Add
        </Button>
      </div>
    </div>
  );
}
