import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ChevronDown,
  ChevronRight,
  FolderTree,
  Package,
  Plus,
  Trash2,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

import { ApiError } from "@/api/client";
import {
  createCategory,
  createItem,
  deleteCategory,
  listItems,
  formatCents,
  type CatalogCategory,
  type CatalogItem,
} from "@/api/endpoints/productDepth";

interface Props {
  categories: CatalogCategory[];
  loading: boolean;
  selectedCategoryId: string | null;
  selectedItemId: string | null;
  onSelectCategory: (categoryId: string) => void;
  onSelectItem: (categoryId: string, item: CatalogItem) => void;
}

export function CategoryTreePanel({
  categories,
  loading,
  selectedItemId,
  onSelectCategory,
  onSelectItem,
}: Props) {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showNewCategory, setShowNewCategory] = useState(false);
  const [catName, setCatName] = useState("");
  const [catDesc, setCatDesc] = useState("");
  const [newItemCatId, setNewItemCatId] = useState<string | null>(null);
  const [itemName, setItemName] = useState("");
  const [itemPrice, setItemPrice] = useState("");

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["catalogDepth", "categories"] });

  const createCatMut = useMutation({
    mutationFn: () =>
      createCategory({ name: catName.trim(), description: catDesc.trim() || null }),
    onSuccess: () => {
      toast.success("Category created");
      setShowNewCategory(false);
      setCatName("");
      setCatDesc("");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to create category"),
  });

  const deleteCatMut = useMutation({
    mutationFn: (categoryId: string) => deleteCategory(categoryId, true),
    onSuccess: () => {
      toast.success("Category deleted");
      invalidate();
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to delete category"),
  });

  const createItemMut = useMutation({
    mutationFn: () => {
      const cents = Math.round(parseFloat(itemPrice || "0") * 100);
      return createItem(newItemCatId!, {
        name: itemName.trim(),
        price_cents: Number.isFinite(cents) ? cents : 0,
      });
    },
    onSuccess: (_data, _vars) => {
      toast.success("Item created");
      const catId = newItemCatId!;
      setNewItemCatId(null);
      setItemName("");
      setItemPrice("");
      qc.invalidateQueries({ queryKey: ["catalogDepth", "items", catId] });
    },
    onError: (e: ApiError) => toast.error(e.detail || "Failed to create item"),
  });

  if (loading) {
    return (
      <div className="space-y-2">
        {[0, 1, 2].map((i) => (
          <Skeleton key={i} className="h-9 w-full" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          <FolderTree className="h-3.5 w-3.5" /> {categories.length} categories
        </span>
        <Button size="sm" variant="outline" onClick={() => setShowNewCategory(true)}>
          <Plus className="mr-1 h-3.5 w-3.5" /> Category
        </Button>
      </div>

      {categories.length === 0 ? (
        <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
          No categories yet. Create one to start building your catalog.
        </div>
      ) : (
        <ul className="space-y-1">
          {categories.map((cat) => (
            <CategoryNode
              key={cat.category_id}
              category={cat}
              expanded={!!expanded[cat.category_id]}
              selectedItemId={selectedItemId}
              onToggle={() => {
                setExpanded((p) => ({
                  ...p,
                  [cat.category_id]: !p[cat.category_id],
                }));
                onSelectCategory(cat.category_id);
              }}
              onAddItem={() => setNewItemCatId(cat.category_id)}
              onDelete={() => deleteCatMut.mutate(cat.category_id)}
              onSelectItem={(item) => onSelectItem(cat.category_id, item)}
            />
          ))}
        </ul>
      )}

      {/* New category dialog */}
      <Dialog open={showNewCategory} onOpenChange={setShowNewCategory}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Category</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="cat-name">Name</Label>
              <Input
                id="cat-name"
                value={catName}
                onChange={(e) => setCatName(e.target.value)}
                placeholder="e.g. Apparel"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cat-desc">Description</Label>
              <Textarea
                id="cat-desc"
                value={catDesc}
                onChange={(e) => setCatDesc(e.target.value)}
                placeholder="Optional"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowNewCategory(false)}>
              Cancel
            </Button>
            <Button
              disabled={!catName.trim() || createCatMut.isPending}
              onClick={() => createCatMut.mutate()}
            >
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* New item dialog */}
      <Dialog
        open={newItemCatId !== null}
        onOpenChange={(open) => !open && setNewItemCatId(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Item</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="item-name">Name</Label>
              <Input
                id="item-name"
                value={itemName}
                onChange={(e) => setItemName(e.target.value)}
                placeholder="e.g. Classic T-Shirt"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="item-price">Price (USD)</Label>
              <Input
                id="item-price"
                type="number"
                min="0"
                step="0.01"
                value={itemPrice}
                onChange={(e) => setItemPrice(e.target.value)}
                placeholder="0.00"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setNewItemCatId(null)}>
              Cancel
            </Button>
            <Button
              disabled={!itemName.trim() || createItemMut.isPending}
              onClick={() => createItemMut.mutate()}
            >
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

interface NodeProps {
  category: CatalogCategory;
  expanded: boolean;
  selectedItemId: string | null;
  onToggle: () => void;
  onAddItem: () => void;
  onDelete: () => void;
  onSelectItem: (item: CatalogItem) => void;
}

function CategoryNode({
  category,
  expanded,
  selectedItemId,
  onToggle,
  onAddItem,
  onDelete,
  onSelectItem,
}: NodeProps) {
  const itemsQuery = useQuery({
    queryKey: ["catalogDepth", "items", category.category_id],
    queryFn: async () => (await listItems(category.category_id)).items,
    enabled: expanded,
    staleTime: 15_000,
  });

  return (
    <li>
      <div className="group flex items-center gap-1 rounded-md px-1 py-1 hover:bg-muted/60">
        <button
          type="button"
          onClick={onToggle}
          className="flex flex-1 items-center gap-1.5 truncate text-left text-sm font-medium"
        >
          {expanded ? (
            <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
          )}
          <span className="truncate">{category.name}</span>
        </button>
        <Button
          size="icon"
          variant="ghost"
          className="h-7 w-7 opacity-0 group-hover:opacity-100"
          title="Add item"
          onClick={onAddItem}
        >
          <Plus className="h-3.5 w-3.5" />
        </Button>
        <Button
          size="icon"
          variant="ghost"
          className="h-7 w-7 text-destructive opacity-0 group-hover:opacity-100"
          title="Delete category"
          onClick={onDelete}
        >
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </div>

      {expanded && (
        <ul className="ml-6 mt-1 space-y-0.5 border-l pl-2">
          {itemsQuery.isLoading && (
            <li className="py-1">
              <Skeleton className="h-7 w-full" />
            </li>
          )}
          {itemsQuery.data && itemsQuery.data.length === 0 && (
            <li className="px-1 py-1 text-xs text-muted-foreground">
              No items.
            </li>
          )}
          {itemsQuery.data?.map((item) => (
            <li key={item.item_id}>
              <button
                type="button"
                onClick={() => onSelectItem(item)}
                className={`flex w-full items-center justify-between gap-2 rounded px-2 py-1 text-left text-sm hover:bg-muted ${
                  selectedItemId === item.item_id ? "bg-muted font-medium" : ""
                }`}
              >
                <span className="flex min-w-0 items-center gap-1.5">
                  <Package className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  <span className="truncate">{item.name}</span>
                </span>
                <Badge variant="outline" className="shrink-0 tabular-nums">
                  {formatCents(item.price_cents, item.currency)}
                </Badge>
              </button>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}
