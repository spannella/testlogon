import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  FolderPlus,
  Loader2,
  Package,
  Pencil,
  Plus,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/shared/EmptyState";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  getCategories,
  getCategoryItems,
  createCategory,
  deleteCategory,
  deleteCatalogItem,
} from "@/api/endpoints/cart";
import { ItemEditor } from "./ItemEditor";
import type { CatalogCategory, CatalogItem } from "@/api/types";

function formatPrice(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(cents / 100);
}

export function AdminCatalog() {
  const qc = useQueryClient();
  const [selectedCat, setSelectedCat] = useState<string | null>(null);

  // Category creation dialog
  const [catDialogOpen, setCatDialogOpen] = useState(false);
  const [catName, setCatName] = useState("");
  const [catDesc, setCatDesc] = useState("");

  // Delete confirmations
  const [deleteCatTarget, setDeleteCatTarget] = useState<CatalogCategory | null>(null);
  const [deleteItemTarget, setDeleteItemTarget] = useState<CatalogItem | null>(null);

  // Item editor
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<CatalogItem | undefined>(undefined);

  const categoriesQuery = useQuery({
    queryKey: ["catalog", "categories"],
    queryFn: () => getCategories(),
  });

  const itemsQuery = useQuery({
    queryKey: ["catalog", "admin-items", selectedCat],
    queryFn: () => getCategoryItems(selectedCat!),
    enabled: !!selectedCat,
  });

  const createCatMutation = useMutation({
    mutationFn: () =>
      createCategory({ name: catName.trim(), description: catDesc.trim() || undefined }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["catalog", "categories"] });
      toast.success("Category created");
      setCatDialogOpen(false);
      setCatName("");
      setCatDesc("");
    },
    onError: () => toast.error("Failed to create category"),
  });

  const deleteCatMutation = useMutation({
    mutationFn: (catId: string) => deleteCategory(catId, true),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["catalog", "categories"] });
      if (deleteCatTarget && selectedCat === deleteCatTarget.category_id) {
        setSelectedCat(null);
      }
      toast.success("Category deleted");
      setDeleteCatTarget(null);
    },
    onError: () => toast.error("Failed to delete category"),
  });

  const deleteItemMutation = useMutation({
    mutationFn: (item: CatalogItem) => deleteCatalogItem(item.category_id, item.item_id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["catalog", "admin-items", selectedCat] });
      toast.success("Item deleted");
      setDeleteItemTarget(null);
    },
    onError: () => toast.error("Failed to delete item"),
  });

  const categories = categoriesQuery.data?.items ?? [];
  const items = itemsQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      {/* Categories section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold">Categories</h3>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setCatName("");
              setCatDesc("");
              setCatDialogOpen(true);
            }}
          >
            <FolderPlus className="mr-1 h-3.5 w-3.5" />
            Add Category
          </Button>
        </div>

        {categories.length === 0 ? (
          <EmptyState
            icon={<Package className="h-6 w-6" />}
            title="No categories"
            description="Create a category to start adding products"
            className="py-8"
          />
        ) : (
          <div className="flex flex-wrap gap-2">
            {categories.map((cat) => (
              <div key={cat.category_id} className="flex items-center gap-1">
                <Button
                  variant={selectedCat === cat.category_id ? "default" : "outline"}
                  size="sm"
                  onClick={() => setSelectedCat(cat.category_id)}
                >
                  {cat.name}
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-muted-foreground hover:text-destructive"
                  onClick={() => setDeleteCatTarget(cat)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Items section */}
      {selectedCat && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold">
              Items ({items.length})
            </h3>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setEditingItem(undefined);
                setEditorOpen(true);
              }}
            >
              <Plus className="mr-1 h-3.5 w-3.5" />
              Add Item
            </Button>
          </div>

          {itemsQuery.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : items.length === 0 ? (
            <EmptyState
              icon={<Package className="h-6 w-6" />}
              title="No items"
              description="Add items to this category"
              className="py-8"
            />
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {items.map((item) => (
                <Card key={item.item_id}>
                  <CardContent className="p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium">{item.name}</p>
                        <p className="text-sm font-semibold text-primary">
                          {formatPrice(item.price_cents, item.currency)}
                        </p>
                        {item.description && (
                          <p className="mt-1 text-xs text-muted-foreground line-clamp-2">
                            {item.description}
                          </p>
                        )}
                      </div>
                      <div className="flex shrink-0 gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          onClick={() => {
                            setEditingItem(item);
                            setEditorOpen(true);
                          }}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-muted-foreground hover:text-destructive"
                          onClick={() => setDeleteItemTarget(item)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                    {item.image_urls.length > 0 && (
                      <img
                        src={item.image_urls[0]}
                        alt={item.name}
                        className="mt-2 h-24 w-full rounded border object-contain"
                      />
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Create category dialog */}
      <Dialog open={catDialogOpen} onOpenChange={setCatDialogOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>New Category</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-1">
              <Label htmlFor="cat-name">Name</Label>
              <Input
                id="cat-name"
                value={catName}
                onChange={(e) => setCatName(e.target.value)}
                placeholder="Category name"
                autoFocus
                onKeyDown={(e) => {
                  if (e.key === "Enter" && catName.trim()) createCatMutation.mutate();
                }}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="cat-desc">Description (optional)</Label>
              <Input
                id="cat-desc"
                value={catDesc}
                onChange={(e) => setCatDesc(e.target.value)}
                placeholder="Short description"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              onClick={() => createCatMutation.mutate()}
              disabled={!catName.trim() || createCatMutation.isPending}
            >
              {createCatMutation.isPending && (
                <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
              )}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete category confirmation */}
      <ConfirmDialog
        open={!!deleteCatTarget}
        onOpenChange={(open) => { if (!open) setDeleteCatTarget(null); }}
        title="Delete category"
        description={`This will permanently delete "${deleteCatTarget?.name}" and all its items.`}
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => {
          if (deleteCatTarget) deleteCatMutation.mutate(deleteCatTarget.category_id);
        }}
        loading={deleteCatMutation.isPending}
      />

      {/* Delete item confirmation */}
      <ConfirmDialog
        open={!!deleteItemTarget}
        onOpenChange={(open) => { if (!open) setDeleteItemTarget(null); }}
        title="Delete item"
        description={`This will permanently delete "${deleteItemTarget?.name}".`}
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => {
          if (deleteItemTarget) deleteItemMutation.mutate(deleteItemTarget);
        }}
        loading={deleteItemMutation.isPending}
      />

      {/* Item editor dialog */}
      {selectedCat && (
        <ItemEditor
          open={editorOpen}
          onOpenChange={setEditorOpen}
          categoryId={selectedCat}
          item={editingItem}
          onSaved={() =>
            qc.invalidateQueries({ queryKey: ["catalog", "admin-items", selectedCat] })
          }
        />
      )}
    </div>
  );
}
