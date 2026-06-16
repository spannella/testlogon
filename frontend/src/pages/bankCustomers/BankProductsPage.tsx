/**
 * CUS-004 + CUS-005: Financial Products catalog page (admin).
 *
 * Features:
 *  - List financial products (filterable by category)
 *  - Create / edit / delete products
 *  - Manage product attributes
 *  - Manage product collections
 *
 * Gated by OPEN_BANK_PROJECT_ENABLED + financial_products_enabled.
 * 404/503 = feature not enabled.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Landmark,
  Plus,
  Pencil,
  Trash2,
  RefreshCw,
  Tag,
  X,
  FolderOpen,
  ChevronDown,
  ChevronRight,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { ApiError } from "@/api/client";
import {
  listFinancialProducts,
  getFinancialProduct,
  createFinancialProduct,
  patchFinancialProduct,
  deleteFinancialProduct,
  listProductAttributes,
  setProductAttribute,
  deleteProductAttribute,
  listCollections,
  upsertCollection,
  addToCollection,
  removeFromCollection,
  type FinancialProductOut,
  type ProductAttributeSetIn,
  type ProductCollectionOut,
} from "@/api/endpoints/bankCustomers";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

// ─── Product attributes panel ─────────────────────────────────────────────────

function ProductAttributesPanel({ productCode }: { productCode: string }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [type, setType] = useState<"STRING" | "INTEGER" | "DOUBLE" | "DATE_WITH_DAY">("STRING");

  const attrsQ = useQuery({
    queryKey: ["bank-products", productCode, "attributes"],
    queryFn: () => listProductAttributes(productCode),
    retry: false,
  });

  const setAttrMut = useMutation({
    mutationFn: (body: ProductAttributeSetIn) => setProductAttribute(productCode, body),
    onSuccess: () => {
      toast.success("Attribute saved");
      setName("");
      setValue("");
      void qc.invalidateQueries({ queryKey: ["bank-products", productCode, "attributes"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed"),
  });

  const delAttrMut = useMutation({
    mutationFn: (attribute_id: string) => deleteProductAttribute(productCode, attribute_id),
    onSuccess: () => {
      toast.success("Attribute removed");
      void qc.invalidateQueries({ queryKey: ["bank-products", productCode, "attributes"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed"),
  });

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold flex items-center gap-2">
        <Tag className="h-4 w-4" /> Product Attributes
      </h4>

      {attrsQ.isLoading && <Skeleton className="h-8 w-full" />}

      {attrsQ.data?.attributes.length === 0 && (
        <p className="text-sm text-muted-foreground">No attributes.</p>
      )}

      {attrsQ.data?.attributes.map((attr) => (
        <div key={attr.attribute_id} className="flex items-center justify-between rounded border px-3 py-2 text-sm">
          <span>
            <span className="font-medium">{attr.name}</span>
            <span className="text-muted-foreground mx-2">({attr.type})</span>
            <span>{attr.value}</span>
          </span>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 text-muted-foreground"
            onClick={() => delAttrMut.mutate(attr.attribute_id)}
          >
            <X className="h-3 w-3" />
          </Button>
        </div>
      ))}

      <div className="flex gap-2 flex-wrap items-end">
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Name</Label>
          <Input className="h-8 w-32 text-xs" value={name} onChange={(e) => setName(e.target.value)} placeholder="name" />
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Type</Label>
          <select
            className="h-8 rounded-md border bg-background px-2 text-xs"
            value={type}
            onChange={(e) => setType(e.target.value as typeof type)}
          >
            <option>STRING</option>
            <option>INTEGER</option>
            <option>DOUBLE</option>
            <option>DATE_WITH_DAY</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Value</Label>
          <Input className="h-8 w-32 text-xs" value={value} onChange={(e) => setValue(e.target.value)} placeholder="value" />
        </div>
        <Button
          size="sm"
          className="h-8"
          disabled={!name.trim() || !value.trim() || setAttrMut.isPending}
          onClick={() => setAttrMut.mutate({ name: name.trim(), type, value: value.trim() })}
        >
          Set
        </Button>
      </div>
    </div>
  );
}

// ─── Product detail / edit dialog ─────────────────────────────────────────────

function ProductDetailDialog({
  productCode,
  open,
  onClose,
  onDeleted,
}: {
  productCode: string;
  open: boolean;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const qc = useQueryClient();
  const [editMode, setEditMode] = useState(false);
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [category, setCategory] = useState("");
  const [family, setFamily] = useState("");
  const [superFamily, setSuperFamily] = useState("");
  const [moreInfoUrl, setMoreInfoUrl] = useState("");
  const [parentCode, setParentCode] = useState("");

  const detailQ = useQuery({
    queryKey: ["bank-products", "detail", productCode],
    queryFn: () => getFinancialProduct(productCode),
    enabled: open && !!productCode,
    retry: false,
  });

  const p = detailQ.data;

  function startEdit(prod: FinancialProductOut) {
    setName(prod.name);
    setDesc(prod.description ?? "");
    setCategory(prod.category ?? "");
    setFamily(prod.family ?? "");
    setSuperFamily(prod.super_family ?? "");
    setMoreInfoUrl(prod.more_info_url ?? "");
    setParentCode(prod.parent_product_code ?? "");
    setEditMode(true);
  }

  const patchMut = useMutation({
    mutationFn: () =>
      patchFinancialProduct(productCode, {
        name: name.trim() || undefined,
        description: desc.trim() || null,
        category: category.trim() || null,
        family: family.trim() || null,
        super_family: superFamily.trim() || null,
        more_info_url: moreInfoUrl.trim() || null,
        parent_product_code: parentCode.trim() || null,
        expected_version: p!.version,
      }),
    onSuccess: () => {
      toast.success("Product updated");
      setEditMode(false);
      void qc.invalidateQueries({ queryKey: ["bank-products"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Update failed"),
  });

  const delMut = useMutation({
    mutationFn: () => deleteFinancialProduct(productCode),
    onSuccess: () => {
      toast.success("Product deleted");
      void qc.invalidateQueries({ queryKey: ["bank-products"] });
      onDeleted();
      onClose();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Delete failed"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Landmark className="h-5 w-5" />
            {productCode}
          </DialogTitle>
        </DialogHeader>

        {detailQ.isLoading && (
          <div className="space-y-2">
            {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-6 w-full" />)}
          </div>
        )}

        {p && !editMode && (
          <div className="space-y-2 text-sm">
            <div className="grid grid-cols-2 gap-2">
              <div><span className="text-muted-foreground">Code:</span> <span className="font-mono text-xs">{p.product_code}</span></div>
              <div><span className="text-muted-foreground">Name:</span> <strong>{p.name}</strong></div>
              <div><span className="text-muted-foreground">Category:</span> {p.category ?? "—"}</div>
              <div><span className="text-muted-foreground">Family:</span> {p.family ?? "—"}</div>
              <div><span className="text-muted-foreground">Super Family:</span> {p.super_family ?? "—"}</div>
              <div><span className="text-muted-foreground">Parent:</span> {p.parent_product_code ?? "—"}</div>
              <div className="col-span-2"><span className="text-muted-foreground">Description:</span> {p.description ?? "—"}</div>
              {p.more_info_url && (
                <div className="col-span-2">
                  <a href={p.more_info_url} target="_blank" rel="noreferrer" className="text-primary underline text-xs break-all">{p.more_info_url}</a>
                </div>
              )}
              <div><span className="text-muted-foreground">Created:</span> {fmt(p.created_at)}</div>
              <div><span className="text-muted-foreground">Updated:</span> {fmt(p.updated_at)}</div>
              <div><span className="text-muted-foreground">Version:</span> {p.version}</div>
            </div>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={() => startEdit(p)}>
                <Pencil className="h-3 w-3 mr-1" /> Edit
              </Button>
              <Button
                size="sm"
                variant="destructive"
                disabled={delMut.isPending}
                onClick={() => delMut.mutate()}
              >
                <Trash2 className="h-3 w-3 mr-1" /> Delete
              </Button>
            </div>
          </div>
        )}

        {p && editMode && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>Name</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label>Category</Label>
                <Input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="e.g. CURRENT" />
              </div>
              <div className="space-y-1">
                <Label>Family</Label>
                <Input value={family} onChange={(e) => setFamily(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label>Super Family</Label>
                <Input value={superFamily} onChange={(e) => setSuperFamily(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label>Parent Code</Label>
                <Input value={parentCode} onChange={(e) => setParentCode(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label>More Info URL</Label>
                <Input value={moreInfoUrl} onChange={(e) => setMoreInfoUrl(e.target.value)} />
              </div>
              <div className="col-span-2 space-y-1">
                <Label>Description</Label>
                <Textarea value={desc} onChange={(e) => setDesc(e.target.value)} rows={3} />
              </div>
            </div>
            <div className="flex gap-2">
              <Button size="sm" disabled={patchMut.isPending} onClick={() => patchMut.mutate()}>Save</Button>
              <Button size="sm" variant="outline" onClick={() => setEditMode(false)}>Cancel</Button>
            </div>
          </div>
        )}

        {p && (
          <>
            <Separator className="my-2" />
            <ProductAttributesPanel productCode={productCode} />
          </>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Create product dialog ────────────────────────────────────────────────────

function CreateProductDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (code: string) => void;
}) {
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [category, setCategory] = useState("");
  const [family, setFamily] = useState("");

  const createMut = useMutation({
    mutationFn: () =>
      createFinancialProduct({
        product_code: code.trim(),
        name: name.trim(),
        description: desc.trim() || null,
        category: category.trim() || null,
        family: family.trim() || null,
      }),
    onSuccess: (p) => {
      toast.success(`Product "${p.name}" created`);
      setCode("");
      setName("");
      setDesc("");
      setCategory("");
      setFamily("");
      onCreated(p.product_code);
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Create failed"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>New Financial Product</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label>Product Code <span className="text-destructive">*</span></Label>
            <Input value={code} onChange={(e) => setCode(e.target.value)} placeholder="e.g. SAVINGS_BASIC" />
          </div>
          <div className="space-y-1">
            <Label>Name <span className="text-destructive">*</span></Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Basic Savings Account" />
          </div>
          <div className="space-y-1">
            <Label>Category</Label>
            <Input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="e.g. SAVINGS" />
          </div>
          <div className="space-y-1">
            <Label>Family</Label>
            <Input value={family} onChange={(e) => setFamily(e.target.value)} placeholder="e.g. Retail" />
          </div>
          <div className="space-y-1">
            <Label>Description</Label>
            <Textarea value={desc} onChange={(e) => setDesc(e.target.value)} rows={2} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            disabled={!code.trim() || !name.trim() || createMut.isPending}
            onClick={() => createMut.mutate()}
          >
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Collections tab ──────────────────────────────────────────────────────────

function CollectionsTab() {
  const qc = useQueryClient();
  const [expandedCode, setExpandedCode] = useState<string | null>(null);
  const [showUpsert, setShowUpsert] = useState(false);
  const [upsertCode, setUpsertCode] = useState("");
  const [upsertName, setUpsertName] = useState("");
  const [addProductCode, setAddProductCode] = useState<Record<string, string>>({});

  const collectionsQ = useQuery({
    queryKey: ["bank-product-collections"],
    queryFn: () => listCollections({ limit: 50 }),
    retry: false,
  });

  const upsertMut = useMutation({
    mutationFn: () =>
      upsertCollection(upsertCode.trim(), {
        name: upsertName.trim(),
        product_codes: [],
      }),
    onSuccess: () => {
      toast.success("Collection saved");
      setUpsertCode("");
      setUpsertName("");
      setShowUpsert(false);
      void qc.invalidateQueries({ queryKey: ["bank-product-collections"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed"),
  });

  const addMemberMut = useMutation({
    mutationFn: ({ collectionCode, productCode }: { collectionCode: string; productCode: string }) =>
      addToCollection(collectionCode, productCode),
    onSuccess: (_, vars) => {
      toast.success("Product added to collection");
      setAddProductCode((prev) => ({ ...prev, [vars.collectionCode]: "" }));
      void qc.invalidateQueries({ queryKey: ["bank-product-collections"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed"),
  });

  const removeMemberMut = useMutation({
    mutationFn: ({ collectionCode, productCode }: { collectionCode: string; productCode: string }) =>
      removeFromCollection(collectionCode, productCode),
    onSuccess: () => {
      toast.success("Product removed");
      void qc.invalidateQueries({ queryKey: ["bank-product-collections"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed"),
  });

  const collections = collectionsQ.data?.items ?? [];

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button size="sm" onClick={() => setShowUpsert(true)}>
          <Plus className="h-4 w-4 mr-1" /> New Collection
        </Button>
      </div>

      {collectionsQ.isLoading && (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}
        </div>
      )}

      {collections.length === 0 && !collectionsQ.isLoading && (
        <EmptyState
          icon={<FolderOpen className="h-8 w-8" />}
          title="No collections"
          description="Create a collection to group related financial products."
        />
      )}

      {collections.map((col: ProductCollectionOut) => (
        <Card key={col.collection_code}>
          <CardHeader
            className="pb-2 cursor-pointer"
            onClick={() => setExpandedCode(expandedCode === col.collection_code ? null : col.collection_code)}
          >
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm flex items-center gap-2">
                <FolderOpen className="h-4 w-4" />
                {col.name}
                <Badge variant="outline" className="text-xs">{col.collection_code}</Badge>
              </CardTitle>
              <div className="flex items-center gap-2">
                <Badge variant="secondary">{col.product_codes.length} products</Badge>
                {expandedCode === col.collection_code
                  ? <ChevronDown className="h-4 w-4" />
                  : <ChevronRight className="h-4 w-4" />}
              </div>
            </div>
          </CardHeader>

          {expandedCode === col.collection_code && (
            <CardContent className="space-y-3">
              {col.product_codes.length === 0 && (
                <p className="text-sm text-muted-foreground">No products in this collection.</p>
              )}
              {col.product_codes.map((pc) => (
                <div key={pc} className="flex items-center justify-between rounded border px-3 py-2 text-sm">
                  <span className="font-mono text-xs">{pc}</span>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 text-muted-foreground"
                    onClick={() => removeMemberMut.mutate({ collectionCode: col.collection_code, productCode: pc })}
                  >
                    <X className="h-3 w-3" />
                  </Button>
                </div>
              ))}

              <div className="flex gap-2 items-center">
                <Input
                  className="h-8 text-xs"
                  placeholder="Product code to add"
                  value={addProductCode[col.collection_code] ?? ""}
                  onChange={(e) =>
                    setAddProductCode((prev) => ({ ...prev, [col.collection_code]: e.target.value }))
                  }
                />
                <Button
                  size="sm"
                  className="h-8"
                  disabled={!(addProductCode[col.collection_code] ?? "").trim() || addMemberMut.isPending}
                  onClick={() =>
                    addMemberMut.mutate({
                      collectionCode: col.collection_code,
                      productCode: (addProductCode[col.collection_code] ?? "").trim(),
                    })
                  }
                >
                  Add
                </Button>
              </div>
            </CardContent>
          )}
        </Card>
      ))}

      {/* Upsert collection dialog */}
      <Dialog open={showUpsert} onOpenChange={(v) => { if (!v) setShowUpsert(false); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader><DialogTitle>Create / Update Collection</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label>Collection Code <span className="text-destructive">*</span></Label>
              <Input value={upsertCode} onChange={(e) => setUpsertCode(e.target.value)} placeholder="e.g. RETAIL_BUNDLE" />
            </div>
            <div className="space-y-1">
              <Label>Name <span className="text-destructive">*</span></Label>
              <Input value={upsertName} onChange={(e) => setUpsertName(e.target.value)} placeholder="Retail Product Bundle" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowUpsert(false)}>Cancel</Button>
            <Button
              disabled={!upsertCode.trim() || !upsertName.trim() || upsertMut.isPending}
              onClick={() => upsertMut.mutate()}
            >
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function BankProductsPage() {
  const qc = useQueryClient();
  const [categoryFilter, setCategoryFilter] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [showCreate, setShowCreate] = useState(false);
  const [selectedCode, setSelectedCode] = useState<string | null>(null);

  const productsQ = useQuery({
    queryKey: ["bank-products", "list", categoryFilter, cursor],
    queryFn: () =>
      listFinancialProducts({
        category: categoryFilter.trim() || undefined,
        cursor,
        limit: 25,
      }),
    retry: false,
  });

  if (
    productsQ.error instanceof ApiError &&
    (productsQ.error.status === 404 || productsQ.error.status === 503)
  ) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader title="Financial Products" description="OBP CUS-004..CUS-005" />
        <EmptyState
          icon={<Landmark className="h-8 w-8" />}
          title="Financial Products not available"
          description="The financial products feature is not enabled on this platform."
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Financial Products"
        description="Define bank product catalog: savings, loans, current accounts, and collections."
        actions={
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4 mr-1" /> New Product
          </Button>
        }
      />

      <Tabs defaultValue="products">
        <TabsList>
          <TabsTrigger value="products">Products</TabsTrigger>
          <TabsTrigger value="collections">Collections</TabsTrigger>
        </TabsList>

        <TabsContent value="products" className="mt-4 space-y-4">
          {/* Filters */}
          <div className="flex gap-3 items-end flex-wrap">
            <div className="flex flex-col gap-1">
              <Label className="text-xs">Category</Label>
              <Input
                className="h-8 w-48 text-sm"
                placeholder="Filter by category…"
                value={categoryFilter}
                onChange={(e) => { setCategoryFilter(e.target.value); setCursor(undefined); }}
              />
            </div>
            <Button
              variant="outline"
              size="sm"
              className="h-8"
              onClick={() => void qc.invalidateQueries({ queryKey: ["bank-products", "list"] })}
            >
              <RefreshCw className="h-3 w-3 mr-1" /> Refresh
            </Button>
          </div>

          {/* Product list */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Products</CardTitle>
              <CardDescription>
                {productsQ.data ? `${productsQ.data.items.length} loaded` : "Loading…"}
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              {productsQ.isLoading && (
                <div className="p-4 space-y-2">
                  {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
                </div>
              )}

              {productsQ.data?.items.length === 0 && (
                <EmptyState
                  icon={<Landmark className="h-8 w-8" />}
                  title="No products found"
                  description="Add a financial product to populate the catalog."
                />
              )}

              {productsQ.data && productsQ.data.items.length > 0 && (
                <div className="divide-y">
                  {productsQ.data.items.map((p) => (
                    <button
                      key={p.product_code}
                      className="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/50 transition-colors text-left"
                      onClick={() => setSelectedCode(p.product_code)}
                    >
                      <div className="space-y-0.5">
                        <p className="font-medium text-sm">{p.name}</p>
                        <p className="text-xs text-muted-foreground">
                          <span className="font-mono">{p.product_code}</span>
                          {p.category && <span> · {p.category}</span>}
                          {p.family && <span> · {p.family}</span>}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        {p.category && <Badge variant="outline">{p.category}</Badge>}
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      </div>
                    </button>
                  ))}
                </div>
              )}

              {productsQ.data?.cursor && (
                <div className="p-3 border-t flex justify-center">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCursor(productsQ.data!.cursor!)}
                  >
                    Load more
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="collections" className="mt-4">
          <CollectionsTab />
        </TabsContent>
      </Tabs>

      {/* Dialogs */}
      <CreateProductDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={(code) => {
          setShowCreate(false);
          setSelectedCode(code);
          void qc.invalidateQueries({ queryKey: ["bank-products", "list"] });
        }}
      />

      {selectedCode && (
        <ProductDetailDialog
          productCode={selectedCode}
          open={!!selectedCode}
          onClose={() => setSelectedCode(null)}
          onDeleted={() => {
            void qc.invalidateQueries({ queryKey: ["bank-products", "list"] });
          }}
        />
      )}
    </div>
  );
}
