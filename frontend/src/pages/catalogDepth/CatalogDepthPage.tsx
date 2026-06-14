import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Boxes, Layers, Tags } from "lucide-react";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

import { ApiError } from "@/api/client";
import { listCategories } from "@/api/endpoints/productDepth";
import { CategoryTreePanel } from "./CategoryTreePanel";
import { FeatureCategoriesPanel } from "./FeatureCategoriesPanel";
import { ItemDepthPanel } from "./ItemDepthPanel";

/**
 * OFBiz CATALOG-DEPTH admin console (PRD-006 / PRD-007 / PRD-012).
 *
 * Admin-oriented: manages categories, items, feature categories/values,
 * product types (virtual/variant), variants, and price components.
 *
 * The product-depth feature flag defaults OFF on the backend → depth endpoints
 * return 404. The page degrades gracefully: the base catalog tree always works,
 * and the depth panels show an informative empty state when the flag is off.
 */
export default function CatalogDepthPage() {
  const [selectedCategoryId, setSelectedCategoryId] = useState<string | null>(null);
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);
  const [selectedItemName, setSelectedItemName] = useState<string>("");

  const categoriesQuery = useQuery({
    queryKey: ["catalogDepth", "categories"],
    queryFn: async () => (await listCategories()).items,
    staleTime: 30_000,
  });

  const loadError = categoriesQuery.error as ApiError | undefined;

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6 p-4 md:p-6">
      <div className="space-y-1">
        <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
          <Boxes className="h-6 w-6" /> Catalog Depth
        </h1>
        <p className="text-sm text-muted-foreground">
          Manage categories, items, feature axes, product variants, and
          time-bounded price components (OFBiz product depth).
        </p>
      </div>

      <Tabs defaultValue="catalog" className="w-full">
        <TabsList>
          <TabsTrigger value="catalog">
            <Layers className="mr-2 h-4 w-4" /> Catalog Tree
          </TabsTrigger>
          <TabsTrigger value="features">
            <Tags className="mr-2 h-4 w-4" /> Feature Categories
          </TabsTrigger>
        </TabsList>

        <TabsContent value="catalog" className="mt-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,360px)_1fr]">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Categories & Items</CardTitle>
                <CardDescription>
                  Select an item to manage its depth attributes.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {loadError && loadError.status !== 404 ? (
                  <Alert variant="destructive">
                    <AlertTitle>Failed to load catalog</AlertTitle>
                    <AlertDescription>{loadError.detail}</AlertDescription>
                  </Alert>
                ) : (
                  <CategoryTreePanel
                    categories={categoriesQuery.data ?? []}
                    loading={categoriesQuery.isLoading}
                    selectedCategoryId={selectedCategoryId}
                    selectedItemId={selectedItemId}
                    onSelectCategory={(id) => {
                      setSelectedCategoryId(id);
                      setSelectedItemId(null);
                      setSelectedItemName("");
                    }}
                    onSelectItem={(catId, item) => {
                      setSelectedCategoryId(catId);
                      setSelectedItemId(item.item_id);
                      setSelectedItemName(item.name);
                    }}
                  />
                )}
              </CardContent>
            </Card>

            <div className="min-w-0">
              {selectedItemId ? (
                <ItemDepthPanel
                  key={selectedItemId}
                  itemId={selectedItemId}
                  itemName={selectedItemName}
                />
              ) : (
                <Card className="flex min-h-[320px] items-center justify-center">
                  <CardContent className="py-10 text-center text-sm text-muted-foreground">
                    Select a catalog item from the tree to manage its product
                    type, feature axes, variants, and price components.
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        </TabsContent>

        <TabsContent value="features" className="mt-4">
          <FeatureCategoriesPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}
