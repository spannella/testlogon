import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { PageHeader } from "@/components/shared/PageHeader";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ProductCard } from "./ProductCard";
import {
  listStorefrontCategories,
  listStorefrontItems,
} from "@/api/endpoints/storeIntegration";

export default function StorefrontPage() {
  const [categoryId, setCategoryId] = useState<string>("");

  const categoriesQuery = useQuery({
    queryKey: ["storefront", "categories"],
    queryFn: () => listStorefrontCategories({ pageSize: 100 }),
    retry: false,
  });

  // Default to the first category once loaded.
  useEffect(() => {
    const first = categoriesQuery.data?.items?.[0]?.category_id;
    if (!categoryId && first) setCategoryId(first);
  }, [categoriesQuery.data, categoryId]);

  const itemsQuery = useQuery({
    queryKey: ["storefront", "items", categoryId],
    queryFn: () => listStorefrontItems(categoryId, { pageSize: 100 }),
    enabled: !!categoryId,
    retry: false,
  });

  const categories = categoriesQuery.data?.items ?? [];
  const items = itemsQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Storefront"
        description="Browse products with live availability and variant selection."
        actions={
          categories.length > 0 ? (
            <Select value={categoryId} onValueChange={setCategoryId}>
              <SelectTrigger className="w-56" data-testid="category-picker">
                <SelectValue placeholder="Select a category" />
              </SelectTrigger>
              <SelectContent>
                {categories.map((c) => (
                  <SelectItem key={c.category_id} value={c.category_id}>
                    {c.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : null
        }
      />

      {categoriesQuery.isLoading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-72 w-full" />
          ))}
        </div>
      ) : categories.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No catalog categories are available yet.
          </CardContent>
        </Card>
      ) : itemsQuery.isLoading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-72 w-full" />
          ))}
        </div>
      ) : items.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            This category has no products.
          </CardContent>
        </Card>
      ) : (
        <div
          className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3"
          data-testid="product-grid"
        >
          {items.map((item) => (
            <ProductCard key={item.item_id} item={item} />
          ))}
        </div>
      )}
    </div>
  );
}
