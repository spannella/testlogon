import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Search, Package, Star } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { EmptyState } from "@/components/shared/EmptyState";
import {
  getCategories,
  getCategoryItems,
  searchCatalogItems,
} from "@/api/endpoints/cart";
import type { CatalogItem } from "@/api/types";

function formatPrice(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(cents / 100);
}

export function Catalog() {
  const navigate = useNavigate();
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const categoriesQuery = useQuery({
    queryKey: ["catalog", "categories"],
    queryFn: () => getCategories(),
  });

  const itemsQuery = useQuery({
    queryKey: ["catalog", "items", selectedCategory],
    queryFn: () => getCategoryItems(selectedCategory!),
    enabled: !!selectedCategory && search.trim().length === 0,
  });

  const searchQuery = useQuery({
    queryKey: ["catalog", "search", search],
    queryFn: () => searchCatalogItems(search),
    enabled: search.trim().length > 0,
  });

  const categories = categoriesQuery.data?.items ?? [];
  const isSearching = search.trim().length > 0;
  const items: CatalogItem[] = isSearching
    ? (searchQuery.data?.items ?? [])
    : (itemsQuery.data?.items ?? []);
  const isLoadingItems = isSearching ? searchQuery.isLoading : itemsQuery.isLoading;

  // Auto-select first category
  if (!selectedCategory && categories.length > 0 && !isSearching) {
    setSelectedCategory(categories[0]!.category_id);
  }

  return (
    <div className="flex h-full gap-6">
      {/* Category sidebar */}
      <aside className="hidden w-48 shrink-0 md:block">
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Categories
        </h3>
        {categoriesQuery.isLoading ? (
          <div className="space-y-1">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-8 w-full rounded-md" />
            ))}
          </div>
        ) : (
          <ScrollArea className="max-h-[calc(100vh-200px)]">
            <nav className="space-y-0.5">
              {categories.map((cat) => (
                <button
                  key={cat.category_id}
                  onClick={() => {
                    setSelectedCategory(cat.category_id);
                    setSearch("");
                  }}
                  className={cn(
                    "flex w-full items-center rounded-md px-3 py-2 text-sm font-medium transition-colors",
                    selectedCategory === cat.category_id
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground",
                  )}
                >
                  {cat.name}
                </button>
              ))}
            </nav>
          </ScrollArea>
        )}
      </aside>

      {/* Main content */}
      <div className="min-w-0 flex-1 space-y-4">
        {/* Search bar */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search products..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>

        {/* Mobile category selector */}
        <div className="flex gap-2 overflow-x-auto pb-1 md:hidden">
          {categories.map((cat) => (
            <Button
              key={cat.category_id}
              variant={selectedCategory === cat.category_id ? "default" : "outline"}
              size="sm"
              className="shrink-0"
              onClick={() => {
                setSelectedCategory(cat.category_id);
                setSearch("");
              }}
            >
              {cat.name}
            </Button>
          ))}
        </div>

        {/* Product grid */}
        {isLoadingItems ? (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <Skeleton key={i} className="h-56 rounded-xl" />
            ))}
          </div>
        ) : items.length === 0 ? (
          <EmptyState
            icon={<Package className="h-8 w-8" />}
            title={isSearching ? "No results" : "No products"}
            description={
              isSearching
                ? "Try a different search term"
                : selectedCategory
                  ? "This category has no products yet"
                  : "Select a category to browse products"
            }
            className="py-16"
          />
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {items.map((item) => (
              <Card
                key={item.item_id}
                className="cursor-pointer transition-shadow hover:shadow-md"
                onClick={() =>
                  navigate(`/shop/${item.category_id}/${item.item_id}`)
                }
              >
                <CardContent className="p-0">
                  {/* Image placeholder */}
                  <div className="flex h-36 items-center justify-center rounded-t-xl bg-muted">
                    {item.image_urls.length > 0 ? (
                      <img
                        src={item.image_urls[0]}
                        alt={item.name}
                        className="h-full w-full rounded-t-xl object-cover"
                      />
                    ) : (
                      <Package className="h-10 w-10 text-muted-foreground/50" />
                    )}
                  </div>
                  <div className="p-3">
                    <h4 className="text-sm font-medium leading-tight line-clamp-2">
                      {item.name}
                    </h4>
                    <p className="mt-1 text-base font-semibold text-primary">
                      {formatPrice(item.price_cents, item.currency)}
                    </p>
                    {/* Star rating placeholder */}
                    <div className="mt-1 flex items-center gap-0.5">
                      {Array.from({ length: 5 }).map((_, i) => (
                        <Star
                          key={i}
                          className="h-3 w-3 fill-yellow-400 text-yellow-400"
                        />
                      ))}
                      <span className="ml-1 text-[10px] text-muted-foreground">
                        5.0
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
