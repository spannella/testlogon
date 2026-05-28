import { useEffect, useState, useCallback } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Search, SearchX, User, FileText, ShoppingBag, FolderOpen } from "lucide-react";

import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { globalSearch, type SearchResultItem } from "@/api/endpoints/search";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

function resultIcon(type: string) {
  switch (type) {
    case "user":
      return <User className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "post":
      return <FileText className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "catalog":
      return <ShoppingBag className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "file":
      return <FolderOpen className="h-4 w-4 text-muted-foreground shrink-0" />;
    default:
      return <Search className="h-4 w-4 text-muted-foreground shrink-0" />;
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ResultRow({
  item,
  onClick,
}: {
  item: SearchResultItem;
  onClick: () => void;
}) {
  return (
    <button
      className="flex w-full items-start gap-3 rounded-md px-3 py-2 text-left hover:bg-accent transition-colors"
      onClick={onClick}
      data-testid={`search-result-${item.type}`}
    >
      <div className="mt-0.5">{resultIcon(item.type)}</div>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium truncate">{item.title}</p>
        {item.snippet && item.snippet !== item.title && (
          <p className="text-xs text-muted-foreground truncate mt-0.5">
            {item.snippet}
          </p>
        )}
      </div>
      <Badge variant="secondary" className="text-[10px] shrink-0 mt-0.5">
        {item.type}
      </Badge>
    </button>
  );
}

function SectionCard({
  title,
  items,
  onViewAll,
  onItemClick,
}: {
  title: string;
  items: SearchResultItem[];
  onViewAll?: () => void;
  onItemClick: (item: SearchResultItem) => void;
}) {
  if (items.length === 0) return null;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold">{title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-1 pb-3">
        {items.map((item) => (
          <ResultRow
            key={`${item.type}-${item.id}`}
            item={item}
            onClick={() => onItemClick(item)}
          />
        ))}
        {onViewAll && (
          <Button
            variant="ghost"
            size="sm"
            className="w-full text-xs mt-1"
            onClick={onViewAll}
          >
            View all {title.toLowerCase()}
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function SearchPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQuery = searchParams.get("q") || "";
  const [inputValue, setInputValue] = useState(initialQuery);
  const debouncedQuery = useDebounce(inputValue, 300);

  const [activeTab, setActiveTab] = useState("all");

  // Sync URL when debounced query changes
  useEffect(() => {
    if (debouncedQuery) {
      setSearchParams({ q: debouncedQuery }, { replace: true });
    }
  }, [debouncedQuery, setSearchParams]);

  const { data, isLoading } = useQuery({
    queryKey: ["global-search", debouncedQuery],
    queryFn: () => globalSearch(debouncedQuery, undefined, 10),
    enabled: debouncedQuery.length >= 1,
    staleTime: 60_000,
  });

  const handleItemClick = useCallback(
    (item: SearchResultItem) => {
      navigate(item.url);
    },
    [navigate],
  );

  const results = data?.results;
  const totalItems =
    (results?.users?.items?.length ?? 0) +
    (results?.posts?.items?.length ?? 0) +
    (results?.catalog?.items?.length ?? 0) +
    (results?.files?.items?.length ?? 0);

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4 md:p-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Search</h1>
        <div className="relative mt-3">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search users, posts, catalog, files..."
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            className="pl-10"
            data-testid="search-input"
            autoFocus
          />
        </div>
      </div>

      {/* Tabs */}
      {debouncedQuery.length >= 1 && (
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="all">All</TabsTrigger>
            <TabsTrigger value="users">
              Users
              {(results?.users?.items?.length ?? 0) > 0 && (
                <Badge variant="secondary" className="ml-1 text-[10px]">
                  {results!.users.items.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="posts">
              Posts
              {(results?.posts?.items?.length ?? 0) > 0 && (
                <Badge variant="secondary" className="ml-1 text-[10px]">
                  {results!.posts.items.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="catalog">
              Catalog
              {(results?.catalog?.items?.length ?? 0) > 0 && (
                <Badge variant="secondary" className="ml-1 text-[10px]">
                  {results!.catalog.items.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="files">
              Files
              {(results?.files?.items?.length ?? 0) > 0 && (
                <Badge variant="secondary" className="ml-1 text-[10px]">
                  {results!.files.items.length}
                </Badge>
              )}
            </TabsTrigger>
          </TabsList>

          {/* All tab */}
          <TabsContent value="all" className="space-y-4 mt-4">
            {isLoading && (
              <p className="text-sm text-muted-foreground">Searching...</p>
            )}
            {!isLoading && totalItems === 0 && debouncedQuery.length >= 1 && (
              <div className="flex flex-col items-center gap-3 py-12 text-center">
                <SearchX className="h-10 w-10 text-muted-foreground" />
                <p className="text-sm text-muted-foreground" data-testid="no-results">
                  No results found for &quot;{debouncedQuery}&quot;
                </p>
              </div>
            )}
            <SectionCard
              title="Users"
              items={results?.users?.items ?? []}
              onViewAll={() => setActiveTab("users")}
              onItemClick={handleItemClick}
            />
            <SectionCard
              title="Posts"
              items={results?.posts?.items ?? []}
              onViewAll={() => setActiveTab("posts")}
              onItemClick={handleItemClick}
            />
            <SectionCard
              title="Catalog"
              items={results?.catalog?.items ?? []}
              onViewAll={() => setActiveTab("catalog")}
              onItemClick={handleItemClick}
            />
            <SectionCard
              title="Files"
              items={results?.files?.items ?? []}
              onViewAll={() => setActiveTab("files")}
              onItemClick={handleItemClick}
            />
          </TabsContent>

          {/* Individual type tabs */}
          <TabsContent value="users" className="space-y-2 mt-4">
            {(results?.users?.items ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground py-8 text-center">No users found</p>
            ) : (
              (results?.users?.items ?? []).map((item) => (
                <ResultRow
                  key={item.id}
                  item={item}
                  onClick={() => handleItemClick(item)}
                />
              ))
            )}
          </TabsContent>

          <TabsContent value="posts" className="space-y-2 mt-4">
            {(results?.posts?.items ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground py-8 text-center">No posts found</p>
            ) : (
              (results?.posts?.items ?? []).map((item) => (
                <ResultRow
                  key={item.id}
                  item={item}
                  onClick={() => handleItemClick(item)}
                />
              ))
            )}
          </TabsContent>

          <TabsContent value="catalog" className="space-y-2 mt-4">
            {(results?.catalog?.items ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground py-8 text-center">No catalog items found</p>
            ) : (
              (results?.catalog?.items ?? []).map((item) => (
                <ResultRow
                  key={item.id}
                  item={item}
                  onClick={() => handleItemClick(item)}
                />
              ))
            )}
          </TabsContent>

          <TabsContent value="files" className="space-y-2 mt-4">
            {(results?.files?.items ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground py-8 text-center">No files found</p>
            ) : (
              (results?.files?.items ?? []).map((item) => (
                <ResultRow
                  key={item.id}
                  item={item}
                  onClick={() => handleItemClick(item)}
                />
              ))
            )}
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}
