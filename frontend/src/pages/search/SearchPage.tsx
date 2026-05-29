import { useEffect, useState, useCallback } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Search,
  SearchX,
  User,
  FileText,
  ShoppingBag,
  FolderOpen,
  MessageSquare,
  Ticket,
  Users,
  Play,
  Calendar as CalendarIcon,
  Clock,
  X,
  Trash2,
} from "lucide-react";

import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  globalSearch,
  getSearchHistory,
  deleteSearchHistoryItem,
  clearSearchHistory,
  recordSearchHistory,
  type SearchResultItem,
} from "@/api/endpoints/search";

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
    case "message":
      return <MessageSquare className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "ticket":
      return <Ticket className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "contact":
      return <Users className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "video":
      return <Play className="h-4 w-4 text-muted-foreground shrink-0" />;
    case "calendar":
      return <CalendarIcon className="h-4 w-4 text-muted-foreground shrink-0" />;
    default:
      return <Search className="h-4 w-4 text-muted-foreground shrink-0" />;
  }
}

const SEARCH_TABS = [
  { value: "all", label: "All" },
  { value: "users", label: "Users" },
  { value: "posts", label: "Posts" },
  { value: "catalog", label: "Catalog" },
  { value: "files", label: "Files" },
  { value: "messages", label: "Messages" },
  { value: "tickets", label: "Tickets" },
  { value: "contacts", label: "Contacts" },
  { value: "videos", label: "Videos" },
  { value: "calendar", label: "Calendar" },
] as const;

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

function SearchHistorySidebar({
  onSelectQuery,
}: {
  onSelectQuery: (query: string) => void;
}) {
  const queryClient = useQueryClient();

  const historyQuery = useQuery({
    queryKey: ["search-history"],
    queryFn: () => getSearchHistory(20),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteSearchHistoryItem(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["search-history"] }),
  });

  const clearMut = useMutation({
    mutationFn: clearSearchHistory,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["search-history"] }),
  });

  const items = historyQuery.data?.items ?? [];

  if (items.length === 0) return null;

  return (
    <div className="space-y-3" data-testid="search-history-sidebar">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium flex items-center gap-1">
          <Clock className="h-4 w-4" />
          Recent Searches
        </h3>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 text-xs"
          onClick={() => clearMut.mutate()}
          data-testid="clear-history"
        >
          <Trash2 className="h-3 w-3 mr-1" />
          Clear
        </Button>
      </div>
      <div className="space-y-1">
        {items.map((item) => (
          <div key={item.id} className="flex items-center gap-2 group">
            <button
              className="flex-1 flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-accent text-left"
              onClick={() => onSelectQuery(item.query)}
              data-testid="history-item"
            >
              <Clock className="h-3 w-3 text-muted-foreground shrink-0" />
              <span className="truncate">{item.query}</span>
            </button>
            <button
              className="opacity-0 group-hover:opacity-100 p-1"
              onClick={() => deleteMut.mutate(item.id)}
              data-testid="delete-history-item"
            >
              <X className="h-3 w-3 text-muted-foreground" />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function SearchPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQuery = searchParams.get("q") || "";
  const initialTab = searchParams.get("tab") || "all";
  const [inputValue, setInputValue] = useState(initialQuery);
  const debouncedQuery = useDebounce(inputValue, 300);

  const [activeTab, setActiveTab] = useState(initialTab);

  // Sync URL when debounced query changes
  useEffect(() => {
    if (debouncedQuery) {
      const params: Record<string, string> = { q: debouncedQuery };
      if (activeTab !== "all") params.tab = activeTab;
      setSearchParams(params, { replace: true });
    }
  }, [debouncedQuery, activeTab, setSearchParams]);

  // Record search history when query changes
  const recordMut = useMutation({
    mutationFn: ({ query, count }: { query: string; count: number }) =>
      recordSearchHistory(query, count),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["search-history"] }),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["global-search", debouncedQuery],
    queryFn: () => globalSearch(debouncedQuery, undefined, 10),
    enabled: debouncedQuery.length >= 1,
    staleTime: 60_000,
  });

  // Record history when search results arrive
  useEffect(() => {
    if (data && debouncedQuery.length >= 2) {
      const totalResults = Object.values(data.results).reduce(
        (sum, section) => sum + (section?.items?.length ?? 0),
        0,
      );
      recordMut.mutate({ query: debouncedQuery, count: totalResults });
    }
    // Only fire when data changes, not on every render
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  const handleItemClick = useCallback(
    (item: SearchResultItem) => {
      navigate(item.url);
    },
    [navigate],
  );

  const handleTabChange = useCallback((tab: string) => {
    setActiveTab(tab);
  }, []);

  const handleHistorySelect = useCallback((query: string) => {
    setInputValue(query);
  }, []);

  const results = data?.results;
  const totalItems =
    (results?.users?.items?.length ?? 0) +
    (results?.posts?.items?.length ?? 0) +
    (results?.catalog?.items?.length ?? 0) +
    (results?.files?.items?.length ?? 0) +
    (results?.messages?.items?.length ?? 0) +
    (results?.tickets?.items?.length ?? 0) +
    (results?.contacts?.items?.length ?? 0) +
    (results?.videos?.items?.length ?? 0) +
    (results?.calendar?.items?.length ?? 0);

  const sectionCount = (key: string) => {
    const section = results?.[key as keyof typeof results];
    return section?.items?.length ?? 0;
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4 md:p-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Search</h1>
        <div className="relative mt-3">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search across all content..."
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            className="pl-10"
            data-testid="search-input"
            autoFocus
          />
        </div>
      </div>

      <div className="flex gap-6">
        {/* Main content */}
        <div className="flex-1 min-w-0">
          {/* Tabs */}
          {debouncedQuery.length >= 1 && (
            <Tabs value={activeTab} onValueChange={handleTabChange}>
              <TabsList className="flex-wrap h-auto gap-1">
                {SEARCH_TABS.map((tab) => {
                  const count = tab.value === "all" ? totalItems : sectionCount(tab.value);
                  return (
                    <TabsTrigger key={tab.value} value={tab.value}>
                      {tab.label}
                      {count > 0 && (
                        <Badge variant="secondary" className="ml-1 text-[10px]">
                          {count}
                        </Badge>
                      )}
                    </TabsTrigger>
                  );
                })}
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
                  onViewAll={() => handleTabChange("users")}
                  onItemClick={handleItemClick}
                />
                <SectionCard
                  title="Posts"
                  items={results?.posts?.items ?? []}
                  onViewAll={() => handleTabChange("posts")}
                  onItemClick={handleItemClick}
                />
                <SectionCard
                  title="Catalog"
                  items={results?.catalog?.items ?? []}
                  onViewAll={() => handleTabChange("catalog")}
                  onItemClick={handleItemClick}
                />
                <SectionCard
                  title="Files"
                  items={results?.files?.items ?? []}
                  onViewAll={() => handleTabChange("files")}
                  onItemClick={handleItemClick}
                />
                <SectionCard
                  title="Messages"
                  items={results?.messages?.items ?? []}
                  onViewAll={() => handleTabChange("messages")}
                  onItemClick={handleItemClick}
                />
                <SectionCard
                  title="Tickets"
                  items={results?.tickets?.items ?? []}
                  onViewAll={() => handleTabChange("tickets")}
                  onItemClick={handleItemClick}
                />
                <SectionCard
                  title="Contacts"
                  items={results?.contacts?.items ?? []}
                  onViewAll={() => handleTabChange("contacts")}
                  onItemClick={handleItemClick}
                />
                <SectionCard
                  title="Videos"
                  items={results?.videos?.items ?? []}
                  onViewAll={() => handleTabChange("videos")}
                  onItemClick={handleItemClick}
                />
                <SectionCard
                  title="Calendar"
                  items={results?.calendar?.items ?? []}
                  onViewAll={() => handleTabChange("calendar")}
                  onItemClick={handleItemClick}
                />
              </TabsContent>

              {/* Individual type tabs */}
              {SEARCH_TABS.filter((t) => t.value !== "all").map((tab) => (
                <TabsContent key={tab.value} value={tab.value} className="space-y-2 mt-4">
                  {sectionCount(tab.value) === 0 ? (
                    <p className="text-sm text-muted-foreground py-8 text-center">
                      No {tab.label.toLowerCase()} found
                    </p>
                  ) : (
                    (results?.[tab.value as keyof typeof results]?.items ?? []).map((item) => (
                      <ResultRow
                        key={item.id}
                        item={item}
                        onClick={() => handleItemClick(item)}
                      />
                    ))
                  )}
                </TabsContent>
              ))}
            </Tabs>
          )}
        </div>

        {/* Search history sidebar (right side) */}
        <div className="hidden md:block w-64 shrink-0">
          <SearchHistorySidebar onSelectQuery={handleHistorySelect} />
        </div>
      </div>
    </div>
  );
}
