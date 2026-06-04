import * as React from "react";
import { useInfiniteQuery, useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Search,
  Bell,
  CheckCheck,
  ChevronDown,
  ChevronUp,
  Filter,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { EmptyState } from "@/components/shared/EmptyState";
import { getAlerts, searchAlerts, getAlertTypes, markRead } from "@/api/endpoints/alerts";
import type { Alert } from "@/api/types";

export function AlertCenter() {
  const queryClient = useQueryClient();
  const [search, setSearch] = React.useState("");
  const [typeFilter, setTypeFilter] = React.useState("all");
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set());

  // Fetch available alert types for the filter
  const typesQuery = useQuery({
    queryKey: ["alert-types"],
    queryFn: getAlertTypes,
  });

  // Search query (simple query, not infinite)
  const searchQuery = useQuery({
    queryKey: ["alerts", "search", search],
    queryFn: () => searchAlerts(search),
    enabled: search.trim().length > 0,
  });

  // Infinite query for paginated alerts
  const alertsQuery = useInfiniteQuery({
    queryKey: ["alerts", "list", typeFilter],
    queryFn: ({ pageParam }) =>
      getAlerts({
        limit: 25,
        cursor: pageParam as string | undefined,
        unread_only: typeFilter === "unread" ? true : undefined,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
    enabled: search.trim().length === 0,
  });

  const markReadMutation = useMutation({
    mutationFn: (alertIds: string[]) => markRead({ alert_ids: alertIds }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      setSelected(new Set());
      toast.success("Marked as read");
    },
    onError: () => {
      toast.error("Failed to mark alerts as read");
    },
  });

  // Determine which alerts to show
  const isSearching = search.trim().length > 0;
  const allAlerts: Alert[] = isSearching
    ? (searchQuery.data?.alerts ?? [])
    : (alertsQuery.data?.pages ?? []).flatMap((p) => p.alerts);

  // Filter by event type if not "all" or "unread"
  const filteredAlerts = typeFilter !== "all" && typeFilter !== "unread"
    ? allAlerts.filter((a) => a.event === typeFilter)
    : allAlerts;

  const eventTypes = typesQuery.data?.event_types ?? [];

  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    if (selected.size === filteredAlerts.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filteredAlerts.map((a) => a.alert_id)));
    }
  };

  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleMarkSelected = () => {
    const ids = Array.from(selected);
    if (ids.length > 0) markReadMutation.mutate(ids);
  };

  const isLoading = isSearching ? searchQuery.isLoading : alertsQuery.isLoading;

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search alerts..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>

        {/* Filter */}
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <Select value={typeFilter} onValueChange={setTypeFilter}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="All alerts" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All alerts</SelectItem>
              <SelectItem value="unread">Unread only</SelectItem>
              {eventTypes.map((t) => (
                <SelectItem key={t} value={t}>
                  {t.replace(/_/g, " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Bulk actions */}
      {filteredAlerts.length > 0 && (
        <div className="flex items-center gap-3 rounded-lg border bg-muted/50 px-3 py-2">
          <Checkbox
            checked={selected.size === filteredAlerts.length && filteredAlerts.length > 0}
            onCheckedChange={selectAll}
            aria-label="Select all"
          />
          <span className="text-xs text-muted-foreground">
            {selected.size > 0
              ? `${selected.size} selected`
              : `${filteredAlerts.length} alert${filteredAlerts.length !== 1 ? "s" : ""}`}
          </span>
          {selected.size > 0 && (
            <Button
              variant="outline"
              size="sm"
              className="ml-auto h-7 text-xs"
              onClick={handleMarkSelected}
              disabled={markReadMutation.isPending}
            >
              <CheckCheck className="mr-1 h-3 w-3" />
              Mark as read
            </Button>
          )}
        </div>
      )}

      {/* Alert list */}
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full rounded-lg" />
          ))}
        </div>
      ) : filteredAlerts.length === 0 ? (
        <EmptyState
          icon={<Bell className="h-8 w-8" />}
          title={isSearching ? "No matching alerts" : "No alerts"}
          description={isSearching ? "Try a different search term" : "You're all caught up!"}
          className="py-16"
        />
      ) : (
        <div className="space-y-1">
          {filteredAlerts.map((alert) => {
            const isExpanded = expanded.has(alert.alert_id);
            const isSelected = selected.has(alert.alert_id);
            const isUnread = !alert.read_at;

            return (
              <div
                key={alert.alert_id}
                className={cn(
                  "rounded-lg border transition-colors",
                  isSelected && "border-primary/50 bg-primary/5",
                  isUnread && !isSelected && "bg-accent/30",
                )}
              >
                <div className="flex items-start gap-3 px-4 py-3">
                  <Checkbox
                    checked={isSelected}
                    onCheckedChange={() => toggleSelect(alert.alert_id)}
                    className="mt-0.5"
                    aria-label={`Select alert: ${alert.title}`}
                  />

                  {/* Unread dot */}
                  <div className="mt-1.5 shrink-0">
                    {isUnread ? (
                      <div className="h-2 w-2 rounded-full bg-primary" />
                    ) : (
                      <div className="h-2 w-2" />
                    )}
                  </div>

                  <div className="min-w-0 flex-1">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className={cn("text-sm", isUnread && "font-medium")}>
                          {alert.title}
                        </p>
                        {!isExpanded && alert.details && (
                          <p className="mt-0.5 truncate text-xs text-muted-foreground">
                            {formatAlertDetails(alert.details)}
                          </p>
                        )}
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <Badge variant="outline" className="text-[10px]">
                          {(alert.event ?? "").replace(/_/g, " ")}
                        </Badge>
                        <span className="text-[10px] text-muted-foreground whitespace-nowrap">
                          {formatAlertDate(alert.ts)}
                        </span>
                      </div>
                    </div>

                    {/* Expanded details */}
                    {isExpanded && alert.details && (
                      <pre className="mt-2 whitespace-pre-wrap break-all text-xs text-muted-foreground">
                        {JSON.stringify(alert.details, null, 2)}
                      </pre>
                    )}
                  </div>

                  {/* Expand toggle */}
                  {alert.details && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 shrink-0"
                      onClick={() => toggleExpand(alert.alert_id)}
                    >
                      {isExpanded ? (
                        <ChevronUp className="h-3.5 w-3.5" />
                      ) : (
                        <ChevronDown className="h-3.5 w-3.5" />
                      )}
                    </Button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Load more */}
      {!isSearching && alertsQuery.hasNextPage && (
        <div className="flex justify-center pt-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => alertsQuery.fetchNextPage()}
            disabled={alertsQuery.isFetchingNextPage}
          >
            {alertsQuery.isFetchingNextPage ? "Loading..." : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────

function formatAlertDetails(details: Record<string, unknown>): string {
  if (details.ip) return `IP: ${details.ip}`;
  const skip = new Set(["user_sub", "ts", "event", "outcome", "alert_type"]);
  const parts = Object.entries(details)
    .filter(([k, v]) => !skip.has(k) && v != null)
    .slice(0, 2)
    .map(([k, v]) => `${k}: ${v}`);
  return parts.join(", ");
}

function formatAlertDate(ts: number): string {
  const date = new Date(ts * 1000);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMin = Math.floor(diffMs / 60_000);

  if (diffMin < 1) return "Just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHrs = Math.floor(diffMin / 60);
  if (diffHrs < 24) return `${diffHrs}h ago`;
  const diffDays = Math.floor(diffHrs / 24);
  if (diffDays === 1) return "Yesterday";
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
