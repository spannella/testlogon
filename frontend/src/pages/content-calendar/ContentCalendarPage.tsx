import { useState, useMemo, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ChevronLeft,
  ChevronRight,
  FileText,
  Radio,
  Video,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/shared/PageHeader";
import {
  getContentCalendar,
  rescheduleCalendarItem,
  cancelCalendarItem,
} from "@/api/endpoints/content-calendar";
import type { ContentCalendarItem, ContentItemType } from "@/api/types";
import { ContentCalendarWeek } from "./ContentCalendarWeek";
import { ContentCalendarMonth } from "./ContentCalendarMonth";
import { ContentCalendarMobileList } from "./ContentCalendarMobileList";
import { ConflictBanner } from "./ConflictBanner";
import { QuickScheduleDialog } from "./QuickScheduleDialog";
import { ContentItemDetail } from "./ContentItemDetail";

function getWeekRange(date: Date): { from_ts: number; to_ts: number } {
  const day = date.getDay();
  const start = new Date(date);
  start.setDate(start.getDate() - day);
  start.setHours(0, 0, 0, 0);
  const end = new Date(start);
  end.setDate(end.getDate() + 7);
  return {
    from_ts: Math.floor(start.getTime() / 1000),
    to_ts: Math.floor(end.getTime() / 1000),
  };
}

function getMonthRange(date: Date): { from_ts: number; to_ts: number } {
  const start = new Date(date.getFullYear(), date.getMonth(), 1);
  const end = new Date(date.getFullYear(), date.getMonth() + 1, 1);
  return {
    from_ts: Math.floor(start.getTime() / 1000),
    to_ts: Math.floor(end.getTime() / 1000),
  };
}

const TYPE_LABELS: Record<ContentItemType, string> = {
  post: "Posts",
  broadcast: "Broadcasts",
  vod: "Videos",
};

const TYPE_ICONS: Record<ContentItemType, typeof FileText> = {
  post: FileText,
  broadcast: Radio,
  vod: Video,
};

export default function ContentCalendarPage() {
  const queryClient = useQueryClient();
  const [view, setView] = useState<"week" | "month">("week");
  const [anchorDate, setAnchorDate] = useState(new Date());
  const [typeFilter, setTypeFilter] = useState<Set<ContentItemType>>(
    new Set(["post", "broadcast", "vod"]),
  );
  const [quickScheduleTime, setQuickScheduleTime] = useState<number | null>(null);
  const [selectedItem, setSelectedItem] = useState<ContentCalendarItem | null>(null);
  const [undoState, setUndoState] = useState<{
    item: ContentCalendarItem;
    originalTs: number;
  } | null>(null);

  const range = useMemo(
    () => (view === "week" ? getWeekRange(anchorDate) : getMonthRange(anchorDate)),
    [view, anchorDate],
  );

  const filterKey = useMemo(() => [...typeFilter].sort().join(","), [typeFilter]);

  const calendarQuery = useQuery({
    queryKey: ["content-calendar", range.from_ts, range.to_ts, filterKey],
    queryFn: () =>
      getContentCalendar(
        range.from_ts,
        range.to_ts,
        typeFilter.size === 3 ? undefined : [...typeFilter],
      ),
    refetchInterval: 60_000,
  });

  const rescheduleMut = useMutation({
    mutationFn: ({
      item,
      newTs,
    }: {
      item: ContentCalendarItem;
      newTs: number;
    }) => rescheduleCalendarItem(item.id, item.type, newTs),
    onMutate: ({ item, newTs }) => {
      const oldTs = item.scheduled_at;
      queryClient.setQueryData(
        ["content-calendar", range.from_ts, range.to_ts, filterKey],
        (old: unknown) => {
          if (!old || typeof old !== "object") return old;
          const o = old as { items: ContentCalendarItem[] };
          return {
            ...o,
            items: o.items.map((i: ContentCalendarItem) =>
              i.id === item.id && i.type === item.type
                ? { ...i, scheduled_at: newTs }
                : i,
            ),
          };
        },
      );
      setUndoState({ item, originalTs: oldTs });
      return { oldTs };
    },
    onSuccess: (_data, { item }) => {
      toast.success(`${item.type} rescheduled`, {
        action: undoState
          ? {
              label: "Undo",
              onClick: () => {
                if (undoState) {
                  rescheduleMut.mutate({
                    item: undoState.item,
                    newTs: undoState.originalTs,
                  });
                }
              },
            }
          : undefined,
        duration: 5000,
      });
      void queryClient.invalidateQueries({ queryKey: ["content-calendar"] });
      void queryClient.invalidateQueries({ queryKey: ["scheduled-posts"] });
    },
    onError: (err, { item }, context) => {
      if (context?.oldTs) {
        queryClient.setQueryData(
          ["content-calendar", range.from_ts, range.to_ts, filterKey],
          (old: unknown) => {
            if (!old || typeof old !== "object") return old;
            const o = old as { items: ContentCalendarItem[] };
            return {
              ...o,
              items: o.items.map((i: ContentCalendarItem) =>
                i.id === item.id && i.type === item.type
                  ? { ...i, scheduled_at: context.oldTs }
                  : i,
              ),
            };
          },
        );
      }
      toast.error(err instanceof Error ? err.message : "Failed to reschedule");
    },
  });

  const cancelMut = useMutation({
    mutationFn: (item: ContentCalendarItem) =>
      cancelCalendarItem(item.id, item.type),
    onSuccess: (_data, item) => {
      toast.success(`${item.type} cancelled`);
      setSelectedItem(null);
      void queryClient.invalidateQueries({ queryKey: ["content-calendar"] });
      void queryClient.invalidateQueries({ queryKey: ["scheduled-posts"] });
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : "Failed to cancel");
    },
  });

  const navigate = useCallback(
    (delta: number) => {
      setAnchorDate((prev) => {
        const next = new Date(prev);
        if (view === "week") {
          next.setDate(next.getDate() + delta * 7);
        } else {
          next.setMonth(next.getMonth() + delta);
        }
        return next;
      });
    },
    [view],
  );

  const goToToday = useCallback(() => setAnchorDate(new Date()), []);

  const toggleType = useCallback((type: ContentItemType) => {
    setTypeFilter((prev) => {
      const next = new Set(prev);
      if (next.has(type)) {
        if (next.size > 1) next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  }, []);

  const items = calendarQuery.data?.items ?? [];
  const conflicts = calendarQuery.data?.conflicts ?? [];

  const headerLabel = useMemo(() => {
    if (view === "week") {
      const weekStart = new Date(range.from_ts * 1000);
      const weekEnd = new Date(range.to_ts * 1000 - 86400000);
      const opts: Intl.DateTimeFormatOptions = { month: "short", day: "numeric" };
      return `${weekStart.toLocaleDateString(undefined, opts)} - ${weekEnd.toLocaleDateString(undefined, opts)}, ${weekEnd.getFullYear()}`;
    }
    return anchorDate.toLocaleDateString(undefined, { month: "long", year: "numeric" });
  }, [view, range, anchorDate]);

  return (
    <div className="mx-auto w-full max-w-6xl space-y-4 p-4 sm:p-6">
      <PageHeader
        title="Content Calendar"
        description="Manage your scheduled posts, broadcasts, and video releases"
      />

      {/* Conflict Banner */}
      {conflicts.length > 0 && (
        <ConflictBanner
          conflicts={conflicts}
          items={items}
          onResolve={(itemId, itemType, newTs) => {
            const item = items.find((i) => i.id === itemId && i.type === itemType);
            if (item) rescheduleMut.mutate({ item, newTs });
          }}
        />
      )}

      {/* Controls */}
      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-2 py-3">
          {/* Navigation */}
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="icon"
              onClick={() => navigate(-1)}
              aria-label={`Previous ${view}`}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="sm" onClick={goToToday}>
              Today
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => navigate(1)}
              aria-label={`Next ${view}`}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
            <span className="text-sm font-medium">{headerLabel}</span>
          </div>

          {/* View Toggle + Type Filters */}
          <div className="flex items-center gap-2">
            {(["post", "broadcast", "vod"] as ContentItemType[]).map((type) => {
              const Icon = TYPE_ICONS[type];
              const active = typeFilter.has(type);
              return (
                <Button
                  key={type}
                  variant={active ? "default" : "outline"}
                  size="sm"
                  onClick={() => toggleType(type)}
                  className="gap-1"
                  aria-pressed={active}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {TYPE_LABELS[type]}
                </Button>
              );
            })}
            <Tabs value={view} onValueChange={(v) => setView(v as "week" | "month")}>
              <TabsList>
                <TabsTrigger value="week">Week</TabsTrigger>
                <TabsTrigger value="month">Month</TabsTrigger>
              </TabsList>
            </Tabs>
          </div>
        </CardContent>
      </Card>

      {/* Calendar Grid */}
      <Card>
        <CardContent className="p-0">
          {/* Desktop */}
          <div className="hidden md:block">
            {view === "week" ? (
              <ContentCalendarWeek
                anchorDate={anchorDate}
                items={items}
                onDrop={(item, newTs) => rescheduleMut.mutate({ item, newTs })}
                onSlotClick={(ts) => setQuickScheduleTime(ts)}
                onItemClick={setSelectedItem}
              />
            ) : (
              <ContentCalendarMonth
                anchorDate={anchorDate}
                items={items}
                onDayClick={(date) => {
                  setAnchorDate(date);
                  setView("week");
                }}
                onItemClick={setSelectedItem}
              />
            )}
          </div>

          {/* Mobile */}
          <div className="block md:hidden">
            <ContentCalendarMobileList
              items={items}
              onItemClick={setSelectedItem}
              onCancel={(item) => cancelMut.mutate(item)}
            />
          </div>
        </CardContent>
      </Card>

      {/* Quick Schedule Dialog */}
      {quickScheduleTime !== null && (
        <QuickScheduleDialog
          open
          scheduledAt={quickScheduleTime}
          onClose={() => setQuickScheduleTime(null)}
          onCreated={() => {
            setQuickScheduleTime(null);
            void queryClient.invalidateQueries({ queryKey: ["content-calendar"] });
          }}
        />
      )}

      {/* Item Detail Panel */}
      {selectedItem && (
        <ContentItemDetail
          item={selectedItem}
          open
          onClose={() => setSelectedItem(null)}
          onCancel={() => cancelMut.mutate(selectedItem)}
          onReschedule={(newTs) =>
            rescheduleMut.mutate({ item: selectedItem, newTs })
          }
        />
      )}
    </div>
  );
}
