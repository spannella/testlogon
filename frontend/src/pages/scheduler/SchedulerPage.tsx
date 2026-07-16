import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listScheduledActions,
  deleteScheduledAction,
  getSchedulerCalendar,
  type ScheduledActionOut,
} from "@/api/endpoints/scheduler";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { CalendarClock, X, ChevronLeft, ChevronRight } from "lucide-react";
import { toast } from "sonner";

// ─── Color coding ───────────────────────────────────────────────

const TYPE_COLORS: Record<string, string> = {
  post: "bg-green-500",
  file_share: "bg-purple-500",
  catalog_sale: "bg-orange-500",
  message: "bg-blue-500",
  broadcast: "bg-red-500",
};

const TYPE_LABELS: Record<string, string> = {
  post: "Post",
  file_share: "File Share",
  catalog_sale: "Sale",
  message: "Message",
  broadcast: "Broadcast",
};

const STATUS_VARIANTS: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  pending: "default",
  executing: "secondary",
  completed: "outline",
  failed: "destructive",
  cancelled: "secondary",
};

function formatDateTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

// ─── Calendar Grid ──────────────────────────────────────────────

function CalendarGrid({
  year,
  month,
  actions,
}: {
  year: number;
  month: number;
  actions: ScheduledActionOut[];
}) {
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  const firstDay = new Date(year, month, 1).getDay();

  const dayActionMap = useMemo(() => {
    const m: Record<number, ScheduledActionOut[]> = {};
    for (const a of actions) {
      const d = new Date(a.scheduled_at * 1000);
      if (d.getFullYear() === year && d.getMonth() === month) {
        const day = d.getDate();
        if (!m[day]) m[day] = [];
        m[day].push(a);
      }
    }
    return m;
  }, [actions, year, month]);

  const cells = [];
  // Empty cells for days before the first
  for (let i = 0; i < firstDay; i++) {
    cells.push(<div key={`empty-${i}`} className="h-24 border border-border/30" />);
  }
  for (let day = 1; day <= daysInMonth; day++) {
    const dayActions = dayActionMap[day] || [];
    cells.push(
      <div key={day} className="h-24 border border-border/30 p-1 overflow-hidden">
        <div className="text-xs font-medium text-muted-foreground">{day}</div>
        <div className="mt-0.5 space-y-0.5">
          {dayActions.slice(0, 3).map((a) => (
            <div
              key={a.action_id}
              className={`text-xs text-white rounded px-1 truncate ${TYPE_COLORS[a.action_type] || "bg-gray-500"}`}
              title={`${a.title || a.action_type} - ${formatDateTime(a.scheduled_at)}`}
            >
              {a.title || TYPE_LABELS[a.action_type] || a.action_type}
            </div>
          ))}
          {dayActions.length > 3 && (
            <div className="text-xs text-muted-foreground">+{dayActions.length - 3} more</div>
          )}
        </div>
      </div>,
    );
  }

  return (
    <div>
      <div className="grid grid-cols-7 text-center text-xs font-medium text-muted-foreground mb-1">
        {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map((d) => (
          <div key={d}>{d}</div>
        ))}
      </div>
      <div className="grid grid-cols-7">{cells}</div>
    </div>
  );
}

// ─── Action List ────────────────────────────────────────────────

function ActionRow({
  action,
  onCancel,
}: {
  action: ScheduledActionOut;
  onCancel: (id: string) => void;
}) {
  return (
    <div className="flex items-center gap-3 py-2 border-b last:border-b-0">
      <div className={`w-2 h-2 rounded-full ${TYPE_COLORS[action.action_type] || "bg-gray-500"}`} />
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium truncate">
          {action.title || TYPE_LABELS[action.action_type] || action.action_type}
        </div>
        <div className="text-xs text-muted-foreground">
          {formatDateTime(action.scheduled_at)}
        </div>
      </div>
      <Badge variant={STATUS_VARIANTS[action.status] || "default"}>
        {action.status}
      </Badge>
      {action.status === "pending" && (
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          onClick={() => onCancel(action.action_id)}
          title="Cancel"
        >
          <X className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────

export default function SchedulerPage() {
  const qc = useQueryClient();
  const [typeFilter, setTypeFilter] = useState("all");
  const [viewMonth, setViewMonth] = useState(() => {
    const d = new Date();
    return { year: d.getFullYear(), month: d.getMonth() };
  });

  // Calendar data -- full month range
  const fromDate = Math.floor(
    new Date(viewMonth.year, viewMonth.month, 1).getTime() / 1000,
  );
  const toDate = Math.floor(
    new Date(viewMonth.year, viewMonth.month + 1, 0, 23, 59, 59).getTime() / 1000,
  );

  const calendarQ = useQuery({
    queryKey: ["scheduler", "calendar", { from: fromDate, to: toDate, types: typeFilter === "all" ? undefined : typeFilter }],
    queryFn: () =>
      getSchedulerCalendar({
        from_date: fromDate,
        to_date: toDate,
        types: typeFilter === "all" ? undefined : typeFilter,
      }),
  });

  const listQ = useQuery({
    queryKey: ["scheduler", "actions", { types: typeFilter === "all" ? undefined : typeFilter }],
    queryFn: () =>
      listScheduledActions({
        types: typeFilter === "all" ? undefined : typeFilter,
      }),
  });

  const cancelMut = useMutation({
    mutationFn: (actionId: string) => deleteScheduledAction(actionId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scheduler"] });
      toast.success("Action cancelled");
    },
    onError: () => toast.error("Failed to cancel action"),
  });

  const prevMonth = () =>
    setViewMonth((v) => {
      const m = v.month - 1;
      return m < 0 ? { year: v.year - 1, month: 11 } : { year: v.year, month: m };
    });

  const nextMonth = () =>
    setViewMonth((v) => {
      const m = v.month + 1;
      return m > 11 ? { year: v.year + 1, month: 0 } : { year: v.year, month: m };
    });

  const monthLabel = new Date(viewMonth.year, viewMonth.month).toLocaleDateString(undefined, {
    month: "long",
    year: "numeric",
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <CalendarClock className="h-6 w-6" />
        <h1 className="text-2xl font-bold">Scheduled Content</h1>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="All types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            <SelectItem value="post">Posts</SelectItem>
            <SelectItem value="file_share">File Shares</SelectItem>
            <SelectItem value="catalog_sale">Sales</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Calendar view */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle>Calendar</CardTitle>
            <div className="flex items-center gap-2">
              <Button variant="ghost" size="icon" onClick={prevMonth}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-sm font-medium min-w-[140px] text-center">
                {monthLabel}
              </span>
              <Button variant="ghost" size="icon" onClick={nextMonth}>
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <CardDescription>
            {calendarQ.data?.total ?? 0} scheduled items this month
          </CardDescription>
        </CardHeader>
        <CardContent>
          <CalendarGrid
            year={viewMonth.year}
            month={viewMonth.month}
            actions={calendarQ.data?.actions || []}
          />
        </CardContent>
      </Card>

      {/* Action list */}
      <Card>
        <CardHeader>
          <CardTitle>All Scheduled Actions</CardTitle>
          <CardDescription>
            {listQ.data?.actions?.length ?? 0} actions
          </CardDescription>
        </CardHeader>
        <CardContent>
          {listQ.isLoading && <p className="text-muted-foreground">Loading...</p>}
          {listQ.data?.actions?.length === 0 && (
            <p className="text-muted-foreground text-sm">No scheduled content yet.</p>
          )}
          {listQ.data?.actions?.map((action) => (
            <ActionRow
              key={action.action_id}
              action={action}
              onCancel={(id) => cancelMut.mutate(id)}
            />
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
