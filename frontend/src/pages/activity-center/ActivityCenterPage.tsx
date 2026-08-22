import * as React from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  TrendingUp,
  Coins,
  AlertTriangle,
  ShieldAlert,
  Wallet,
  Bell,
  CheckCheck,
  Loader2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { relativeTime } from "@/hooks/useTradingAlerts";
import {
  filterByCategory,
  groupByDay,
  isUnread,
  type ActivityCategory,
  type ActivityEvent,
  type ActivitySeverity,
} from "@/lib/activity";
import {
  useActivityEvents,
  loadLastSeen,
  saveLastSeen,
  ACTIVITY_SEEN_EVENT,
} from "@/hooks/useActivity";

// ── Category filter chips ────────────────────────────────────────────
const CHIPS: { key: ActivityCategory | "all"; label: string }[] = [
  { key: "all", label: "All" },
  { key: "trade", label: "Trades" },
  { key: "funding", label: "Funding" },
  { key: "liquidation", label: "Liquidations" },
  { key: "risk", label: "Risk" },
  { key: "money", label: "Money" },
  { key: "system", label: "System" },
];

function CategoryIcon({
  category,
  severity,
}: {
  category: ActivityCategory;
  severity: ActivitySeverity;
}) {
  const cls = cn(
    "h-4 w-4 shrink-0",
    severity === "success" && "text-emerald-500",
    severity === "warning" && "text-amber-500",
    severity === "critical" && "text-destructive",
    severity === "info" && "text-sky-500",
  );
  switch (category) {
    case "trade":
      return <TrendingUp className={cls} />;
    case "funding":
      return <Coins className={cls} />;
    case "liquidation":
      return <AlertTriangle className={cls} />;
    case "risk":
      return <ShieldAlert className={cls} />;
    case "money":
      return <Wallet className={cls} />;
    default:
      return <Activity className={cls} />;
  }
}

function EventRow({
  ev,
  unread,
  now,
}: {
  ev: ActivityEvent;
  unread: boolean;
  now: number;
}) {
  const body = (
    <div
      className={cn(
        "flex items-start gap-3 rounded-lg border px-4 py-3 transition-colors",
        ev.href && "hover:bg-accent",
        unread && "border-primary/40 bg-accent/40",
      )}
    >
      <CategoryIcon category={ev.category} severity={ev.severity} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-medium">{ev.title}</span>
          {unread && (
            <span className="ml-auto h-2 w-2 shrink-0 rounded-full bg-primary" aria-label="unread" />
          )}
        </div>
        {ev.subtitle && (
          <p className="truncate text-xs text-muted-foreground">{ev.subtitle}</p>
        )}
        <p className="mt-0.5 text-[10px] text-muted-foreground">{relativeTime(ev.ts, now)}</p>
      </div>
    </div>
  );
  return ev.href ? (
    <Link to={ev.href} className="block focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-lg">
      {body}
    </Link>
  ) : (
    body
  );
}

/** Human day heading — "Today" / "Yesterday" / a full date. */
function dayLabel(dayKey: string, now: number): string {
  const today = new Date(now);
  const todayKey = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, "0")}-${String(today.getDate()).padStart(2, "0")}`;
  const yest = new Date(now - 86_400_000);
  const yestKey = `${yest.getFullYear()}-${String(yest.getMonth() + 1).padStart(2, "0")}-${String(yest.getDate()).padStart(2, "0")}`;
  if (dayKey === todayKey) return "Today";
  if (dayKey === yestKey) return "Yesterday";
  const [y = 1970, m = 1, d = 1] = dayKey.split("-").map(Number);
  return new Date(y, m - 1, d).toLocaleDateString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

/**
 * Activity Center — a durable, filterable, day-grouped timeline of every
 * account event, aggregated client-side from the same `/me/*` feeds that power
 * the transient alerts bell. Unread is tracked against a persisted last-seen
 * marker; "Mark all read" advances it to the newest event.
 */
export default function ActivityCenterPage() {
  const { events, sources, isLoading } = useActivityEvents(true);
  const [category, setCategory] = React.useState<ActivityCategory | "all">("all");
  const [lastSeen, setLastSeen] = React.useState<number>(() => loadLastSeen());

  // Refresh relative times periodically.
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, []);

  const newestTs = events.length > 0 ? events[0]!.ts : 0;
  const unread = React.useMemo(
    () => events.reduce((n, e) => (isUnread(e, lastSeen) ? n + 1 : n), 0),
    [events, lastSeen],
  );

  const markAllRead = React.useCallback(() => {
    const ts = newestTs || Date.now();
    saveLastSeen(ts);
    setLastSeen(ts);
    try {
      window.dispatchEvent(new CustomEvent(ACTIVITY_SEEN_EVENT));
    } catch {
      /* SSR / no window */
    }
  }, [newestTs]);

  const filtered = React.useMemo(
    () => filterByCategory(events, category),
    [events, category],
  );
  const groups = React.useMemo(() => groupByDay(filtered), [filtered]);

  const anySourceDown = !sources.fills || !sources.funding || !sources.liquidations;
  const downList = [
    !sources.fills ? "fills" : null,
    !sources.funding ? "funding" : null,
    !sources.liquidations ? "liquidations" : null,
  ].filter(Boolean);

  return (
    <div className="mx-auto w-full max-w-3xl space-y-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Activity className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-semibold">Activity Center</h1>
          {unread > 0 && (
            <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-destructive px-1.5 text-xs font-bold text-destructive-foreground">
              {unread > 99 ? "99+" : unread}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="ghost" size="sm" className="gap-2">
            <Link to="/markets/price-alerts">
              <Bell className="h-4 w-4" />
              Price alerts
            </Link>
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
            onClick={markAllRead}
            disabled={unread === 0}
          >
            <CheckCheck className="h-4 w-4" />
            Mark all read
          </Button>
        </div>
      </div>

      <p className="text-sm text-muted-foreground">
        A durable history of your fills, funding, liquidations and risk events — the
        permanent record behind the transient alerts bell.
      </p>

      {/* Category filter chips */}
      <div className="flex flex-wrap gap-2">
        {CHIPS.map((c) => (
          <Button
            key={c.key}
            variant={category === c.key ? "default" : "outline"}
            size="sm"
            className="h-7 rounded-full px-3 text-xs"
            onClick={() => setCategory(c.key)}
          >
            {c.label}
          </Button>
        ))}
      </div>

      {anySourceDown && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            Some activity sources are unavailable ({downList.join(", ")}). Showing what
            is available.
          </span>
        </div>
      )}

      {isLoading && events.length === 0 ? (
        <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          Loading activity…
        </div>
      ) : groups.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center gap-2 py-16 text-center">
            <Activity className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm font-medium">No activity yet</p>
            <p className="max-w-sm text-xs text-muted-foreground">
              {category === "all"
                ? "Your fills, funding payments, liquidations and risk events will appear here as they happen."
                : "No events in this category yet. Try a different filter."}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-6">
          {groups.map((g) => (
            <div key={g.day} className="space-y-2">
              <h2 className="sticky top-0 z-10 bg-background/80 py-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground backdrop-blur">
                {dayLabel(g.day, now)}
              </h2>
              <div className="space-y-2">
                {g.events.map((ev) => (
                  <EventRow key={ev.id} ev={ev} unread={isUnread(ev, lastSeen)} now={now} />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
