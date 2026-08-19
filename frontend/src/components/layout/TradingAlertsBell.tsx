import * as React from "react";
import {
  Bell,
  TrendingUp,
  AlertTriangle,
  Coins,
  Gavel,
  ShieldAlert,
  CheckCheck,
  Trash2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  useTradingAlerts,
  relativeTime,
  type TradingAlert,
  type TradingAlertKind,
} from "@/hooks/useTradingAlerts";

/** Per-kind icon for the alert row. */
function KindIcon({ kind }: { kind: TradingAlertKind }) {
  const cls = "h-4 w-4 shrink-0";
  switch (kind) {
    case "fill":
      return <TrendingUp className={cn(cls, "text-emerald-500")} />;
    case "liquidation":
      return <AlertTriangle className={cn(cls, "text-destructive")} />;
    case "funding":
      return <Coins className={cn(cls, "text-amber-500")} />;
    case "margin":
      return <ShieldAlert className={cn(cls, "text-destructive")} />;
    case "pm_resolved":
      return <Gavel className={cn(cls, "text-sky-500")} />;
    default:
      return <Bell className={cls} />;
  }
}

function AlertRow({
  alert,
  onClick,
  now,
}: {
  alert: TradingAlert;
  onClick: () => void;
  now: number;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex w-full items-start gap-3 px-4 py-2.5 text-left transition-colors hover:bg-accent",
        !alert.read && "bg-accent/40",
      )}
    >
      <KindIcon kind={alert.kind} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-medium">{alert.title}</span>
          {!alert.read && (
            <span className="ml-auto h-2 w-2 shrink-0 rounded-full bg-primary" />
          )}
        </div>
        <p className="truncate text-xs text-muted-foreground">{alert.message}</p>
        <p className="mt-0.5 text-[10px] text-muted-foreground">
          {relativeTime(alert.ts, now)}
        </p>
      </div>
    </button>
  );
}

/**
 * Trading notification bell — a self-contained chrome widget. It runs
 * `useTradingAlerts()` (which derives alerts from the `/me/*` trader feeds),
 * shows an unread badge, and lists recent alerts with mark-read / clear.
 * Toasts are fired inside the hook on genuinely-new alerts.
 */
export default function TradingAlertsBell({ enabled = true }: { enabled?: boolean }) {
  const { alerts, unreadCount, markAllRead, markRead, clearAll } =
    useTradingAlerts(enabled);
  const [open, setOpen] = React.useState(false);

  // Re-render relative times every 30s while the popover is open.
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    if (!open) return;
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, [open]);

  // Shake the bell when the unread count rises.
  const [shake, setShake] = React.useState(false);
  const prevUnread = React.useRef(unreadCount);
  React.useEffect(() => {
    if (unreadCount > prevUnread.current) {
      setShake(true);
      const t = setTimeout(() => setShake(false), 500);
      prevUnread.current = unreadCount;
      return () => clearTimeout(t);
    }
    prevUnread.current = unreadCount;
  }, [unreadCount]);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="relative focus-visible:ring-2 focus-visible:ring-ring"
          aria-label="Trading alerts"
        >
          <Bell className={cn("h-5 w-5", shake && "animate-bell-shake")} />
          {unreadCount > 0 && (
            <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-bold text-destructive-foreground">
              {unreadCount > 99 ? "99+" : unreadCount}
            </span>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96 p-0">
        <div className="flex items-center justify-between border-b px-4 py-2">
          <span className="text-sm font-semibold">Trading alerts</span>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-xs"
              onClick={markAllRead}
              disabled={unreadCount === 0}
            >
              <CheckCheck className="h-3.5 w-3.5" />
              Mark read
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 gap-1 px-2 text-xs"
              onClick={clearAll}
              disabled={alerts.length === 0}
            >
              <Trash2 className="h-3.5 w-3.5" />
              Clear
            </Button>
          </div>
        </div>
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center">
            <Bell className="h-6 w-6 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No trading alerts yet</p>
            <p className="text-xs text-muted-foreground">
              Fills, liquidations, funding, margin &amp; market resolutions show up here.
            </p>
          </div>
        ) : (
          <ScrollArea className="max-h-96">
            <div className="divide-y">
              {alerts.map((a) => (
                <AlertRow key={a.id} alert={a} now={now} onClick={() => markRead(a.id)} />
              ))}
            </div>
          </ScrollArea>
        )}
      </PopoverContent>
    </Popover>
  );
}
