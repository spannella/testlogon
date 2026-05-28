import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  MessageSquare,
  CreditCard,
  FolderOpen,
  CalendarDays,
  Bell,
  ShoppingCart,
  ArrowRight,
  Clock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/shared/PageHeader";
import { PageMeta } from "@/components/shared/PageMeta";
import { cn } from "@/lib/utils";
import { OnboardingChecklist } from "@/components/shared/OnboardingChecklist";

import { getConversations } from "@/api/endpoints/messaging";
import { getBalance, getSettings as getBillingSettings } from "@/api/endpoints/billing";
import { listFiles } from "@/api/endpoints/files";
import { getAlerts } from "@/api/endpoints/alerts";
import { getCarts } from "@/api/endpoints/cart";
import { getCalendars, getEvents } from "@/api/endpoints/calendar";

// ─── Helpers ─────────────────────────────────────────────────────

function formatCents(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(cents / 100);
}

function formatAlertDetails(details: Record<string, unknown>): string {
  if (details.ip) return `IP: ${details.ip}`;
  const skip = new Set(["user_sub", "ts", "event", "outcome", "alert_type"]);
  const parts = Object.entries(details)
    .filter(([k, v]) => !skip.has(k) && v != null)
    .slice(0, 2)
    .map(([k, v]) => `${k}: ${v}`);
  return parts.join(", ");
}

function relativeTime(ts: number): string {
  const now = Date.now();
  const diff = now - ts * 1000;
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// ─── Dashboard Page ─────────────────────────────────────────────

export default function Dashboard() {
  const navigate = useNavigate();

  // ── Data queries ────────────────────────────────────────────────

  const conversations = useQuery({
    queryKey: ["conversations"],
    queryFn: () => getConversations(),
  });

  const balance = useQuery({
    queryKey: ["billing", "balance"],
    queryFn: getBalance,
  });

  const billingSettings = useQuery({
    queryKey: ["billing", "settings"],
    queryFn: getBillingSettings,
  });

  const files = useQuery({
    queryKey: ["files", "root"],
    queryFn: () => listFiles("/", { limit: 100 }),
  });

  const alerts = useQuery({
    queryKey: ["alerts", "recent"],
    queryFn: () => getAlerts({ limit: 5 }),
  });

  const carts = useQuery({
    queryKey: ["carts"],
    queryFn: getCarts,
  });

  const calendars = useQuery({
    queryKey: ["calendars"],
    queryFn: () => getCalendars(1),
  });

  const firstCalendarId = calendars.data?.[0]?.calendar_id;

  const events = useQuery({
    queryKey: ["events", "upcoming", firstCalendarId],
    queryFn: () => getEvents(firstCalendarId!),
    enabled: !!firstCalendarId,
    retry: false,
  });

  // ── Derived values ──────────────────────────────────────────────

  const unreadMessages = conversations.data?.conversations?.reduce(
    (sum, c) => sum + (c.unread_count ?? 0),
    0,
  ) ?? 0;

  const totalConversations = conversations.data?.conversations?.length ?? 0;

  const balanceOwed = (balance.data?.owed_settled_cents ?? 0) + (balance.data?.owed_pending_cents ?? 0);
  const balanceCurrency = balance.data?.currency ?? "USD";

  const fileCount = files.data?.items?.length ?? 0;

  const unreadAlerts = alerts.data?.alerts?.filter((a) => !a.read_at).length ?? 0;
  const recentAlerts = alerts.data?.alerts ?? [];

  const activeCarts = carts.data?.filter((c) => c.status === "open") ?? [];
  const activeCartCount = activeCarts.length;

  const nextEvent = events.data?.events?.[0];

  // ── Render ──────────────────────────────────────────────────────

  return (
    <div className="p-4 md:p-6 lg:p-8 space-y-6">
      <PageMeta title="Dashboard" />
      <PageHeader
        title="Dashboard"
        description="Overview of your account activity"
      />

      {/* Onboarding checklist for new users */}
      <OnboardingChecklist />

      {/* Summary cards */}
      <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
        {/* Messages */}
        <SummaryCard
          icon={<MessageSquare className="h-5 w-5" />}
          title="Messages"
          onClick={() => navigate("/messages")}
          loading={conversations.isLoading}
        >
          <p className="text-2xl font-bold">
            {unreadMessages > 0 ? (
              <>
                {unreadMessages} <span className="text-sm font-normal text-muted-foreground">unread</span>
              </>
            ) : (
              "No unread"
            )}
          </p>
          <p className="text-xs text-muted-foreground">
            {totalConversations} conversation{totalConversations !== 1 && "s"}
          </p>
        </SummaryCard>

        {/* Balance */}
        <SummaryCard
          icon={<CreditCard className="h-5 w-5" />}
          title="Balance"
          onClick={() => navigate("/billing")}
          loading={balance.isLoading}
        >
          <p className={cn("text-2xl font-bold", balanceOwed > 0 ? "text-destructive" : "text-success")}>
            {formatCents(balanceOwed, balanceCurrency)}
          </p>
          <p className="text-xs text-muted-foreground">
            {billingSettings.data?.autopay_enabled !== undefined
              ? `Autopay: ${billingSettings.data.autopay_enabled ? "ON" : "OFF"}`
              : "Billing overview"}
          </p>
        </SummaryCard>

        {/* Files */}
        <SummaryCard
          icon={<FolderOpen className="h-5 w-5" />}
          title="Files"
          onClick={() => navigate("/files")}
          loading={files.isLoading}
        >
          <p className="text-2xl font-bold">
            {fileCount} <span className="text-sm font-normal text-muted-foreground">item{fileCount !== 1 && "s"}</span>
          </p>
          <p className="text-xs text-muted-foreground">
            In root directory
          </p>
        </SummaryCard>

        {/* Calendar */}
        <SummaryCard
          icon={<CalendarDays className="h-5 w-5" />}
          title="Calendar"
          onClick={() => navigate("/calendar")}
          loading={calendars.isLoading || events.isLoading}
        >
          {nextEvent ? (
            <>
              <p className="text-sm font-semibold truncate">{nextEvent.name}</p>
              <p className="text-xs text-muted-foreground">
                {nextEvent.all_day
                  ? nextEvent.all_day_date ?? "All day"
                  : nextEvent.start_utc
                    ? new Date(nextEvent.start_utc).toLocaleString(undefined, {
                        month: "short",
                        day: "numeric",
                        hour: "numeric",
                        minute: "2-digit",
                      })
                    : "Upcoming"}
              </p>
            </>
          ) : (
            <>
              <p className="text-sm font-semibold">No upcoming events</p>
              <p className="text-xs text-muted-foreground">Your schedule is clear</p>
            </>
          )}
        </SummaryCard>

        {/* Alerts */}
        <SummaryCard
          icon={<Bell className="h-5 w-5" />}
          title="Alerts"
          onClick={() => navigate("/alerts")}
          loading={alerts.isLoading}
        >
          <p className="text-2xl font-bold">
            {unreadAlerts > 0 ? (
              <>
                {unreadAlerts} <span className="text-sm font-normal text-muted-foreground">unread</span>
              </>
            ) : (
              "All caught up"
            )}
          </p>
          <p className="text-xs text-muted-foreground">
            View all alerts
          </p>
        </SummaryCard>

        {/* Cart */}
        <SummaryCard
          icon={<ShoppingCart className="h-5 w-5" />}
          title="Cart"
          onClick={() => navigate("/cart")}
          loading={carts.isLoading}
        >
          <p className="text-2xl font-bold">
            {activeCartCount} <span className="text-sm font-normal text-muted-foreground">active cart{activeCartCount !== 1 && "s"}</span>
          </p>
          <p className="text-xs text-muted-foreground">
            {activeCartCount > 0 ? "View your carts" : "Start shopping"}
          </p>
        </SummaryCard>
      </div>

      {/* Recent Activity */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <CardTitle className="text-base">Recent Activity</CardTitle>
          <button
            className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
            onClick={() => navigate("/alerts")}
          >
            View all <ArrowRight className="h-3 w-3" />
          </button>
        </CardHeader>
        <CardContent>
          {alerts.isLoading ? (
            <div className="space-y-4">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="flex items-start gap-3">
                  <Skeleton className="h-8 w-8 rounded-full" />
                  <div className="flex-1 space-y-1.5">
                    <Skeleton className="h-3.5 w-3/4" />
                    <Skeleton className="h-3 w-1/2" />
                  </div>
                </div>
              ))}
            </div>
          ) : recentAlerts.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No recent activity
            </p>
          ) : (
            <div className="space-y-4">
              {recentAlerts.map((alert) => (
                <div key={alert.alert_id} className="flex items-start gap-3">
                  <div className={cn(
                    "mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full",
                    alert.read_at ? "bg-muted" : "bg-primary/10",
                  )}>
                    <Clock className={cn("h-4 w-4", alert.read_at ? "text-muted-foreground" : "text-primary")} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium truncate">{alert.title}</p>
                      {!alert.read_at && <Badge variant="default" className="h-4 px-1 text-[10px]">New</Badge>}
                    </div>
                    {alert.details && (
                      <p className="text-xs text-muted-foreground truncate">{formatAlertDetails(alert.details)}</p>
                    )}
                    <p className="text-[11px] text-muted-foreground">{relativeTime(alert.ts)}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Summary Card ───────────────────────────────────────────────

interface SummaryCardProps {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
  onClick: () => void;
  loading?: boolean;
}

function SummaryCard({ icon, title, children, onClick, loading }: SummaryCardProps) {
  return (
    <Card
      className="cursor-pointer transition-shadow hover:shadow-md"
      onClick={onClick}
    >
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <div className="text-muted-foreground">{icon}</div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="space-y-2">
            <Skeleton className="h-7 w-24" />
            <Skeleton className="h-3 w-32" />
          </div>
        ) : (
          children
        )}
      </CardContent>
    </Card>
  );
}
