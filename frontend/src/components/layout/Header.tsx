import * as React from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Search,
  Bell,
  Sun,
  Moon,
  Monitor,
  LogOut,
  User,
  Settings,
  Menu,
  CheckCheck,
  Check,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import TradingAlertsBell from "@/components/layout/TradingAlertsBell";
import PriceAlertEvaluator from "@/components/layout/PriceAlertEvaluator";
import { useGlobalShortcuts, type Shortcut } from "@/hooks/useGlobalShortcuts";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { useAuthStore } from "@/stores/authStore";
import { useUiStore, type Theme } from "@/stores/uiStore";
import { logout as apiLogout } from "@/api/endpoints/auth";
import { getAlerts, markAllAlertRead, getActivityFeed } from "@/api/endpoints/alerts";
import { getProfile } from "@/api/endpoints/profile";
import { useAlertStream } from "@/hooks/useAlertStream";
import type { Profile } from "@/api/types";

function getInitials(profile: Profile | undefined, userId: string | null): string {
  const first = profile?.first_name?.trim();
  const last = profile?.last_name?.trim();
  if (first && last) return (first[0]! + last[0]!).toUpperCase();
  if (first) return first.slice(0, 2).toUpperCase();
  if (last) return last.slice(0, 2).toUpperCase();
  const display = profile?.display_name?.trim();
  if (display) {
    const parts = display.split(/\s+/);
    if (parts.length >= 2) return (parts[0]![0]! + parts[parts.length - 1]![0]!).toUpperCase();
    return display.slice(0, 2).toUpperCase();
  }
  return userId ? userId.slice(0, 2).toUpperCase() : "U";
}

interface HeaderProps {
  onMobileMenuToggle?: () => void;
}

// ─── Header Component ───────────────────────────────────────────

export default function Header({ onMobileMenuToggle }: HeaderProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const userId = useAuthStore((s) => s.userId);
  const logoutAuth = useAuthStore((s) => s.logout);
  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);

  const profileQuery = useQuery({
    queryKey: ["profile"],
    queryFn: getProfile,
    staleTime: 5 * 60 * 1000,
  });

  const [alertsOpen, setAlertsOpen] = React.useState(false);

  // Real-time alert stream
  const { unreadCount, resetUnread } = useAlertStream(true);

  // Bell shake animation when unread count increases
  const [bellShake, setBellShake] = React.useState(false);
  const prevUnreadRef = React.useRef(unreadCount);
  React.useEffect(() => {
    if (unreadCount > prevUnreadRef.current) {
      setBellShake(true);
      const timer = setTimeout(() => setBellShake(false), 500);
      return () => clearTimeout(timer);
    }
    prevUnreadRef.current = unreadCount;
  }, [unreadCount]);

  // Fetch recent alerts for the popover
  const recentAlerts = useQuery({
    queryKey: ["alerts", "recent"],
    queryFn: () => getAlerts({ limit: 10 }),
    enabled: alertsOpen,
  });

  const markAllRead = useMutation({
    mutationFn: () => markAllAlertRead(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      resetUnread();
    },
  });

  // ─── Global keyboard shortcuts ────────────────────────────────
  const shortcuts = React.useMemo<Shortcut[]>(() => [
    {
      key: "ctrl+shift+d",
      label: "Toggle dark mode",
      group: "Actions",
      action: () => setTheme(theme === "dark" ? "light" : "dark"),
    },
    {
      key: "ctrl+shift+n",
      label: "New message",
      group: "Actions",
      action: () => navigate("/messages?new=1"),
    },
    {
      key: "ctrl+shift+p",
      label: "New post",
      group: "Actions",
      action: () => navigate("/feed?compose=1"),
    },
    {
      key: "ctrl+enter",
      label: "Send message",
      group: "Messaging",
      action: () => { /* handled locally in ComposeBar */ },
      activeInInput: true,
    },
  ], [navigate, setTheme, theme]);

  useGlobalShortcuts(shortcuts);


  const handleLogout = async () => {
    try {
      await apiLogout();
    } catch {
      // Logout even if API call fails
    }
    logoutAuth();
    navigate("/login", { replace: true });
  };

  const themeIcon = {
    system: <Monitor className="h-4 w-4" />,
    light: <Sun className="h-4 w-4" />,
    dark: <Moon className="h-4 w-4" />,
  }[theme];

  const THEME_OPTIONS: { value: Theme; label: string; icon: React.ReactNode }[] = [
    { value: "system", label: "System", icon: <Monitor className="h-4 w-4" /> },
    { value: "light",  label: "Light",  icon: <Sun    className="h-4 w-4" /> },
    { value: "dark",   label: "Dark",   icon: <Moon   className="h-4 w-4" /> },
  ];

  const initials = getInitials(profileQuery.data?.profile, userId);

  const alerts = recentAlerts.data?.alerts ?? [];

  // Bell popover tab state (PLATFORM-012)
  const [bellTab, setBellTab] = React.useState<"activity" | "system">("activity");

  // Activity feed for bell popover
  const bellActivityQuery = useQuery({
    queryKey: ["alerts", "activity-feed-bell"],
    queryFn: () => getActivityFeed({ limit: 10 }),
    enabled: alertsOpen && bellTab === "activity",
  });
  const bellActivityItems = bellActivityQuery.data?.items ?? [];

  return (
    <>
      <header className="flex h-14 items-center gap-2 border-b border-border bg-card px-4">
        {/* Mobile menu button */}
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden focus-visible:ring-2 focus-visible:ring-ring"
          onClick={onMobileMenuToggle}
          aria-label="Open menu"
        >
          <Menu className="h-5 w-5" />
        </Button>

        {/* Search */}
        <Button
          variant="outline"
          className={cn(
            "relative h-9 justify-start gap-2 text-sm text-muted-foreground",
            "w-40 sm:w-64 lg:w-80",
          )}
          onClick={() =>
            window.dispatchEvent(
              new KeyboardEvent("keydown", {
                key: "k",
                ctrlKey: !navigator.userAgent.includes("Mac"),
                metaKey: navigator.userAgent.includes("Mac"),
                bubbles: true,
              }),
            )
          }
        >
          <Search className="h-4 w-4" />
          <span className="hidden sm:inline">Search...</span>
          <kbd className="pointer-events-none ml-auto hidden select-none rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px] font-medium text-muted-foreground sm:inline-block">
            {navigator.userAgent.includes("Mac") ? "\u2318K" : "Ctrl+K"}
          </kbd>
        </Button>

        <div className="flex-1" />

        {/* Theme picker */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              aria-label={`Theme: ${theme}`}
              className="focus-visible:ring-2 focus-visible:ring-ring"
            >
              {themeIcon}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-36">
            <DropdownMenuLabel className="text-xs text-muted-foreground font-normal pb-1">
              Appearance
            </DropdownMenuLabel>
            {THEME_OPTIONS.map((opt) => (
              <DropdownMenuItem
                key={opt.value}
                onClick={() => setTheme(opt.value)}
                className="gap-2"
              >
                {opt.icon}
                {opt.label}
                {theme === opt.value && <Check className="ml-auto h-3.5 w-3.5" />}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Trading alerts bell (client-derived from /me/* feeds) */}
        <TradingAlertsBell enabled={!!userId} />
        <PriceAlertEvaluator enabled={!!userId} />

        {/* Alert bell with popover */}
        <Popover open={alertsOpen} onOpenChange={setAlertsOpen}>
          <PopoverTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="relative focus-visible:ring-2 focus-visible:ring-ring"
              aria-label="Alerts"
            >
              <Bell className={cn("h-5 w-5", bellShake && "animate-bell-shake")} />
              {unreadCount > 0 && (
                <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-bold text-destructive-foreground">
                  {unreadCount > 99 ? "99+" : unreadCount}
                </span>
              )}
            </Button>
          </PopoverTrigger>
          <PopoverContent align="end" className="w-96 p-0">
            {/* Header with tabs */}
            <div className="flex items-center justify-between border-b px-4 py-2">
              <span className="text-sm font-semibold">Notifications</span>
              {alerts.some((a) => !a.read_at) && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 text-xs"
                  onClick={() => markAllRead.mutate()}
                  disabled={markAllRead.isPending}
                >
                  <CheckCheck className="mr-1 h-3 w-3" />
                  Mark all read
                </Button>
              )}
            </div>

            {/* Tab bar */}
            <div className="flex border-b">
              <button
                className={cn("flex-1 px-4 py-2 text-sm font-medium",
                  bellTab === "activity" && "border-b-2 border-primary text-primary"
                )}
                onClick={() => setBellTab("activity")}
              >
                Activity
              </button>
              <button
                className={cn("flex-1 px-4 py-2 text-sm font-medium",
                  bellTab === "system" && "border-b-2 border-primary text-primary"
                )}
                onClick={() => setBellTab("system")}
              >
                Security
              </button>
            </div>

            {/* Content */}
            <ScrollArea className="max-h-80">
              {bellTab === "activity" ? (
                bellActivityItems.length === 0 ? (
                  <div className="flex flex-col items-center gap-1 py-8 text-center">
                    <Bell className="h-6 w-6 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">No activity</p>
                  </div>
                ) : (
                  <div className="divide-y">
                    {bellActivityItems.map((item) => (
                      <button
                        key={`${item.source_type}:${item.source_id}`}
                        className={cn(
                          "w-full text-left px-4 py-3 hover:bg-accent transition-colors",
                          item.unread && "bg-primary/5"
                        )}
                        onClick={() => {
                          if (item.action_url) {
                            navigate(item.action_url);
                            setAlertsOpen(false);
                          }
                        }}
                      >
                        <div className="flex items-center gap-3">
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate">{item.title}</p>
                            <p className="text-xs text-muted-foreground">
                              {formatAlertTime(item.latest_ts)}
                            </p>
                          </div>
                          {item.unread && <div className="w-2 h-2 rounded-full bg-primary shrink-0" />}
                        </div>
                      </button>
                    ))}
                  </div>
                )
              ) : alerts.length === 0 ? (
                <div className="flex flex-col items-center gap-1 py-8 text-center">
                  <Bell className="h-6 w-6 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">No notifications</p>
                </div>
              ) : (
                <div className="divide-y">
                  {alerts.map((alert) => (
                    <button
                      key={alert.alert_id}
                      className={cn(
                        "w-full text-left flex gap-3 px-4 py-3 transition-colors hover:bg-accent/50",
                      )}
                      onClick={() => {
                        if (alert.action_url) {
                          navigate(alert.action_url);
                          setAlertsOpen(false);
                        }
                      }}
                    >
                      {/* Unread indicator */}
                      <div className="mt-1.5 shrink-0">
                        {!alert.read_at ? (
                          <div className="h-2 w-2 rounded-full bg-primary" />
                        ) : (
                          <div className="h-2 w-2" />
                        )}
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className={cn("text-sm", !alert.read_at && "font-medium")}>
                          {alert.title}
                        </p>
                        <p className="mt-1 text-[10px] text-muted-foreground">
                          {formatAlertTime(alert.ts)}
                        </p>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </ScrollArea>

            {/* Footer */}
            <Separator />
            <div className="p-2">
              <Button
                variant="ghost"
                size="sm"
                className="w-full text-xs"
                onClick={() => {
                  setAlertsOpen(false);
                  navigate("/alerts");
                }}
              >
                View all notifications
              </Button>
            </div>
          </PopoverContent>
        </Popover>

        {/* User menu */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="rounded-full" aria-label="User menu">
              <Avatar className="h-8 w-8">
                <AvatarFallback className="text-xs">{initials}</AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuLabel className="font-normal">
              <p className="text-sm font-medium">Account</p>
              <p className="text-xs text-muted-foreground truncate">{userId ?? "User"}</p>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => navigate("/profile")}>
              <User className="h-4 w-4" />
              Profile
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => navigate("/settings")}>
              <Settings className="h-4 w-4" />
              Settings
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={handleLogout} className="text-destructive focus:text-destructive">
              <LogOut className="h-4 w-4" />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </header>
    </>
  );

}

// ─── Helpers ─────────────────────────────────────────────────────

function formatAlertTime(ts: number): string {
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
