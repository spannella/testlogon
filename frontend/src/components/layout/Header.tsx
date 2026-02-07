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
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from "@/components/ui/command";
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
import { getAlerts, markRead } from "@/api/endpoints/alerts";
import { useAlertStream } from "@/hooks/useAlertStream";

interface HeaderProps {
  onMobileMenuToggle?: () => void;
}

// ─── Navigation items for search ────────────────────────────────

const SEARCH_PAGES = [
  { label: "Dashboard", path: "/", group: "Pages" },
  { label: "Messages", path: "/messages", group: "Pages" },
  { label: "Feed", path: "/feed", group: "Pages" },
  { label: "Shop", path: "/shop", group: "Pages" },
  { label: "Cart", path: "/cart", group: "Pages" },
  { label: "Billing", path: "/billing", group: "Pages" },
  { label: "Files", path: "/files", group: "Pages" },
  { label: "Calendar", path: "/calendar", group: "Pages" },
  { label: "Profile", path: "/profile", group: "Account" },
  { label: "Security", path: "/security", group: "Account" },
  { label: "Alerts", path: "/alerts", group: "Account" },
  { label: "Settings", path: "/settings", group: "Account" },
];

// ─── Header Component ───────────────────────────────────────────

export default function Header({ onMobileMenuToggle }: HeaderProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const userId = useAuthStore((s) => s.userId);
  const logoutAuth = useAuthStore((s) => s.logout);
  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);

  const [searchOpen, setSearchOpen] = React.useState(false);
  const [alertsOpen, setAlertsOpen] = React.useState(false);

  // Real-time alert stream
  const { unreadCount, resetUnread } = useAlertStream(true);

  // Fetch recent alerts for the popover
  const recentAlerts = useQuery({
    queryKey: ["alerts", "recent"],
    queryFn: () => getAlerts({ limit: 10 }),
    enabled: alertsOpen,
  });

  const markAllRead = useMutation({
    mutationFn: () => {
      const ids = (recentAlerts.data?.alerts ?? [])
        .filter((a) => !a.read_at)
        .map((a) => a.alert_id);
      if (ids.length === 0) return Promise.resolve({ ok: true, updated: 0 });
      return markRead({ alert_ids: ids });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      resetUnread();
    },
  });

  // Cmd+K / Ctrl+K to open search
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen(true);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handleLogout = async () => {
    try {
      await apiLogout();
    } catch {
      // Logout even if API call fails
    }
    logoutAuth();
    navigate("/login", { replace: true });
  };

  const cycleTheme = () => {
    const next: Record<Theme, Theme> = {
      system: "light",
      light: "dark",
      dark: "system",
    };
    setTheme(next[theme]);
  };

  const themeIcon = {
    system: <Monitor className="h-4 w-4" />,
    light: <Sun className="h-4 w-4" />,
    dark: <Moon className="h-4 w-4" />,
  }[theme];

  const initials = userId ? userId.slice(0, 2).toUpperCase() : "U";

  const alerts = recentAlerts.data?.alerts ?? [];

  return (
    <>
      <header className="flex h-14 items-center gap-2 border-b border-border bg-card px-4">
        {/* Mobile menu button */}
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
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
          onClick={() => setSearchOpen(true)}
        >
          <Search className="h-4 w-4" />
          <span className="hidden sm:inline">Search...</span>
          <kbd className="pointer-events-none ml-auto hidden select-none rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px] font-medium text-muted-foreground sm:inline-block">
            {navigator.userAgent.includes("Mac") ? "\u2318K" : "Ctrl+K"}
          </kbd>
        </Button>

        <div className="flex-1" />

        {/* Theme toggle */}
        <Button
          variant="ghost"
          size="icon"
          onClick={cycleTheme}
          aria-label={`Theme: ${theme}`}
        >
          {themeIcon}
        </Button>

        {/* Alert bell with popover */}
        <Popover open={alertsOpen} onOpenChange={setAlertsOpen}>
          <PopoverTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="relative"
              aria-label="Alerts"
            >
              <Bell className="h-5 w-5" />
              {unreadCount > 0 && (
                <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-bold text-destructive-foreground">
                  {unreadCount > 99 ? "99+" : unreadCount}
                </span>
              )}
            </Button>
          </PopoverTrigger>
          <PopoverContent align="end" className="w-80 p-0">
            {/* Header */}
            <div className="flex items-center justify-between border-b px-4 py-3">
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

            {/* Alert list */}
            <ScrollArea className="max-h-80">
              {alerts.length === 0 ? (
                <div className="flex flex-col items-center gap-1 py-8 text-center">
                  <Bell className="h-6 w-6 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">No notifications</p>
                </div>
              ) : (
                <div className="divide-y">
                  {alerts.map((alert) => (
                    <div
                      key={alert.alert_id}
                      className="flex gap-3 px-4 py-3 transition-colors hover:bg-accent/50"
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
                        {alert.details && (
                          <p className="mt-0.5 truncate text-xs text-muted-foreground">
                            {alert.details}
                          </p>
                        )}
                        <p className="mt-1 text-[10px] text-muted-foreground">
                          {formatAlertTime(alert.ts)}
                        </p>
                      </div>
                    </div>
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

      {/* Command palette / search dialog */}
      <CommandDialog open={searchOpen} onOpenChange={setSearchOpen}>
        <CommandInput placeholder="Search pages..." />
        <CommandList>
          <CommandEmpty>No results found.</CommandEmpty>
          {["Pages", "Account"].map((group) => (
            <CommandGroup key={group} heading={group}>
              {SEARCH_PAGES.filter((p) => p.group === group).map((page) => (
                <CommandItem
                  key={page.path}
                  value={page.label}
                  onSelect={() => {
                    navigate(page.path);
                    setSearchOpen(false);
                  }}
                >
                  {page.label}
                </CommandItem>
              ))}
            </CommandGroup>
          ))}
        </CommandList>
      </CommandDialog>
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
