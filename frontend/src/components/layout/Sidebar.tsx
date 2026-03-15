import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  MessageSquare,
  Rss,
  Store,
  ShoppingCart,
  CreditCard,
  ClipboardList,
  Repeat,
  FolderOpen,
  FolderKanban,
  FilePen,
  CalendarDays,
  User,
  Shield,
  Settings,
  Bell,
  LifeBuoy,
  UsersRound,
  BookUser,
  Headphones,
  PanelLeftClose,
  PanelLeft,
  MonitorSmartphone,
  Scale,
  Wrench,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Separator } from "@/components/ui/separator";
import { useUiStore } from "@/stores/uiStore";
import { useAuthStore } from "@/stores/authStore";
import { canAccessModerationBoard, canSeeRootRoleManagement } from "@/lib/adminCapabilities";
import { useQuery } from "@tanstack/react-query";
import { getConversations } from "@/api/endpoints/messaging";
import { isVncRemoteDesktopEnabled, isDevtoolsLogUiEnabled } from "@/lib/featureFlags";

// ─── Navigation Config ──────────────────────────────────────────

interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;
  badge?: number;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: "Main",
    items: [
      { label: "Dashboard", path: "/", icon: <LayoutDashboard className="h-5 w-5" /> },
      { label: "Messages", path: "/messages", icon: <MessageSquare className="h-5 w-5" /> },
      { label: "Contacts", path: "/contacts", icon: <BookUser className="h-5 w-5" /> },
      { label: "Helpdesk", path: "/helpdesk", icon: <Headphones className="h-5 w-5" /> },
      { label: "Feed", path: "/feed", icon: <Rss className="h-5 w-5" /> },
    ],
  },
  {
    title: "Commerce",
    items: [
      { label: "Shop", path: "/shop", icon: <Store className="h-5 w-5" /> },
      { label: "Cart", path: "/cart", icon: <ShoppingCart className="h-5 w-5" /> },
      { label: "Billing", path: "/billing", icon: <CreditCard className="h-5 w-5" /> },
      { label: "Orders", path: "/purchases", icon: <ClipboardList className="h-5 w-5" /> },
      { label: "Subscriptions", path: "/subscriptions", icon: <Repeat className="h-5 w-5" /> },
    ],
  },
  {
    title: "Productivity",
    items: [
      { label: "Files", path: "/files", icon: <FolderOpen className="h-5 w-5" /> },
      { label: "Projects", path: "/projects", icon: <FolderKanban className="h-5 w-5" /> },
      { label: "Calendar", path: "/calendar", icon: <CalendarDays className="h-5 w-5" /> },
      { label: "Signing", path: "/signing", icon: <FilePen className="h-5 w-5" /> },
    ],
  },
  {
    title: "Account",
    items: [
      { label: "Profile", path: "/profile", icon: <User className="h-5 w-5" /> },
      { label: "Security", path: "/security", icon: <Shield className="h-5 w-5" /> },
      { label: "Alerts", path: "/alerts", icon: <Bell className="h-5 w-5" /> },
      { label: "Tickets", path: "/tickets", icon: <LifeBuoy className="h-5 w-5" /> },
      { label: "Ticket Spaces", path: "/tickets/spaces", icon: <LifeBuoy className="h-5 w-5" /> },
      { label: "Remote Desktop", path: "/remote-desktop", icon: <MonitorSmartphone className="h-5 w-5" /> },
      { label: "Settings", path: "/settings", icon: <Settings className="h-5 w-5" /> },
      { label: "Role Management", path: "/root/roles", icon: <UsersRound className="h-5 w-5" /> },
      { label: "Moderation Board", path: "/admin/moderation", icon: <Scale className="h-5 w-5" /> },
    ],
  },
];

// ─── Sidebar Component ──────────────────────────────────────────

export default function Sidebar() {
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const location = useLocation();
  const accessToken = useAuthStore((s) => s.accessToken);
  const showRootRoleManagement = canSeeRootRoleManagement(accessToken);
  const showModerationBoard = canAccessModerationBoard(accessToken);

  const { data: convoData } = useQuery({
    queryKey: ["conversations"],
    queryFn: () => getConversations(),
    staleTime: 30_000,
    refetchOnWindowFocus: true,
  });
  const totalUnread = (convoData?.conversations ?? []).reduce(
    (sum, c) => sum + (c.unread_count ?? 0),
    0,
  );

  const isActive = (path: string) => {
    if (path === "/") return location.pathname === "/";
    return location.pathname.startsWith(path);
  };

  return (
    <aside
      className={cn(
        "hidden md:flex flex-col border-r border-border bg-card transition-all duration-200 ease-in-out",
        collapsed ? "w-16" : "w-60",
      )}
    >
      {/* Logo */}
      <div className={cn("flex h-14 items-center border-b border-border px-4", collapsed && "justify-center px-0")}>
        {collapsed ? (
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <span className="text-sm font-bold">T</span>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <span className="text-sm font-bold">T</span>
            </div>
            <span className="text-base font-semibold tracking-tight">TestLogon</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {NAV_GROUPS.map((group, gi) => {
          const items = group.items.filter((item) => {
            if (item.path === "/root/roles") return showRootRoleManagement;
            if (item.path === "/remote-desktop") return isVncRemoteDesktopEnabled();
            if (item.path === "/admin/moderation") return showModerationBoard;
            return true;
          });
          if (items.length === 0) return null;
          return (
          <div key={group.title}>
            {gi > 0 && <Separator className="my-2" />}
            {!collapsed && (
              <span className="mb-1 block px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                {group.title}
              </span>
            )}
            <ul className="space-y-0.5">
              {items.map((item) => {
                const active = isActive(item.path);
                const badge = item.path === "/messages" ? totalUnread : (item.badge ?? 0);
                const link = (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={cn(
                      "group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                      active
                        ? "bg-primary/10 text-primary border-l-2 border-primary -ml-px"
                        : "text-muted-foreground hover:bg-accent hover:text-foreground",
                      collapsed && "justify-center px-0 gap-0",
                    )}
                  >
                    <span className={cn("relative shrink-0", active && "text-primary")}>
                      {item.icon}
                      {collapsed && badge > 0 && (
                        <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-primary px-0.5 text-[9px] font-bold text-primary-foreground">
                          {badge > 9 ? "9+" : badge}
                        </span>
                      )}
                    </span>
                    {!collapsed && (
                      <span className="truncate">{item.label}</span>
                    )}
                    {!collapsed && badge > 0 && (
                      <span className="ml-auto flex h-5 min-w-5 items-center justify-center rounded-full bg-primary px-1.5 text-[10px] font-semibold text-primary-foreground">
                        {badge > 99 ? "99+" : badge}
                      </span>
                    )}
                  </NavLink>
                );

                if (collapsed) {
                  return (
                    <li key={item.path}>
                      <Tooltip>
                        <TooltipTrigger asChild>{link}</TooltipTrigger>
                        <TooltipContent side="right" sideOffset={8}>
                          {item.label}
                        </TooltipContent>
                      </Tooltip>
                    </li>
                  );
                }

                return <li key={item.path}>{link}</li>;
              })}
            </ul>
          </div>
          );
        })}
      </nav>

      {/* Dev Tools link (dev-mode only, gated by feature flag) */}
      {isDevtoolsLogUiEnabled() && (
        <div className="border-t border-border px-2 py-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <a
                href="http://localhost:3001/devtools.html"
                target="_blank"
                rel="noopener noreferrer"
                className={cn(
                  "group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors text-muted-foreground hover:bg-accent hover:text-foreground",
                  collapsed && "justify-center px-0 gap-0",
                )}
              >
                <Wrench className="h-5 w-5 shrink-0" />
                {!collapsed && <span className="truncate">Dev Tools</span>}
              </a>
            </TooltipTrigger>
            <TooltipContent side="right" sideOffset={8}>Dev Tools</TooltipContent>
          </Tooltip>
        </div>
      )}

      {/* Collapse toggle */}
      <div className="border-t border-border p-2">
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className={cn("w-full", collapsed ? "justify-center" : "justify-start")}
              onClick={toggleSidebar}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {collapsed ? (
                <PanelLeft className="h-4 w-4" />
              ) : (
                <>
                  <PanelLeftClose className="h-4 w-4" />
                  <span className="ml-2">Collapse</span>
                </>
              )}
            </Button>
          </TooltipTrigger>
          <TooltipContent side="right" sideOffset={8}>
            {collapsed ? "Expand sidebar" : "Collapse sidebar"}
          </TooltipContent>
        </Tooltip>
      </div>
    </aside>
  );
}
