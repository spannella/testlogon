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
  Users,
  BookUser,
  Headphones,
  PanelLeftClose,
  PanelLeft,
  MonitorSmartphone,
  Radio,
  Video,
  Scale,
  Wrench,
  Compass,
  Bookmark,
  PlaySquare,
  BarChart3,
  ShieldCheck,
  Share2,
  Tag,
  Webhook,
  Globe,
  CalendarClock,
  Ban,
  Wallet,
  Layers,
  Link2,
  Handshake,
  Trophy,
  Building2,
  Tv,
  Scissors,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Separator } from "@/components/ui/separator";
import { useUiStore } from "@/stores/uiStore";
import { useAuthStore } from "@/stores/authStore";
import { canAccessModerationBoard, canAccessPaymentIncidentQueue, canSeeRootRoleManagement } from "@/lib/adminCapabilities";
import { useQuery } from "@tanstack/react-query";
import { getConversations } from "@/api/endpoints/messaging";
import { isBroadcastNavigationEnabled, isVncRemoteDesktopEnabled, isDevtoolsLogUiEnabled } from "@/lib/featureFlags";

// ─── Navigation Config ──────────────────────────────────────────

interface NavItem {
  label: string;
  i18nKey?: string;
  path: string;
  icon: React.ReactNode;
  badge?: number;
}

interface NavGroup {
  title: string;
  i18nKey?: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: "Main",
    i18nKey: "nav.main",
    items: [
      { label: "Dashboard", i18nKey: "nav.dashboard", path: "/", icon: <LayoutDashboard className="h-5 w-5" /> },
      { label: "Messages", i18nKey: "nav.messages", path: "/messages", icon: <MessageSquare className="h-5 w-5" /> },
      { label: "Contacts", i18nKey: "nav.contacts", path: "/contacts", icon: <BookUser className="h-5 w-5" /> },
      { label: "Helpdesk", i18nKey: "nav.helpdesk", path: "/helpdesk", icon: <Headphones className="h-5 w-5" /> },
      { label: "Feed", i18nKey: "nav.feed", path: "/feed", icon: <Rss className="h-5 w-5" /> },
      { label: "Discover", i18nKey: "nav.discover", path: "/discover", icon: <Compass className="h-5 w-5" /> },
      { label: "Saved", i18nKey: "nav.saved", path: "/saved", icon: <Bookmark className="h-5 w-5" /> },
      { label: "Achievements", i18nKey: "nav.achievements", path: "/achievements", icon: <Trophy className="h-5 w-5" /> },
    ],
  },
  {
    title: "Commerce",
    i18nKey: "nav.commerce",
    items: [
      { label: "Shop", i18nKey: "nav.shop", path: "/shop", icon: <Store className="h-5 w-5" /> },
      { label: "Cart", i18nKey: "nav.cart", path: "/cart", icon: <ShoppingCart className="h-5 w-5" /> },
      { label: "Billing", i18nKey: "nav.billing", path: "/billing", icon: <CreditCard className="h-5 w-5" /> },
      { label: "Orders", i18nKey: "nav.orders", path: "/purchases", icon: <ClipboardList className="h-5 w-5" /> },
      { label: "Subscriptions", i18nKey: "nav.subscriptions", path: "/subscriptions", icon: <Repeat className="h-5 w-5" /> },
      { label: "Tier Manager", i18nKey: "nav.tierManager", path: "/subscriptions/manage", icon: <Layers className="h-5 w-5" /> },
      { label: "Creator Dashboard", i18nKey: "nav.creatorDashboard", path: "/creator-dashboard", icon: <BarChart3 className="h-5 w-5" /> },
      { label: "Analytics", i18nKey: "nav.analytics", path: "/analytics", icon: <BarChart3 className="h-5 w-5" /> },
      { label: "Payouts", i18nKey: "nav.payouts", path: "/payouts", icon: <Wallet className="h-5 w-5" /> },
      { label: "Referrals", i18nKey: "nav.referrals", path: "/referrals", icon: <Share2 className="h-5 w-5" /> },
      { label: "Promo Codes", i18nKey: "nav.promoCodes", path: "/promo", icon: <Tag className="h-5 w-5" /> },
      { label: "Affiliates", i18nKey: "nav.affiliates", path: "/affiliates", icon: <Link2 className="h-5 w-5" /> },
      { label: "Collaborations", i18nKey: "nav.collaborations", path: "/collaborations", icon: <Handshake className="h-5 w-5" /> },
      { label: "Fan Club", i18nKey: "nav.fanClub", path: "/fan-club", icon: <UsersRound className="h-5 w-5" /> },
      { label: "Groups", i18nKey: "nav.groups", path: "/groups", icon: <Users className="h-5 w-5" /> },
    ],
  },
  {
    title: "Productivity",
    i18nKey: "nav.productivity",
    items: [
      { label: "Files", i18nKey: "nav.files", path: "/files", icon: <FolderOpen className="h-5 w-5" /> },
      { label: "Projects", i18nKey: "nav.projects", path: "/projects", icon: <FolderKanban className="h-5 w-5" /> },
      { label: "Calendar", i18nKey: "nav.calendar", path: "/calendar", icon: <CalendarDays className="h-5 w-5" /> },
      { label: "Content Calendar", i18nKey: "nav.contentCalendar", path: "/content-calendar", icon: <CalendarClock className="h-5 w-5" /> },
      { label: "Scheduled", i18nKey: "nav.scheduled", path: "/scheduler", icon: <CalendarClock className="h-5 w-5" /> },
      { label: "Signing", i18nKey: "nav.signing", path: "/signing", icon: <FilePen className="h-5 w-5" /> },
      { label: "Organizations", i18nKey: "nav.organizations", path: "/orgs", icon: <Building2 className="h-5 w-5" /> },
    ],
  },
  {
    title: "Media",
    i18nKey: "nav.media",
    items: [
      { label: "Gallery", i18nKey: "nav.gallery", path: "/gallery", icon: <PlaySquare className="h-5 w-5" /> },
      { label: "Videos", i18nKey: "nav.videos", path: "/videos", icon: <Video className="h-5 w-5" /> },
      { label: "Broadcast", i18nKey: "nav.broadcast", path: "/broadcast", icon: <Radio className="h-5 w-5" /> },
      { label: "Clips", i18nKey: "nav.clips", path: "/clips", icon: <Scissors className="h-5 w-5" /> },
      { label: "Watch Parties", i18nKey: "nav.watchParties", path: "/watch-parties", icon: <Tv className="h-5 w-5" /> },
    ],
  },
  {
    title: "Account",
    i18nKey: "nav.account",
    items: [
      { label: "Profile", i18nKey: "nav.profile", path: "/profile", icon: <User className="h-5 w-5" /> },
      { label: "Security", i18nKey: "nav.security", path: "/security", icon: <Shield className="h-5 w-5" /> },
      { label: "Alerts", i18nKey: "nav.alerts", path: "/alerts", icon: <Bell className="h-5 w-5" /> },
      { label: "Tickets", i18nKey: "nav.tickets", path: "/tickets", icon: <LifeBuoy className="h-5 w-5" /> },
      { label: "Ticket Spaces", i18nKey: "nav.ticketSpaces", path: "/tickets/spaces", icon: <LifeBuoy className="h-5 w-5" /> },
      { label: "Remote Desktop", i18nKey: "nav.remoteDesktop", path: "/remote-desktop", icon: <MonitorSmartphone className="h-5 w-5" /> },
      { label: "Settings", i18nKey: "nav.settings", path: "/settings", icon: <Settings className="h-5 w-5" /> },
      { label: "Privacy", i18nKey: "nav.privacy", path: "/settings/privacy", icon: <ShieldCheck className="h-5 w-5" /> },
      { label: "Blocked Users", i18nKey: "nav.blockedUsers", path: "/settings/blocked", icon: <Ban className="h-5 w-5" /> },
      { label: "Webhooks", i18nKey: "nav.webhooks", path: "/settings/webhooks", icon: <Webhook className="h-5 w-5" /> },
      { label: "Geo Rules", i18nKey: "nav.geoRules", path: "/settings/geo", icon: <Globe className="h-5 w-5" /> },
      { label: "Role Management", i18nKey: "nav.roleManagement", path: "/root/roles", icon: <UsersRound className="h-5 w-5" /> },
      { label: "Moderation Board", i18nKey: "nav.moderationBoard", path: "/admin/moderation", icon: <Scale className="h-5 w-5" /> },
      { label: "Payment Incidents", i18nKey: "nav.paymentIncidents", path: "/admin/payment-incidents", icon: <CreditCard className="h-5 w-5" /> },
      { label: "Video Review", i18nKey: "nav.videoReview", path: "/admin/video-review", icon: <Video className="h-5 w-5" /> },
      { label: "DMCA Claims", i18nKey: "nav.dmcaClaims", path: "/admin/dmca", icon: <Scale className="h-5 w-5" /> },
      { label: "Refund Queue", i18nKey: "nav.refundQueue", path: "/admin/refunds", icon: <CreditCard className="h-5 w-5" /> },
    ],
  },
];

// ─── Sidebar Component ──────────────────────────────────────────

export default function Sidebar() {
  const { t } = useTranslation();
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const location = useLocation();
  const accessToken = useAuthStore((s) => s.accessToken);
  const showRootRoleManagement = canSeeRootRoleManagement(accessToken);
  const showModerationBoard = canAccessModerationBoard(accessToken);
  const showPaymentIncidents = canAccessPaymentIncidentQueue(accessToken);

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
            if (item.path === "/broadcast") return isBroadcastNavigationEnabled();
            if (item.path === "/root/roles") return showRootRoleManagement;
            if (item.path === "/remote-desktop") return isVncRemoteDesktopEnabled();
            if (item.path === "/admin/moderation") return showModerationBoard;
            if (item.path === "/admin/payment-incidents") return showPaymentIncidents;
            if (item.path === "/admin/video-review") return showModerationBoard;
            if (item.path === "/admin/dmca") return showModerationBoard;
            return true;
          });
          if (items.length === 0) return null;
          return (
          <div key={group.title}>
            {gi > 0 && <Separator className="my-2" />}
            {!collapsed && (
              <span className="mb-1 block px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                {group.i18nKey ? t(group.i18nKey) : group.title}
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
                      <span className="truncate">{item.i18nKey ? t(item.i18nKey) : item.label}</span>
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
                          {item.i18nKey ? t(item.i18nKey) : item.label}
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
                  <span className="ml-2">{t("nav.collapse")}</span>
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
