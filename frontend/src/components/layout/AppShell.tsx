import * as React from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Header from "./Header";
import MobileNav from "./MobileNav";
import ImpersonationBanner from "@/components/shared/ImpersonationBanner";
import { PageTransition } from "@/components/shared/PageTransition";
import { OfflineBanner } from "@/components/shared/OfflineBanner";
import { UpdateBanner } from "@/components/shared/UpdateBanner";
import { AppDropZone } from "@/components/shared/AppDropZone";
import { InstallPrompt } from "@/components/shared/InstallPrompt";
import { SessionExpiryWarning } from "@/components/shared/SessionExpiryWarning";
import { useOfflineQueue } from "@/hooks/useOfflineQueue";
import { useOfflineOptimisticRestore } from "@/hooks/useOfflineOptimisticRestore";
import { useServiceWorkerSync } from "@/hooks/useServiceWorkerSync";
import { useQueryClient } from "@tanstack/react-query";
import { DeadLetterPanel } from "@/components/shared/DeadLetterPanel";
import { useUiStore } from "@/stores/uiStore";
import {
  Sheet,
  SheetContent,
  SheetTitle,
} from "@/components/ui/sheet";
import { VisuallyHidden } from "@radix-ui/react-visually-hidden";

/** Mounts the offline queue flush side-effect — renders nothing. */
function OfflineQueueFlusher() {
  useOfflineQueue();
  return null;
}

/** PWA-005: Restores offline optimistic messages into React Query cache after reload. */
function OfflineOptimisticRestorer() {
  const queryClient = useQueryClient();
  useOfflineOptimisticRestore(queryClient);
  return null;
}

/** PWA-005: Listens for service worker sync messages. */
function ServiceWorkerSyncListener() {
  useServiceWorkerSync();
  return null;
}

export default function AppShell() {
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);
  const prefsLoaded = useUiStore((s) => s.prefsLoaded);
  const loadServerPreferences = useUiStore((s) => s.loadServerPreferences);

  React.useEffect(() => {
    if (!prefsLoaded) {
      loadServerPreferences();
    }
  }, [prefsLoaded, loadServerPreferences]);

  return (
    <AppDropZone>
      <div className="flex h-screen overflow-hidden bg-background">
        {/* Skip to content link for keyboard/screen reader users */}
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-primary focus:px-4 focus:py-2 focus:text-primary-foreground focus:outline-none"
        >
          Skip to content
        </a>

        {/* Desktop sidebar */}
        <Sidebar />

        {/* Mobile sidebar (drawer) */}
        <Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
          <SheetContent side="left" className="w-60 p-0">
            <VisuallyHidden>
              <SheetTitle>Navigation</SheetTitle>
            </VisuallyHidden>
            <MobileSidebar onNavigate={() => setMobileMenuOpen(false)} />
          </SheetContent>
        </Sheet>

        {/* Main area */}
        <div className="flex flex-1 flex-col overflow-hidden">
          <OfflineBanner />
          <UpdateBanner />
          <InstallPrompt />
          <DeadLetterPanel />
          <OfflineQueueFlusher />
          <OfflineOptimisticRestorer />
          <ServiceWorkerSyncListener />
          <Header onMobileMenuToggle={() => setMobileMenuOpen(true)} />
          <ImpersonationBanner />
          <SessionExpiryWarning />

          <main id="main-content" tabIndex={-1} className="flex flex-col flex-1 overflow-y-auto pb-16 md:pb-0 outline-none">
            <PageTransition>
              <Outlet />
            </PageTransition>
          </main>
        </div>

        {/* Mobile bottom tab bar */}
        <MobileNav />
      </div>
    </AppDropZone>
  );
}

// ─── Mobile Sidebar (used inside the Sheet drawer) ──────────────

import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  MessageSquare,
  Radio,
  Video,
  PlaySquare,
  Rss,
  Store,
  ShoppingCart,
  CreditCard,
  ClipboardList,
  Repeat,
  FolderOpen,
  FilePen,
  FileCheck,
  CalendarDays,
  CalendarClock,
  User,
  Shield,
  Settings,
  Bell,
  LifeBuoy,
  UsersRound,
  Scale,
  ShieldCheck,
  BarChart3,
  Share2,
  Tag,
  Webhook,
  Globe,
  Bookmark,
  Wallet,
  DollarSign,
  Layers,
  Trophy,
  Building2,
  Scissors,
  KeyRound,
  UserCog,
  Users,
  Bot,
  Activity,
  Phone,
  LayoutGrid,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Separator } from "@/components/ui/separator";
import { useAuthStore } from "@/stores/authStore";
import { canAccessModerationBoard, canSeeRootRoleManagement } from "@/lib/adminCapabilities";
import { isBroadcastNavigationEnabled } from "@/lib/featureFlags";

const MOBILE_NAV_GROUPS = [
  {
    title: "Main",
    items: [
      { label: "Dashboard", path: "/", icon: LayoutDashboard },
      { label: "Messages", path: "/messages", icon: MessageSquare },
      { label: "Call History", path: "/calls/history", icon: Phone },
      { label: "Feed", path: "/feed", icon: Rss },
      { label: "Activity", path: "/activity", icon: Activity },
      { label: "Saved", path: "/saved", icon: Bookmark },
      { label: "Achievements", path: "/achievements", icon: Trophy },
    ],
  },
  {
    title: "Commerce",
    items: [
      { label: "Shop", path: "/shop", icon: Store },
      { label: "Cart", path: "/cart", icon: ShoppingCart },
      { label: "Billing", path: "/billing", icon: CreditCard },
      { label: "Orders", path: "/purchases", icon: ClipboardList },
      { label: "Subscriptions", path: "/subscriptions", icon: Repeat },
      { label: "Tier Manager", path: "/subscriptions/manage", icon: Layers },
      { label: "Analytics", path: "/analytics", icon: BarChart3 },
      { label: "Earnings", path: "/earnings", icon: DollarSign },
      { label: "Payouts", path: "/payouts", icon: Wallet },
      { label: "Referrals", path: "/referrals", icon: Share2 },
      { label: "Promo Codes", path: "/promo", icon: Tag },
      { label: "Fan Club", path: "/fan-club", icon: UsersRound },
      { label: "Syndicates", path: "/syndicates", icon: Users },
      { label: "Groups", path: "/groups", icon: Users },
    ],
  },
  {
    title: "Productivity",
    items: [
      { label: "Files", path: "/files", icon: FolderOpen },
      { label: "Calendar", path: "/calendar", icon: CalendarDays },
      { label: "Content Calendar", path: "/content-calendar", icon: CalendarClock },
      { label: "Scheduled", path: "/scheduler", icon: CalendarClock },
      { label: "Signing", path: "/signing", icon: FilePen },
      { label: "Licenses", path: "/licenses", icon: FileCheck },
      { label: "Bots", path: "/bots", icon: Bot },
      { label: "Organizations", path: "/orgs", icon: Building2 },
    ],
  },
  {
    title: "Media",
    items: [
      { label: "Gallery", path: "/gallery", icon: PlaySquare },
      { label: "Videos", path: "/videos", icon: Video },
      { label: "Broadcast", path: "/broadcast", icon: Radio },
      { label: "Clips", path: "/clips", icon: Scissors },
    ],
  },
  {
    title: "AI Agents",
    items: [
      { label: "LLM Keys", path: "/agents/llm-keys", icon: KeyRound },
      { label: "Fleet Dashboard", path: "/agents/fleet", icon: LayoutGrid },
      { label: "Project Dashboard", path: "/agents/project-dashboard", icon: LayoutDashboard },
      { label: "Submit Idea", path: "/ideas/submit", icon: ClipboardList },
    ],
  },
  {
    title: "Account",
    items: [
      { label: "Profile", path: "/profile", icon: User },
      { label: "Security", path: "/security", icon: Shield },
      { label: "Alerts", path: "/alerts", icon: Bell },
      { label: "Tickets", path: "/tickets", icon: LifeBuoy },
  { label: "Ticket Spaces", path: "/tickets/spaces", icon: LifeBuoy },
      { label: "Delegates", path: "/delegates", icon: UserCog },
      { label: "Ticket Spaces", path: "/tickets/spaces", icon: LifeBuoy },
      { label: "SSH Keys", path: "/remote/ssh-keys", icon: KeyRound },
      { label: "Settings", path: "/settings", icon: Settings },
      { label: "Privacy", path: "/settings/privacy", icon: ShieldCheck },
      { label: "Webhooks", path: "/settings/webhooks", icon: Webhook },
      { label: "Geo Rules", path: "/settings/geo", icon: Globe },
      { label: "Role Mgmt", path: "/root/roles", icon: UsersRound },
      { label: "Moderation Board", path: "/admin/moderation", icon: Scale },
      { label: "Video Review", path: "/admin/video-review", icon: Video },
      { label: "DMCA Claims", path: "/admin/dmca", icon: Scale },
      { label: "KYC Review", path: "/admin/kyc", icon: ShieldCheck },
    ],
  },
];

function MobileSidebar({ onNavigate }: { onNavigate: () => void }) {
  const location = useLocation();
  const accessToken = useAuthStore((s) => s.accessToken);
  const showRootRoleManagement = canSeeRootRoleManagement(accessToken);
  const showModerationBoard = canAccessModerationBoard(accessToken);

  const isActive = (path: string) => {
    if (path === "/") return location.pathname === "/";
    return location.pathname.startsWith(path);
  };

  return (
    <div className="flex h-full flex-col">
      {/* Logo */}
      <div className="flex h-14 items-center border-b border-border px-4">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <span className="text-sm font-bold">T</span>
          </div>
          <span className="text-base font-semibold tracking-tight">TestLogon</span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {MOBILE_NAV_GROUPS.map((group, gi) => {
          const items = group.items.filter((item) => {
            if (item.path === "/broadcast") return isBroadcastNavigationEnabled();
            if (item.path === "/root/roles") return showRootRoleManagement;
            if (item.path === "/admin/moderation") return showModerationBoard;
            if (item.path === "/admin/video-review") return showModerationBoard;
            if (item.path === "/admin/dmca") return showModerationBoard;
            if (item.path === "/admin/kyc") return showModerationBoard;
            return true;
          });
          if (items.length === 0) return null;
          return (
          <div key={group.title}>
            {gi > 0 && <Separator className="my-2" />}
            <span className="mb-1 block px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              {group.title}
            </span>
            <ul className="space-y-0.5">
              {items.map((item) => {
                const active = isActive(item.path);
                return (
                  <li key={item.path}>
                    <NavLink
                      to={item.path}
                      onClick={onNavigate}
                      className={cn(
                        "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                        active
                          ? "bg-primary/10 text-primary"
                          : "text-muted-foreground hover:bg-accent hover:text-foreground",
                      )}
                    >
                      <item.icon className="h-5 w-5 shrink-0" />
                      <span className="truncate">{item.label}</span>
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </div>
          );
        })}
      </nav>
    </div>
  );
}
