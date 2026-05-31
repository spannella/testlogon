import * as React from "react";
import { NavLink, useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  MessageSquare,
  FolderOpen,
  Store,
  MoreHorizontal,
  Rss,
  ShoppingCart,
  CreditCard,
  CalendarDays,
  User,
  Shield,
  Bell,
  LifeBuoy,
  FilePen,
  Settings,
  UsersRound,
  MonitorSmartphone,
  Radio,
  Video,
  PlaySquare,
  Scale,
  Compass,
  BarChart3,
  ShieldCheck,
  Share2,
  Tag,
  Webhook,
  Globe,
  Bookmark,
  Wallet,
  Layers,
  Link2,
  Handshake,
  Trophy,
  CalendarClock,
  Scissors,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { useAuthStore } from "@/stores/authStore";
import { canAccessModerationBoard, canSeeRootRoleManagement } from "@/lib/adminCapabilities";
import { isBroadcastNavigationEnabled, isVncRemoteDesktopEnabled } from "@/lib/featureFlags";

// ─── Tab config ─────────────────────────────────────────────────

const PRIMARY_TABS = [
  { label: "Home", i18nKey: "nav.dashboard", path: "/", icon: LayoutDashboard },
  { label: "Messages", i18nKey: "nav.messages", path: "/messages", icon: MessageSquare },
  { label: "Files", i18nKey: "nav.files", path: "/files", icon: FolderOpen },
  { label: "Shop", i18nKey: "nav.shop", path: "/shop", icon: Store },
];

const MORE_LINKS = [
  { label: "Feed", i18nKey: "nav.feed", path: "/feed", icon: Rss },
  { label: "Discover", i18nKey: "nav.discover", path: "/discover", icon: Compass },
  { label: "Saved", i18nKey: "nav.saved", path: "/saved", icon: Bookmark },
  { label: "Cart", i18nKey: "nav.cart", path: "/cart", icon: ShoppingCart },
  { label: "Billing", i18nKey: "nav.billing", path: "/billing", icon: CreditCard },
  { label: "Tier Manager", i18nKey: "nav.tierManager", path: "/subscriptions/manage", icon: Layers },
  { label: "Calendar", i18nKey: "nav.calendar", path: "/calendar", icon: CalendarDays },
  { label: "Content Calendar", i18nKey: "nav.contentCalendar", path: "/content-calendar", icon: CalendarClock },
  { label: "Signing", i18nKey: "nav.signing", path: "/signing", icon: FilePen },
  { label: "Gallery", i18nKey: "nav.gallery", path: "/gallery", icon: PlaySquare },
  { label: "Videos", i18nKey: "nav.videos", path: "/videos", icon: Video },
  { label: "Broadcast", i18nKey: "nav.broadcast", path: "/broadcast", icon: Radio },
  { label: "Clips", i18nKey: "nav.clips", path: "/clips", icon: Scissors },
  { label: "Profile", i18nKey: "nav.profile", path: "/profile", icon: User },
  { label: "Security", i18nKey: "nav.security", path: "/security", icon: Shield },
  { label: "Alerts", i18nKey: "nav.alerts", path: "/alerts", icon: Bell },
  { label: "Notifications", i18nKey: "nav.notifications", path: "/notifications", icon: Bell },
  { label: "Tickets", i18nKey: "nav.tickets", path: "/tickets", icon: LifeBuoy },
  { label: "Ticket Spaces", i18nKey: "nav.ticketSpaces", path: "/tickets/spaces", icon: LifeBuoy },
  { label: "Remote Desktop", i18nKey: "nav.remoteDesktop", path: "/remote-desktop", icon: MonitorSmartphone },
  { label: "Settings", i18nKey: "nav.settings", path: "/settings", icon: Settings },
  { label: "Privacy", i18nKey: "nav.privacy", path: "/settings/privacy", icon: ShieldCheck },
  { label: "Webhooks", i18nKey: "nav.webhooks", path: "/settings/webhooks", icon: Webhook },
  { label: "Geo Rules", i18nKey: "nav.geoRules", path: "/settings/geo", icon: Globe },
  { label: "Role Mgmt", i18nKey: "nav.roleManagement", path: "/root/roles", icon: UsersRound },
  { label: "Moderation Board", i18nKey: "nav.moderationBoard", path: "/admin/moderation", icon: Scale },
  { label: "Video Review", i18nKey: "nav.videoReview", path: "/admin/video-review", icon: Video },
  { label: "DMCA Claims", i18nKey: "nav.dmcaClaims", path: "/admin/dmca", icon: Scale },
  { label: "Creator Dashboard", i18nKey: "nav.creatorDashboard", path: "/creator-dashboard", icon: BarChart3 },
  { label: "Analytics", i18nKey: "nav.analytics", path: "/analytics", icon: BarChart3 },
  { label: "Payouts", i18nKey: "nav.payouts", path: "/payouts", icon: Wallet },
  { label: "Referrals", i18nKey: "nav.referrals", path: "/referrals", icon: Share2 },
  { label: "Promo Codes", i18nKey: "nav.promoCodes", path: "/promo", icon: Tag },
  { label: "Affiliates", i18nKey: "nav.affiliates", path: "/affiliates", icon: Link2 },
  { label: "Collaborations", i18nKey: "nav.collaborations", path: "/collaborations", icon: Handshake },
  { label: "Fan Club", i18nKey: "nav.fanClub", path: "/fan-club", icon: UsersRound },
  { label: "Achievements", i18nKey: "nav.achievements", path: "/achievements", icon: Trophy },
];

// ─── MobileNav Component ────────────────────────────────────────

export default function MobileNav() {
  const { t } = useTranslation();
  const [moreOpen, setMoreOpen] = React.useState(false);
  const navigate = useNavigate();
  const accessToken = useAuthStore((s) => s.accessToken);
  const showRootRoleManagement = canSeeRootRoleManagement(accessToken);
  const showModerationBoard = canAccessModerationBoard(accessToken);

  const moreLinks = MORE_LINKS.filter((item) => {
    if (item.path === "/broadcast") return isBroadcastNavigationEnabled();
    if (item.path === "/root/roles") return showRootRoleManagement;
    if (item.path === "/remote-desktop") return isVncRemoteDesktopEnabled();
    if (item.path === "/admin/moderation") return showModerationBoard;
    if (item.path === "/admin/video-review") return showModerationBoard;
    if (item.path === "/admin/dmca") return showModerationBoard;
    return true;
  });

  return (
    <>
      <nav className="fixed inset-x-0 bottom-0 z-40 flex h-16 items-center justify-around border-t border-border bg-card md:hidden">
        {PRIMARY_TABS.map((tab) => (
          <NavLink
            key={tab.path}
            to={tab.path}
            end={tab.path === "/"}
            className={({ isActive }) =>
              cn(
                "flex flex-col items-center gap-0.5 px-3 py-1 text-[10px] font-medium transition-colors",
                isActive
                  ? "text-primary"
                  : "text-muted-foreground",
              )
            }
          >
            <tab.icon className="h-5 w-5" />
            {tab.i18nKey ? t(tab.i18nKey) : tab.label}
          </NavLink>
        ))}
        <button
          className="flex flex-col items-center gap-0.5 px-3 py-1 text-[10px] font-medium text-muted-foreground transition-colors"
          onClick={() => setMoreOpen(true)}
        >
          <MoreHorizontal className="h-5 w-5" />
          More
        </button>
      </nav>

      {/* "More" sheet */}
      <Sheet open={moreOpen} onOpenChange={setMoreOpen}>
        <SheetContent side="bottom" className="rounded-t-2xl pb-safe">
          <SheetHeader>
            <SheetTitle>More</SheetTitle>
          </SheetHeader>
          <Separator className="my-3" />
          <div className="grid grid-cols-4 gap-4 pb-4">
            {moreLinks.map((link) => (
              <Button
                key={link.path}
                variant="ghost"
                className="flex h-auto flex-col gap-1 py-3"
                onClick={() => {
                  navigate(link.path);
                  setMoreOpen(false);
                }}
              >
                <link.icon className="h-5 w-5" />
                <span className="text-[10px]">{link.i18nKey ? t(link.i18nKey) : link.label}</span>
              </Button>
            ))}
          </div>
        </SheetContent>
      </Sheet>
    </>
  );
}
