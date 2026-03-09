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
  Settings,
  UsersRound,
  Bug,
  Scale,
} from "lucide-react";
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
import { isDevtoolsLogUiEnabled } from "@/lib/featureFlags";

// ─── Tab config ─────────────────────────────────────────────────

const PRIMARY_TABS = [
  { label: "Home", path: "/", icon: LayoutDashboard },
  { label: "Messages", path: "/messages", icon: MessageSquare },
  { label: "Files", path: "/files", icon: FolderOpen },
  { label: "Shop", path: "/shop", icon: Store },
];

const MORE_LINKS = [
  { label: "Feed", path: "/feed", icon: Rss },
  { label: "Cart", path: "/cart", icon: ShoppingCart },
  { label: "Billing", path: "/billing", icon: CreditCard },
  { label: "Calendar", path: "/calendar", icon: CalendarDays },
  { label: "Profile", path: "/profile", icon: User },
  { label: "Security", path: "/security", icon: Shield },
  { label: "Alerts", path: "/alerts", icon: Bell },
  { label: "Tickets", path: "/tickets", icon: LifeBuoy },
  { label: "Ticket Spaces", path: "/tickets/spaces", icon: LifeBuoy },
  { label: "Settings", path: "/settings", icon: Settings },
  { label: "Dev Tools", path: "/dev-tools/log-ui", icon: Bug },
  { label: "Role Mgmt", path: "/root/roles", icon: UsersRound },
  { label: "Moderation Board", path: "/admin/moderation", icon: Scale },
];

// ─── MobileNav Component ────────────────────────────────────────

export default function MobileNav() {
  const [moreOpen, setMoreOpen] = React.useState(false);
  const navigate = useNavigate();
  const accessToken = useAuthStore((s) => s.accessToken);
  const showRootRoleManagement = canSeeRootRoleManagement(accessToken);
  const showModerationBoard = canAccessModerationBoard(accessToken);

  const moreLinks = MORE_LINKS.filter((item) => {
    if (item.path === "/root/roles") return showRootRoleManagement;
    if (item.path === "/dev-tools/log-ui") return isDevtoolsLogUiEnabled();
    if (item.path === "/admin/moderation") return showModerationBoard;
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
            {tab.label}
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
                <span className="text-[10px]">{link.label}</span>
              </Button>
            ))}
          </div>
        </SheetContent>
      </Sheet>
    </>
  );
}
