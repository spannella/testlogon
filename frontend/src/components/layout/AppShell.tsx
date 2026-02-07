import * as React from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Header from "./Header";
import MobileNav from "./MobileNav";
import {
  Sheet,
  SheetContent,
  SheetTitle,
} from "@/components/ui/sheet";
import { VisuallyHidden } from "@radix-ui/react-visually-hidden";

export default function AppShell() {
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

  return (
    <div className="flex h-screen overflow-hidden bg-background">
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
        <Header onMobileMenuToggle={() => setMobileMenuOpen(true)} />

        <main className="flex-1 overflow-y-auto pb-16 md:pb-0">
          <Outlet />
        </main>
      </div>

      {/* Mobile bottom tab bar */}
      <MobileNav />
    </div>
  );
}

// ─── Mobile Sidebar (used inside the Sheet drawer) ──────────────

import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  MessageSquare,
  Rss,
  Store,
  ShoppingCart,
  CreditCard,
  FolderOpen,
  CalendarDays,
  User,
  Shield,
  Settings,
  Bell,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Separator } from "@/components/ui/separator";

const MOBILE_NAV_GROUPS = [
  {
    title: "Main",
    items: [
      { label: "Dashboard", path: "/", icon: LayoutDashboard },
      { label: "Messages", path: "/messages", icon: MessageSquare },
      { label: "Feed", path: "/feed", icon: Rss },
    ],
  },
  {
    title: "Commerce",
    items: [
      { label: "Shop", path: "/shop", icon: Store },
      { label: "Cart", path: "/cart", icon: ShoppingCart },
      { label: "Billing", path: "/billing", icon: CreditCard },
    ],
  },
  {
    title: "Productivity",
    items: [
      { label: "Files", path: "/files", icon: FolderOpen },
      { label: "Calendar", path: "/calendar", icon: CalendarDays },
    ],
  },
  {
    title: "Account",
    items: [
      { label: "Profile", path: "/profile", icon: User },
      { label: "Security", path: "/security", icon: Shield },
      { label: "Alerts", path: "/alerts", icon: Bell },
      { label: "Settings", path: "/settings", icon: Settings },
    ],
  },
];

function MobileSidebar({ onNavigate }: { onNavigate: () => void }) {
  const location = useLocation();

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
        {MOBILE_NAV_GROUPS.map((group, gi) => (
          <div key={group.title}>
            {gi > 0 && <Separator className="my-2" />}
            <span className="mb-1 block px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              {group.title}
            </span>
            <ul className="space-y-0.5">
              {group.items.map((item) => {
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
        ))}
      </nav>
    </div>
  );
}
