import * as React from "react";
import { useNavigate } from "react-router-dom";
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
import { useAuthStore } from "@/stores/authStore";
import { useUiStore, type Theme } from "@/stores/uiStore";
import { logout as apiLogout } from "@/api/endpoints/auth";

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
  const userId = useAuthStore((s) => s.userId);
  const logoutAuth = useAuthStore((s) => s.logout);
  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);

  const [searchOpen, setSearchOpen] = React.useState(false);

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

        {/* Alert bell */}
        <Button
          variant="ghost"
          size="icon"
          className="relative"
          onClick={() => navigate("/alerts")}
          aria-label="Alerts"
        >
          <Bell className="h-5 w-5" />
          {/* Placeholder unread dot — will be wired to real data in Step 11 */}
        </Button>

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
