import * as React from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  TrendingUp,
  Gauge,
  CandlestickChart,
  Bell,
  PieChart,
  LineChart,
  LayoutGrid,
  Coins,
  Settings,
  Plus,
  ArrowDownToLine,
  Search,
  Clock,
  Loader2,
  User,
  FileText,
  ShoppingBag,
  FolderOpen,
  MessageSquare,
  Ticket,
  Users,
  Play,
  Calendar as CalendarIcon,
  Keyboard,
} from "lucide-react";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandShortcut,
} from "@/components/ui/command";
import { useSymbols } from "@/hooks/useMarketData";
import { usePredictionProbe } from "@/hooks/useInstrumentClasses";
import {
  CLASS_ORDER,
  CLASS_LABELS,
  classesForSymbol,
  type InstrumentClass,
} from "@/lib/instrumentClass";
import { useUiStore } from "@/stores/uiStore";
import { globalSearch, type SearchResultItem } from "@/api/endpoints/search";
import { openShortcutsHelp } from "@/components/layout/KeyboardShortcutsHost";

/**
 * Unified global command palette (Cmd/Ctrl+K quick-switcher).
 *
 * Self-contained: mounts a window keydown listener so Cmd+K / Ctrl+K opens it
 * anywhere while logged in. Local sources (Symbols / Pages / Actions) are
 * instant and require no network. In addition, as the user types (>=2 chars,
 * debounced) it queries the content/social `globalSearch` API and renders those
 * results in their own groups (People / Posts / Catalog / Files / Messages /
 * Tickets / Contacts / Videos / Calendar), each navigating to the URL the API
 * returns. Content search failing never breaks the local palette.
 */

const RECENTS_KEY = "cmdpalette:recents";
const RECENTS_MAX = 5;

interface PageDest {
  id: string;
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  keywords?: string;
}

// Trading nav destinations (mirrors the Sidebar Trading group + Settings).
const PAGES: PageDest[] = [
  { id: "page:home", label: "Trading Home", path: "/home", icon: Gauge, keywords: "dashboard" },
  { id: "page:markets", label: "Markets", path: "/markets", icon: CandlestickChart, keywords: "symbols instruments" },
  { id: "page:price-alerts", label: "Price Alerts", path: "/markets/price-alerts", icon: Bell, keywords: "alerts notify" },
  { id: "page:portfolio", label: "Portfolio", path: "/portfolio", icon: PieChart, keywords: "positions holdings balances" },
  { id: "page:pnl", label: "PnL", path: "/pnl", icon: LineChart, keywords: "profit loss realized unrealized" },
  { id: "page:reports", label: "Reports", path: "/reports", icon: FileText, keywords: "export csv pdf statement trades print" },
  { id: "page:blotter", label: "Blotter / Workspace", path: "/blotter", icon: LayoutGrid, keywords: "orders fills positions workspace" },
  { id: "page:blotter-single", label: "Blotter (single panel)", path: "/blotter/single", icon: LayoutGrid, keywords: "orders fills" },
  { id: "page:custody", label: "Custody", path: "/custody", icon: Coins, keywords: "wallet deposit withdraw" },
  { id: "page:settings", label: "Settings", path: "/settings", icon: Settings, keywords: "preferences config" },
];

interface ActionDest {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  run: (ctx: ActionCtx) => void;
  keywords?: string;
}

interface ActionCtx {
  navigate: (path: string) => void;
  defaultSymbolId: number | null;
}

const ACTIONS: ActionDest[] = [
  {
    id: "action:new-alert",
    label: "New price alert",
    icon: Plus,
    keywords: "create alert notify price",
    run: ({ navigate }) => navigate("/markets/price-alerts"),
  },
  {
    id: "action:deposit",
    label: "Deposit",
    icon: ArrowDownToLine,
    keywords: "fund custody wallet add money",
    run: ({ navigate }) => navigate("/custody"),
  },
  {
    id: "action:trade-default",
    label: "Trade default symbol",
    icon: TrendingUp,
    keywords: "buy sell order ticket",
    run: ({ navigate, defaultSymbolId }) =>
      navigate(defaultSymbolId != null ? `/markets/${defaultSymbolId}` : "/markets"),
  },
  {
    id: "action:shortcuts",
    label: "Keyboard shortcuts",
    icon: Keyboard,
    keywords: "hotkeys keys help shortcuts kbd",
    run: () => openShortcutsHelp(),
  },
];

// Content search groups: which response section maps to which heading/icon.
interface ContentGroup {
  key:
    | "users"
    | "posts"
    | "catalog"
    | "files"
    | "messages"
    | "tickets"
    | "contacts"
    | "videos"
    | "calendar";
  heading: string;
  icon: React.ComponentType<{ className?: string }>;
  // Primary label to render for an item.
  primary: (item: SearchResultItem) => string;
  secondary?: (item: SearchResultItem) => string | undefined;
}

const CONTENT_GROUPS: ContentGroup[] = [
  { key: "users", heading: "People", icon: User, primary: (i) => i.title },
  { key: "posts", heading: "Posts", icon: FileText, primary: (i) => i.snippet || i.title },
  { key: "catalog", heading: "Catalog", icon: ShoppingBag, primary: (i) => i.title },
  { key: "files", heading: "Files", icon: FolderOpen, primary: (i) => i.title },
  { key: "messages", heading: "Messages", icon: MessageSquare, primary: (i) => i.title, secondary: (i) => i.snippet },
  { key: "tickets", heading: "Tickets", icon: Ticket, primary: (i) => i.title, secondary: (i) => i.snippet },
  { key: "contacts", heading: "Contacts", icon: Users, primary: (i) => i.title, secondary: (i) => i.snippet },
  { key: "videos", heading: "Videos", icon: Play, primary: (i) => i.title },
  { key: "calendar", heading: "Calendar", icon: CalendarIcon, primary: (i) => i.title },
];

function loadRecents(): string[] {
  try {
    const raw = localStorage.getItem(RECENTS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x) => typeof x === "string").slice(0, RECENTS_MAX) : [];
  } catch {
    return [];
  }
}

function saveRecent(id: string, current: string[]): string[] {
  const next = [id, ...current.filter((c) => c !== id)].slice(0, RECENTS_MAX);
  try {
    localStorage.setItem(RECENTS_KEY, JSON.stringify(next));
  } catch {
    /* ignore quota or availability errors */
  }
  return next;
}

export default function CommandPalette() {
  const navigate = useNavigate();
  const [open, setOpen] = React.useState(false);
  const [recents, setRecents] = React.useState<string[]>(() => loadRecents());

  // Controlled query + debounced value that drives the content search.
  const [query, setQuery] = React.useState("");
  const [debouncedQuery, setDebouncedQuery] = React.useState("");

  const trackRecentSearch = useUiStore((s) => s.trackRecentSearch);

  const symbolsQuery = useSymbols();
  const symbols = symbolsQuery.data?.symbols ?? [];

  // Debounce the query (~250ms) for the content search.
  React.useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(query.trim()), 250);
    return () => clearTimeout(t);
  }, [query]);

  // Reset query state whenever the palette closes.
  React.useEffect(() => {
    if (!open) {
      setQuery("");
      setDebouncedQuery("");
    }
  }, [open]);

  // Content/social search. Only fires with a real query (>=2 chars). Failure
  // here must never break the local palette, so errors are simply ignored.
  const contentQuery = useQuery({
    queryKey: ["cmdpalette-search", debouncedQuery],
    queryFn: () => globalSearch(debouncedQuery, undefined, 5),
    enabled: open && debouncedQuery.length >= 2,
    staleTime: 60_000,
  });
  const contentResults = contentQuery.data?.results;
  const contentLoading = contentQuery.isFetching && debouncedQuery.length >= 2;

  // Default symbol: last-recent traded symbol if present, else first catalog entry.
  const defaultSymbolId = React.useMemo<number | null>(() => {
    const recentSym = recents.find((r) => r.startsWith("symbol:"));
    if (recentSym) {
      const parsed = Number(recentSym.slice("symbol:".length));
      if (Number.isFinite(parsed)) return parsed;
    }
    return symbols.length > 0 ? symbols[0]!.symbol_id : null;
  }, [recents, symbols]);

  // Global Cmd/Ctrl+K listener. Toggle open; the palette own input still
  // works once open (cmdk owns focus inside the dialog).
  React.useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const go = React.useCallback(
    (id: string, path: string) => {
      setRecents((cur) => saveRecent(id, cur));
      setOpen(false);
      navigate(path);
    },
    [navigate],
  );

  const runAction = React.useCallback(
    (action: ActionDest) => {
      setRecents((cur) => saveRecent(action.id, cur));
      setOpen(false);
      action.run({ navigate, defaultSymbolId });
    },
    [navigate, defaultSymbolId],
  );

  // Navigate to a content-search result's target URL (same as the old dialog).
  const goContent = React.useCallback(
    (url: string) => {
      if (debouncedQuery) trackRecentSearch(debouncedQuery);
      setOpen(false);
      navigate(url);
    },
    [navigate, debouncedQuery, trackRecentSearch],
  );

  // Resolve a recent id back to a rendered, selectable item.
  const recentItems = React.useMemo(() => {
    return recents
      .map((id) => {
        if (id.startsWith("page:")) {
          const p = PAGES.find((x) => x.id === id);
          return p ? { key: id, label: p.label, icon: p.icon, onSelect: () => go(id, p.path) } : null;
        }
        if (id.startsWith("action:")) {
          const a = ACTIONS.find((x) => x.id === id);
          return a ? { key: id, label: a.label, icon: a.icon, onSelect: () => runAction(a) } : null;
        }
        if (id.startsWith("symbol:")) {
          const sid = Number(id.slice("symbol:".length));
          const s = symbols.find((x) => x.symbol_id === sid);
          if (!s) return null;
          return {
            key: id,
            label: s.symbol,
            icon: TrendingUp,
            onSelect: () => go(id, `/markets/${s.symbol_id}`),
          };
        }
        return null;
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
  }, [recents, symbols, go, runAction]);

  const hasQuery = debouncedQuery.length >= 2;
  const q = query.toLowerCase();

  // Substring-filtered symbols shown in the palette. We probe PM state only for
  // this (already small, cmdk-visible) slice so the palette + Markets list use
  // the SAME classifier without a catalog-wide probe storm.
  const filteredSymbols = React.useMemo(
    () => symbols.filter((sc) => !query || sc.symbol.toLowerCase().includes(q)),
    [symbols, query, q],
  );
  const probeIds = React.useMemo(() => filteredSymbols.map((sc) => sc.symbol_id), [filteredSymbols]);
  // Only probe while the palette is open; capped inside the hook.
  const probe = usePredictionProbe(probeIds, open);

  // Group the visible symbols by instrument class (a symbol may appear under
  // several headings — a perp is also in the funding book).
  const symbolsByClass = React.useMemo(() => {
    const groups = new Map<InstrumentClass, typeof filteredSymbols>();
    for (const cls of CLASS_ORDER) groups.set(cls, []);
    for (const sc of filteredSymbols) {
      const classes = classesForSymbol(sc, { isPrediction: probe.isPrediction(sc.symbol_id) });
      for (const cls of classes) groups.get(cls)!.push(sc);
    }
    return groups;
  }, [filteredSymbols, probe]);


  return (
    <CommandDialog open={open} onOpenChange={setOpen} shouldFilter={false}>
      <CommandInput
        placeholder="Search symbols, pages, people, posts..."
        value={query}
        onValueChange={setQuery}
      />
      <CommandList>
        <CommandEmpty>
          {contentLoading ? "Searching..." : "No results found."}
        </CommandEmpty>

        {recentItems.length > 0 && !query && (
          <CommandGroup heading="Recent">
            {recentItems.map((item) => (
              <CommandItem key={`recent-${item.key}`} value={`recent ${item.label}`} onSelect={item.onSelect}>
                <Clock className="mr-2 h-4 w-4 text-muted-foreground" />
                {item.label}
              </CommandItem>
            ))}
          </CommandGroup>
        )}

        {CLASS_ORDER.map((cls) => {
          const group = symbolsByClass.get(cls) ?? [];
          if (group.length === 0) return null;
          return (
            <CommandGroup key={`symbols-${cls}`} heading={CLASS_LABELS[cls]}>
              {group.map((sc) => (
                <CommandItem
                  key={`symbol-${cls}-${sc.symbol_id}`}
                  value={`symbol ${cls} ${sc.symbol}`}
                  onSelect={() => go(`symbol:${sc.symbol_id}`, `/markets/${sc.symbol_id}`)}
                >
                  <TrendingUp className="mr-2 h-4 w-4 text-muted-foreground" />
                  {sc.symbol}
                </CommandItem>
              ))}
            </CommandGroup>
          );
        })}

        <CommandGroup heading="Pages">
          {PAGES.filter(
            (p) => !query || `${p.label} ${p.keywords ?? ""}`.toLowerCase().includes(q),
          ).map((p) => (
            <CommandItem
              key={p.id}
              value={`page ${p.label} ${p.keywords ?? ""}`}
              onSelect={() => go(p.id, p.path)}
            >
              <p.icon className="mr-2 h-4 w-4 text-muted-foreground" />
              {p.label}
            </CommandItem>
          ))}
        </CommandGroup>

        <CommandGroup heading="Actions">
          {ACTIONS.filter(
            (a) => !query || `${a.label} ${a.keywords ?? ""}`.toLowerCase().includes(q),
          ).map((a) => (
            <CommandItem
              key={a.id}
              value={`action ${a.label} ${a.keywords ?? ""}`}
              onSelect={() => runAction(a)}
            >
              <a.icon className="mr-2 h-4 w-4 text-muted-foreground" />
              {a.label}
              {a.id === "action:trade-default" && defaultSymbolId != null && (
                <CommandShortcut>
                  {symbols.find((s) => s.symbol_id === defaultSymbolId)?.symbol ?? ""}
                </CommandShortcut>
              )}
            </CommandItem>
          ))}
        </CommandGroup>

        {/* Subtle loading indicator while the content query is in flight. */}
        {contentLoading && (
          <div className="flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Searching content...
          </div>
        )}

        {/* Live content/social results. Only rendered with a query + results;
            a failed content query simply yields nothing here. */}
        {hasQuery &&
          contentResults &&
          CONTENT_GROUPS.map((g) => {
            const section = contentResults[g.key];
            const items = section?.items ?? [];
            if (items.length === 0) return null;
            const Icon = g.icon;
            return (
              <CommandGroup key={`content-${g.key}`} heading={g.heading}>
                {items.map((item) => {
                  const primary = g.primary(item) || item.title || item.snippet;
                  const secondary = g.secondary?.(item);
                  return (
                    <CommandItem
                      key={`${g.key}-${item.id}`}
                      value={`${g.key}-${item.id}-${primary}`}
                      onSelect={() => goContent(item.url)}
                    >
                      <Icon className="mr-2 h-4 w-4 text-muted-foreground" />
                      {secondary ? (
                        <div className="flex min-w-0 flex-col">
                          <span className="truncate text-sm">{primary}</span>
                          <span className="truncate text-xs text-muted-foreground">{secondary}</span>
                        </div>
                      ) : (
                        <span className="truncate">{primary}</span>
                      )}
                    </CommandItem>
                  );
                })}
              </CommandGroup>
            );
          })}

        {/* View all results link (mirrors the old content dialog). */}
        {hasQuery && (
          <CommandGroup>
            <CommandItem
              value={`view-all-results-${debouncedQuery}`}
              onSelect={() => goContent(`/search?q=${encodeURIComponent(debouncedQuery)}`)}
            >
              <Search className="mr-2 h-4 w-4" />
              View all results for &quot;{debouncedQuery}&quot;
            </CommandItem>
          </CommandGroup>
        )}
      </CommandList>
    </CommandDialog>
  );
}

/** Small header affordance that opens the palette. Dispatches a synthetic
 * Cmd+K so the single global listener owns open/close state. */
export function CommandPaletteTrigger({ className }: { className?: string }) {
  const isMac = typeof navigator !== "undefined" && navigator.userAgent.includes("Mac");
  const openPalette = () => {
    window.dispatchEvent(
      new KeyboardEvent("keydown", { key: "k", ctrlKey: !isMac, metaKey: isMac, bubbles: true }),
    );
  };
  return (
    <button
      type="button"
      onClick={openPalette}
      aria-label="Open command palette"
      className={
        className ??
        "inline-flex h-9 items-center gap-2 rounded-md border border-border bg-background px-3 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      }
    >
      <Search className="h-4 w-4" />
      <span className="hidden sm:inline">Search...</span>
      <kbd className="pointer-events-none ml-auto hidden select-none rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px] font-medium text-muted-foreground sm:inline-block">
        {isMac ? "⌘K" : "Ctrl+K"}
      </kbd>
    </button>
  );
}
