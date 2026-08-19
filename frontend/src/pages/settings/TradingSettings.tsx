import * as React from "react";
import { Bell, RotateCcw, Check } from "lucide-react";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useUiStore, type Theme } from "@/stores/uiStore";
import { useSymbols } from "@/hooks/useMarketData";
import type { TradingAlertKind } from "@/hooks/useTradingAlerts";
import {
  loadAlertPrefs,
  saveAlertPrefs,
  loadDefaultSymbol,
  saveDefaultSymbol,
  resetBlotterLayout,
  type AlertPrefs,
} from "@/lib/tradingPrefs";

const NO_DEFAULT = "__none__";

const THEME_OPTIONS: { value: Theme; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "system", label: "System" },
];

const ALERT_KINDS: { kind: TradingAlertKind; label: string; hint: string }[] = [
  { kind: "fill", label: "Fills", hint: "Your orders are filled" },
  { kind: "liquidation", label: "Liquidations", hint: "A position is force-closed" },
  { kind: "funding", label: "Funding", hint: "Perpetual funding settlements" },
  { kind: "margin", label: "Margin distress", hint: "Your account nears liquidation" },
  { kind: "pm_resolved", label: "PM resolutions", hint: "A prediction market resolves" },
  { kind: "price", label: "Price alerts", hint: "A market crosses your target price" },
];

type NotifyStatus = "unsupported" | NotificationPermission;

function currentNotifyStatus(): NotifyStatus {
  if (typeof Notification === "undefined") return "unsupported";
  return Notification.permission;
}

export function TradingSettings() {
  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);

  const symbolsQuery = useSymbols();
  const symbols = symbolsQuery.data?.symbols ?? [];

  const [defaultSymbol, setDefaultSymbol] = React.useState<number | null>(() =>
    loadDefaultSymbol(),
  );
  const [alertPrefs, setAlertPrefs] = React.useState<AlertPrefs>(() =>
    loadAlertPrefs(),
  );
  const [notifyStatus, setNotifyStatus] = React.useState<NotifyStatus>(() =>
    currentNotifyStatus(),
  );

  const onDefaultSymbolChange = (value: string) => {
    const id = value === NO_DEFAULT ? null : Number(value);
    setDefaultSymbol(id);
    saveDefaultSymbol(id);
    const name =
      id == null ? null : symbols.find((s) => s.symbol_id === id)?.symbol;
    toast.success(
      name ? `Default market set to ${name}` : "Default market cleared",
    );
  };

  const toggleAlert = (kind: TradingAlertKind, enabled: boolean) => {
    setAlertPrefs((prev) => {
      const next = { ...prev, [kind]: enabled };
      saveAlertPrefs(next);
      // Notify the alerts hook (same-tab) to re-read prefs immediately.
      window.dispatchEvent(new Event("tl:alertPrefsChanged"));
      return next;
    });
  };

  const requestNotifyPermission = async () => {
    if (typeof Notification === "undefined") {
      toast.error("This browser does not support notifications");
      return;
    }
    try {
      const result = await Notification.requestPermission();
      setNotifyStatus(result);
      if (result === "granted") {
        toast.success("Notifications enabled");
      } else if (result === "denied") {
        toast.error("Notifications blocked — enable them in browser settings");
      }
    } catch {
      toast.error("Could not request notification permission");
    }
  };

  const resetLayout = () => {
    resetBlotterLayout();
    toast.success("Blotter layout reset — reopen the workspace to see defaults");
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Trading</CardTitle>
      </CardHeader>
      <Separator />
      <CardContent className="space-y-6 pt-4">
        {/* Theme */}
        <div className="space-y-2">
          <Label className="text-sm font-medium">Theme</Label>
          <p className="text-xs text-muted-foreground">
            Light, dark, or follow your system. Applied everywhere.
          </p>
          <Select value={theme} onValueChange={(v) => setTheme(v as Theme)}>
            <SelectTrigger className="w-full sm:w-64" data-testid="trading-theme-select">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {THEME_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={o.value}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <Separator />

        {/* Default market */}
        <div className="space-y-2">
          <Label className="text-sm font-medium">Default market</Label>
          <p className="text-xs text-muted-foreground">
            The symbol trading surfaces prefer when no market is specified.
          </p>
          <Select
            value={defaultSymbol == null ? NO_DEFAULT : String(defaultSymbol)}
            onValueChange={onDefaultSymbolChange}
          >
            <SelectTrigger
              className="w-full sm:w-64"
              data-testid="trading-default-symbol-select"
            >
              <SelectValue placeholder="No default" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={NO_DEFAULT}>No default</SelectItem>
              {symbols.map((s) => (
                <SelectItem key={s.symbol_id} value={String(s.symbol_id)}>
                  {s.symbol}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <Separator />

        {/* Alert preferences */}
        <div className="space-y-3">
          <div>
            <Label className="text-sm font-medium">Trading alerts</Label>
            <p className="text-xs text-muted-foreground">
              Choose which trading events surface as alerts and toasts.
            </p>
          </div>
          <div className="space-y-3">
            {ALERT_KINDS.map(({ kind, label, hint }) => (
              <div key={kind} className="flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{label}</p>
                  <p className="text-xs text-muted-foreground">{hint}</p>
                </div>
                <Switch
                  checked={alertPrefs[kind] !== false}
                  onCheckedChange={(v) => toggleAlert(kind, v)}
                  aria-label={`Toggle ${label} alerts`}
                  data-testid={`trading-alert-${kind}`}
                />
              </div>
            ))}
          </div>
        </div>

        <Separator />

        {/* Notifications */}
        <div className="space-y-2">
          <Label className="text-sm font-medium">Browser notifications</Label>
          <p className="text-xs text-muted-foreground">
            Grant permission so trading alerts can surface as OS notifications
            even when this tab is not focused.
          </p>
          <div className="flex items-center gap-3">
            {notifyStatus === "granted" ? (
              <span className="inline-flex items-center gap-1.5 text-sm font-medium text-green-600 dark:text-green-500">
                <Check className="h-4 w-4" /> Enabled
              </span>
            ) : (
              <Button
                variant="outline"
                onClick={requestNotifyPermission}
                disabled={notifyStatus === "unsupported"}
                data-testid="trading-notify-permission"
              >
                <Bell className="mr-2 h-4 w-4" />
                {notifyStatus === "denied"
                  ? "Notifications blocked"
                  : notifyStatus === "unsupported"
                    ? "Not supported"
                    : "Enable notifications"}
              </Button>
            )}
            <span className="text-xs text-muted-foreground">
              Status: {notifyStatus}
            </span>
          </div>
        </div>

        <Separator />

        {/* Reset blotter layout */}
        <div className="space-y-2">
          <Label className="text-sm font-medium">Blotter workspace</Label>
          <p className="text-xs text-muted-foreground">
            Reset the dockable blotter panels to their default arrangement.
          </p>
          <Button
            variant="outline"
            onClick={resetLayout}
            data-testid="trading-reset-blotter"
          >
            <RotateCcw className="mr-2 h-4 w-4" />
            Reset blotter layout
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
