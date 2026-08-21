import * as React from "react";
import { LifeBuoy, Save } from "lucide-react";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useBailoutPrefs, usePutBailoutPrefs, isPendingBackend } from "@/hooks/useBailouts";
import { formatBps, pctToBps, bpsToPct } from "@/lib/bailout";

const LS_KEY = "tl:bailoutPrefs";

interface LocalPrefs {
  auto_enabled: boolean;
  default_max_share_bps: number;
}

const DEFAULT_PREFS: LocalPrefs = { auto_enabled: false, default_max_share_bps: 2000 };

function loadLocal(): LocalPrefs {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return DEFAULT_PREFS;
    const p = JSON.parse(raw) as Partial<LocalPrefs>;
    return {
      auto_enabled: !!p.auto_enabled,
      default_max_share_bps:
        Number.isFinite(p.default_max_share_bps) && (p.default_max_share_bps as number) > 0
          ? (p.default_max_share_bps as number)
          : DEFAULT_PREFS.default_max_share_bps,
    };
  } catch {
    return DEFAULT_PREFS;
  }
}

function saveLocal(p: LocalPrefs) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(p));
  } catch {
    /* ignore quota / disabled storage */
  }
}

/**
 * Auto-bailout protection account setting. Reads `GET /me/prefs/bailout` and
 * writes `PUT /me/prefs/bailout`. Degrades on 404: persists the preference
 * CLIENT-SIDE (localStorage) as a clearly-labelled fallback until the backend
 * ships. When auto is ON, an eligible position opens a bailout automatically on
 * distress band-entry (server-side); when OFF, the trader opens one manually.
 */
export function BailoutSettings() {
  const prefsQ = useBailoutPrefs();
  const put = usePutBailoutPrefs();

  const pendingBackend = prefsQ.isError && isPendingBackend(prefsQ.error);

  const [auto, setAuto] = React.useState<boolean>(DEFAULT_PREFS.auto_enabled);
  const [sharePct, setSharePct] = React.useState<string>(String(bpsToPct(DEFAULT_PREFS.default_max_share_bps)));
  const [hydrated, setHydrated] = React.useState(false);

  // Hydrate from the server read, else the local fallback.
  React.useEffect(() => {
    if (hydrated) return;
    if (prefsQ.data) {
      setAuto(!!prefsQ.data.auto_enabled);
      setSharePct(String(bpsToPct(prefsQ.data.default_max_share_bps)));
      setHydrated(true);
    } else if (prefsQ.isError) {
      const local = loadLocal();
      setAuto(local.auto_enabled);
      setSharePct(String(bpsToPct(local.default_max_share_bps)));
      setHydrated(true);
    }
  }, [prefsQ.data, prefsQ.isError, hydrated]);

  const maxShareBps = pctToBps(Number(sharePct));
  const invalid = !(Number(sharePct) > 0) || Number(sharePct) > 100;

  const onSave = async () => {
    const body = { auto_enabled: auto, default_max_share_bps: maxShareBps };
    try {
      await put.mutateAsync(body);
      toast.success("Auto-bailout preference saved.");
    } catch (err) {
      if (isPendingBackend(err)) {
        // Backend not shipped — persist client-side as a clearly-labelled fallback.
        saveLocal(body);
        toast.success("Saved locally (backend pending) — will sync when the surface ships.");
      }
      /* other errors toast in the hook */
    }
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <LifeBuoy className="h-4 w-4" /> Auto-bailout protection
        </CardTitle>
      </CardHeader>
      <Separator />
      <CardContent className="space-y-5 pt-4">
        <p className="text-sm text-muted-foreground">
          A bailout auction raises rescue capital from other traders in exchange for a slice of a
          distressed (but still solvent) margin position — pre-empting a forced liquidation. When
          this is on, an eligible position opens one automatically the moment it enters the
          volatility-scaled distress band. Off means you open one manually after a prompt.
        </p>

        {pendingBackend && (
          <p className="rounded-md border border-amber-300/50 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-500/30 dark:bg-amber-950/40 dark:text-amber-300">
            <span className="font-semibold">Backend pending:</span> the preference endpoint has not
            shipped on this environment, so this setting is saved locally in this browser and will
            sync automatically once the backend deploys.
          </p>
        )}

        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-medium">Auto-open on band-entry</p>
            <p className="text-xs text-muted-foreground">
              Automatically open a bailout auction when a position enters distress.
            </p>
          </div>
          <Switch
            checked={auto}
            onCheckedChange={setAuto}
            aria-label="Toggle auto-bailout protection"
            data-testid="bailout-auto-toggle"
          />
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="bailout-default-share" className="text-sm font-medium">
            Default max position-share to give up (%)
          </Label>
          <Input
            id="bailout-default-share"
            type="number"
            min={1}
            max={100}
            step={1}
            value={sharePct}
            onChange={(e) => setSharePct(e.target.value)}
            className="w-full sm:w-48"
            data-testid="bailout-default-share"
          />
          <p className="text-xs text-muted-foreground">
            The dilution ceiling ({formatBps(maxShareBps)}) an auto-opened auction uses by default.
          </p>
        </div>

        <Button onClick={onSave} disabled={invalid || put.isPending} data-testid="bailout-prefs-save">
          <Save className="mr-2 h-4 w-4" />
          {put.isPending ? "Saving..." : "Save preference"}
        </Button>
      </CardContent>
    </Card>
  );
}
