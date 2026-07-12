/**
 * PLT-001: Rate-limit consumer info tab.
 *
 * Shows the current user's API keys along with their per-window rate-limit
 * overrides. Allows setting overrides via /ui/api_keys/self_limits.
 *
 * Flag gate: Umbrella OPEN_BANK_PROJECT_ENABLED + API_CONSUMER_RATE_LIMIT_ENABLED.
 * The /ui/api_keys endpoint is always available (not gated); the rate_limit_overrides
 * field simply stays null when PLT-001 is disabled.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { KeyRound, RefreshCw, Save, ChevronDown, ChevronUp } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  listApiKeys,
  setApiKeySelfLimits,
  type ApiKeyItem,
  type ApiKeyRateLimitOverrides,
} from "@/api/endpoints/bankPlatform";

const WINDOWS: (keyof ApiKeyRateLimitOverrides)[] = ["minute", "hour", "day", "week", "month"];

const WINDOW_LABELS: Record<keyof ApiKeyRateLimitOverrides, string> = {
  minute: "Per minute",
  hour: "Per hour",
  day: "Per day",
  week: "Per week",
  month: "Per month",
};

function OverrideForm({
  keyItem,
  onClose,
}: {
  keyItem: ApiKeyItem;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const existing = keyItem.rate_limit_overrides ?? {};
  const [overrides, setOverrides] = useState<Record<string, string>>({
    minute: existing.minute != null ? String(existing.minute) : "",
    hour: existing.hour != null ? String(existing.hour) : "",
    day: existing.day != null ? String(existing.day) : "",
    week: existing.week != null ? String(existing.week) : "",
    month: existing.month != null ? String(existing.month) : "",
  });

  const saveMut = useMutation({
    mutationFn: () => {
      const parsed: ApiKeyRateLimitOverrides = {};
      for (const w of WINDOWS) {
        const raw = overrides[w] ?? "";
        if (raw === "") {
          parsed[w] = null;
        } else {
          const n = parseInt(raw, 10);
          if (!isNaN(n) && n >= 0) parsed[w] = n;
        }
      }
      return setApiKeySelfLimits({
        key_id: keyItem.key_id,
        rate_limit_overrides: parsed,
      });
    },
    onSuccess: () => {
      toast.success("Rate-limit overrides saved.");
      qc.invalidateQueries({ queryKey: ["bank-platform", "api-keys"] });
      onClose();
    },
    onError: (err: Error) => {
      toast.error(err.message ?? "Failed to save overrides");
    },
  });

  return (
    <form
      className="mt-3 rounded-md border bg-muted/30 p-4"
      onSubmit={(e) => {
        e.preventDefault();
        saveMut.mutate();
      }}
    >
      <p className="text-xs font-medium text-muted-foreground mb-3">
        Rate-limit overrides (blank = use account default; 0 = disable window)
      </p>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {WINDOWS.map((w) => (
          <div key={w} className="flex flex-col gap-1">
            <Label className="text-xs">{WINDOW_LABELS[w]}</Label>
            <Input
              type="number"
              min={0}
              placeholder="default"
              value={overrides[w]}
              onChange={(e) => setOverrides((prev) => ({ ...prev, [w]: e.target.value }))}
            />
          </div>
        ))}
      </div>
      <div className="mt-3 flex gap-2">
        <Button type="submit" size="sm" disabled={saveMut.isPending} className="gap-1.5">
          <Save className="h-4 w-4" />
          {saveMut.isPending ? "Saving…" : "Save overrides"}
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

function ApiKeyCard({ keyItem }: { keyItem: ApiKeyItem }) {
  const [expanded, setExpanded] = useState(false);
  const overrides = keyItem.rate_limit_overrides;
  const hasOverrides = overrides && Object.values(overrides).some((v) => v != null);

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <KeyRound className="h-4 w-4 shrink-0 text-muted-foreground" />
            <span className="truncate text-sm font-medium">{keyItem.label || keyItem.key_id}</span>
            {keyItem.revoked && (
              <Badge variant="destructive" className="text-xs">Revoked</Badge>
            )}
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setExpanded((e) => !e)}
            className="gap-1 shrink-0"
          >
            {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            {expanded ? "Hide" : "Edit limits"}
          </Button>
        </div>
        <CardDescription className="text-xs font-mono">{keyItem.key_id}</CardDescription>
      </CardHeader>
      <CardContent className="pb-3">
        {/* Rate-limit overrides summary */}
        {hasOverrides ? (
          <div className="flex flex-wrap gap-2">
            {WINDOWS.map((w) => {
              const v = overrides![w];
              if (v == null) return null;
              return (
                <Badge key={w} variant="secondary" className="text-xs">
                  {WINDOW_LABELS[w]}: {v === 0 ? "disabled" : v.toLocaleString()}
                </Badge>
              );
            })}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">Using account defaults for all windows.</p>
        )}

        {/* Monthly caps */}
        <div className="mt-2 flex flex-wrap gap-2">
          {keyItem.monthly_calls_cap != null && (
            <Badge variant="outline" className="text-xs">
              Monthly calls cap: {keyItem.monthly_calls_cap.toLocaleString()}
            </Badge>
          )}
          {keyItem.monthly_spend_cap_micros != null && (
            <Badge variant="outline" className="text-xs">
              Monthly spend cap: ${(keyItem.monthly_spend_cap_micros / 1_000_000).toFixed(4)}
            </Badge>
          )}
        </div>

        {expanded && !keyItem.revoked && (
          <OverrideForm keyItem={keyItem} onClose={() => setExpanded(false)} />
        )}
      </CardContent>
    </Card>
  );
}

export default function RateLimitsTab() {
  const query = useQuery({
    queryKey: ["bank-platform", "api-keys"],
    queryFn: listApiKeys,
    retry: false,
  });

  const keys = query.data?.keys ?? [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Per-Consumer Rate Limits</h2>
          <p className="text-sm text-muted-foreground">
            Configure windowed call budgets for each of your API keys (PLT-001).
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => query.refetch()}
          disabled={query.isFetching}
          className="gap-1.5"
        >
          <RefreshCw className={`h-4 w-4 ${query.isFetching ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {query.isLoading && (
        <div className="flex flex-col gap-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      )}

      {query.isError && (
        <Card className="border-destructive">
          <CardContent className="pt-4 text-sm text-destructive">
            Failed to load API keys: {query.error instanceof Error ? query.error.message : "Unknown error"}
          </CardContent>
        </Card>
      )}

      {!query.isLoading && !query.isError && keys.length === 0 && (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No API keys found. Create an API key in{" "}
            <a href="/security/api-keys" className="text-primary underline-offset-2 hover:underline">
              Security &gt; API Keys
            </a>{" "}
            first.
          </CardContent>
        </Card>
      )}

      <div className="flex flex-col gap-3">
        {keys.map((k) => (
          <ApiKeyCard key={k.key_id} keyItem={k} />
        ))}
      </div>
    </div>
  );
}
