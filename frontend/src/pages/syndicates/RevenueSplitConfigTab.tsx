import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Percent } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  getSplitConfig,
  setSplitConfig,
} from "@/api/endpoints/syndicateRevenueSplit";
import { listMembers } from "@/api/endpoints/syndicates";
import type { SplitMode } from "@/api/types";

const PREVIEW_GROSS_CENTS = 2000; // $20.00 hypothetical payment

export default function RevenueSplitConfigTab({
  syndicateId,
  isAdmin,
}: {
  syndicateId: string;
  isAdmin: boolean;
}) {
  const queryClient = useQueryClient();

  const { data: config } = useQuery({
    queryKey: ["revenue-split", syndicateId, "config"],
    queryFn: () => getSplitConfig(syndicateId),
    enabled: !!syndicateId,
  });

  const { data: members = [] } = useQuery({
    queryKey: ["syndicates", syndicateId, "members"],
    queryFn: () => listMembers(syndicateId),
    enabled: !!syndicateId,
  });

  const [mode, setMode] = useState<SplitMode>("equal");
  const [platformFeePct, setPlatformFeePct] = useState(15);
  const [metric, setMetric] = useState("views");
  const [windowDays, setWindowDays] = useState(30);
  const [weightsPct, setWeightsPct] = useState<Record<string, number>>({});
  const [error, setError] = useState("");

  useEffect(() => {
    if (!config) return;
    setMode(config.mode);
    setPlatformFeePct(Math.round(config.platform_fee_bps / 100));
    setMetric(config.performance_metric || "views");
    setWindowDays(config.performance_window_days || 30);
    const w: Record<string, number> = {};
    Object.entries(config.weights_bps || {}).forEach(([uid, bps]) => {
      w[uid] = Math.round((bps as number) / 100);
    });
    setWeightsPct(w);
  }, [config]);

  const weightsTotal = members.reduce(
    (sum, m) => sum + (weightsPct[m.user_id] || 0),
    0,
  );

  const mut = useMutation({
    mutationFn: () => {
      const body: Parameters<typeof setSplitConfig>[1] = {
        mode,
        platform_fee_bps: Math.round(platformFeePct * 100),
      };
      if (mode === "weighted") {
        const weights_bps: Record<string, number> = {};
        members.forEach((m) => {
          weights_bps[m.user_id] = Math.round((weightsPct[m.user_id] || 0) * 100);
        });
        body.weights_bps = weights_bps;
      }
      if (mode === "performance") {
        body.performance_metric = metric;
        body.performance_window_days = windowDays;
      }
      return setSplitConfig(syndicateId, body);
    },
    onSuccess: () => {
      setError("");
      queryClient.invalidateQueries({ queryKey: ["revenue-split", syndicateId] });
    },
    onError: (e: unknown) => {
      setError(e instanceof Error ? e.message : "Failed to save configuration");
    },
  });

  const netCents = Math.floor(
    PREVIEW_GROSS_CENTS - (PREVIEW_GROSS_CENTS * platformFeePct) / 100,
  );

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Percent className="h-5 w-5" />
            Revenue Split Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-sm font-medium">Split Mode</label>
            <Select
              value={mode}
              onValueChange={(v) => setMode(v as SplitMode)}
              disabled={!isAdmin}
            >
              <SelectTrigger aria-label="Split mode">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="equal">Equal Split</SelectItem>
                <SelectItem value="weighted">Weighted Split</SelectItem>
                <SelectItem value="performance">Performance-Based</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {mode === "weighted" && (
            <div className="space-y-2" data-testid="weight-editor">
              <p className="text-sm font-medium">Per-member percentages</p>
              {members.map((m) => (
                <div key={m.user_id} className="flex items-center gap-2">
                  <span className="flex-1 text-sm">{m.display_name || m.user_id}</span>
                  <Input
                    type="number"
                    className="w-24"
                    aria-label={`weight-${m.user_id}`}
                    min={0}
                    max={100}
                    value={weightsPct[m.user_id] ?? 0}
                    disabled={!isAdmin}
                    onChange={(e) =>
                      setWeightsPct((prev) => ({
                        ...prev,
                        [m.user_id]: Number(e.target.value),
                      }))
                    }
                  />
                  <span className="text-sm text-muted-foreground">%</span>
                </div>
              ))}
              <p
                className={`text-sm ${weightsTotal === 100 ? "text-green-600" : "text-destructive"}`}
              >
                Total: {weightsTotal}% {weightsTotal !== 100 && "(must equal 100%)"}
              </p>
            </div>
          )}

          {mode === "performance" && (
            <div className="space-y-2">
              <div>
                <label className="text-sm font-medium">Metric</label>
                <Select value={metric} onValueChange={setMetric} disabled={!isAdmin}>
                  <SelectTrigger aria-label="Performance metric">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="views">Views</SelectItem>
                    <SelectItem value="engagement">Engagement</SelectItem>
                    <SelectItem value="subscribers">Subscribers</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-sm font-medium">Window (days)</label>
                <Select
                  value={String(windowDays)}
                  onValueChange={(v) => setWindowDays(Number(v))}
                  disabled={!isAdmin}
                >
                  <SelectTrigger aria-label="Performance window">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="7">7 days</SelectItem>
                    <SelectItem value="14">14 days</SelectItem>
                    <SelectItem value="30">30 days</SelectItem>
                    <SelectItem value="90">90 days</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          <div>
            <label className="text-sm font-medium">Platform Fee (%)</label>
            <Input
              type="number"
              className="w-24"
              aria-label="Platform fee"
              min={0}
              max={50}
              value={platformFeePct}
              disabled={!isAdmin}
              onChange={(e) => setPlatformFeePct(Number(e.target.value))}
            />
          </div>

          {error && <p className="text-sm text-destructive">{error}</p>}

          {isAdmin && (
            <Button
              onClick={() => mut.mutate()}
              disabled={mut.isPending || (mode === "weighted" && weightsTotal !== 100)}
            >
              {mut.isPending ? "Saving..." : "Save Configuration"}
            </Button>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Split Preview</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1 text-sm">
          <p>Hypothetical payment: ${(PREVIEW_GROSS_CENTS / 100).toFixed(2)}</p>
          <p>
            Platform fee ({platformFeePct}%):{" "}
            <Badge variant="secondary">
              ${((PREVIEW_GROSS_CENTS - netCents) / 100).toFixed(2)}
            </Badge>
          </p>
          <p>
            Net distributable:{" "}
            <Badge>${(netCents / 100).toFixed(2)}</Badge> among {members.length}{" "}
            member(s)
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
