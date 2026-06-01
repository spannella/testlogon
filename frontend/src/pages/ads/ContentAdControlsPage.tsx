import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Settings2, Save, Trash2, Percent } from "lucide-react";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  listContentAdOverrides,
  upsertContentAdOverride,
  deleteContentAdOverride,
  getRevenueShare,
  setRevenueShare,
} from "@/api/endpoints/contentAdControls";
import type {
  ContentAdOverride,
  ContentAdOverrideInput,
  RevenueShare,
} from "@/api/types";
import AdRevenueBreakdownCard from "./AdRevenueBreakdownCard";

type Density = "low" | "standard" | "high";

/**
 * ContentAdControlsPage (ADS-010) — per-content ad overrides, revenue share,
 * and the ad-revenue transparency/breakdown card.
 */
export default function ContentAdControlsPage() {
  const queryClient = useQueryClient();

  const [contentId, setContentId] = useState("");
  const [adEnabled, setAdEnabled] = useState(true);
  const [adDensity, setAdDensity] = useState<Density>("standard");
  const [preRoll, setPreRoll] = useState(true);
  const [midRoll, setMidRoll] = useState(true);
  const [adsFreeSubs, setAdsFreeSubs] = useState(false);
  const [sharePct, setSharePct] = useState("");

  const { data: overrides, isLoading } = useQuery<ContentAdOverride[]>({
    queryKey: ["content-ad-overrides"],
    queryFn: listContentAdOverrides,
    staleTime: 30_000,
  });

  const { data: share } = useQuery<RevenueShare>({
    queryKey: ["content-ad-revenue-share"],
    queryFn: getRevenueShare,
    staleTime: 60_000,
  });

  const upsertMut = useMutation({
    mutationFn: () => {
      const body: ContentAdOverrideInput = {
        content_type: "video",
        ad_enabled: adEnabled,
        ad_density: adDensity,
        pre_roll_enabled: preRoll,
        mid_roll_enabled: midRoll,
        ads_free_for_subscribers: adsFreeSubs,
      };
      return upsertContentAdOverride(contentId.trim(), body);
    },
    onSuccess: () => {
      toast.success("Override saved");
      setContentId("");
      queryClient.invalidateQueries({ queryKey: ["content-ad-overrides"] });
    },
    onError: () => toast.error("Failed to save override (do you own this content?)"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteContentAdOverride(id),
    onSuccess: () => {
      toast.success("Override removed");
      queryClient.invalidateQueries({ queryKey: ["content-ad-overrides"] });
    },
  });

  const shareMut = useMutation({
    mutationFn: () => setRevenueShare(Math.round(parseFloat(sharePct) * 100)),
    onSuccess: () => {
      toast.success("Revenue share updated");
      setSharePct("");
      queryClient.invalidateQueries({ queryKey: ["content-ad-revenue-share"] });
      queryClient.invalidateQueries({ queryKey: ["ad-revenue-breakdown"] });
    },
    onError: () => toast.error("Failed to update revenue share"),
  });

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4" data-testid="content-ad-controls">
      <div>
        <h1 className="text-2xl font-bold">Content Ad Controls</h1>
        <p className="text-sm text-muted-foreground">
          Override your global ad settings for specific content, manage your
          revenue share, and review your ad earnings.
        </p>
      </div>

      {/* Per-content override editor */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings2 className="h-5 w-5" /> Per-Content Override
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1">
            <Label htmlFor="content_id">Content ID (video)</Label>
            <Input
              id="content_id"
              data-testid="override-content-id"
              placeholder="vid_..."
              value={contentId}
              onChange={(e) => setContentId(e.target.value)}
            />
          </div>

          <div className="flex items-center justify-between">
            <Label htmlFor="ad_enabled">Ads enabled on this content</Label>
            <Switch
              id="ad_enabled"
              data-testid="override-ad-enabled"
              checked={adEnabled}
              onCheckedChange={setAdEnabled}
            />
          </div>

          <div className="space-y-1">
            <Label>Ad density</Label>
            <Select value={adDensity} onValueChange={(v) => setAdDensity(v as Density)}>
              <SelectTrigger data-testid="override-density">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="standard">Standard</SelectItem>
                <SelectItem value="high">High</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center justify-between">
            <Label htmlFor="pre_roll">Pre-roll enabled</Label>
            <Switch id="pre_roll" checked={preRoll} onCheckedChange={setPreRoll} />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="mid_roll">Mid-roll enabled</Label>
            <Switch id="mid_roll" checked={midRoll} onCheckedChange={setMidRoll} />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="ads_free_subs">Ad-free for subscribers</Label>
            <Switch
              id="ads_free_subs"
              checked={adsFreeSubs}
              onCheckedChange={setAdsFreeSubs}
            />
          </div>

          <Button
            data-testid="override-save"
            disabled={!contentId.trim() || upsertMut.isPending}
            onClick={() => upsertMut.mutate()}
          >
            <Save className="mr-2 h-4 w-4" /> Save Override
          </Button>
        </CardContent>
      </Card>

      {/* Existing overrides */}
      <Card>
        <CardHeader>
          <CardTitle>Active Overrides</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : !overrides || overrides.length === 0 ? (
            <p className="text-sm text-muted-foreground" data-testid="overrides-empty">
              No per-content overrides yet.
            </p>
          ) : (
            <ul className="space-y-2">
              {overrides.map((o) => (
                <li
                  key={o.content_id}
                  className="flex items-center justify-between rounded border p-2"
                >
                  <div className="min-w-0">
                    <p className="truncate font-mono text-sm">{o.content_id}</p>
                    <div className="mt-1 flex flex-wrap gap-1">
                      <Badge variant={o.ad_enabled ? "default" : "secondary"}>
                        {o.ad_enabled ? "Ads on" : "Ads off"}
                      </Badge>
                      <Badge variant="outline">{o.ad_density}</Badge>
                      {!o.pre_roll_enabled && <Badge variant="outline">no pre-roll</Badge>}
                      {!o.mid_roll_enabled && <Badge variant="outline">no mid-roll</Badge>}
                      {o.ads_free_for_subscribers && (
                        <Badge variant="outline">subs ad-free</Badge>
                      )}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label="Delete override"
                    onClick={() => deleteMut.mutate(o.content_id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* Revenue share */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Percent className="h-5 w-5" /> Revenue Share
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm">
            Current creator share:{" "}
            <span className="font-semibold" data-testid="revenue-share-current">
              {((share?.revenue_share_bps ?? 7000) / 100).toFixed(0)}%
            </span>
          </p>
          <div className="flex items-end gap-2">
            <div className="space-y-1">
              <Label htmlFor="share_pct">New share (%)</Label>
              <Input
                id="share_pct"
                data-testid="revenue-share-input"
                type="number"
                min={0}
                max={100}
                placeholder="70"
                value={sharePct}
                onChange={(e) => setSharePct(e.target.value)}
              />
            </div>
            <Button
              data-testid="revenue-share-save"
              disabled={!sharePct.trim() || shareMut.isPending}
              onClick={() => shareMut.mutate()}
            >
              Update
            </Button>
          </div>
        </CardContent>
      </Card>

      <AdRevenueBreakdownCard />
    </div>
  );
}
