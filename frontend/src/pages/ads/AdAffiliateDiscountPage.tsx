import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Tag, Plus, Trash2, RefreshCw, Link2 } from "lucide-react";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  attachAdAffiliateDiscount,
  listAdAffiliateDiscounts,
  removeAdAffiliateDiscount,
  getAdAffiliateStats,
} from "@/api/endpoints/adCreativeAffiliate";
import type { AdAffiliateDiscount, AdAffiliateStats } from "@/api/types";

function PromoBadge({ text }: { text: string }) {
  return (
    <span className="rounded-md bg-red-600 px-2 py-1 text-xs font-bold text-white shadow-lg">
      {text}
    </span>
  );
}

export default function AdAffiliateDiscountPage() {
  const queryClient = useQueryClient();
  const [creativeId, setCreativeId] = useState("");
  const [campaignId, setCampaignId] = useState("");
  const [affiliateCode, setAffiliateCode] = useState("");
  const [promoCode, setPromoCode] = useState("");
  const [promoDisplay, setPromoDisplay] = useState("");
  const [clickUrl, setClickUrl] = useState("");
  const [statsFor, setStatsFor] = useState<string | null>(null);

  const { data: list, isLoading } = useQuery({
    queryKey: ["ad-affiliate-discounts"],
    queryFn: listAdAffiliateDiscounts,
    staleTime: 15_000,
  });

  const { data: stats } = useQuery<AdAffiliateStats>({
    queryKey: ["ad-affiliate-stats", statsFor],
    queryFn: () => getAdAffiliateStats(statsFor as string),
    enabled: !!statsFor,
  });

  const attachMut = useMutation({
    mutationFn: () =>
      attachAdAffiliateDiscount(creativeId.trim(), {
        campaign_id: campaignId.trim(),
        affiliate_code: affiliateCode.trim() || null,
        promo_code: promoCode.trim() || null,
        promo_value_display: promoDisplay.trim() || null,
        click_through_url: clickUrl.trim() || null,
      }),
    onSuccess: () => {
      toast.success("Affiliate discount attached");
      setAffiliateCode("");
      setPromoCode("");
      setPromoDisplay("");
      setClickUrl("");
      queryClient.invalidateQueries({ queryKey: ["ad-affiliate-discounts"] });
    },
    onError: (e: unknown) => {
      const msg = (e as { message?: string })?.message ?? "Failed to attach discount";
      toast.error(msg);
    },
  });

  const removeMut = useMutation({
    mutationFn: (id: string) => removeAdAffiliateDiscount(id),
    onSuccess: () => {
      toast.success("Discount removed");
      queryClient.invalidateQueries({ queryKey: ["ad-affiliate-discounts"] });
    },
    onError: () => toast.error("Failed to remove discount"),
  });

  const items: AdAffiliateDiscount[] = list?.items ?? [];

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      <Card>
        <CardHeader className="flex flex-row items-center gap-2">
          <Tag className="h-6 w-6" />
          <CardTitle>Ad Creative Affiliate Discounts</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Attach an affiliate tracking code and/or a promo discount code to an
            ad creative. Codes are validated against your existing affiliate links
            and promo codes.
          </p>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor="aff-creative">Creative ID</Label>
              <Input
                id="aff-creative"
                value={creativeId}
                onChange={(e) => setCreativeId(e.target.value)}
                placeholder="cr_..."
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="aff-campaign">Campaign ID</Label>
              <Input
                id="aff-campaign"
                value={campaignId}
                onChange={(e) => setCampaignId(e.target.value)}
                placeholder="camp_..."
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="aff-code">Affiliate Code</Label>
              <Input
                id="aff-code"
                value={affiliateCode}
                onChange={(e) => setAffiliateCode(e.target.value)}
                placeholder="ABC12345"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="promo-code">Promo Code</Label>
              <Input
                id="promo-code"
                value={promoCode}
                onChange={(e) => setPromoCode(e.target.value)}
                placeholder="SUMMER20"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="promo-display">Promo Badge Text</Label>
              <Input
                id="promo-display"
                value={promoDisplay}
                onChange={(e) => setPromoDisplay(e.target.value)}
                placeholder="20% OFF"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="click-url">Click-through URL</Label>
              <Input
                id="click-url"
                value={clickUrl}
                onChange={(e) => setClickUrl(e.target.value)}
                placeholder="https://shop.com/sale"
              />
            </div>
          </div>
          {promoDisplay.trim() && (
            <div className="flex items-center gap-2 text-sm">
              <span className="text-muted-foreground">Badge preview:</span>
              <PromoBadge text={promoDisplay.trim()} />
            </div>
          )}
          <Button
            onClick={() => attachMut.mutate()}
            disabled={!creativeId.trim() || !campaignId.trim() || attachMut.isPending}
          >
            <Plus className="mr-2 h-4 w-4" />
            Attach Discount
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-lg">Attached Discounts</CardTitle>
          <Button
            size="sm"
            variant="outline"
            onClick={() => queryClient.invalidateQueries({ queryKey: ["ad-affiliate-discounts"] })}
          >
            <RefreshCw className="mr-1 h-3 w-3" />
            Refresh
          </Button>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-muted-foreground">Loading...</p>
          ) : items.length === 0 ? (
            <p className="text-muted-foreground">No affiliate discounts attached yet.</p>
          ) : (
            <div className="space-y-3">
              {items.map((d) => (
                <Card key={d.creative_id}>
                  <CardContent className="flex items-center justify-between gap-4 py-4">
                    <div className="min-w-0 flex-1 space-y-1">
                      <p className="truncate font-mono text-sm font-semibold">{d.creative_id}</p>
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        {d.affiliate_code && (
                          <Badge variant="secondary">
                            <Link2 className="mr-1 h-3 w-3" />
                            {d.affiliate_code}
                          </Badge>
                        )}
                        {d.promo_code && <Badge variant="outline">{d.promo_code}</Badge>}
                        {d.promo_value_display && <PromoBadge text={d.promo_value_display} />}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Clicks: {d.click_count} &middot; Redemptions: {d.redemption_count}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setStatsFor(d.creative_id)}
                      >
                        Stats
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => removeMut.mutate(d.creative_id)}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
          {statsFor && stats && (
            <div className="mt-4 rounded-md border p-3 text-sm">
              <p className="font-semibold">Stats for {statsFor}</p>
              <p>Clicks: {stats.click_count}</p>
              <p>Redemptions: {stats.redemption_count}</p>
              <p>Total discount: ${(stats.total_discount_cents / 100).toFixed(2)}</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
