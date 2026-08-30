// FE-162 (EPIC G, <- BE-161/BE-162/BE-163): "promote an entity" campaign flow.
//
// Pick WHAT to promote (a market / creator-token / product) via a searchable
// picker populated from the existing entity reads, choose behavioral targeting
// segments (opt-in-respecting), see a live debounced audience estimate, and on
// submit create the campaign + its targeting set. Every network read/write
// degrades on 404 (no crash; the estimate simply hides).
import { useMemo, useState, useEffect, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Users, ShieldCheck } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { ScrollArea } from "@/components/ui/scroll-area";
import { createCampaign, createTargeting, estimateAudience } from "@/api/endpoints/ads";
import { getSymbols } from "@/api/endpoints/marketData";
import { getTokenMarket } from "@/api/endpoints/tokens";
import { searchCatalogItems } from "@/api/endpoints/cart";
import type { AudienceEstimate } from "@/api/types";
import {
  PROMOTE_ENTITY_KINDS,
  PROMOTE_ENTITY_LABELS,
  SEGMENT_OPTIONS,
  respectsOptInNote,
  buildTargetingPayload,
  buildPromotePayload,
  validatePromoteCampaign,
  summarizeTargeting,
  formatEstimatedReach,
  type PromoteEntityKind,
  type SelectedSegments,
} from "@/lib/promoteTargeting";

interface PickerOption {
  id: string;
  label: string;
  sub?: string;
}

interface PromoteCampaignDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  accountId: string;
  onCreated?: () => void;
}

export default function PromoteCampaignDialog({
  open,
  onOpenChange,
  accountId,
  onCreated,
}: PromoteCampaignDialogProps) {
  const [name, setName] = useState("");
  const [budgetDollars, setBudgetDollars] = useState("10");
  const [kind, setKind] = useState<PromoteEntityKind>("market");
  const [entityId, setEntityId] = useState<string | null>(null);
  const [entityLabel, setEntityLabel] = useState<string>("");
  const [search, setSearch] = useState("");
  const [segments, setSegments] = useState<SelectedSegments>({});
  const [estimate, setEstimate] = useState<AudienceEstimate | null>(null);
  const [submitErrors, setSubmitErrors] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);

  const resetAll = () => {
    setName("");
    setBudgetDollars("10");
    setKind("market");
    setEntityId(null);
    setEntityLabel("");
    setSearch("");
    setSegments({});
    setEstimate(null);
    setSubmitErrors([]);
    setServerError(null);
  };

  // Entity reads (reuse existing endpoints), degrade on 404 -> []
  const marketsQ = useQuery({
    queryKey: ["promote", "markets"],
    queryFn: getSymbols,
    enabled: open && kind === "market",
    retry: false,
    staleTime: 60_000,
  });
  const tokensQ = useQuery({
    queryKey: ["promote", "tokens"],
    queryFn: getTokenMarket,
    enabled: open && kind === "creator_token",
    retry: false,
    staleTime: 60_000,
  });
  const productsQ = useQuery({
    queryKey: ["promote", "products", search],
    queryFn: () => searchCatalogItems(search.trim() || "a"),
    enabled: open && kind === "product",
    retry: false,
    staleTime: 30_000,
  });

  const options: PickerOption[] = useMemo(() => {
    if (kind === "market") {
      return (marketsQ.data?.symbols ?? []).map((s) => ({
        id: String(s.symbol_id),
        label: s.symbol,
        sub: s.is_perpetual ? "perpetual" : "spot",
      }));
    }
    if (kind === "creator_token") {
      return (tokensQ.data?.tokens ?? []).map((t) => ({
        id: t.token_id,
        label: t.ticker + " - " + t.name,
        sub: t.status,
      }));
    }
    return (productsQ.data?.items ?? []).map((i) => ({
      id: i.item_id,
      label: i.name,
      sub: "$" + (i.price_cents / 100).toFixed(2),
    }));
  }, [kind, marketsQ.data, tokensQ.data, productsQ.data]);

  const filteredOptions = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q || kind === "product") return options; // product search is server-side
    return options.filter((o) => o.label.toLowerCase().includes(q));
  }, [options, search, kind]);

  const budgetCents = Math.round((parseFloat(budgetDollars) || 0) * 100);

  // Debounced audience estimate (degrade on 404 -> hide)
  const targetingBody = useMemo(
    () => buildTargetingPayload({ ...segments, name: name || "Promote" }),
    [segments, name],
  );

  const fetchEstimate = useCallback(async () => {
    try {
      const est = await estimateAudience("preview", targetingBody);
      setEstimate(est);
    } catch {
      setEstimate(null); // degrade-on-404: hide the estimate
    }
  }, [targetingBody]);

  useEffect(() => {
    if (!open) return;
    const t = setTimeout(fetchEstimate, 500);
    return () => clearTimeout(t);
  }, [open, fetchEstimate]);

  const toggle = (field: keyof SelectedSegments, value: string) => {
    setSegments((prev) => {
      const arr = (prev[field] as string[] | undefined) ?? [];
      const next = arr.includes(value)
        ? arr.filter((v) => v !== value)
        : [...arr, value];
      return { ...prev, [field]: next };
    });
  };
  const isOn = (field: keyof SelectedSegments, value: string) =>
    ((segments[field] as string[] | undefined) ?? []).includes(value);

  const handleSubmit = async () => {
    setServerError(null);
    const errs = validatePromoteCampaign({ name, budgetCents, kind, entityId });
    setSubmitErrors(errs);
    if (errs.length) return;

    setSubmitting(true);
    try {
      const promote = buildPromotePayload(kind, entityId!);
      const campaign = await createCampaign(accountId, {
        name: name.trim(),
        objective: "conversions",
        budget_cents: budgetCents,
        budget_type: "lifetime",
        promote_kind: promote.promote_kind,
        promote_entity_id: promote.promote_entity_id,
      });
      // Best-effort targeting set; degrade-on-404 (older backend) without
      // failing the whole flow - the campaign is already created.
      try {
        await createTargeting(campaign.campaign_id, {
          ...buildTargetingPayload({ ...segments, name: name || "Promote" }),
          ...(kind === "market" ? { market_ids: [promote.promote_entity_id] } : {}),
          ...(kind === "creator_token" ? { token_ids: [promote.promote_entity_id] } : {}),
          ...(kind === "product" ? { product_ids: [promote.promote_entity_id] } : {}),
        });
      } catch {
        /* targeting is optional; campaign already exists */
      }
      resetAll();
      onOpenChange(false);
      onCreated?.();
    } catch {
      setServerError(
        "Could not create the campaign. The promote-campaign API may be unavailable.",
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) resetAll();
        onOpenChange(o);
      }}
    >
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Promote an entity</DialogTitle>
          <DialogDescription>
            Create a campaign that promotes a market, creator token, or product.
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="max-h-[70vh] pr-3">
          <div className="space-y-6 py-1">
            {/* Basics */}
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <Label htmlFor="promo-name">Campaign name</Label>
                <Input
                  id="promo-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Promote BTC-PERP"
                  data-testid="promote-name"
                />
              </div>
              <div>
                <Label htmlFor="promo-budget">Lifetime budget ($)</Label>
                <Input
                  id="promo-budget"
                  type="number"
                  min={1}
                  step="0.01"
                  value={budgetDollars}
                  onChange={(e) => setBudgetDollars(e.target.value)}
                  data-testid="promote-budget"
                />
              </div>
            </div>

            {/* What to promote */}
            <div>
              <h3 className="mb-2 font-semibold">What do you want to promote?</h3>
              <div className="flex gap-2">
                {PROMOTE_ENTITY_KINDS.map((k) => (
                  <Button
                    key={k}
                    type="button"
                    size="sm"
                    variant={kind === k ? "default" : "outline"}
                    onClick={() => {
                      setKind(k);
                      setEntityId(null);
                      setEntityLabel("");
                      setSearch("");
                    }}
                    data-testid={"promote-kind-" + k}
                  >
                    {PROMOTE_ENTITY_LABELS[k]}
                  </Button>
                ))}
              </div>

              <div className="relative mt-3">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  className="pl-8"
                  placeholder={"Search " + PROMOTE_ENTITY_LABELS[kind].toLowerCase() + "s..."}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  data-testid="promote-search"
                />
              </div>

              <div className="mt-2 rounded border">
                <ScrollArea className="h-40">
                  <div className="divide-y">
                    {filteredOptions.length === 0 ? (
                      <p className="p-3 text-sm text-muted-foreground">
                        No items found.
                      </p>
                    ) : (
                      filteredOptions.map((o) => (
                        <button
                          key={o.id}
                          type="button"
                          onClick={() => {
                            setEntityId(o.id);
                            setEntityLabel(o.label);
                          }}
                          className={
                            "flex w-full items-center justify-between px-3 py-2 text-left text-sm hover:bg-accent " +
                            (entityId === o.id ? "bg-accent" : "")
                          }
                          data-testid={"promote-option-" + o.id}
                        >
                          <span className="font-medium">{o.label}</span>
                          {o.sub && (
                            <span className="text-xs text-muted-foreground">
                              {o.sub}
                            </span>
                          )}
                        </button>
                      ))
                    )}
                  </div>
                </ScrollArea>
              </div>
              {entityId && (
                <p className="mt-2 text-sm" data-testid="promote-selected">
                  Promoting:{" "}
                  <Badge variant="secondary">{entityLabel || entityId}</Badge>
                </p>
              )}
            </div>

            {/* Behavioral targeting */}
            <div>
              <h3 className="mb-1 font-semibold">Behavioral targeting</h3>
              <div
                className="mb-3 flex items-start gap-2 rounded-md bg-muted/50 p-2 text-xs text-muted-foreground"
                data-testid="opt-in-disclosure"
              >
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{respectsOptInNote}</span>
              </div>

              <div className="space-y-4">
                <div>
                  <Label>Age ranges</Label>
                  <div className="mt-1 flex flex-wrap gap-3">
                    {SEGMENT_OPTIONS.age_ranges.map((r) => (
                      <label key={r} className="flex items-center gap-1.5">
                        <Checkbox
                          checked={isOn("age_ranges", r)}
                          onCheckedChange={() => toggle("age_ranges", r)}
                          data-testid={"seg-age-" + r}
                        />
                        <span className="text-sm">{r}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div>
                  <Label>Gender</Label>
                  <div className="mt-1 flex flex-wrap gap-3">
                    {SEGMENT_OPTIONS.genders.map((g) => (
                      <label key={g} className="flex items-center gap-1.5">
                        <Checkbox
                          checked={isOn("genders", g)}
                          onCheckedChange={() => toggle("genders", g)}
                        />
                        <span className="text-sm capitalize">{g}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div>
                  <Label>Countries</Label>
                  <div className="mt-1 flex flex-wrap gap-2">
                    {SEGMENT_OPTIONS.countries.map((c) => (
                      <Button
                        key={c.code}
                        type="button"
                        size="sm"
                        variant={isOn("country_codes", c.code) ? "default" : "outline"}
                        onClick={() => toggle("country_codes", c.code)}
                        data-testid={"seg-country-" + c.code}
                      >
                        {c.code}
                      </Button>
                    ))}
                  </div>
                </div>

                <div>
                  <Label>Devices</Label>
                  <div className="mt-1 flex flex-wrap gap-3">
                    {SEGMENT_OPTIONS.device_types.map((d) => (
                      <label key={d} className="flex items-center gap-1.5">
                        <Checkbox
                          checked={isOn("device_types", d)}
                          onCheckedChange={() => toggle("device_types", d)}
                        />
                        <span className="text-sm capitalize">{d}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div>
                  <Label>Content categories</Label>
                  <div className="mt-1 flex flex-wrap gap-2">
                    {SEGMENT_OPTIONS.content_categories.map((c) => (
                      <Button
                        key={c}
                        type="button"
                        size="sm"
                        variant={isOn("content_categories", c) ? "default" : "outline"}
                        onClick={() => toggle("content_categories", c)}
                      >
                        {c}
                      </Button>
                    ))}
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <Switch
                    checked={segments.new_user_only ?? false}
                    onCheckedChange={(v) =>
                      setSegments((p) => ({ ...p, new_user_only: v }))
                    }
                    data-testid="seg-new-user-only"
                  />
                  <Label>New users only</Label>
                </div>
              </div>

              <p className="mt-3 text-sm text-muted-foreground">
                {summarizeTargeting(targetingBody)}
              </p>

              {estimate && (
                <div
                  className="mt-3 flex items-center gap-3 rounded-md border p-3"
                  data-testid="promote-estimate"
                >
                  <Users className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <div className="text-lg font-semibold">
                      {formatEstimatedReach(estimate.estimated_reach)}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Estimated reach
                    </div>
                  </div>
                </div>
              )}
            </div>

            {submitErrors.length > 0 && (
              <ul className="list-disc space-y-1 pl-5 text-sm text-destructive">
                {submitErrors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            )}
            {serverError && (
              <p className="text-sm text-destructive">{serverError}</p>
            )}
          </div>
        </ScrollArea>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            onClick={handleSubmit}
            disabled={submitting}
            data-testid="promote-submit"
          >
            {submitting ? "Creating..." : "Create campaign"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
