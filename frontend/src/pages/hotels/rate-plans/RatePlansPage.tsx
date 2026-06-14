/**
 * RatePlansPage — Hotel rate-plan manager (QloApps, HTL-014..HTL-016).
 *
 * Admin page: create/edit multi-night rate plans, manage pricing rules
 * (season, weekend, occupancy, LOS, advance-purchase), and get a computed
 * nightly price quote for any stay.
 *
 * Feature-gated by HOTEL_PMS_ENABLED (default OFF): returns HTTP 404 when
 * the flag is off; handled as a "not enabled" state with no retry.
 *
 * Money is stored and rendered as integer cents. Display helpers format
 * cents to "$X.XX" for the UI.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Plus,
  Pencil,
  Trash2,
  RefreshCw,
  ConciergeBell,
  ChevronDown,
  ChevronRight,
  Calculator,
  ToggleLeft,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  listRatePlans,
  createRatePlan,
  updateRatePlan,
  deactivateRatePlan,
  listRules,
  addRule,
  deleteRule,
  quoteStay,
  type RatePlanOut,
  type RatePlanRuleOut,
  type StayQuoteOut,
  type NightLineOut,
} from "@/api/endpoints/hotelInventory";

// ─── Money helpers ─────────────────────────────────────────────────────────────

function formatCents(cents: number, currency = "USD"): string {
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency,
      minimumFractionDigits: 2,
    }).format(cents / 100);
  } catch {
    return `${(cents / 100).toFixed(2)} ${currency}`;
  }
}

// ─── Rule config description ───────────────────────────────────────────────────

function ruleDescription(rule: RatePlanRuleOut, currency: string): string {
  const rc = rule.rule_config as Record<string, unknown>;
  switch (rule.kind) {
    case "season":
      return `${rc["start_date"]} – ${rc["end_date"]}: ${rc["mode"] === "absolute" ? formatCents(Number(rc["value_cents"]), currency) + " flat" : (Number(rc["value_cents"]) >= 0 ? "+" : "") + formatCents(Number(rc["value_cents"]), currency) + " delta"}`;
    case "occupancy":
      return `+${formatCents(Number(rc["extra_adult_cents"]), currency)}/extra adult, +${formatCents(Number(rc["extra_child_cents"]), currency)}/child`;
    case "los":
      return `Min ${rc["min_nights"]}${rc["max_nights"] != null ? `–${rc["max_nights"]}` : "+"} nights: ${rc["discount_value"]}${rc["discount_type"] === "percentage" ? "%" : formatCents(Number(rc["discount_value"]), currency)} off`;
    case "advance":
      return `Booked ${rc["comparator"] === "gte" ? ">=" : "<="} ${rc["days_before_checkin"]} days ahead: ${rc["mode"] === "percentage" ? rc["value"] + "%" : formatCents(Number(rc["value"]), currency)} ${rc["comparator"] === "gte" ? "discount" : "surcharge"}`;
    case "weekend":
      return `DOW [${(rc["dow"] as number[]).join(",")}]: ${rc["mode"] === "absolute" ? formatCents(Number(rc["value_cents"]), currency) + " flat" : (Number(rc["value_cents"]) >= 0 ? "+" : "") + formatCents(Number(rc["value_cents"]), currency) + " delta"}`;
    default:
      return JSON.stringify(rc);
  }
}

// ─── Add Rule dialog ───────────────────────────────────────────────────────────

type RuleKind = "season" | "occupancy" | "los" | "advance" | "weekend";

interface AddRuleDialogProps {
  open: boolean;
  onClose: () => void;
  hotelId: string;
  roomTypeId: string;
  onSaved: () => void;
}

function AddRuleDialog({ open, onClose, hotelId, roomTypeId, onSaved }: AddRuleDialogProps) {
  const [kind, setKind] = useState<RuleKind>("season");
  const [priority, setPriority] = useState("500");

  // Season fields
  const [seasonStart, setSeasonStart] = useState("");
  const [seasonEnd, setSeasonEnd] = useState("");
  const [seasonMode, setSeasonMode] = useState<"absolute" | "delta">("delta");
  const [seasonValue, setSeasonValue] = useState("0");

  // Occupancy fields
  const [extraAdult, setExtraAdult] = useState("0");
  const [extraChild, setExtraChild] = useState("0");

  // LOS fields
  const [losMin, setLosMin] = useState("3");
  const [losMax, setLosMax] = useState("");
  const [losDiscountType, setLosDiscountType] = useState<"percentage" | "fixed_cents">("percentage");
  const [losDiscountValue, setLosDiscountValue] = useState("10");

  // Advance fields
  const [advDays, setAdvDays] = useState("14");
  const [advComparator, setAdvComparator] = useState<"gte" | "lte">("gte");
  const [advMode, setAdvMode] = useState<"percentage" | "fixed_cents">("percentage");
  const [advValue, setAdvValue] = useState("10");

  // Weekend fields
  const [wkndDow, setWkndDow] = useState("6,7");
  const [wkndMode, setWkndMode] = useState<"absolute" | "delta">("delta");
  const [wkndValue, setWkndValue] = useState("1500");

  const mut = useMutation({
    mutationFn: () => {
      let rule_config: Record<string, unknown> = {};
      if (kind === "season") {
        rule_config = {
          start_date: seasonStart,
          end_date: seasonEnd,
          mode: seasonMode,
          value_cents: Number(seasonValue),
        };
      } else if (kind === "occupancy") {
        rule_config = {
          extra_adult_cents: Number(extraAdult),
          extra_child_cents: Number(extraChild),
        };
      } else if (kind === "los") {
        rule_config = {
          min_nights: Number(losMin),
          max_nights: losMax.trim() ? Number(losMax) : null,
          discount_type: losDiscountType,
          discount_value: Number(losDiscountValue),
        };
      } else if (kind === "advance") {
        rule_config = {
          days_before_checkin: Number(advDays),
          comparator: advComparator,
          mode: advMode,
          value: Number(advValue),
        };
      } else if (kind === "weekend") {
        rule_config = {
          dow: wkndDow.split(",").map((d) => Number(d.trim())).filter(Boolean),
          mode: wkndMode,
          value_cents: Number(wkndValue),
        };
      }
      return addRule(hotelId, roomTypeId, {
        kind,
        rule_config,
        priority: Number(priority),
      });
    },
    onSuccess: () => {
      toast.success("Rule added");
      onSaved();
      onClose();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to add rule"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add Pricing Rule</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>Rule Kind</Label>
              <Select value={kind} onValueChange={(v) => setKind(v as RuleKind)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="season">Season</SelectItem>
                  <SelectItem value="weekend">Weekend</SelectItem>
                  <SelectItem value="occupancy">Occupancy</SelectItem>
                  <SelectItem value="los">Length of Stay</SelectItem>
                  <SelectItem value="advance">Advance Purchase</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="rule-priority">Priority (low wins)</Label>
              <Input
                id="rule-priority"
                type="number"
                min={0}
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
              />
            </div>
          </div>

          <Separator />

          {kind === "season" && (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label htmlFor="season-start">Start Date</Label>
                  <Input
                    id="season-start"
                    type="date"
                    value={seasonStart}
                    onChange={(e) => setSeasonStart(e.target.value)}
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="season-end">End Date</Label>
                  <Input
                    id="season-end"
                    type="date"
                    value={seasonEnd}
                    onChange={(e) => setSeasonEnd(e.target.value)}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label>Mode</Label>
                  <Select value={seasonMode} onValueChange={(v) => setSeasonMode(v as "absolute" | "delta")}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="absolute">Absolute (flat rate)</SelectItem>
                      <SelectItem value="delta">Delta (+/- adjustment)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="season-value">Value (cents)</Label>
                  <Input
                    id="season-value"
                    type="number"
                    value={seasonValue}
                    onChange={(e) => setSeasonValue(e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          {kind === "occupancy" && (
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label htmlFor="occ-adult">Extra adult surcharge (cents/night)</Label>
                <Input
                  id="occ-adult"
                  type="number"
                  min={0}
                  value={extraAdult}
                  onChange={(e) => setExtraAdult(e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="occ-child">Extra child surcharge (cents/night)</Label>
                <Input
                  id="occ-child"
                  type="number"
                  min={0}
                  value={extraChild}
                  onChange={(e) => setExtraChild(e.target.value)}
                />
              </div>
            </div>
          )}

          {kind === "los" && (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label htmlFor="los-min">Min nights</Label>
                  <Input
                    id="los-min"
                    type="number"
                    min={1}
                    value={losMin}
                    onChange={(e) => setLosMin(e.target.value)}
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="los-max">Max nights (blank = no max)</Label>
                  <Input
                    id="los-max"
                    type="number"
                    min={1}
                    value={losMax}
                    onChange={(e) => setLosMax(e.target.value)}
                    placeholder="None"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label>Discount type</Label>
                  <Select value={losDiscountType} onValueChange={(v) => setLosDiscountType(v as "percentage" | "fixed_cents")}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="percentage">Percentage</SelectItem>
                      <SelectItem value="fixed_cents">Fixed cents</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="los-dv">Discount value</Label>
                  <Input
                    id="los-dv"
                    type="number"
                    min={0}
                    value={losDiscountValue}
                    onChange={(e) => setLosDiscountValue(e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          {kind === "advance" && (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label htmlFor="adv-days">Days before check-in</Label>
                  <Input
                    id="adv-days"
                    type="number"
                    min={0}
                    value={advDays}
                    onChange={(e) => setAdvDays(e.target.value)}
                  />
                </div>
                <div className="space-y-1">
                  <Label>Comparator</Label>
                  <Select value={advComparator} onValueChange={(v) => setAdvComparator(v as "gte" | "lte")}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="gte">&gt;= (early bird discount)</SelectItem>
                      <SelectItem value="lte">&lt;= (last-minute surcharge)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label>Mode</Label>
                  <Select value={advMode} onValueChange={(v) => setAdvMode(v as "percentage" | "fixed_cents")}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="percentage">Percentage</SelectItem>
                      <SelectItem value="fixed_cents">Fixed cents</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="adv-value">Value</Label>
                  <Input
                    id="adv-value"
                    type="number"
                    min={0}
                    value={advValue}
                    onChange={(e) => setAdvValue(e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          {kind === "weekend" && (
            <div className="space-y-3">
              <div className="space-y-1">
                <Label htmlFor="wknd-dow">Day of week (comma-separated, Mon=1..Sun=7)</Label>
                <Input
                  id="wknd-dow"
                  placeholder="e.g. 6,7 for Sat/Sun"
                  value={wkndDow}
                  onChange={(e) => setWkndDow(e.target.value)}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label>Mode</Label>
                  <Select value={wkndMode} onValueChange={(v) => setWkndMode(v as "absolute" | "delta")}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="absolute">Absolute (flat rate)</SelectItem>
                      <SelectItem value="delta">Delta (+/- adjustment)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="wknd-value">Value (cents)</Label>
                  <Input
                    id="wknd-value"
                    type="number"
                    value={wkndValue}
                    onChange={(e) => setWkndValue(e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          <Button
            className="w-full"
            onClick={() => mut.mutate()}
            disabled={mut.isPending}
          >
            {mut.isPending ? "Adding..." : "Add Rule"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Stay Quote dialog ─────────────────────────────────────────────────────────

interface QuoteDialogProps {
  open: boolean;
  onClose: () => void;
  hotelId: string;
  roomTypeId: string;
  currency: string;
}

function QuoteDialog({ open, onClose, hotelId, roomTypeId }: QuoteDialogProps) {
  const [checkin, setCheckin] = useState("");
  const [checkout, setCheckout] = useState("");
  const [adults, setAdults] = useState("2");
  const [children, setChildren] = useState("0");
  const [rooms, setRooms] = useState("1");

  const [quote, setQuote] = useState<StayQuoteOut | null>(null);
  const [quoteError, setQuoteError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () =>
      quoteStay(hotelId, roomTypeId, {
        checkin,
        checkout,
        adults: Number(adults),
        children: Number(children),
        rooms: Number(rooms),
      }),
    onSuccess: (data) => {
      setQuote(data);
      setQuoteError(null);
    },
    onError: (err: unknown) => {
      setQuote(null);
      setQuoteError(err instanceof Error ? err.message : "Failed to compute quote");
    },
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Calculator className="h-5 w-5" />
            Stay Price Quote
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="q-checkin">Check-in</Label>
              <Input id="q-checkin" type="date" value={checkin} onChange={(e) => setCheckin(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="q-checkout">Check-out</Label>
              <Input id="q-checkout" type="date" value={checkout} onChange={(e) => setCheckout(e.target.value)} />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-1">
              <Label htmlFor="q-adults">Adults</Label>
              <Input id="q-adults" type="number" min={1} value={adults} onChange={(e) => setAdults(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="q-children">Children</Label>
              <Input id="q-children" type="number" min={0} value={children} onChange={(e) => setChildren(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="q-rooms">Rooms</Label>
              <Input id="q-rooms" type="number" min={1} value={rooms} onChange={(e) => setRooms(e.target.value)} />
            </div>
          </div>

          <Button
            className="w-full"
            onClick={() => mut.mutate()}
            disabled={mut.isPending || !checkin || !checkout}
          >
            <Calculator className="h-4 w-4 mr-2" />
            {mut.isPending ? "Computing..." : "Compute Quote"}
          </Button>

          {quoteError && (
            <p className="text-sm text-destructive">{quoteError}</p>
          )}

          {quote && (
            <div className="rounded-lg border p-4 space-y-3">
              <div className="flex justify-between items-center">
                <span className="font-semibold">
                  {quote.nights} night{quote.nights !== 1 ? "s" : ""} × {rooms} room{Number(rooms) !== 1 ? "s" : ""}
                </span>
                <span className="text-xl font-bold">
                  {formatCents(quote.total_cents, quote.currency)}
                </span>
              </div>

              <Separator />

              {/* Nightly breakdown */}
              <div className="space-y-1">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                  Nightly breakdown (1 room)
                </p>
                <div className="space-y-1 text-sm">
                  {quote.per_night.map((n: NightLineOut) => (
                    <div key={n.date} className="flex justify-between">
                      <span className="text-muted-foreground">{n.date}</span>
                      <span className="font-medium">
                        {formatCents(n.night_total_cents, quote.currency)}
                        {n.season_delta_cents !== 0 && (
                          <span className="ml-1 text-xs text-muted-foreground">
                            (season {n.season_delta_cents > 0 ? "+" : ""}{formatCents(n.season_delta_cents, quote.currency)})
                          </span>
                        )}
                        {n.weekend_delta_cents !== 0 && (
                          <span className="ml-1 text-xs text-muted-foreground">
                            (wknd {n.weekend_delta_cents > 0 ? "+" : ""}{formatCents(n.weekend_delta_cents, quote.currency)})
                          </span>
                        )}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <Separator />

              {/* Whole-stay modifiers */}
              <div className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Subtotal (1 room)</span>
                  <span>{formatCents(quote.stay_subtotal_cents, quote.currency)}</span>
                </div>
                {quote.los_discount_cents !== 0 && (
                  <div className="flex justify-between text-green-700 dark:text-green-400">
                    <span>LOS discount</span>
                    <span>-{formatCents(quote.los_discount_cents, quote.currency)}</span>
                  </div>
                )}
                {quote.advance_modifier_cents !== 0 && (
                  <div className={`flex justify-between ${quote.advance_modifier_cents < 0 ? "text-green-700 dark:text-green-400" : "text-orange-700 dark:text-orange-400"}`}>
                    <span>Advance modifier</span>
                    <span>
                      {quote.advance_modifier_cents < 0 ? "-" : "+"}
                      {formatCents(Math.abs(quote.advance_modifier_cents), quote.currency)}
                    </span>
                  </div>
                )}
                {Number(rooms) > 1 && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">× {rooms} rooms</span>
                    <span className="font-semibold">{formatCents(quote.total_cents, quote.currency)}</span>
                  </div>
                )}
              </div>

              {quote.applied_rule_ids.length > 0 && (
                <p className="text-xs text-muted-foreground">
                  Applied rule IDs: {quote.applied_rule_ids.join(", ")}
                </p>
              )}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Rate plan card ────────────────────────────────────────────────────────────

interface RatePlanCardProps {
  plan: RatePlanOut;
  hotelId: string;
  onRefresh: () => void;
}

function RatePlanCard({ plan, hotelId, onRefresh }: RatePlanCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [addRuleOpen, setAddRuleOpen] = useState(false);
  const [quoteOpen, setQuoteOpen] = useState(false);
  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState(plan.name);
  const [editRate, setEditRate] = useState(String(plan.base_nightly_rate_cents));
  const [editOccupancy, setEditOccupancy] = useState(String(plan.base_occupancy));

  const rulesQuery = useQuery({
    queryKey: ["hotel-rate-plan-rules", hotelId, plan.room_type_id],
    queryFn: () => listRules(hotelId, plan.room_type_id),
    enabled: expanded,
  });

  const deactivateMut = useMutation({
    mutationFn: () => deactivateRatePlan(hotelId, plan.room_type_id),
    onSuccess: () => {
      toast.success("Rate plan deactivated");
      onRefresh();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to deactivate"),
  });

  const updateMut = useMutation({
    mutationFn: () =>
      updateRatePlan(hotelId, plan.room_type_id, {
        name: editName.trim(),
        base_nightly_rate_cents: Number(editRate),
        base_occupancy: Number(editOccupancy),
      }),
    onSuccess: () => {
      toast.success("Rate plan updated");
      setEditing(false);
      onRefresh();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to update"),
  });

  const deleteRuleMut = useMutation({
    mutationFn: ({ ruleId, kind }: { ruleId: string; kind: string }) =>
      deleteRule(hotelId, plan.room_type_id, ruleId, kind),
    onSuccess: () => {
      toast.success("Rule removed");
      void rulesQuery.refetch();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to delete rule"),
  });

  const rules = rulesQuery.data ?? [];

  return (
    <Card className={plan.active ? "" : "opacity-60"}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            {editing ? (
              <div className="space-y-2">
                <Input
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  placeholder="Plan name"
                  className="h-7 text-sm font-semibold"
                />
                <div className="flex gap-2">
                  <div className="flex-1 space-y-1">
                    <Label className="text-xs">Base nightly rate (cents)</Label>
                    <Input
                      type="number"
                      min={0}
                      value={editRate}
                      onChange={(e) => setEditRate(e.target.value)}
                      className="h-7 text-sm"
                    />
                  </div>
                  <div className="flex-1 space-y-1">
                    <Label className="text-xs">Base occupancy</Label>
                    <Input
                      type="number"
                      min={1}
                      value={editOccupancy}
                      onChange={(e) => setEditOccupancy(e.target.value)}
                      className="h-7 text-sm"
                    />
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" onClick={() => updateMut.mutate()} disabled={updateMut.isPending}>
                    Save
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>
                    Cancel
                  </Button>
                </div>
              </div>
            ) : (
              <>
                <CardTitle className="text-base truncate">{plan.name}</CardTitle>
                <CardDescription className="text-xs mt-0.5">
                  Room type: <span className="font-mono">{plan.room_type_id}</span> •{" "}
                  Base: {formatCents(plan.base_nightly_rate_cents, plan.currency)}/night •{" "}
                  Occupancy: {plan.base_occupancy} adults
                </CardDescription>
              </>
            )}
          </div>
          <div className="flex items-center gap-1 shrink-0">
            <Badge variant={plan.active ? "default" : "secondary"} className="text-xs">
              {plan.active ? "Active" : "Inactive"}
            </Badge>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              title="Edit plan"
              onClick={() => setEditing((v) => !v)}
            >
              <Pencil className="h-3.5 w-3.5" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              title="Quote stay"
              onClick={() => setQuoteOpen(true)}
            >
              <Calculator className="h-3.5 w-3.5" />
            </Button>
            {plan.active && (
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7 text-destructive"
                title="Deactivate plan"
                onClick={() => {
                  if (confirm("Deactivate this rate plan?")) deactivateMut.mutate();
                }}
                disabled={deactivateMut.isPending}
              >
                <ToggleLeft className="h-3.5 w-3.5" />
              </Button>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={() => setExpanded((v) => !v)}
            >
              {expanded ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
            </Button>
          </div>
        </div>
      </CardHeader>

      {expanded && (
        <CardContent className="pt-0">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium">Pricing Rules</p>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setAddRuleOpen(true)}
              >
                <Plus className="h-3.5 w-3.5 mr-1" />
                Add Rule
              </Button>
            </div>

            {rulesQuery.isPending ? (
              <div className="space-y-1">
                <Skeleton className="h-8 w-full" />
                <Skeleton className="h-8 w-full" />
              </div>
            ) : rules.length === 0 ? (
              <p className="text-sm text-muted-foreground py-2">
                No pricing rules configured. The base nightly rate applies uniformly.
              </p>
            ) : (
              <div className="space-y-1">
                {rules.map((rule) => (
                  <div
                    key={rule.rule_id}
                    className="flex items-center justify-between rounded-md border px-3 py-2 text-sm"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[10px] shrink-0">
                          {rule.kind}
                        </Badge>
                        <span className="text-xs text-muted-foreground truncate">
                          {ruleDescription(rule, plan.currency)}
                        </span>
                      </div>
                      <p className="text-[10px] text-muted-foreground mt-0.5">
                        Priority: {rule.priority} • ID: {rule.rule_id.slice(0, 8)}…
                      </p>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-6 w-6 shrink-0 text-destructive"
                      onClick={() => {
                        if (confirm("Delete this rule?")) {
                          deleteRuleMut.mutate({ ruleId: rule.rule_id, kind: rule.kind });
                        }
                      }}
                      disabled={deleteRuleMut.isPending}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </CardContent>
      )}

      {addRuleOpen && (
        <AddRuleDialog
          open={addRuleOpen}
          onClose={() => setAddRuleOpen(false)}
          hotelId={hotelId}
          roomTypeId={plan.room_type_id}
          onSaved={() => void rulesQuery.refetch()}
        />
      )}

      {quoteOpen && (
        <QuoteDialog
          open={quoteOpen}
          onClose={() => setQuoteOpen(false)}
          hotelId={hotelId}
          roomTypeId={plan.room_type_id}
          currency={plan.currency}
        />
      )}
    </Card>
  );
}

// ─── Create plan dialog ────────────────────────────────────────────────────────

interface CreatePlanDialogProps {
  open: boolean;
  onClose: () => void;
  hotelId: string;
  onCreated: () => void;
}

function CreatePlanDialog({ open, onClose, hotelId, onCreated }: CreatePlanDialogProps) {
  const [roomTypeId, setRoomTypeId] = useState("");
  const [name, setName] = useState("");
  const [baseRate, setBaseRate] = useState("");
  const [baseOccupancy, setBaseOccupancy] = useState("2");
  const [currency, setCurrency] = useState("USD");

  const mut = useMutation({
    mutationFn: () =>
      createRatePlan(hotelId, {
        room_type_id: roomTypeId.trim(),
        name: name.trim(),
        base_nightly_rate_cents: baseRate.trim() ? Number(baseRate) : undefined,
        base_occupancy: Number(baseOccupancy),
        currency: currency.trim().toUpperCase(),
      }),
    onSuccess: () => {
      toast.success("Rate plan created");
      setRoomTypeId("");
      setName("");
      setBaseRate("");
      setBaseOccupancy("2");
      setCurrency("USD");
      onCreated();
      onClose();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Failed to create rate plan"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Create Rate Plan</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1">
            <Label htmlFor="cp-rt">Room Type ID</Label>
            <Input
              id="cp-rt"
              placeholder="e.g. rt_standard"
              value={roomTypeId}
              onChange={(e) => setRoomTypeId(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="cp-name">Plan Name</Label>
            <Input
              id="cp-name"
              placeholder="e.g. Standard Summer Rate"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2 space-y-1">
              <Label htmlFor="cp-rate">Base nightly rate (cents)</Label>
              <Input
                id="cp-rate"
                type="number"
                min={0}
                placeholder="e.g. 15000 = $150.00"
                value={baseRate}
                onChange={(e) => setBaseRate(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="cp-occ">Base occupancy</Label>
              <Input
                id="cp-occ"
                type="number"
                min={1}
                value={baseOccupancy}
                onChange={(e) => setBaseOccupancy(e.target.value)}
              />
            </div>
          </div>
          <div className="space-y-1">
            <Label htmlFor="cp-currency">Currency (3-char ISO)</Label>
            <Input
              id="cp-currency"
              maxLength={3}
              value={currency}
              onChange={(e) => setCurrency(e.target.value.toUpperCase())}
              className="w-24"
            />
          </div>

          <Button
            className="w-full"
            onClick={() => mut.mutate()}
            disabled={mut.isPending || !roomTypeId.trim() || !name.trim()}
          >
            {mut.isPending ? "Creating..." : "Create Rate Plan"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export default function RatePlansPage() {
  const qc = useQueryClient();

  const [hotelId, setHotelId] = useState("hotel_1");
  const [pendingHotelId, setPendingHotelId] = useState("hotel_1");
  const [createOpen, setCreateOpen] = useState(false);
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const plansQuery = useQuery({
    queryKey: ["hotel-rate-plans", hotelId, cursor],
    queryFn: () => listRatePlans(hotelId, { cursor, limit: 20 }),
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 403)) return false;
      return count < 2;
    },
  });

  const plans = plansQuery.data?.rate_plans ?? [];
  const nextCursor = plansQuery.data?.cursor ?? null;

  function refresh() {
    void qc.invalidateQueries({ queryKey: ["hotel-rate-plans", hotelId] });
  }

  // Feature not enabled
  if (plansQuery.isError && plansQuery.error instanceof ApiError && plansQuery.error.status === 404) {
    return (
      <div className="space-y-6 p-4 md:p-6 lg:p-8">
        <PageHeader
          title="Rate Plans"
          description="Multi-night pricing plans for hotel room types."
        />
        <Card>
          <CardContent className="flex flex-col items-center gap-4 py-16 text-center">
            <ConciergeBell className="h-12 w-12 text-muted-foreground" />
            <p className="text-lg font-medium">Hotel PMS not enabled</p>
            <p className="text-sm text-muted-foreground max-w-sm">
              The Hotel PMS feature is currently disabled. Enable it via the
              HOTEL_PMS_ENABLED environment variable to manage rate plans.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="Rate Plans"
        description="Create and manage multi-night pricing plans with seasonal, weekend, occupancy, and advance-purchase rules."
        actions={
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={refresh}
              disabled={plansQuery.isFetching}
            >
              <RefreshCw className={`h-4 w-4 mr-1 ${plansQuery.isFetching ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4 mr-1" />
              New Plan
            </Button>
          </div>
        }
      />

      {/* Hotel selector */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Hotel</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <Input
              placeholder="Hotel ID (e.g. hotel_1)"
              value={pendingHotelId}
              onChange={(e) => setPendingHotelId(e.target.value)}
              className="max-w-xs"
            />
            <Button
              onClick={() => {
                setHotelId(pendingHotelId.trim());
                setCursor(undefined);
                void qc.invalidateQueries({ queryKey: ["hotel-rate-plans"] });
              }}
              disabled={!pendingHotelId.trim()}
            >
              Load
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Plans list */}
      {plansQuery.isPending ? (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-24 w-full rounded-xl" />
          ))}
        </div>
      ) : plansQuery.isError ? (
        <Card>
          <CardContent className="py-10 text-center">
            <p className="text-muted-foreground">
              Failed to load rate plans: {(plansQuery.error as Error).message}
            </p>
            <Button variant="outline" size="sm" className="mt-3" onClick={refresh}>
              Retry
            </Button>
          </CardContent>
        </Card>
      ) : plans.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-4 py-16 text-center">
            <ConciergeBell className="h-10 w-10 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              No rate plans for hotel <strong>{hotelId}</strong>.
            </p>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4 mr-1" />
              Create first plan
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {plans.map((plan) => (
            <RatePlanCard
              key={plan.rate_plan_id}
              plan={plan}
              hotelId={hotelId}
              onRefresh={refresh}
            />
          ))}

          {nextCursor && (
            <Button
              variant="outline"
              className="w-full"
              onClick={() => setCursor(nextCursor)}
              disabled={plansQuery.isFetching}
            >
              Load more
            </Button>
          )}

          <p className="text-xs text-muted-foreground text-right">
            Showing {plans.length} plan{plans.length !== 1 ? "s" : ""} for hotel{" "}
            <span className="font-mono">{hotelId}</span>
          </p>
        </div>
      )}

      {createOpen && (
        <CreatePlanDialog
          open={createOpen}
          onClose={() => setCreateOpen(false)}
          hotelId={hotelId}
          onCreated={refresh}
        />
      )}
    </div>
  );
}
