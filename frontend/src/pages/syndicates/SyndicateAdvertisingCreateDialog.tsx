import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogTrigger,
} from "@/components/ui/dialog";
import { createSyndicateCampaign } from "@/api/endpoints/syndicateAdvertising";

export default function SyndicateAdvertisingCreateDialog({
  syndicateId,
  treasuryCents,
}: {
  syndicateId: string;
  treasuryCents: number;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [budgetDollars, setBudgetDollars] = useState("");
  const [headline, setHeadline] = useState("");
  const [body, setBody] = useState("");
  const [ctaText, setCtaText] = useState("");
  const [ctaUrl, setCtaUrl] = useState("");
  const [error, setError] = useState("");
  const queryClient = useQueryClient();

  const budgetCents = Math.round(parseFloat(budgetDollars || "0") * 100);

  const reset = () => {
    setName("");
    setDescription("");
    setBudgetDollars("");
    setHeadline("");
    setBody("");
    setCtaText("");
    setCtaUrl("");
    setError("");
  };

  const mut = useMutation({
    mutationFn: () =>
      createSyndicateCampaign(syndicateId, {
        name,
        description,
        budget_cents: budgetCents,
        creative: {
          headline,
          body,
          cta_text: ctaText,
          cta_url: ctaUrl,
        },
        targeting: { audience: "all" },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicate-campaigns", syndicateId] });
      queryClient.invalidateQueries({ queryKey: ["syndicate-treasury", syndicateId] });
      setOpen(false);
      reset();
    },
    onError: (e: unknown) => {
      setError(e instanceof Error ? e.message : "Failed to create campaign");
    },
  });

  const overBudget = budgetCents > treasuryCents;
  const valid =
    name.length >= 2 &&
    budgetCents >= 100 &&
    !overBudget &&
    headline.length >= 1 &&
    body.length >= 1 &&
    ctaText.length >= 1 &&
    ctaUrl.length >= 1;

  return (
    <Dialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) reset(); }}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="h-4 w-4 mr-1" /> New Campaign
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Advertising Campaign</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 max-h-[60vh] overflow-y-auto">
          <div>
            <label className="text-sm font-medium">Campaign Name</label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Summer Promotion"
              maxLength={100}
            />
          </div>
          <div>
            <label className="text-sm font-medium">Description</label>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Promoting our syndicate to new subscribers"
              maxLength={500}
            />
          </div>
          <div>
            <label className="text-sm font-medium">Budget (USD)</label>
            <Input
              type="number"
              value={budgetDollars}
              onChange={(e) => setBudgetDollars(e.target.value)}
              placeholder="50.00"
              min={1}
              step={0.01}
            />
            <p className="text-xs text-muted-foreground mt-1">
              Treasury balance: ${(treasuryCents / 100).toFixed(2)}
            </p>
            {overBudget && (
              <p className="text-xs text-destructive mt-1">Budget exceeds treasury balance</p>
            )}
          </div>
          <div className="border-t pt-3">
            <p className="text-sm font-semibold mb-2">Ad Creative</p>
            <div className="space-y-2">
              <Input
                value={headline}
                onChange={(e) => setHeadline(e.target.value)}
                placeholder="Headline"
                maxLength={100}
              />
              <Textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder="Ad body text"
                maxLength={500}
              />
              <Input
                value={ctaText}
                onChange={(e) => setCtaText(e.target.value)}
                placeholder="CTA text (e.g. Subscribe Now)"
                maxLength={50}
              />
              <Input
                value={ctaUrl}
                onChange={(e) => setCtaUrl(e.target.value)}
                placeholder="CTA URL (e.g. /syndicates/...)"
                maxLength={200}
              />
            </div>
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={() => mut.mutate()} disabled={!valid || mut.isPending}>
            {mut.isPending ? "Creating..." : "Create Campaign"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
