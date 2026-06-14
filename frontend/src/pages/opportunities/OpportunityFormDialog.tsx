import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  LEAD_SOURCE_CHOICES,
  stageLabel,
  type OpportunityCreateIn,
  type OpportunityOut,
  type StageConfigItemOut,
} from "@/api/endpoints/opportunities";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  stages: StageConfigItemOut[];
  /** When set, the dialog edits this opportunity (name/amount/probability/etc). */
  existing?: OpportunityOut | null;
  onSubmit: (body: OpportunityCreateIn) => void;
  saving?: boolean;
}

function toDateInput(ts?: number): string {
  const d = ts ? new Date(ts * 1000) : new Date(Date.now() + 14 * 86400 * 1000);
  return d.toISOString().slice(0, 10);
}

export function OpportunityFormDialog({
  open,
  onOpenChange,
  stages,
  existing,
  onSubmit,
  saving,
}: Props) {
  const [name, setName] = useState("");
  const [stage, setStage] = useState("");
  const [amount, setAmount] = useState("");
  const [closeDate, setCloseDate] = useState(toDateInput());
  const [probability, setProbability] = useState("0");
  const [leadSource, setLeadSource] = useState<string>("none");
  const [description, setDescription] = useState("");
  const [accountId, setAccountId] = useState("");
  const [contactId, setContactId] = useState("");
  const [error, setError] = useState<string | null>(null);

  const isEdit = !!existing;

  useEffect(() => {
    if (!open) return;
    if (existing) {
      setName(existing.name);
      setStage(existing.stage);
      setAmount((existing.amount_cents / 100).toString());
      setCloseDate(toDateInput(existing.close_date));
      setProbability(String(existing.probability));
      setLeadSource(existing.lead_source ?? "none");
      setDescription(existing.description ?? "");
      setAccountId(existing.account_party_id ?? "");
      setContactId(existing.contact_party_id ?? "");
    } else {
      setName("");
      setStage(stages[0]?.stage_key ?? "prospecting");
      setAmount("");
      setCloseDate(toDateInput());
      setProbability(String(stages[0]?.probability_default ?? 0));
      setLeadSource("none");
      setDescription("");
      setAccountId("");
      setContactId("");
    }
    setError(null);
  }, [open, existing, stages]);

  const handleStageChange = (next: string) => {
    setStage(next);
    if (!isEdit) {
      const cfg = stages.find((s) => s.stage_key === next);
      if (cfg) setProbability(String(cfg.probability_default));
    }
  };

  const handleSubmit = () => {
    setError(null);
    if (!name.trim()) {
      setError("Name is required");
      return;
    }
    const amountNum = Math.round(parseFloat(amount || "0") * 100);
    if (Number.isNaN(amountNum) || amountNum < 0) {
      setError("Amount must be a positive number");
      return;
    }
    const closeTs = Math.floor(new Date(closeDate + "T00:00:00Z").getTime() / 1000);
    if (Number.isNaN(closeTs)) {
      setError("Close date is invalid");
      return;
    }
    const prob = Math.max(0, Math.min(100, parseInt(probability || "0", 10) || 0));
    onSubmit({
      name: name.trim(),
      stage,
      amount_cents: amountNum,
      close_date: closeTs,
      probability: prob,
      lead_source: leadSource === "none" ? null : leadSource,
      description: description.trim() || null,
      account_party_id: accountId.trim() || null,
      contact_party_id: contactId.trim() || null,
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg" data-testid="opp-form-dialog">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit opportunity" : "New opportunity"}</DialogTitle>
          <DialogDescription>
            {isEdit
              ? "Update the deal details, stage, amount and probability."
              : "Create a new deal in the sales pipeline."}
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <div className="grid gap-1.5">
            <Label htmlFor="opp-name">Name</Label>
            <Input
              id="opp-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Acme Corp — Annual License"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-1.5">
              <Label htmlFor="opp-stage">Stage</Label>
              <Select value={stage} onValueChange={handleStageChange}>
                <SelectTrigger id="opp-stage">
                  <SelectValue placeholder="Select stage" />
                </SelectTrigger>
                <SelectContent>
                  {stages.map((s) => (
                    <SelectItem key={s.stage_key} value={s.stage_key}>
                      {s.label || stageLabel(s.stage_key)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="opp-prob">Probability (%)</Label>
              <Input
                id="opp-prob"
                type="number"
                min={0}
                max={100}
                value={probability}
                onChange={(e) => setProbability(e.target.value)}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-1.5">
              <Label htmlFor="opp-amount">Amount ($)</Label>
              <Input
                id="opp-amount"
                type="number"
                min={0}
                step="0.01"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="10000.00"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="opp-close">Close date</Label>
              <Input
                id="opp-close"
                type="date"
                value={closeDate}
                onChange={(e) => setCloseDate(e.target.value)}
              />
            </div>
          </div>

          <div className="grid gap-1.5">
            <Label htmlFor="opp-source">Lead source</Label>
            <Select value={leadSource} onValueChange={setLeadSource}>
              <SelectTrigger id="opp-source">
                <SelectValue placeholder="None" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">— None —</SelectItem>
                {LEAD_SOURCE_CHOICES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-1.5">
              <Label htmlFor="opp-account">Account ID</Label>
              <Input
                id="opp-account"
                value={accountId}
                onChange={(e) => setAccountId(e.target.value)}
                placeholder="optional"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="opp-contact">Contact ID</Label>
              <Input
                id="opp-contact"
                value={contactId}
                onChange={(e) => setContactId(e.target.value)}
                placeholder="optional"
              />
            </div>
          </div>

          <div className="grid gap-1.5">
            <Label htmlFor="opp-desc">Description</Label>
            <Textarea
              id="opp-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
            />
          </div>

          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={saving}>
            {saving ? "Saving…" : isEdit ? "Save changes" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
