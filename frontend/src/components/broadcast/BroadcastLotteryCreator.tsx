import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Plus, Trash2, Ticket } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createLottery } from "@/api/endpoints/broadcast-chat";
import type { BroadcastLotteryOutcomeIn } from "@/api/types";

interface BroadcastLotteryCreatorProps {
  sessionId: string;
  onCreated: (lotteryId: string) => void;
  onCancel: () => void;
}

function emptyOutcome(): BroadcastLotteryOutcomeIn & { _key: string } {
  return {
    _key: Math.random().toString(36).slice(2),
    display_label: "",
    weight_bps: 5000,
    payload_type: "text",
    text_content: "",
  };
}

export function BroadcastLotteryCreator({
  sessionId,
  onCreated,
  onCancel,
}: BroadcastLotteryCreatorProps) {
  const [title, setTitle] = useState("");
  const [outcomes, setOutcomes] = useState<
    (BroadcastLotteryOutcomeIn & { _key: string })[]
  >([emptyOutcome(), emptyOutcome()]);
  const [entryFeeCents, setEntryFeeCents] = useState(0);
  const [maxEntries, setMaxEntries] = useState<number | "">("");
  const [durationMinutes, setDurationMinutes] = useState<number | "">("");

  const totalWeight = outcomes.reduce((sum, o) => sum + (o.weight_bps || 0), 0);
  const weightOk = totalWeight === 10_000;

  const createMut = useMutation({
    mutationFn: () => {
      const outcomeDtos: BroadcastLotteryOutcomeIn[] = outcomes.map((o) => ({
        display_label: o.display_label || undefined,
        weight_bps: o.weight_bps,
        payload_type: o.payload_type,
        text_content: o.text_content || undefined,
        media_asset_id: o.media_asset_id || undefined,
      }));
      return createLottery(sessionId, {
        title,
        outcomes: outcomeDtos,
        entry_fee_cents: entryFeeCents,
        max_entries: maxEntries || null,
        duration_seconds: durationMinutes ? durationMinutes * 60 : null,
      });
    },
    onSuccess: (data) => {
      onCreated(data.lottery_id);
    },
  });

  const addOutcome = () => {
    if (outcomes.length >= 10) return;
    setOutcomes([...outcomes, emptyOutcome()]);
  };

  const removeOutcome = (idx: number) => {
    if (outcomes.length <= 2) return;
    setOutcomes(outcomes.filter((_, i) => i !== idx));
  };

  const updateOutcome = (
    idx: number,
    field: string,
    value: string | number,
  ) => {
    setOutcomes(
      outcomes.map((o, i) => (i === idx ? { ...o, [field]: value } : o)),
    );
  };

  return (
    <div
      className="border border-border rounded-lg p-3 space-y-3 bg-card"
      data-testid="lottery-creator"
    >
      <div className="flex items-center gap-2 text-sm font-semibold">
        <Ticket className="h-4 w-4" />
        Create Lottery
      </div>

      <div>
        <Label className="text-xs">Title</Label>
        <Input
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          maxLength={120}
          className="h-7 text-xs mt-1"
          placeholder="e.g. Friday Night Giveaway"
          data-testid="lottery-title-input"
        />
      </div>

      <div className="space-y-2">
        <Label className="text-xs">
          Outcomes ({outcomes.length}/10) &mdash; Weight total:{" "}
          <span className={weightOk ? "text-green-500" : "text-destructive"}>
            {(totalWeight / 100).toFixed(0)}%
          </span>
        </Label>
        {outcomes.map((o, idx) => (
          <div key={o._key} className="flex items-center gap-1">
            <Input
              value={o.display_label || ""}
              onChange={(e) =>
                updateOutcome(idx, "display_label", e.target.value)
              }
              placeholder="Label"
              className="h-7 text-xs flex-1"
              data-testid={`outcome-label-${idx}`}
            />
            <Input
              type="number"
              value={o.weight_bps / 100}
              onChange={(e) =>
                updateOutcome(
                  idx,
                  "weight_bps",
                  Math.round(parseFloat(e.target.value || "0") * 100),
                )
              }
              className="h-7 text-xs w-16"
              data-testid={`outcome-weight-${idx}`}
            />
            <span className="text-xs text-muted-foreground">%</span>
            <Input
              value={o.text_content || ""}
              onChange={(e) =>
                updateOutcome(idx, "text_content", e.target.value)
              }
              placeholder="Prize text"
              className="h-7 text-xs flex-1"
              data-testid={`outcome-content-${idx}`}
            />
            {outcomes.length > 2 && (
              <Button
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0"
                onClick={() => removeOutcome(idx)}
              >
                <Trash2 className="h-3 w-3 text-destructive" />
              </Button>
            )}
          </div>
        ))}
        {outcomes.length < 10 && (
          <Button
            variant="outline"
            size="sm"
            className="text-xs h-7"
            onClick={addOutcome}
            data-testid="add-outcome-btn"
          >
            <Plus className="h-3 w-3 mr-1" /> Add Outcome
          </Button>
        )}
      </div>

      <div className="grid grid-cols-3 gap-2">
        <div>
          <Label className="text-xs">Entry Fee ($)</Label>
          <Input
            type="number"
            value={entryFeeCents / 100}
            onChange={(e) =>
              setEntryFeeCents(
                Math.round(parseFloat(e.target.value || "0") * 100),
              )
            }
            min={0}
            className="h-7 text-xs mt-1"
            data-testid="lottery-fee-input"
          />
        </div>
        <div>
          <Label className="text-xs">Max Entries</Label>
          <Input
            type="number"
            value={maxEntries}
            onChange={(e) =>
              setMaxEntries(e.target.value ? parseInt(e.target.value) : "")
            }
            min={1}
            className="h-7 text-xs mt-1"
            placeholder="Unlimited"
            data-testid="lottery-max-entries-input"
          />
        </div>
        <div>
          <Label className="text-xs">Duration (min)</Label>
          <Input
            type="number"
            value={durationMinutes}
            onChange={(e) =>
              setDurationMinutes(
                e.target.value ? parseInt(e.target.value) : "",
              )
            }
            min={1}
            max={60}
            className="h-7 text-xs mt-1"
            placeholder="Manual"
            data-testid="lottery-duration-input"
          />
        </div>
      </div>

      <div className="flex gap-2 justify-end">
        <Button
          variant="outline"
          size="sm"
          className="text-xs h-7"
          onClick={onCancel}
        >
          Cancel
        </Button>
        <Button
          size="sm"
          className="text-xs h-7"
          disabled={
            !title.trim() ||
            !weightOk ||
            outcomes.some(
              (o) => o.payload_type === "text" && !o.text_content?.trim(),
            ) ||
            createMut.isPending
          }
          onClick={() => createMut.mutate()}
          data-testid="lottery-create-btn"
        >
          Create Lottery
        </Button>
      </div>
    </div>
  );
}
