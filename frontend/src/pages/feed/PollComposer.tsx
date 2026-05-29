import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus, X, Clock } from "lucide-react";

export interface PollDataInput {
  questions: Array<{
    text: string;
    choice_mode: "single" | "multi";
    options: Array<{ text: string }>;
    max_selections?: number;
  }>;
  closes_at?: number;
  anonymous: boolean;
  allow_vote_change: boolean;
}

interface PollComposerProps {
  onPollDataChange: (data: PollDataInput | null) => void;
}

export function PollComposer({ onPollDataChange }: PollComposerProps) {
  const [question, setQuestion] = useState("");
  const [options, setOptions] = useState(["", ""]);
  const [choiceMode, setChoiceMode] = useState<"single" | "multi">("single");
  const [anonymous, setAnonymous] = useState(true);
  const [allowChange, setAllowChange] = useState(true);
  const [closesInHours, setClosesInHours] = useState<string>("");

  useEffect(() => {
    const filledOptions = options.filter((o) => o.trim());
    if (!question.trim() || filledOptions.length < 2) {
      onPollDataChange(null);
      return;
    }
    const closesAt = closesInHours
      ? Math.floor(Date.now() / 1000) + Number(closesInHours) * 3600
      : undefined;
    onPollDataChange({
      questions: [
        {
          text: question.trim(),
          choice_mode: choiceMode,
          options: filledOptions.map((o) => ({ text: o.trim() })),
          max_selections: choiceMode === "multi" ? undefined : 1,
        },
      ],
      closes_at: closesAt,
      anonymous,
      allow_vote_change: allowChange,
    });
  }, [question, options, choiceMode, anonymous, allowChange, closesInHours]);

  const addOption = () => {
    if (options.length < 6) setOptions([...options, ""]);
  };

  const removeOption = (index: number) => {
    if (options.length > 2) setOptions(options.filter((_, i) => i !== index));
  };

  const updateOption = (index: number, text: string) => {
    const updated = [...options];
    updated[index] = text;
    setOptions(updated);
  };

  return (
    <div className="space-y-4 p-4 border rounded-lg" data-testid="poll-composer">
      <div>
        <Label>Question</Label>
        <Input
          placeholder="Ask your audience something..."
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          maxLength={500}
          data-testid="poll-question-input"
        />
      </div>

      <div className="space-y-2">
        <Label>Options</Label>
        {options.map((opt, i) => (
          <div key={i} className="flex gap-2">
            <Input
              placeholder={`Option ${i + 1}`}
              value={opt}
              onChange={(e) => updateOption(i, e.target.value)}
              maxLength={200}
              data-testid={`poll-option-${i}`}
            />
            {options.length > 2 && (
              <Button
                variant="ghost"
                size="icon"
                onClick={() => removeOption(i)}
                data-testid={`poll-remove-option-${i}`}
              >
                <X className="h-4 w-4" />
              </Button>
            )}
          </div>
        ))}
        {options.length < 6 && (
          <Button
            variant="outline"
            size="sm"
            onClick={addOption}
            data-testid="poll-add-option"
          >
            <Plus className="h-4 w-4 mr-1" /> Add Option
          </Button>
        )}
      </div>

      <div className="flex flex-wrap gap-4">
        <div className="flex items-center gap-2">
          <Label>Mode:</Label>
          <Select
            value={choiceMode}
            onValueChange={(v) => setChoiceMode(v as "single" | "multi")}
          >
            <SelectTrigger className="w-32" data-testid="poll-choice-mode">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="single">Single choice</SelectItem>
              <SelectItem value="multi">Multi choice</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-2">
          <Switch checked={anonymous} onCheckedChange={setAnonymous} />
          <Label>Anonymous voting</Label>
        </div>
        <div className="flex items-center gap-2">
          <Switch checked={allowChange} onCheckedChange={setAllowChange} />
          <Label>Allow vote change</Label>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <Clock className="h-4 w-4 text-muted-foreground" />
        <Select
          value={closesInHours}
          onValueChange={(v) => setClosesInHours(v)}
        >
          <SelectTrigger className="w-40" data-testid="poll-closes-in">
            <SelectValue placeholder="No time limit" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="">No time limit</SelectItem>
            <SelectItem value="1">1 hour</SelectItem>
            <SelectItem value="6">6 hours</SelectItem>
            <SelectItem value="24">24 hours</SelectItem>
            <SelectItem value="72">3 days</SelectItem>
            <SelectItem value="168">1 week</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}
