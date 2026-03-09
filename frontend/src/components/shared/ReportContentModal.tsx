import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";

export const MODERATION_TOPICS = ["sexual", "extortion", "criminal", "spam", "racist"] as const;

export type ModerationTopic = (typeof MODERATION_TOPICS)[number];

export interface ReportContentPayload {
  topics: ModerationTopic[];
  reason_text: string;
}

interface ReportContentModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title?: string;
  description?: string;
  submitLabel?: string;
  cancelLabel?: string;
  isSubmitting?: boolean;
  serverError?: string | null;
  onSubmit: (payload: ReportContentPayload) => Promise<void> | void;
}

const TOPIC_LABELS: Record<ModerationTopic, string> = {
  sexual: "Sexual",
  extortion: "Extortion",
  criminal: "Criminal",
  spam: "Spam",
  racist: "Racist",
};

export function ReportContentModal({
  open,
  onOpenChange,
  title = "Report content",
  description = "Select at least one topic and explain why this content should be reviewed.",
  submitLabel = "Submit report",
  cancelLabel = "Cancel",
  isSubmitting,
  serverError,
  onSubmit,
}: ReportContentModalProps) {
  const [selectedTopics, setSelectedTopics] = useState<ModerationTopic[]>([]);
  const [reasonText, setReasonText] = useState("");
  const [clientError, setClientError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setSelectedTopics([]);
      setReasonText("");
      setClientError(null);
    }
  }, [open]);

  const trimmedReasonText = useMemo(() => reasonText.trim(), [reasonText]);

  const toggleTopic = (topic: ModerationTopic, checked: boolean) => {
    setClientError(null);
    setSelectedTopics((prev) => {
      if (checked) {
        if (prev.includes(topic)) return prev;
        return [...prev, topic];
      }
      return prev.filter((item) => item !== topic);
    });
  };

  const handleSubmit = async () => {
    if (!selectedTopics.length) {
      setClientError("Select at least one topic.");
      return;
    }

    if (trimmedReasonText.length < 5) {
      setClientError("Reason must be at least 5 characters.");
      return;
    }

    setClientError(null);
    try {
      await onSubmit({ topics: selectedTopics, reason_text: trimmedReasonText });
    } catch {
      // server-side error is surfaced by parent via `serverError`
    }
  };

  return (
    <Dialog open={open} onOpenChange={(next) => !isSubmitting && onOpenChange(next)}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">Topics</legend>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2" role="group" aria-label="Report topics">
              {MODERATION_TOPICS.map((topic) => {
                const checked = selectedTopics.includes(topic);
                return (
                  <label
                    key={topic}
                    htmlFor={`report-topic-${topic}`}
                    className={cn(
                      "flex cursor-pointer items-center gap-2 rounded-md border p-2 text-sm transition-colors",
                      checked ? "border-primary bg-primary/5" : "border-border",
                    )}
                  >
                    <Checkbox
                      id={`report-topic-${topic}`}
                      checked={checked}
                      onCheckedChange={(value) => toggleTopic(topic, value === true)}
                    />
                    {TOPIC_LABELS[topic]}
                  </label>
                );
              })}
            </div>
          </fieldset>

          <div className="space-y-1.5">
            <label htmlFor="report-reason-text" className="text-sm font-medium">Reason</label>
            <Textarea
              id="report-reason-text"
              value={reasonText}
              onChange={(event) => {
                setReasonText(event.target.value);
                setClientError(null);
              }}
              placeholder="Describe why this should be reviewed."
              rows={4}
              minLength={5}
              maxLength={2000}
              aria-describedby="report-reason-help"
            />
            <p id="report-reason-help" className="text-xs text-muted-foreground">
              Required (5–2000 characters).
            </p>
          </div>

          {(clientError || serverError) && (
            <p role="alert" className="text-sm text-red-600">{clientError ?? serverError}</p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
            {cancelLabel}
          </Button>
          <Button onClick={() => void handleSubmit()} disabled={isSubmitting}>
            {submitLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
