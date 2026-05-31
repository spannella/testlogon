import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { submitLiveQaQuestion } from "@/api/endpoints/liveQa";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import { Send } from "lucide-react";

interface LiveQaQuestionInputProps {
  sessionId: string;
  onSubmitted?: () => void;
}

export function LiveQaQuestionInput({ sessionId, onSubmitted }: LiveQaQuestionInputProps) {
  const [text, setText] = useState("");
  const queryClient = useQueryClient();

  const submitMut = useMutation({
    mutationFn: (questionText: string) => submitLiveQaQuestion(sessionId, questionText),
    onSuccess: () => {
      toast.success("Question submitted! The host will review it.");
      setText("");
      queryClient.invalidateQueries({ queryKey: ["live-qa-questions", sessionId] });
      onSubmitted?.();
    },
    onError: (err: unknown) => {
      const code = (err as { detail?: { code?: string } })?.detail?.code;
      if (code === "LIVE_QA_RATE_LIMITED") {
        toast.error("Please wait before submitting another question.");
      } else if (code === "BROADCAST_CHAT_MUTED") {
        toast.error("You are currently muted.");
      } else if (code === "LIVE_QA_DISABLED") {
        toast.error("Q&A is not active right now.");
      } else {
        toast.error("Failed to submit question.");
      }
    },
  });

  return (
    <div className="space-y-2" data-testid="live-qa-input">
      <Textarea
        placeholder="Ask a question…"
        value={text}
        onChange={(e) => setText(e.target.value)}
        maxLength={500}
        rows={3}
      />
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">{text.length}/500</span>
        <Button
          onClick={() => submitMut.mutate(text)}
          disabled={!text.trim() || submitMut.isPending}
          size="sm"
        >
          <Send className="mr-1 h-4 w-4" />
          {submitMut.isPending ? "Submitting…" : "Submit"}
        </Button>
      </div>
    </div>
  );
}
