import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { submitQuestion } from "@/api/endpoints/broadcastQA";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { Send } from "lucide-react";

interface QAQuestionInputProps {
  sessionId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function QAQuestionInput({
  sessionId,
  open,
  onOpenChange,
}: QAQuestionInputProps) {
  const [text, setText] = useState("");

  const submitMut = useMutation({
    mutationFn: (questionText: string) =>
      submitQuestion(sessionId, questionText),
    onSuccess: () => {
      toast.success("Question submitted! The broadcaster will review it.");
      setText("");
      onOpenChange(false);
    },
    onError: (err: any) => {
      const code = err?.response?.data?.detail?.code;
      if (code === "QA_RATE_LIMITED") {
        toast.error("Please wait before submitting another question.");
      } else if (code === "BROADCAST_CHAT_MUTED") {
        toast.error("You are currently muted.");
      } else {
        toast.error("Failed to submit question.");
      }
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Ask a Question</DialogTitle>
        </DialogHeader>
        <Textarea
          placeholder="Type your question..."
          value={text}
          onChange={(e) => setText(e.target.value)}
          maxLength={500}
          rows={3}
        />
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">
            {text.length}/500
          </span>
          <Button
            onClick={() => submitMut.mutate(text)}
            disabled={!text.trim() || submitMut.isPending}
          >
            <Send className="h-4 w-4 mr-1" />
            {submitMut.isPending ? "Submitting..." : "Submit"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
