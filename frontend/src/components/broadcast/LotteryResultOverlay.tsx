import { useEffect } from "react";
import { Trophy, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { BroadcastLotteryResultEntry } from "@/api/types";

interface LotteryResultOverlayProps {
  result: BroadcastLotteryResultEntry;
  onDismiss: () => void;
}

export function LotteryResultOverlay({
  result,
  onDismiss,
}: LotteryResultOverlayProps) {
  // Auto-dismiss after 8 seconds
  useEffect(() => {
    const timer = setTimeout(onDismiss, 8000);
    return () => clearTimeout(timer);
  }, [onDismiss]);

  // Escape key dismisses
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onDismiss();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onDismiss]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 animate-in fade-in duration-300"
      role="dialog"
      aria-modal="true"
      onClick={onDismiss}
      data-testid="lottery-result-overlay"
    >
      <div
        className="relative bg-card border border-primary/40 rounded-lg p-6 max-w-sm w-full mx-4 text-center animate-in slide-in-from-bottom duration-500"
        onClick={(e) => e.stopPropagation()}
      >
        <Button
          variant="ghost"
          size="sm"
          className="absolute top-2 right-2 h-6 w-6 p-0"
          onClick={onDismiss}
          data-testid="lottery-result-dismiss"
        >
          <X className="h-4 w-4" />
        </Button>

        <Trophy className="h-10 w-10 mx-auto text-primary mb-3" />

        <h3 className="text-lg font-bold mb-1">Your Result</h3>

        <div className="text-xl font-semibold text-primary mb-2">
          {result.display_label ?? "Prize"}
        </div>

        {result.text_content && (
          <p className="text-sm text-muted-foreground">{result.text_content}</p>
        )}
      </div>
    </div>
  );
}
