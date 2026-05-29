import { useMutation } from "@tanstack/react-query";
import { toggleQAMode } from "@/api/endpoints/broadcastQA";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";

interface QAModeToggleProps {
  sessionId: string;
  enabled: boolean;
  onToggle: (enabled: boolean) => void;
}

export function QAModeToggle({ sessionId, enabled, onToggle }: QAModeToggleProps) {
  const toggleMut = useMutation({
    mutationFn: (newEnabled: boolean) => toggleQAMode(sessionId, newEnabled),
    onSuccess: (_data, newEnabled) => {
      onToggle(newEnabled);
      toast.success(newEnabled ? "Q&A mode enabled" : "Q&A mode disabled");
    },
    onError: () => {
      toast.error("Failed to toggle Q&A mode");
    },
  });

  return (
    <div className="flex items-center gap-2">
      <Switch
        id="qa-mode-toggle"
        checked={enabled}
        onCheckedChange={(checked) => toggleMut.mutate(checked)}
        disabled={toggleMut.isPending}
      />
      <Label htmlFor="qa-mode-toggle" className="text-sm">
        Q&A Mode
      </Label>
    </div>
  );
}
