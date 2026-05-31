import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getLiveQaMode, setLiveQaMode } from "@/api/endpoints/liveQa";
import { Switch } from "@/components/ui/switch";
import { MessageCircleQuestion } from "lucide-react";
import { toast } from "sonner";

interface LiveQaModeToggleProps {
  sessionId: string;
}

export function LiveQaModeToggle({ sessionId }: LiveQaModeToggleProps) {
  const queryClient = useQueryClient();

  const modeQuery = useQuery({
    queryKey: ["live-qa-mode", sessionId],
    queryFn: () => getLiveQaMode(sessionId),
  });

  const toggleMut = useMutation({
    mutationFn: (enabled: boolean) => setLiveQaMode(sessionId, enabled),
    onSuccess: (res) => {
      queryClient.setQueryData(["live-qa-mode", sessionId], res);
      toast.success(res.qa_mode_enabled ? "Live Q&A enabled" : "Live Q&A disabled");
    },
    onError: () => toast.error("Failed to toggle Q&A mode."),
  });

  const enabled = modeQuery.data?.qa_mode_enabled ?? false;

  return (
    <div className="flex items-center justify-between rounded-md border px-3 py-2">
      <div className="flex items-center gap-2">
        <MessageCircleQuestion className="h-4 w-4 text-primary" />
        <span className="text-sm font-medium">Live Q&amp;A Mode</span>
      </div>
      <Switch
        checked={enabled}
        disabled={toggleMut.isPending || modeQuery.isLoading}
        onCheckedChange={(v) => toggleMut.mutate(v)}
        aria-label="Toggle Live Q&A mode"
      />
    </div>
  );
}
