import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Monitor, Columns2, PictureInPicture2, LayoutGrid } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { switchLayout, getLayout } from "@/api/endpoints/broadcast-inputs";
import type { BroadcastLayout } from "@/api/types";

const LAYOUT_MODES = [
  { mode: "single" as const, label: "Full", icon: Monitor },
  { mode: "side_by_side" as const, label: "Side", icon: Columns2 },
  { mode: "pip" as const, label: "PiP", icon: PictureInPicture2 },
  { mode: "grid" as const, label: "Grid", icon: LayoutGrid },
] as const;

interface LayoutSwitcherProps {
  sessionId: string;
  isBroadcaster: boolean;
}

export default function LayoutSwitcher({ sessionId, isBroadcaster }: LayoutSwitcherProps) {
  const queryClient = useQueryClient();

  const layoutQuery = useQuery({
    queryKey: ["broadcast", "layout", sessionId],
    queryFn: () => getLayout(sessionId),
    refetchInterval: 5000,
  });

  const currentLayout: BroadcastLayout | undefined = layoutQuery.data;

  const switchMut = useMutation({
    mutationFn: (mode: string) => switchLayout(sessionId, { mode }),
    onSuccess: (result) => {
      toast.success(`Layout: ${result.mode}`);
      queryClient.invalidateQueries({ queryKey: ["broadcast", "layout", sessionId] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to switch layout"),
  });

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium">Layout</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex gap-2">
          {LAYOUT_MODES.map(({ mode, label, icon: Icon }) => (
            <Button
              key={mode}
              variant={currentLayout?.mode === mode ? "default" : "outline"}
              size="sm"
              className="flex-1"
              onClick={() => switchMut.mutate(mode)}
              disabled={!isBroadcaster || switchMut.isPending}
              data-testid={`layout-${mode}`}
            >
              <Icon className="h-4 w-4 mr-1" />
              {label}
            </Button>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
