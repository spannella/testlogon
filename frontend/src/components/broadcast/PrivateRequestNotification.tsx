import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { UserCheck, UserX, Lock, DollarSign } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  listPrivateRequests,
  acceptPrivateRequest,
  declinePrivateRequest,
  type PrivateRequest,
} from "@/api/endpoints/broadcastPrivate";

interface PrivateRequestNotificationProps {
  sessionId: string;
  sessionStatus: string;
}

export function PrivateRequestNotification({
  sessionId,
  sessionStatus,
}: PrivateRequestNotificationProps) {
  const queryClient = useQueryClient();
  const [behavior, setBehavior] = useState<"pause" | "end" | "continue">(
    "pause",
  );

  const requestsQuery = useQuery({
    queryKey: ["broadcast", "private-requests", sessionId],
    queryFn: () => listPrivateRequests(sessionId),
    refetchInterval: 5000,
    enabled: sessionStatus === "live",
  });

  const requests: PrivateRequest[] = requestsQuery.data?.requests ?? [];

  const acceptMut = useMutation({
    mutationFn: (requestId: string) =>
      acceptPrivateRequest(sessionId, requestId, { behavior }),
    onSuccess: () => {
      toast.success("Private session accepted");
      queryClient.invalidateQueries({
        queryKey: ["broadcast", "private-requests", sessionId],
      });
    },
    onError: () => toast.error("Failed to accept request"),
  });

  const declineMut = useMutation({
    mutationFn: (requestId: string) =>
      declinePrivateRequest(sessionId, requestId),
    onSuccess: () => {
      toast.info("Request declined");
      queryClient.invalidateQueries({
        queryKey: ["broadcast", "private-requests", sessionId],
      });
    },
    onError: () => toast.error("Failed to decline request"),
  });

  if (requests.length === 0) return null;

  return (
    <Card className="border-yellow-500/50 bg-yellow-50 dark:bg-yellow-900/10">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-base">
          <Lock className="h-4 w-4" />
          Private Session Requests ({requests.length})
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {requests.map((req) => (
          <div
            key={req.request_id}
            className="rounded-lg border bg-background p-3 space-y-2"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">
                  {req.viewer_display_name || req.viewer_id}
                </p>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <DollarSign className="h-3 w-3" />
                  ${(req.rate_per_minute_cents / 100).toFixed(2)}/min
                  <Badge variant="outline" className="text-xs">
                    max {req.max_duration_minutes}m
                  </Badge>
                </div>
              </div>
              <Badge>Pending</Badge>
            </div>

            <div className="flex items-center gap-2">
              <Select
                value={behavior}
                onValueChange={(v) =>
                  setBehavior(v as "pause" | "end" | "continue")
                }
              >
                <SelectTrigger className="w-[140px] h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="pause">Pause broadcast</SelectItem>
                  <SelectItem value="end">End broadcast</SelectItem>
                  <SelectItem value="continue">Continue broadcast</SelectItem>
                </SelectContent>
              </Select>

              <Button
                size="sm"
                variant="default"
                className="gap-1"
                disabled={acceptMut.isPending}
                onClick={() => acceptMut.mutate(req.request_id)}
              >
                <UserCheck className="h-3 w-3" />
                Accept
              </Button>

              <Button
                size="sm"
                variant="outline"
                className="gap-1"
                disabled={declineMut.isPending}
                onClick={() => declineMut.mutate(req.request_id)}
              >
                <UserX className="h-3 w-3" />
                Decline
              </Button>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
