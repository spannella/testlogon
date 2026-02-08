import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Laptop, ShieldCheck, ShieldOff, Globe, Clock } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { EmptyState } from "@/components/shared/EmptyState";
import { getDevices, trustDevice, revokeDevice } from "@/api/endpoints/account";

export function TrustedDevices() {
  const queryClient = useQueryClient();
  const [revokeTarget, setRevokeTarget] = useState<string | null>(null);

  const devicesQuery = useQuery({
    queryKey: ["devices", "trust"],
    queryFn: getDevices,
  });

  const trustMutation = useMutation({
    mutationFn: (deviceId: string) => trustDevice(deviceId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices", "trust"] });
      toast.success("Device trusted");
    },
    onError: () => toast.error("Failed to trust device"),
  });

  const revokeMutation = useMutation({
    mutationFn: (deviceId: string) => revokeDevice(deviceId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices", "trust"] });
      toast.success("Device trust revoked");
      setRevokeTarget(null);
    },
    onError: () => toast.error("Failed to revoke device trust"),
  });

  const devices = devicesQuery.data?.devices ?? [];

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Laptop className="h-5 w-5 text-muted-foreground" />
          <CardTitle className="text-base">Trusted Devices</CardTitle>
        </div>
        <CardDescription>Devices you&apos;ve marked as trusted to skip MFA prompts</CardDescription>
      </CardHeader>
      <CardContent>
        {devicesQuery.isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
          </div>
        ) : devices.length === 0 ? (
          <EmptyState
            icon={<Laptop className="h-8 w-8" />}
            title="No devices"
            description="Devices will appear here when you choose to remember a device during login."
          />
        ) : (
          <ul className="divide-y">
            {devices.map((d) => (
              <li key={d.device_id} className="flex items-center justify-between gap-4 py-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="truncate text-sm font-medium">
                      {d.user_agent
                        ? d.user_agent.length > 60
                          ? d.user_agent.slice(0, 57) + "..."
                          : d.user_agent
                        : "Unknown device"}
                    </p>
                    <Badge variant={d.trusted ? "default" : "secondary"}>
                      {d.trusted ? (
                        <><ShieldCheck className="mr-1 h-3 w-3" />Trusted</>
                      ) : (
                        <><ShieldOff className="mr-1 h-3 w-3" />Untrusted</>
                      )}
                    </Badge>
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                    <span className="inline-flex items-center gap-1">
                      <Globe className="h-3 w-3" />
                      {d.last_ip}
                    </span>
                    <span className="inline-flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      Last seen {new Date(d.last_seen_at * 1000).toLocaleString()}
                    </span>
                  </div>
                </div>
                <div>
                  {d.trusted ? (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setRevokeTarget(d.device_id)}
                    >
                      Revoke Trust
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => trustMutation.mutate(d.device_id)}
                      disabled={trustMutation.isPending}
                    >
                      Trust
                    </Button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      <ConfirmDialog
        open={!!revokeTarget}
        onOpenChange={(o) => { if (!o) setRevokeTarget(null); }}
        title="Revoke Device Trust"
        description="This device will require MFA verification on next login."
        variant="danger"
        confirmLabel="Revoke Trust"
        onConfirm={() => { if (revokeTarget) revokeMutation.mutate(revokeTarget); }}
        loading={revokeMutation.isPending}
      />
    </Card>
  );
}
