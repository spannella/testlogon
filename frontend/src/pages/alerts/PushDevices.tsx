import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Bell, BellOff, Loader2, Smartphone, Trash2, Send } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/shared/EmptyState";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { listPushDevices, registerPush, revokePush, testPush, getVapidKey } from "@/api/endpoints/push";
import { registerServiceWorker, subscribeToPush, unsubscribeFromPush } from "@/lib/pushSetup";
import type { PushDevice } from "@/api/types";

function platformIcon(platform: string) {
  switch (platform.toLowerCase()) {
    case "web":
      return <Bell className="h-4 w-4" />;
    default:
      return <Smartphone className="h-4 w-4" />;
  }
}

export function PushDevices() {
  const qc = useQueryClient();
  const [revokeTarget, setRevokeTarget] = useState<PushDevice | null>(null);
  const [enabling, setEnabling] = useState(false);

  const devicesQuery = useQuery({
    queryKey: ["push", "devices"],
    queryFn: () => listPushDevices(),
  });

  const revokeMutation = useMutation({
    mutationFn: async (deviceId: string) => {
      // Unsubscribe from push in the browser as well
      await unsubscribeFromPush();
      return revokePush({ device_id: deviceId });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["push", "devices"] });
      toast.success("Device removed");
      setRevokeTarget(null);
    },
    onError: () => toast.error("Failed to remove device"),
  });

  const testMutation = useMutation({
    mutationFn: () => testPush(),
    onSuccess: () => toast.success("Test notification sent"),
    onError: () => toast.error("Failed to send test notification"),
  });

  const handleEnable = async () => {
    if (!("Notification" in window) || !("serviceWorker" in navigator)) {
      toast.error("Push notifications are not supported in this browser");
      return;
    }

    setEnabling(true);
    try {
      // 1. Request notification permission
      let permission = Notification.permission;
      if (permission === "default") {
        permission = await Notification.requestPermission();
      }

      if (permission !== "granted") {
        toast.error("Notification permission denied");
        return;
      }

      // 2. Fetch VAPID public key from server
      const vapidResp = await getVapidKey();
      const vapidPublicKey = vapidResp.vapid_public_key;
      if (!vapidPublicKey) {
        toast.error("Push not configured on server");
        return;
      }

      // 3. Register service worker (may already be registered)
      await registerServiceWorker();

      // 4. Subscribe to push using VAPID key
      const subscriptionJson = await subscribeToPush(vapidPublicKey);

      // 5. Send subscription to backend
      await registerPush({ token: subscriptionJson, platform: "web" });

      qc.invalidateQueries({ queryKey: ["push", "devices"] });
      toast.success("Push notifications enabled");
    } catch (err) {
      console.error("Push enable failed:", err);
      toast.error("Failed to enable push notifications");
    } finally {
      setEnabling(false);
    }
  };

  const devices = devicesQuery.data?.devices ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {devices.length} device{devices.length !== 1 ? "s" : ""} registered
        </p>
        <div className="flex gap-2">
          {devices.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => testMutation.mutate()}
              disabled={testMutation.isPending}
            >
              {testMutation.isPending ? (
                <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
              ) : (
                <Send className="mr-1 h-3.5 w-3.5" />
              )}
              Test
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={handleEnable}
            disabled={enabling}
          >
            {enabling ? (
              <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
            ) : (
              <Bell className="mr-1 h-3.5 w-3.5" />
            )}
            Enable Notifications
          </Button>
        </div>
      </div>

      {devices.length === 0 ? (
        <EmptyState
          icon={<BellOff className="h-6 w-6" />}
          title="No push devices"
          description="Enable push notifications to receive alerts on this device"
          className="py-12"
        />
      ) : (
        <div className="divide-y rounded-lg border">
          {devices.map((device) => (
            <div
              key={device.device_id}
              className="flex items-center justify-between px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted">
                  {platformIcon(device.platform)}
                </div>
                <div>
                  <p className="text-sm font-medium capitalize">
                    {device.platform || "Unknown"}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    Registered {new Date(device.created_at * 1000).toLocaleDateString()}
                  </p>
                </div>
              </div>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-muted-foreground hover:text-destructive"
                onClick={() => setRevokeTarget(device)}
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
          ))}
        </div>
      )}

      <ConfirmDialog
        open={!!revokeTarget}
        onOpenChange={(open) => { if (!open) setRevokeTarget(null); }}
        title="Remove device"
        description="This device will no longer receive push notifications."
        confirmLabel="Remove"
        variant="danger"
        onConfirm={() => {
          if (revokeTarget) revokeMutation.mutate(revokeTarget.device_id);
        }}
        loading={revokeMutation.isPending}
      />
    </div>
  );
}
