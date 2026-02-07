import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  getAlertTypes,
  getEmailPrefs,
  setEmailPrefs,
  getSmsPrefs,
  setSmsPrefs,
  getToastPrefs,
  setToastPrefs,
  getWebhookPrefs,
  setWebhookPrefs,
} from "@/api/endpoints/alerts";

// ─── Channel config ──────────────────────────────────────────────

const CHANNELS = [
  { key: "email", label: "Email" },
  { key: "sms", label: "SMS" },
  { key: "toast", label: "In-App Toast" },
] as const;

// ─── Component ───────────────────────────────────────────────────

export function AlertPrefs() {
  const queryClient = useQueryClient();
  const [newWebhookUrl, setNewWebhookUrl] = React.useState("");

  // Fetch all event types
  const typesQuery = useQuery({
    queryKey: ["alert-types"],
    queryFn: getAlertTypes,
  });

  // Fetch preferences per channel
  const emailPrefs = useQuery({
    queryKey: ["alert-prefs", "email"],
    queryFn: getEmailPrefs,
  });
  const smsPrefs = useQuery({
    queryKey: ["alert-prefs", "sms"],
    queryFn: getSmsPrefs,
  });
  const toastPrefs = useQuery({
    queryKey: ["alert-prefs", "toast"],
    queryFn: getToastPrefs,
  });
  const webhookPrefs = useQuery({
    queryKey: ["alert-prefs", "webhook"],
    queryFn: getWebhookPrefs,
  });

  // Mutations
  const emailMutation = useMutation({
    mutationFn: (types: string[]) => setEmailPrefs(types),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert-prefs", "email"] });
      toast.success("Email preferences updated");
    },
  });

  const smsMutation = useMutation({
    mutationFn: (types: string[]) => setSmsPrefs(types),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert-prefs", "sms"] });
      toast.success("SMS preferences updated");
    },
  });

  const toastMutation = useMutation({
    mutationFn: (types: string[]) => setToastPrefs(types),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert-prefs", "toast"] });
      toast.success("Toast preferences updated");
    },
  });

  const webhookMutation = useMutation({
    mutationFn: ({ urls, types }: { urls: string[]; types: string[] }) =>
      setWebhookPrefs(urls, types),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert-prefs", "webhook"] });
      toast.success("Webhook preferences updated");
    },
  });

  const eventTypes = typesQuery.data?.event_types ?? [];

  // Helper: get current event types for a channel
  const getChannelTypes = (channel: string): string[] => {
    switch (channel) {
      case "email":
        return emailPrefs.data?.email_event_types ?? [];
      case "sms":
        return smsPrefs.data?.sms_event_types ?? [];
      case "toast":
        return toastPrefs.data?.toast_event_types ?? [];
      default:
        return [];
    }
  };

  // Helper: toggle an event type for a channel
  const toggleEventType = (channel: string, eventType: string) => {
    const current = getChannelTypes(channel);
    const next = current.includes(eventType)
      ? current.filter((t) => t !== eventType)
      : [...current, eventType];

    switch (channel) {
      case "email":
        emailMutation.mutate(next);
        break;
      case "sms":
        smsMutation.mutate(next);
        break;
      case "toast":
        toastMutation.mutate(next);
        break;
    }
  };

  const webhookUrls = webhookPrefs.data?.webhook_urls ?? [];
  const webhookEventTypes = webhookPrefs.data?.webhook_event_types ?? [];

  const addWebhookUrl = () => {
    const url = newWebhookUrl.trim();
    if (!url) return;
    const next = [...webhookUrls, url];
    webhookMutation.mutate({ urls: next, types: webhookEventTypes });
    setNewWebhookUrl("");
  };

  const removeWebhookUrl = (url: string) => {
    const next = webhookUrls.filter((u) => u !== url);
    webhookMutation.mutate({ urls: next, types: webhookEventTypes });
  };

  const toggleWebhookEvent = (eventType: string) => {
    const next = webhookEventTypes.includes(eventType)
      ? webhookEventTypes.filter((t) => t !== eventType)
      : [...webhookEventTypes, eventType];
    webhookMutation.mutate({ urls: webhookUrls, types: next });
  };

  const isLoading = typesQuery.isLoading || emailPrefs.isLoading || smsPrefs.isLoading || toastPrefs.isLoading;

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-64 w-full rounded-xl" />
        <Skeleton className="h-40 w-full rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Channel toggles grid */}
      <Card>
        <CardHeader>
          <CardTitle>Notification Channels</CardTitle>
          <CardDescription>
            Choose which event types trigger notifications for each channel
          </CardDescription>
        </CardHeader>
        <CardContent>
          {eventTypes.length === 0 ? (
            <p className="text-sm text-muted-foreground">No event types available.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="pb-2 pr-4 text-left font-medium text-muted-foreground">
                      Event Type
                    </th>
                    {CHANNELS.map((ch) => (
                      <th key={ch.key} className="pb-2 px-3 text-center font-medium text-muted-foreground">
                        {ch.label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {eventTypes.map((et) => (
                    <tr key={et} className="border-b last:border-0">
                      <td className="py-2.5 pr-4 capitalize">
                        {et.replace(/_/g, " ")}
                      </td>
                      {CHANNELS.map((ch) => {
                        const enabled = getChannelTypes(ch.key).includes(et);
                        return (
                          <td key={ch.key} className="px-3 py-2.5 text-center">
                            <Switch
                              checked={enabled}
                              onCheckedChange={() => toggleEventType(ch.key, et)}
                            />
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <Separator />

      {/* Webhooks */}
      <Card>
        <CardHeader>
          <CardTitle>Webhooks</CardTitle>
          <CardDescription>
            Send alert notifications to external URLs via HTTP POST
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Current webhook URLs */}
          {webhookUrls.length > 0 && (
            <div className="space-y-2">
              <Label>Webhook URLs</Label>
              {webhookUrls.map((url) => (
                <div key={url} className="flex items-center gap-2 rounded-lg border px-3 py-2">
                  <span className="flex-1 truncate text-xs font-mono">{url}</span>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 shrink-0 text-destructive"
                    onClick={() => removeWebhookUrl(url)}
                  >
                    <X className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ))}
            </div>
          )}

          {/* Add URL */}
          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1.5">
              <Label htmlFor="webhook-url">Add Webhook URL</Label>
              <Input
                id="webhook-url"
                placeholder="https://example.com/webhook"
                value={newWebhookUrl}
                onChange={(e) => setNewWebhookUrl(e.target.value)}
              />
            </div>
            <Button variant="outline" size="sm" onClick={addWebhookUrl}>
              <Plus className="mr-1 h-3.5 w-3.5" />
              Add
            </Button>
          </div>

          {/* Webhook event toggles */}
          {webhookUrls.length > 0 && eventTypes.length > 0 && (
            <>
              <Separator />
              <div className="space-y-2">
                <Label>Webhook Event Types</Label>
                <div className="grid gap-2 sm:grid-cols-2">
                  {eventTypes.map((et) => {
                    const enabled = webhookEventTypes.includes(et);
                    return (
                      <div key={et} className="flex items-center justify-between rounded-lg border px-3 py-2">
                        <span className="text-sm capitalize">{et.replace(/_/g, " ")}</span>
                        <Switch
                          checked={enabled}
                          onCheckedChange={() => toggleWebhookEvent(et)}
                        />
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
