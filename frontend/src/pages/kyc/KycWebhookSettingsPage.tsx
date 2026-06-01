import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  getKycWebhookNotifications,
  getKycWebhookPrefs,
  listKycWebhookEventTypes,
  updateKycWebhookPrefs,
} from "@/api/endpoints/kycWebhooks";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

export default function KycWebhookSettingsPage() {
  const queryClient = useQueryClient();
  const [inApp, setInApp] = useState(true);
  const [email, setEmail] = useState(true);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const eventTypesQuery = useQuery({
    queryKey: ["kyc", "webhook-event-types"],
    queryFn: () => listKycWebhookEventTypes(),
  });

  const prefsQuery = useQuery({
    queryKey: ["kyc", "webhook-prefs"],
    queryFn: () => getKycWebhookPrefs(),
  });

  const notificationsQuery = useQuery({
    queryKey: ["kyc", "webhook-notifications"],
    queryFn: () => getKycWebhookNotifications(50),
  });

  useEffect(() => {
    if (prefsQuery.data) {
      setInApp(prefsQuery.data.in_app_enabled);
      setEmail(prefsQuery.data.email_enabled);
      setSelected(new Set(prefsQuery.data.events));
    }
  }, [prefsQuery.data]);

  const saveMutation = useMutation({
    mutationFn: () =>
      updateKycWebhookPrefs({
        in_app_enabled: inApp,
        email_enabled: email,
        events: Array.from(selected),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["kyc", "webhook-prefs"] });
    },
  });

  function toggleEvent(eventType: string, checked: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(eventType);
      else next.delete(eventType);
      return next;
    });
  }

  const eventTypes = eventTypesQuery.data?.event_types ?? [];
  const notifications = notificationsQuery.data?.items ?? [];

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4" data-testid="kyc-webhook-settings">
      <Card>
        <CardHeader>
          <CardTitle>KYC Webhook & Notification Preferences</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-3">
            <h4 className="text-sm font-semibold">Delivery Channels</h4>
            <div className="flex items-center justify-between">
              <div>
                <Label>In-App Alerts</Label>
                <p className="text-xs text-muted-foreground">Always recorded in your alerts.</p>
              </div>
              <Switch
                checked={inApp}
                onCheckedChange={setInApp}
                data-testid="kyc-webhook-inapp-toggle"
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label>Email</Label>
                <p className="text-xs text-muted-foreground">Sent for key decision events.</p>
              </div>
              <Switch
                checked={email}
                onCheckedChange={setEmail}
                data-testid="kyc-webhook-email-toggle"
              />
            </div>
          </div>

          <div className="space-y-3">
            <h4 className="text-sm font-semibold">Events</h4>
            <p className="text-xs text-muted-foreground">
              Subscribe a webhook endpoint to these event types in Webhook settings to receive
              signed deliveries.
            </p>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {eventTypes.map((et) => (
                <label
                  key={et.event_type}
                  className="flex items-start gap-2 rounded border p-2 text-sm"
                >
                  <Checkbox
                    checked={selected.has(et.event_type)}
                    onCheckedChange={(c) => toggleEvent(et.event_type, c === true)}
                    data-testid={`kyc-webhook-event-${et.event_type}`}
                  />
                  <span>
                    <span className="font-mono text-xs">{et.event_type}</span>
                    <span className="block text-xs text-muted-foreground">{et.description}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>

          <Button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            data-testid="kyc-webhook-save"
          >
            {saveMutation.isPending ? "Saving…" : "Save Preferences"}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Notification History</CardTitle>
        </CardHeader>
        <CardContent>
          {notifications.length === 0 ? (
            <p className="text-sm text-muted-foreground">No KYC notifications yet.</p>
          ) : (
            <ul className="space-y-2" data-testid="kyc-webhook-notifications">
              {notifications.map((n) => (
                <li key={n.alert_id} className="rounded border p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium">{n.title}</span>
                    <Badge variant="outline" className="font-mono text-xs">
                      {n.event}
                    </Badge>
                  </div>
                  {!n.read && (
                    <span className="text-xs text-blue-600">Unread</span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
