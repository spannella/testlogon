import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Mail, Phone, Plus, X } from "lucide-react";
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
  alertEmailBegin,
  alertEmailConfirm,
  alertEmailRemove,
  alertSmsBegin,
  alertSmsConfirm,
  alertSmsRemove,
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

  // Email address management state
  const [emailInput, setEmailInput] = React.useState("");
  const [emailPending, setEmailPending] = React.useState<{ challengeId: string; sentTo: string } | null>(null);
  const [emailCode, setEmailCode] = React.useState("");

  // SMS number management state
  const [phoneInput, setPhoneInput] = React.useState("");
  const [smsPending, setSmsPending] = React.useState<{ challengeId: string; sentTo: string } | null>(null);
  const [smsCode, setSmsCode] = React.useState("");

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

  // Email address mutations
  const emailBeginMut = useMutation({
    mutationFn: (email: string) => alertEmailBegin(email),
    onSuccess: (d) => {
      setEmailPending({ challengeId: d.challenge_id, sentTo: d.sent_to });
      setEmailInput("");
    },
    onError: () => toast.error("Failed to send verification email"),
  });
  const emailConfirmMut = useMutation({
    mutationFn: ({ id, code }: { id: string; code: string }) => alertEmailConfirm(id, code),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert-prefs", "email"] });
      setEmailPending(null);
      setEmailCode("");
      toast.success("Email address added");
    },
    onError: () => toast.error("Invalid or expired code"),
  });
  const emailRemoveMut = useMutation({
    mutationFn: (email: string) => alertEmailRemove(email),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert-prefs", "email"] });
      toast.success("Email address removed");
    },
  });

  // SMS number mutations
  const smsBeginMut = useMutation({
    mutationFn: (phone: string) => alertSmsBegin(phone),
    onSuccess: (d) => {
      setSmsPending({ challengeId: d.challenge_id, sentTo: d.sent_to });
      setPhoneInput("");
    },
    onError: () => toast.error("Failed to send verification SMS"),
  });
  const smsConfirmMut = useMutation({
    mutationFn: ({ id, code }: { id: string; code: string }) => alertSmsConfirm(id, code),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert-prefs", "sms"] });
      setSmsPending(null);
      setSmsCode("");
      toast.success("Phone number added");
    },
    onError: () => toast.error("Invalid or expired code"),
  });
  const smsRemoveMut = useMutation({
    mutationFn: (phone: string) => alertSmsRemove(phone),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert-prefs", "sms"] });
      toast.success("Phone number removed");
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

  const configuredEmails = emailPrefs.data?.emails ?? [];
  const configuredSmsNumbers = smsPrefs.data?.sms_numbers ?? [];

  return (
    <div className="space-y-6">
      {/* Alert Email Addresses */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-4 w-4" />
            Alert Email Addresses
          </CardTitle>
          <CardDescription>Verified emails that receive alert notifications</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {configuredEmails.map((addr) => (
            <div key={addr} className="flex items-center gap-2 rounded-lg border px-3 py-2">
              <span className="flex-1 text-sm font-mono">{addr}</span>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6 shrink-0 text-destructive"
                onClick={() => emailRemoveMut.mutate(addr)}
                disabled={emailRemoveMut.isPending}
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>
          ))}

          {!emailPending ? (
            <div className="flex gap-2">
              <Input
                type="email"
                placeholder="you@example.com"
                value={emailInput}
                onChange={(e) => setEmailInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && emailInput.trim() && emailBeginMut.mutate(emailInput.trim())}
              />
              <Button
                onClick={() => emailBeginMut.mutate(emailInput.trim())}
                disabled={!emailInput.trim() || emailBeginMut.isPending}
              >
                <Plus className="mr-1 h-3.5 w-3.5" />
                Add
              </Button>
            </div>
          ) : (
            <div className="space-y-2 rounded-lg border p-3">
              <p className="text-sm text-muted-foreground">
                Enter the 6-digit code sent to <strong>{emailPending.sentTo}</strong>
              </p>
              <div className="flex gap-2">
                <Input
                  maxLength={6}
                  placeholder="000000"
                  value={emailCode}
                  onChange={(e) => setEmailCode(e.target.value)}
                />
                <Button
                  onClick={() => emailConfirmMut.mutate({ id: emailPending.challengeId, code: emailCode })}
                  disabled={emailCode.length < 6 || emailConfirmMut.isPending}
                >
                  Verify
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => { setEmailPending(null); setEmailCode(""); }}
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Alert SMS Numbers */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Phone className="h-4 w-4" />
            Alert SMS Numbers
          </CardTitle>
          <CardDescription>Verified phone numbers that receive alert notifications</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {configuredSmsNumbers.map((num) => (
            <div key={num} className="flex items-center gap-2 rounded-lg border px-3 py-2">
              <span className="flex-1 text-sm font-mono">{num}</span>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6 shrink-0 text-destructive"
                onClick={() => smsRemoveMut.mutate(num)}
                disabled={smsRemoveMut.isPending}
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>
          ))}

          {!smsPending ? (
            <div className="flex gap-2">
              <Input
                type="tel"
                placeholder="+1 555 000 0000"
                value={phoneInput}
                onChange={(e) => setPhoneInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && phoneInput.trim() && smsBeginMut.mutate(phoneInput.trim())}
              />
              <Button
                onClick={() => smsBeginMut.mutate(phoneInput.trim())}
                disabled={!phoneInput.trim() || smsBeginMut.isPending}
              >
                <Plus className="mr-1 h-3.5 w-3.5" />
                Add
              </Button>
            </div>
          ) : (
            <div className="space-y-2 rounded-lg border p-3">
              <p className="text-sm text-muted-foreground">
                Enter the 6-digit code sent to <strong>{smsPending.sentTo}</strong>
              </p>
              <div className="flex gap-2">
                <Input
                  maxLength={6}
                  placeholder="000000"
                  value={smsCode}
                  onChange={(e) => setSmsCode(e.target.value)}
                />
                <Button
                  onClick={() => smsConfirmMut.mutate({ id: smsPending.challengeId, code: smsCode })}
                  disabled={smsCode.length < 6 || smsConfirmMut.isPending}
                >
                  Verify
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => { setSmsPending(null); setSmsCode(""); }}
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

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
