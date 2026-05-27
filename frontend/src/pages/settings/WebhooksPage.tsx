import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Webhook,
  Plus,
  Trash2,
  RefreshCw,
  TestTube,
  Copy,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  createWebhookEndpoint,
  listWebhookEndpoints,
  deleteWebhookEndpoint,
  testWebhookEndpoint,
  rotateWebhookSecret,
  listWebhookDeliveries,
  listWebhookEventTypes,
} from "@/api/endpoints/webhooks";
import type {
  WebhookEndpointOut,
  WebhookDeliveryOut,
  WebhookEventType,
} from "@/api/types";

// ─── Webhook Delivery Log ───────────────────────────────────────

function WebhookDeliveryLog({ endpointId }: { endpointId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["webhook", endpointId, "deliveries"],
    queryFn: () => listWebhookDeliveries(endpointId, { limit: 20 }),
  });

  if (isLoading) return <p className="text-sm text-muted-foreground px-4 py-2">Loading deliveries...</p>;

  const deliveries = data?.deliveries ?? [];
  if (deliveries.length === 0) {
    return <p className="text-sm text-muted-foreground px-4 py-2">No deliveries yet.</p>;
  }

  return (
    <div className="space-y-2 px-4 pb-4">
      <h4 className="text-sm font-semibold">Recent Deliveries</h4>
      <div className="space-y-1">
        {deliveries.map((d: WebhookDeliveryOut) => (
          <div
            key={d.delivery_id}
            className="flex items-center gap-2 text-xs border rounded px-2 py-1"
          >
            {d.status === "success" ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-green-500 shrink-0" />
            ) : d.status === "failed" ? (
              <XCircle className="h-3.5 w-3.5 text-red-500 shrink-0" />
            ) : d.status === "dead_letter" ? (
              <AlertTriangle className="h-3.5 w-3.5 text-orange-500 shrink-0" />
            ) : (
              <Clock className="h-3.5 w-3.5 text-blue-500 shrink-0" />
            )}
            <Badge variant={d.status === "success" ? "default" : "destructive"} className="text-xs">
              {d.status}
            </Badge>
            <span className="text-muted-foreground">{d.event_type}</span>
            {d.last_response_code && (
              <span className="text-muted-foreground">HTTP {d.last_response_code}</span>
            )}
            <span className="text-muted-foreground ml-auto">
              {d.attempt_count}/{d.max_attempts} attempts
            </span>
            {d.last_error && (
              <span className="text-red-500 truncate max-w-[200px]" title={d.last_error}>
                {d.last_error}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Endpoint Card ──────────────────────────────────────────────

function EndpointCard({
  endpoint,
  onDelete,
  onTest,
  onRotate,
}: {
  endpoint: WebhookEndpointOut;
  onDelete: () => void;
  onTest: () => void;
  onRotate: () => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card>
      <CardContent className="pt-4">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1 min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <Badge variant={endpoint.enabled ? "default" : "destructive"}>
                {endpoint.enabled ? "Active" : "Disabled"}
              </Badge>
              {endpoint.disabled_reason && (
                <Badge variant="outline" className="text-xs">
                  {endpoint.disabled_reason}
                </Badge>
              )}
            </div>
            <p className="text-sm font-mono truncate" title={endpoint.url}>
              {endpoint.url}
            </p>
            {endpoint.description && (
              <p className="text-sm text-muted-foreground">{endpoint.description}</p>
            )}
            <div className="flex flex-wrap gap-1 mt-1">
              {endpoint.event_types.map((et) => (
                <Badge key={et} variant="outline" className="text-xs">
                  {et}
                </Badge>
              ))}
            </div>
            {endpoint.failure_count > 0 && (
              <p className="text-xs text-red-500 mt-1">
                {endpoint.failure_count} consecutive failures
              </p>
            )}
          </div>
          <div className="flex gap-1 shrink-0">
            <Button variant="ghost" size="sm" onClick={onTest} title="Test">
              <TestTube className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm" onClick={onRotate} title="Rotate Secret">
              <RefreshCw className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm" onClick={onDelete} title="Delete">
              <Trash2 className="h-4 w-4 text-red-500" />
            </Button>
          </div>
        </div>
        <div className="mt-2">
          <Button
            variant="ghost"
            size="sm"
            className="text-xs"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? (
              <ChevronDown className="h-3 w-3 mr-1" />
            ) : (
              <ChevronRight className="h-3 w-3 mr-1" />
            )}
            Delivery Log
          </Button>
        </div>
        {expanded && <WebhookDeliveryLog endpointId={endpoint.endpoint_id} />}
      </CardContent>
    </Card>
  );
}

// ─── Create Webhook Form Dialog ─────────────────────────────────

function CreateWebhookDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<string[]>([]);
  const [newSecret, setNewSecret] = useState<string | null>(null);

  const eventTypesQuery = useQuery({
    queryKey: ["webhooks", "event-types"],
    queryFn: listWebhookEventTypes,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createWebhookEndpoint({ url, description, event_types: selectedTypes }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      setNewSecret(data.secret);
      toast.success("Webhook endpoint created");
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.detail || err.message || "Failed to create webhook";
      toast.error(msg);
    },
  });

  const eventTypes: WebhookEventType[] = eventTypesQuery.data?.event_types ?? [];

  function toggleType(t: string) {
    setSelectedTypes((prev) =>
      prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t],
    );
  }

  function handleClose() {
    setUrl("");
    setDescription("");
    setSelectedTypes([]);
    setNewSecret(null);
    onOpenChange(false);
  }

  const urlValid = url.startsWith("https://");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Create Webhook Endpoint</DialogTitle>
          <DialogDescription>
            Register a URL to receive HTTP POST notifications when events occur.
          </DialogDescription>
        </DialogHeader>

        {newSecret ? (
          <div className="space-y-4">
            <div className="rounded-md border border-yellow-200 bg-yellow-50 p-3 dark:bg-yellow-950 dark:border-yellow-800">
              <p className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                Save your signing secret now -- it will not be shown again.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Input readOnly value={newSecret} className="font-mono text-xs" />
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  navigator.clipboard.writeText(newSecret);
                  toast.success("Secret copied to clipboard");
                }}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
            <DialogFooter>
              <Button onClick={handleClose}>Done</Button>
            </DialogFooter>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <Label htmlFor="webhook-url">URL (HTTPS required)</Label>
              <Input
                id="webhook-url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://hooks.example.com/my-webhook"
              />
              {url && !urlValid && (
                <p className="text-xs text-red-500 mt-1">URL must start with https://</p>
              )}
            </div>
            <div>
              <Label htmlFor="webhook-desc">Description</Label>
              <Textarea
                id="webhook-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Production notification handler"
                maxLength={200}
                rows={2}
              />
            </div>
            <div>
              <Label>Event Types</Label>
              <div className="grid grid-cols-2 gap-1 mt-1 max-h-48 overflow-y-auto border rounded p-2">
                {eventTypes.map((et) => (
                  <label
                    key={et.type}
                    className="flex items-center gap-1.5 text-xs cursor-pointer hover:bg-accent p-1 rounded"
                  >
                    <input
                      type="checkbox"
                      checked={selectedTypes.includes(et.type)}
                      onChange={() => toggleType(et.type)}
                      className="rounded"
                    />
                    <span>{et.type}</span>
                  </label>
                ))}
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={handleClose}>
                Cancel
              </Button>
              <Button
                onClick={() => createMut.mutate()}
                disabled={!urlValid || selectedTypes.length === 0 || createMut.isPending}
              >
                {createMut.isPending ? "Creating..." : "Create Endpoint"}
              </Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ─── Main Page ──────────────────────────────────────────────────

export default function WebhooksPage() {
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["webhooks"],
    queryFn: listWebhookEndpoints,
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteWebhookEndpoint(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      toast.success("Webhook deleted");
    },
  });

  const testMut = useMutation({
    mutationFn: (id: string) => testWebhookEndpoint(id),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      if (result.status === "success") {
        toast.success(`Test delivery succeeded (${result.response_code}, ${result.duration_ms}ms)`);
      } else {
        toast.error(`Test delivery failed: ${result.error || "Unknown error"}`);
      }
    },
  });

  const rotateMut = useMutation({
    mutationFn: (id: string) => rotateWebhookSecret(id),
    onSuccess: (result) => {
      navigator.clipboard.writeText(result.secret);
      toast.success("New secret rotated and copied to clipboard");
    },
  });

  const endpoints: WebhookEndpointOut[] = data ?? [];

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <Webhook className="h-5 w-5" />
            <CardTitle>Webhooks</CardTitle>
          </div>
          <Button size="sm" onClick={() => setDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-1" />
            Create Webhook
          </Button>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-muted-foreground">Loading...</p>
          ) : endpoints.length === 0 ? (
            <div className="text-center py-8">
              <Webhook className="h-10 w-10 mx-auto text-muted-foreground mb-2" />
              <p className="text-muted-foreground">No webhooks configured</p>
              <p className="text-xs text-muted-foreground mt-1">
                Create a webhook endpoint to receive event notifications.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {endpoints.map((ep) => (
                <EndpointCard
                  key={ep.endpoint_id}
                  endpoint={ep}
                  onDelete={() => deleteMut.mutate(ep.endpoint_id)}
                  onTest={() => testMut.mutate(ep.endpoint_id)}
                  onRotate={() => rotateMut.mutate(ep.endpoint_id)}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <CreateWebhookDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  );
}
