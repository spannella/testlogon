import { useQuery } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Webhook } from "lucide-react";
import {
  getWebhookEndpoint,
  getWebhookStats,
  listEndpointDeadLetters,
  listWebhookDeliveries,
} from "@/api/endpoints/webhooks";
import type { WebhookEndpointOut } from "@/api/types";

export default function WebhookEndpointDetail() {
  const { endpointId } = useParams<{ endpointId: string }>();

  const epQ = useQuery({
    queryKey: ["webhooks", endpointId],
    queryFn: () => getWebhookEndpoint(endpointId!),
    enabled: !!endpointId,
  });

  const statsQ = useQuery({
    queryKey: ["webhooks", endpointId, "stats"],
    queryFn: () => getWebhookStats(endpointId!, 24),
    enabled: !!endpointId,
  });

  const dlqQ = useQuery({
    queryKey: ["webhooks", endpointId, "dlq"],
    queryFn: () => listEndpointDeadLetters(endpointId!),
    enabled: !!endpointId,
  });

  const deliveriesQ = useQuery({
    queryKey: ["webhooks", endpointId, "deliveries"],
    queryFn: () => listWebhookDeliveries(endpointId!, { limit: 20 }),
    enabled: !!endpointId,
  });

  const ep = epQ.data as WebhookEndpointOut | undefined;
  const stats = statsQ.data as any;
  const dlq = (dlqQ.data as any)?.dead_letters ?? [];
  const deliveries = (deliveriesQ.data as any)?.deliveries ?? [];

  if (!ep && epQ.isLoading) {
    return <p className="p-6 text-muted-foreground">Loading...</p>;
  }
  if (!ep) {
    return <p className="p-6 text-red-500">Endpoint not found.</p>;
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center gap-3">
        <Link to="/webhooks">
          <Button variant="ghost" size="sm">
            <ArrowLeft className="w-4 h-4 mr-1" /> Back
          </Button>
        </Link>
        <Webhook className="w-6 h-6" />
        <h1 className="text-xl font-bold truncate">{ep.url}</h1>
      </div>

      {/* Config summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Status</p>
            <Badge variant={ep.enabled ? "default" : "destructive"}>
              {ep.enabled ? "Active" : "Disabled"}
            </Badge>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Circuit</p>
            <p className="font-semibold">{ep.circuit_state ?? "closed"}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Signature</p>
            <p className="font-semibold">{ep.signature_version}</p>
          </CardContent>
        </Card>
      </div>

      {/* Stats */}
      {stats && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Delivery Statistics (24h)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-2xl font-bold">{stats.total_deliveries}</p>
                <p className="text-xs text-muted-foreground">Total</p>
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {(stats.success_rate * 100).toFixed(1)}%
                </p>
                <p className="text-xs text-muted-foreground">Success Rate</p>
              </div>
              <div>
                <p className="text-2xl font-bold">{stats.avg_latency_ms}ms</p>
                <p className="text-xs text-muted-foreground">Avg Latency</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Dead Letters */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            Dead Letters ({dlq.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {dlq.length === 0 ? (
            <p className="text-sm text-muted-foreground">No dead letters.</p>
          ) : (
            <div className="space-y-2">
              {dlq.map((d: any) => (
                <div
                  key={d.delivery_id}
                  className="border rounded p-2 text-xs space-y-1"
                >
                  <p className="font-mono">{d.event_type}</p>
                  <p className="text-muted-foreground">{d.failure_reason}</p>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Recent Deliveries */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent Deliveries</CardTitle>
        </CardHeader>
        <CardContent>
          {deliveries.length === 0 ? (
            <p className="text-sm text-muted-foreground">No deliveries yet.</p>
          ) : (
            <div className="space-y-1">
              {deliveries.map((d: any) => (
                <div
                  key={d.delivery_id}
                  className="flex items-center gap-2 text-xs border rounded px-2 py-1"
                >
                  <Badge
                    variant={
                      d.status === "success" ? "default" : "destructive"
                    }
                    className="text-xs"
                  >
                    {d.status}
                  </Badge>
                  <span>{d.event_type}</span>
                  <span className="ml-auto text-muted-foreground">
                    {d.attempt_count} attempts
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
