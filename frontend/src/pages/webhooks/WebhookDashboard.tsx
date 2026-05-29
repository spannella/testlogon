import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Webhook,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Activity,
} from "lucide-react";
import { Link } from "react-router-dom";
import { listWebhookEndpoints } from "@/api/endpoints/webhooks";
import type { WebhookEndpointOut } from "@/api/types";

function CircuitBadge({ state }: { state: string | null | undefined }) {
  if (!state || state === "closed") {
    return (
      <Badge className="gap-1 bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
        <CheckCircle2 className="w-3 h-3" /> Healthy
      </Badge>
    );
  }
  if (state === "half_open") {
    return (
      <Badge className="gap-1 bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
        <AlertTriangle className="w-3 h-3" /> Testing
      </Badge>
    );
  }
  return (
    <Badge variant="destructive" className="gap-1">
      <XCircle className="w-3 h-3" /> Open
    </Badge>
  );
}

export default function WebhookDashboard() {
  const endpointsQ = useQuery({
    queryKey: ["webhooks", "endpoints"],
    queryFn: listWebhookEndpoints,
  });

  const endpoints: WebhookEndpointOut[] = (endpointsQ.data as WebhookEndpointOut[] | undefined) ?? [];
  const active = endpoints.filter((e) => e.enabled).length;
  const circuitOpen = endpoints.filter(
    (e) => e.circuit_state === "open",
  ).length;

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center gap-3">
        <Webhook className="w-8 h-8" />
        <h1 className="text-2xl font-bold">Webhooks</h1>
      </div>

      {/* Overview cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Total Endpoints</p>
            <p className="text-2xl font-bold" data-testid="total-endpoints">
              {endpoints.length}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Active</p>
            <p className="text-2xl font-bold text-green-600" data-testid="active-endpoints">
              {active}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Circuit Open</p>
            <p className="text-2xl font-bold text-red-600" data-testid="circuit-open">
              {circuitOpen}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Dead Letters</p>
            <p className="text-2xl font-bold" data-testid="dead-letter-count">0</p>
          </CardContent>
        </Card>
      </div>

      {/* Endpoint list */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center justify-between">
            Endpoints
            <Link to="/settings/webhooks">
              <Button size="sm">Manage Endpoints</Button>
            </Link>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {endpoints.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-4">
              No webhook endpoints configured.
            </p>
          ) : (
            <table className="w-full text-sm" data-testid="webhook-endpoints-table">
              <thead>
                <tr className="border-b">
                  <th className="text-left p-2">URL</th>
                  <th className="text-left p-2">Events</th>
                  <th className="text-left p-2">Status</th>
                  <th className="text-left p-2">Circuit</th>
                  <th className="text-left p-2">Failures</th>
                  <th className="text-left p-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {endpoints.map((ep) => (
                  <tr
                    key={ep.endpoint_id}
                    className="border-b hover:bg-muted/50"
                    data-testid={`endpoint-row-${ep.endpoint_id}`}
                  >
                    <td className="p-2 font-mono text-xs truncate max-w-[200px]">
                      {ep.url}
                    </td>
                    <td className="p-2">
                      <Badge variant="secondary">
                        {ep.event_types?.length ?? 0}
                      </Badge>
                    </td>
                    <td className="p-2">
                      {ep.enabled ? (
                        <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                          Active
                        </Badge>
                      ) : (
                        <Badge variant="destructive">Disabled</Badge>
                      )}
                    </td>
                    <td className="p-2">
                      <CircuitBadge state={ep.circuit_state} />
                    </td>
                    <td className="p-2">{ep.failure_count}</td>
                    <td className="p-2">
                      <Link to={`/webhooks/${ep.endpoint_id}`}>
                        <Button size="sm" variant="ghost">
                          <Activity className="w-4 h-4" />
                        </Button>
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
