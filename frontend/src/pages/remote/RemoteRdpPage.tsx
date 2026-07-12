import * as React from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Copy, Check, MonitorOff } from "lucide-react";
import { PageHeader } from "@/components/shared/PageHeader";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { rdpApi } from "@/api/endpoints/rdp";
import { isRdpRemoteDesktopEnabled } from "@/lib/featureFlags";

// ADR-004 / CTI-005 — Phase 1 RDP fallback surface.
// With RDP_REMOTE_DESKTOP_ENABLED off (default), native in-browser RDP is not
// available. This page surfaces a clear "RDP not available — use VNC/SSH"
// message plus copy-ready connection details for a native RDP client, instead
// of dead-ending a Windows host in the SSH connect form.

function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = React.useState(false);
  const onCopy = React.useCallback(() => {
    void navigator.clipboard?.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [value]);
  if (!value) return null;
  return (
    <div className="flex items-center justify-between rounded-md border px-3 py-2">
      <div className="min-w-0">
        <div className="text-xs text-muted-foreground">{label}</div>
        <div className="truncate font-mono text-sm">{value}</div>
      </div>
      <Button variant="ghost" size="sm" onClick={onCopy} aria-label={`Copy ${label}`}>
        {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </Button>
    </div>
  );
}

export default function RemoteRdpPage() {
  const [params] = useSearchParams();
  const hostId = (params.get("host_id") || "").trim();
  const nativeEnabled = isRdpRemoteDesktopEnabled();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["rdp", "fallback", hostId],
    queryFn: () => rdpApi.fallback(hostId),
    enabled: hostId.length > 0,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Remote Desktop (RDP)"
        description="Connect to a Windows host over RDP."
      />

      <Alert>
        <MonitorOff className="h-4 w-4" />
        <AlertTitle>
          {nativeEnabled
            ? "Native RDP gateway not yet available"
            : "RDP not available — use VNC/SSH"}
        </AlertTitle>
        <AlertDescription>
          In-browser RDP rendering is not available in this build. Use the
          connection details below with a native RDP client, or connect via VNC
          if this host also exposes a VNC endpoint.
        </AlertDescription>
      </Alert>

      {!hostId && (
        <Card>
          <CardContent className="py-6 text-sm text-muted-foreground">
            No host selected. Open this page from a Windows host in your inventory
            or compute instances list.
          </CardContent>
        </Card>
      )}

      {hostId && isLoading && (
        <Card>
          <CardContent className="py-6 text-sm text-muted-foreground">Loading host details…</CardContent>
        </Card>
      )}

      {hostId && isError && (
        <Card>
          <CardContent className="py-6 text-sm text-destructive">
            Could not load this host: {(error as Error)?.message || "not found"}.
          </CardContent>
        </Card>
      )}

      {data && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {data.label}
              <Badge variant="secondary">RDP</Badge>
            </CardTitle>
            <CardDescription>{data.instructions}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <CopyField label="Address" value={data.address} />
            <CopyField label="Hostname" value={data.hostname} />
            <CopyField label="Port" value={String(data.port)} />
            <CopyField label="Username" value={data.username} />
            <div className="pt-2 text-xs text-muted-foreground">
              Suggested native clients: {data.native_clients.join(", ")}.
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
