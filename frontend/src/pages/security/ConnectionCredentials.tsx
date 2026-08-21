import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Radio, Terminal, Zap, Binary, Copy, Check, Download, RefreshCw, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { getKeyProtocols, rotateKeyProtocolSecret } from "@/api/endpoints/tradingCredentials";
import type { ApiKey } from "@/api/types";
import {
  buildFixSessionConfig,
  fixConfigFilename,
  wsSubscribeChannels,
  wsSubscribePayload,
  type Protocol,
} from "@/lib/tradingCredentials";

// A tiny inline copy-to-clipboard field.
function CopyField({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    if (!window.isSecureContext) {
      toast.error("Clipboard copy requires HTTPS.");
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      toast.success("Copied");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Copy failed");
    }
  };
  return (
    <div className="flex items-center gap-2 rounded-md border bg-muted/40 px-2.5 py-1.5">
      <code className="flex-1 break-all text-xs font-mono">{value}</code>
      <button
        type="button"
        onClick={copy}
        aria-label={`Copy ${label ?? "value"}`}
        className={copied ? "text-green-500" : "text-muted-foreground hover:text-foreground"}
      >
        {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      </button>
    </div>
  );
}

function SectionHeader({ icon, title, badge }: { icon: React.ReactNode; title: string; badge?: React.ReactNode }) {
  return (
    <div className="mb-2 flex items-center gap-2 text-sm font-medium">
      {icon}
      {title}
      {badge}
    </div>
  );
}

export function ConnectionCredentialsDialog({ keyData, onClose }: { keyData: ApiKey; onClose: () => void }) {
  const queryClient = useQueryClient();
  // one-time rotated secrets, keyed by protocol
  const [rotated, setRotated] = useState<Partial<Record<Protocol, string>>>({});

  const protocolsQuery = useQuery({
    queryKey: ["keyProtocols", keyData.key_id],
    queryFn: () => getKeyProtocols(keyData.key_id),
    retry: false,
  });

  const rotateMutation = useMutation({
    mutationFn: (protocol: Protocol) => rotateKeyProtocolSecret(keyData.key_id, protocol),
    onSuccess: (data, protocol) => {
      setRotated((prev) => ({ ...prev, [protocol]: data.secret }));
      queryClient.invalidateQueries({ queryKey: ["keyProtocols", keyData.key_id] });
      toast.success("Secret rotated — copy it now");
    },
    onError: () => toast.error("Failed to rotate secret — endpoint may not be available yet"),
  });

  const data = protocolsQuery.data;
  const notAvailable = protocolsQuery.isError;
  const empty = data != null && !data.rest && !data.ws && !data.fix && !data.binary;

  const downloadFix = () => {
    const fix = data?.fix;
    if (!fix) return;
    const cfg = buildFixSessionConfig({
      senderCompId: fix.sender_comp_id,
      targetCompId: fix.target_comp_id,
      host: fix.host,
      port: fix.port,
      username: fix.username,
      msgTypes: fix.msg_types,
    });
    const blob = new Blob([cfg], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fixConfigFilename(fix.sender_comp_id);
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Radio className="h-4 w-4" />
            Connection Credentials
          </DialogTitle>
          <DialogDescription>
            {keyData.label ?? "Unnamed key"} · protocol connection details. Secrets are shown only at create/rotate.
          </DialogDescription>
        </DialogHeader>

        <div className="max-h-[60vh] space-y-4 overflow-y-auto">
          {protocolsQuery.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          ) : notAvailable ? (
            <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>Multi-protocol connection details are not available yet (pending backend). Your key still works for REST access with its configured scopes.</span>
            </div>
          ) : empty ? (
            <p className="text-xs text-muted-foreground">This key has no multi-protocol channels provisioned.</p>
          ) : (
            <>
              {/* REST */}
              {data?.rest && (
                <div>
                  <SectionHeader icon={<Terminal className="h-4 w-4 text-muted-foreground" />} title="REST" />
                  <div className="space-y-1.5">
                    <p className="text-[11px] text-muted-foreground">Base URL</p>
                    <CopyField value={data.rest.base_url} label="REST base URL" />
                    {data.rest.scopes.length > 0 && (
                      <div className="flex flex-wrap gap-1 pt-1">
                        {data.rest.scopes.map((s) => (
                          <Badge key={s} variant="outline" className="text-[10px] font-mono">{s}</Badge>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* WS */}
              {data?.ws && (
                <div>
                  <SectionHeader
                    icon={<Zap className="h-4 w-4 text-muted-foreground" />}
                    title="WebSocket"
                    badge={<Badge variant={data.ws.token_set ? "secondary" : "outline"} className="text-[10px]">{data.ws.token_set ? "token set" : "no token"}</Badge>}
                  />
                  <div className="space-y-1.5">
                    <p className="text-[11px] text-muted-foreground">URL</p>
                    <CopyField value={data.ws.url} label="WS URL" />
                    <p className="pt-1 text-[11px] text-muted-foreground">Subscribe payloads</p>
                    {wsSubscribeChannels(data.ws.subs).map((sub) => (
                      <CopyField key={sub} value={wsSubscribePayload(sub)} label={`subscribe ${sub}`} />
                    ))}
                    {rotated.ws && (
                      <div className="rounded-md border border-green-300 bg-green-50 p-2 dark:border-green-700 dark:bg-green-950">
                        <p className="mb-1 text-[11px] font-medium text-green-700 dark:text-green-400">New WS token (shown once)</p>
                        <CopyField value={rotated.ws} label="WS token" />
                      </div>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      className="mt-1 h-7 text-xs"
                      disabled={rotateMutation.isPending}
                      onClick={() => rotateMutation.mutate("ws")}
                    >
                      <RefreshCw className="mr-1 h-3 w-3" />
                      Rotate WS token
                    </Button>
                  </div>
                </div>
              )}

              {/* FIX */}
              {data?.fix && (
                <div>
                  <SectionHeader
                    icon={<Binary className="h-4 w-4 text-muted-foreground" />}
                    title="FIX"
                    badge={<Badge variant="outline" className="text-[10px]">{data.fix.status}</Badge>}
                  />
                  <div className="grid grid-cols-2 gap-1.5 text-xs">
                    <div><span className="text-muted-foreground">SenderCompID</span><br /><code>{data.fix.sender_comp_id}</code></div>
                    <div><span className="text-muted-foreground">TargetCompID</span><br /><code>{data.fix.target_comp_id}</code></div>
                    <div><span className="text-muted-foreground">Host</span><br /><code>{data.fix.host}</code></div>
                    <div><span className="text-muted-foreground">Port</span><br /><code>{data.fix.port}</code></div>
                    <div><span className="text-muted-foreground">Username</span><br /><code>{data.fix.username}</code></div>
                  </div>
                  {data.fix.msg_types.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {data.fix.msg_types.map((m) => (
                        <Badge key={m} variant="outline" className="text-[10px] font-mono">{m}</Badge>
                      ))}
                    </div>
                  )}
                  {rotated.fix && (
                    <div className="mt-1.5 rounded-md border border-green-300 bg-green-50 p-2 dark:border-green-700 dark:bg-green-950">
                      <p className="mb-1 text-[11px] font-medium text-green-700 dark:text-green-400">New FIX password (shown once)</p>
                      <CopyField value={rotated.fix} label="FIX password" />
                    </div>
                  )}
                  <div className="mt-1.5 flex gap-2">
                    <Button size="sm" variant="outline" className="h-7 text-xs" onClick={downloadFix}>
                      <Download className="mr-1 h-3 w-3" />
                      Download session config
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-7 text-xs"
                      disabled={rotateMutation.isPending}
                      onClick={() => rotateMutation.mutate("fix")}
                    >
                      <RefreshCw className="mr-1 h-3 w-3" />
                      Rotate password
                    </Button>
                  </div>
                </div>
              )}

              {/* Binary */}
              {data?.binary && (
                <div>
                  <SectionHeader
                    icon={<Binary className="h-4 w-4 text-muted-foreground" />}
                    title="Binary"
                    badge={<Badge variant={data.binary.key_set ? "secondary" : "outline"} className="text-[10px]">{data.binary.key_set ? "key set" : "no key"}</Badge>}
                  />
                  <div className="space-y-1.5 text-xs">
                    <p className="text-[11px] text-muted-foreground">Endpoint</p>
                    <CopyField value={data.binary.endpoint} label="binary endpoint" />
                    <p className="pt-1"><span className="text-muted-foreground">HMAC scheme:</span> <code>{data.binary.hmac_scheme}</code></p>
                    {data.binary.ops.length > 0 && (
                      <div className="flex flex-wrap gap-1 pt-1">
                        {data.binary.ops.map((op) => (
                          <Badge key={op} variant="outline" className="text-[10px] font-mono">{op}</Badge>
                        ))}
                      </div>
                    )}
                  </div>
                  {rotated.binary && (
                    <div className="mt-1.5 rounded-md border border-green-300 bg-green-50 p-2 dark:border-green-700 dark:bg-green-950">
                      <p className="mb-1 text-[11px] font-medium text-green-700 dark:text-green-400">New binary secret (shown once)</p>
                      <CopyField value={rotated.binary} label="binary secret" />
                    </div>
                  )}
                  <Button
                    size="sm"
                    variant="outline"
                    className="mt-1.5 h-7 text-xs"
                    disabled={rotateMutation.isPending}
                    onClick={() => rotateMutation.mutate("binary")}
                  >
                    <RefreshCw className="mr-1 h-3 w-3" />
                    Rotate secret
                  </Button>
                </div>
              )}
            </>
          )}
        </div>

        <DialogFooter>
          <Button onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
