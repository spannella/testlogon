import * as React from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, FilePen, Inbox, Send, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SigningWidget } from "@/pages/signing/SigningWidget";
import {
  listAwaitingSignature,
  listSentPackets,
  listCompletedForMe,
  type SigningInboxItem,
} from "@/api/endpoints/signaturePackets";

function formatTs(ts?: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

function StatusChip({ item }: { item: SigningInboxItem }) {
  const label = item.status_chip || item.status_text || item.status;
  return (
    <span className="inline-flex rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700">
      {label}
    </span>
  );
}

function InboxRow({
  item,
  actionLabel,
  onAction,
}: {
  item: SigningInboxItem;
  actionLabel?: string;
  onAction?: (item: SigningInboxItem) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border p-3" data-testid="signing-inbox-row">
      <div className="min-w-0">
        <div className="truncate text-sm font-medium">{item.source_name || item.packet_id}</div>
        <div className="truncate text-xs text-muted-foreground">
          {item.owner_user_id ? `from ${item.owner_user_id} · ` : ""}
          {formatTs(item.sent_at || item.created_at)}
        </div>
        <div className="mt-1">
          <StatusChip item={item} />
        </div>
      </div>
      {actionLabel && onAction && (
        <Button size="sm" onClick={() => onAction(item)} data-testid="signing-open-to-sign-btn">
          {actionLabel}
        </Button>
      )}
    </div>
  );
}

function useAwaitingQuery() {
  return useQuery({
    queryKey: ["signing", "awaiting"],
    queryFn: () => listAwaitingSignature(),
  });
}

/** Sidebar badge count source — exported for reuse if needed. */
export function useAwaitingSignatureCount(): number {
  const { data } = useAwaitingQuery();
  return data?.count ?? 0;
}

export default function SigningInboxPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { packetId } = useParams<{ packetId?: string }>();

  const awaiting = useAwaitingQuery();
  const sent = useQuery({
    queryKey: ["signing", "sent"],
    queryFn: () => listSentPackets(),
  });
  const completed = useQuery({
    queryKey: ["signing", "completed-for-me"],
    queryFn: () => listCompletedForMe(),
  });

  const openToSign = React.useCallback(
    (item: SigningInboxItem) => {
      navigate(`/signing/inbox/${encodeURIComponent(item.packet_id)}`);
    },
    [navigate],
  );

  // In-app open-to-sign widget view (authenticated, no public token).
  if (packetId) {
    return (
      <div className="p-6 space-y-4">
        <Button variant="ghost" size="sm" onClick={() => navigate("/signing/inbox")}>
          <ArrowLeft className="mr-1 h-4 w-4" /> Back to inbox
        </Button>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FilePen className="h-5 w-5" /> Sign document
            </CardTitle>
            <CardDescription>Fill your assigned fields and complete signing.</CardDescription>
          </CardHeader>
          <CardContent>
            <SigningWidget
              packetId={packetId}
              onCompleted={() => {
                void queryClient.invalidateQueries({ queryKey: ["signing"] });
              }}
            />
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-2">
        <FilePen className="h-6 w-6" />
        <h1 className="text-xl font-semibold">Signing inbox</h1>
      </div>

      <Tabs defaultValue="awaiting">
        <TabsList>
          <TabsTrigger value="awaiting" data-testid="tab-awaiting">
            <Inbox className="mr-1 h-4 w-4" /> Awaiting me
            {(awaiting.data?.count ?? 0) > 0 && (
              <Badge className="ml-2" variant="secondary">
                {awaiting.data?.count}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="sent" data-testid="tab-sent">
            <Send className="mr-1 h-4 w-4" /> Sent by me
          </TabsTrigger>
          <TabsTrigger value="completed" data-testid="tab-completed">
            <CheckCircle2 className="mr-1 h-4 w-4" /> Completed
          </TabsTrigger>
        </TabsList>

        <TabsContent value="awaiting" className="space-y-2 pt-3" data-testid="panel-awaiting">
          {awaiting.isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
          {awaiting.isError && (
            <div className="text-sm text-destructive">Failed to load. Try again later.</div>
          )}
          {!awaiting.isLoading && (awaiting.data?.items.length ?? 0) === 0 && (
            <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
              Nothing awaiting your signature.
            </div>
          )}
          {awaiting.data?.items.map((item) => (
            <InboxRow key={item.packet_id} item={item} actionLabel="Open to sign" onAction={openToSign} />
          ))}
        </TabsContent>

        <TabsContent value="sent" className="space-y-2 pt-3" data-testid="panel-sent">
          {sent.isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
          {!sent.isLoading && (sent.data?.items.length ?? 0) === 0 && (
            <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
              You haven't sent any signature requests.
            </div>
          )}
          {sent.data?.items.map((item) => (
            <InboxRow key={item.packet_id} item={item} />
          ))}
        </TabsContent>

        <TabsContent value="completed" className="space-y-2 pt-3" data-testid="panel-completed">
          {completed.isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
          {!completed.isLoading && (completed.data?.items.length ?? 0) === 0 && (
            <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
              No completed signatures yet.
            </div>
          )}
          {completed.data?.items.map((item) => (
            <InboxRow key={item.packet_id} item={item} />
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}
