import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { FileCheck2 } from "lucide-react";
import {
  listSentRequests,
  listReceivedRequests,
  approveRequest,
  denyRequest,
  counterOffer,
  acceptCounter,
  rejectCounter,
  withdrawRequest,
} from "@/api/endpoints/licenseRequests";
import type { LicenseRequestOut, LicenseTerms } from "@/api/types";

const STATUS_OPTIONS = ["all", "pending", "negotiating", "approved", "denied", "withdrawn", "expired"] as const;

function statusBadge(status: string) {
  switch (status) {
    case "pending":
      return <Badge variant="secondary">Pending</Badge>;
    case "negotiating":
      return <Badge className="bg-yellow-500 text-white">Negotiating</Badge>;
    case "approved":
      return <Badge className="bg-green-600 text-white">Approved</Badge>;
    case "denied":
      return <Badge variant="destructive">Denied</Badge>;
    case "withdrawn":
      return <Badge variant="outline">Withdrawn</Badge>;
    case "expired":
      return <Badge variant="outline">Expired</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function termsText(terms: LicenseTerms | null | undefined) {
  if (!terms) return "--";
  const parts: string[] = [];
  if (terms.profit_share_pct) parts.push(`${terms.profit_share_pct}% profit`);
  if (terms.revenue_share_pct) parts.push(`${terms.revenue_share_pct}% revenue`);
  if (terms.fixed_cost_cents) parts.push(`$${(terms.fixed_cost_cents / 100).toFixed(2)} fixed`);
  return parts.length > 0 ? parts.join(", ") : "No cost";
}

function timeAgo(ts: number) {
  if (!ts) return "";
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function LicenseRequestsPage() {
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("inbox");
  const [statusFilter, setStatusFilter] = useState("all");
  const [counterDialogOpen, setCounterDialogOpen] = useState(false);
  const [denyDialogOpen, setDenyDialogOpen] = useState(false);
  const [activeRequest, setActiveRequest] = useState<LicenseRequestOut | null>(null);
  const [denyReason, setDenyReason] = useState("");
  const [counterTerms, setCounterTerms] = useState<LicenseTerms>({
    profit_share_pct: 0,
    fixed_cost_cents: 0,
    revenue_share_pct: 0,
  });

  const filterStatus = statusFilter === "all" ? undefined : statusFilter;

  const sentQuery = useQuery({
    queryKey: ["license-requests", "sent", filterStatus],
    queryFn: () => listSentRequests({ status: filterStatus }),
    enabled: tab === "sent",
  });

  const receivedQuery = useQuery({
    queryKey: ["license-requests", "received", filterStatus],
    queryFn: () => listReceivedRequests({ status: filterStatus }),
    enabled: tab === "inbox",
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["license-requests"] });
  };

  const approveMut = useMutation({
    mutationFn: (r: LicenseRequestOut) => approveRequest(r.request_id, r.content_id),
    onSuccess: invalidate,
  });

  const denyMut = useMutation({
    mutationFn: ({ r, reason }: { r: LicenseRequestOut; reason: string }) =>
      denyRequest(r.request_id, r.content_id, reason),
    onSuccess: () => {
      setDenyDialogOpen(false);
      invalidate();
    },
  });

  const counterMut = useMutation({
    mutationFn: ({ r, terms }: { r: LicenseRequestOut; terms: LicenseTerms }) =>
      counterOffer(r.request_id, r.content_id, terms),
    onSuccess: () => {
      setCounterDialogOpen(false);
      invalidate();
    },
  });

  const acceptCounterMut = useMutation({
    mutationFn: (r: LicenseRequestOut) => acceptCounter(r.request_id, r.content_id),
    onSuccess: invalidate,
  });

  const rejectCounterMut = useMutation({
    mutationFn: (r: LicenseRequestOut) => rejectCounter(r.request_id, r.content_id),
    onSuccess: invalidate,
  });

  const withdrawMut = useMutation({
    mutationFn: (r: LicenseRequestOut) => withdrawRequest(r.request_id, r.content_id),
    onSuccess: invalidate,
  });

  const openCounterDialog = (r: LicenseRequestOut) => {
    setActiveRequest(r);
    setCounterTerms({
      profit_share_pct: r.proposed_terms?.profit_share_pct ?? 0,
      fixed_cost_cents: r.proposed_terms?.fixed_cost_cents ?? 0,
      revenue_share_pct: r.proposed_terms?.revenue_share_pct ?? 0,
    });
    setCounterDialogOpen(true);
  };

  const openDenyDialog = (r: LicenseRequestOut) => {
    setActiveRequest(r);
    setDenyReason("");
    setDenyDialogOpen(true);
  };

  const renderRequestRow = (r: LicenseRequestOut, isInbox: boolean) => (
    <TableRow key={r.request_id}>
      <TableCell className="font-mono text-xs">{r.content_id}</TableCell>
      <TableCell>{r.content_type}</TableCell>
      <TableCell>{isInbox ? r.requester_id : r.owner_id}</TableCell>
      <TableCell>{termsText(r.proposed_terms)}</TableCell>
      <TableCell>{r.counter_terms ? termsText(r.counter_terms) : "--"}</TableCell>
      <TableCell>{statusBadge(r.status)}</TableCell>
      <TableCell>{timeAgo(r.created_at)}</TableCell>
      <TableCell>
        <div className="flex gap-1 flex-wrap">
          {isInbox && (r.status === "pending" || r.status === "negotiating") && (
            <>
              <Button size="sm" variant="default" onClick={() => approveMut.mutate(r)}>
                Approve
              </Button>
              <Button size="sm" variant="outline" onClick={() => openCounterDialog(r)}>
                Counter
              </Button>
              <Button size="sm" variant="destructive" onClick={() => openDenyDialog(r)}>
                Deny
              </Button>
            </>
          )}
          {!isInbox && r.status === "pending" && (
            <Button size="sm" variant="outline" onClick={() => withdrawMut.mutate(r)}>
              Withdraw
            </Button>
          )}
          {!isInbox && r.status === "negotiating" && (
            <>
              <Button size="sm" variant="default" onClick={() => acceptCounterMut.mutate(r)}>
                Accept
              </Button>
              <Button size="sm" variant="destructive" onClick={() => rejectCounterMut.mutate(r)}>
                Reject
              </Button>
              <Button size="sm" variant="outline" onClick={() => withdrawMut.mutate(r)}>
                Withdraw
              </Button>
            </>
          )}
        </div>
      </TableCell>
    </TableRow>
  );

  const renderTable = (items: LicenseRequestOut[], isInbox: boolean) => (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Content</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>{isInbox ? "Requester" : "Owner"}</TableHead>
          <TableHead>Proposed Terms</TableHead>
          <TableHead>Counter Terms</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Requested</TableHead>
          <TableHead>Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.length === 0 ? (
          <TableRow>
            <TableCell colSpan={8} className="text-center text-muted-foreground py-8">
              No license requests found.
            </TableCell>
          </TableRow>
        ) : (
          items.map((r) => renderRequestRow(r, isInbox))
        )}
      </TableBody>
    </Table>
  );

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileCheck2 className="h-5 w-5" />
            License Requests
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs value={tab} onValueChange={setTab}>
            <div className="flex items-center justify-between mb-4">
              <TabsList>
                <TabsTrigger value="inbox">Inbox</TabsTrigger>
                <TabsTrigger value="sent">Sent</TabsTrigger>
              </TabsList>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {STATUS_OPTIONS.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s === "all" ? "All Statuses" : s.charAt(0).toUpperCase() + s.slice(1)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <TabsContent value="inbox">
              {receivedQuery.isLoading ? (
                <p className="text-muted-foreground py-8 text-center">Loading...</p>
              ) : (
                renderTable(receivedQuery.data?.items ?? [], true)
              )}
            </TabsContent>

            <TabsContent value="sent">
              {sentQuery.isLoading ? (
                <p className="text-muted-foreground py-8 text-center">Loading...</p>
              ) : (
                renderTable(sentQuery.data?.items ?? [], false)
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Counter-Offer Dialog */}
      <Dialog open={counterDialogOpen} onOpenChange={setCounterDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Counter-Offer</DialogTitle>
            <DialogDescription>
              Propose different terms for content: {activeRequest?.content_id}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Profit Share %</Label>
              <Input
                type="number"
                min={0}
                max={100}
                value={counterTerms.profit_share_pct}
                onChange={(e) =>
                  setCounterTerms({ ...counterTerms, profit_share_pct: Number(e.target.value) })
                }
              />
            </div>
            <div>
              <Label>Revenue Share %</Label>
              <Input
                type="number"
                min={0}
                max={100}
                value={counterTerms.revenue_share_pct}
                onChange={(e) =>
                  setCounterTerms({ ...counterTerms, revenue_share_pct: Number(e.target.value) })
                }
              />
            </div>
            <div>
              <Label>Fixed Cost (cents)</Label>
              <Input
                type="number"
                min={0}
                value={counterTerms.fixed_cost_cents}
                onChange={(e) =>
                  setCounterTerms({ ...counterTerms, fixed_cost_cents: Number(e.target.value) })
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCounterDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                activeRequest && counterMut.mutate({ r: activeRequest, terms: counterTerms })
              }
            >
              Send Counter-Offer
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Deny Dialog */}
      <Dialog open={denyDialogOpen} onOpenChange={setDenyDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Deny Request</DialogTitle>
            <DialogDescription>
              Optionally provide a reason for denying this request.
            </DialogDescription>
          </DialogHeader>
          <div>
            <Label>Reason (optional)</Label>
            <Textarea
              value={denyReason}
              onChange={(e) => setDenyReason(e.target.value)}
              placeholder="Why are you denying this request?"
              maxLength={500}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDenyDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                activeRequest && denyMut.mutate({ r: activeRequest, reason: denyReason })
              }
            >
              Deny Request
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
