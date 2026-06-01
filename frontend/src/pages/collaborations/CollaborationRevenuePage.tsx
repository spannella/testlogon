import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, DollarSign, Plus, Trash2 } from "lucide-react";
import {
  assignContent,
  listAssignedContent,
  unassignContent,
  getSplitHistory,
  listDisputes,
  resolveDispute,
} from "@/api/endpoints/collaborationRevenue";
import { getCollaboration } from "@/api/endpoints/collaborations";
import type {
  CollabContentAssignIn,
  CollabContentItem,
  CollabSplitRecord,
  CollabDisputeOut,
} from "@/api/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { toast } from "sonner";
import CollaborationSplitDisputeDialog from "./CollaborationSplitDisputeDialog";

function dollars(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

export default function CollaborationRevenuePage() {
  const { collabId = "" } = useParams<{ collabId: string }>();
  const qc = useQueryClient();

  const [assignOpen, setAssignOpen] = useState(false);
  const [assignForm, setAssignForm] = useState<CollabContentAssignIn>({
    content_id: "",
    content_type: "post",
    title: "",
  });
  const [disputeSplit, setDisputeSplit] = useState<CollabSplitRecord | null>(null);

  const collabQ = useQuery({
    queryKey: ["collab", collabId],
    queryFn: () => getCollaboration(collabId),
    enabled: !!collabId,
  });

  const contentQ = useQuery({
    queryKey: ["collab-content", collabId],
    queryFn: () => listAssignedContent(collabId),
    enabled: !!collabId,
  });

  const splitsQ = useQuery({
    queryKey: ["collab-splits", collabId],
    queryFn: () => getSplitHistory(collabId, { limit: 50 }),
    enabled: !!collabId,
  });

  const disputesQ = useQuery({
    queryKey: ["collab-disputes", collabId],
    queryFn: () => listDisputes(collabId),
    enabled: !!collabId,
  });

  const assignMut = useMutation({
    mutationFn: () => assignContent(collabId, assignForm),
    onSuccess: () => {
      toast.success("Content assigned");
      qc.invalidateQueries({ queryKey: ["collab-content", collabId] });
      setAssignOpen(false);
      setAssignForm({ content_id: "", content_type: "post", title: "" });
    },
    onError: (err: unknown) => {
      toast.error((err as { message?: string })?.message || "Failed to assign content");
    },
  });

  const unassignMut = useMutation({
    mutationFn: (contentId: string) => unassignContent(collabId, contentId),
    onSuccess: () => {
      toast.success("Content unassigned");
      qc.invalidateQueries({ queryKey: ["collab-content", collabId] });
    },
    onError: (err: unknown) => {
      toast.error((err as { message?: string })?.message || "Failed to unassign");
    },
  });

  const resolveMut = useMutation({
    mutationFn: (disputeId: string) =>
      resolveDispute(collabId, disputeId, { resolution: "Resolved by collaborator", accept: true }),
    onSuccess: () => {
      toast.success("Dispute resolved");
      qc.invalidateQueries({ queryKey: ["collab-disputes", collabId] });
      qc.invalidateQueries({ queryKey: ["collab-splits", collabId] });
    },
    onError: (err: unknown) => {
      toast.error((err as { message?: string })?.message || "Failed to resolve");
    },
  });

  const collab = collabQ.data;
  const content: CollabContentItem[] = contentQ.data?.items ?? [];
  const splits: CollabSplitRecord[] = splitsQ.data?.items ?? [];
  const disputes: CollabDisputeOut[] = disputesQ.data?.items ?? [];

  return (
    <div className="space-y-6 p-4 md:p-6" data-testid="collab-revenue-page">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" asChild>
          <Link to="/collaborations">
            <ArrowLeft className="h-4 w-4 mr-1" /> Back
          </Link>
        </Button>
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <DollarSign className="h-6 w-6" /> Revenue
        </h1>
      </div>

      {/* Revenue Summary */}
      <Card>
        <CardHeader>
          <CardTitle>Revenue Summary</CardTitle>
          <CardDescription>{collab?.title || collabId}</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <div className="text-xs text-muted-foreground">Total Revenue</div>
            <div className="text-lg font-semibold">
              {dollars(collab?.total_revenue_cents ?? 0)}
            </div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Content Items</div>
            <div className="text-lg font-semibold">{content.length}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Split Count</div>
            <div className="text-lg font-semibold">{splits.length}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Status</div>
            <div className="text-lg font-semibold">{collab?.status ?? "—"}</div>
          </div>
        </CardContent>
      </Card>

      {/* Assigned Content */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Assigned Content</CardTitle>
            <CardDescription>Content that triggers automatic revenue splits</CardDescription>
          </div>
          <Button size="sm" onClick={() => setAssignOpen(true)}>
            <Plus className="h-4 w-4 mr-1" /> Assign Content
          </Button>
        </CardHeader>
        <CardContent>
          {content.length === 0 ? (
            <p className="text-sm text-muted-foreground">No content assigned</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Revenue</TableHead>
                  <TableHead>Splits</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {content.map((c) => (
                  <TableRow key={c.content_id} data-testid="collab-content-row">
                    <TableCell>{c.title || c.content_id}</TableCell>
                    <TableCell><Badge variant="secondary">{c.content_type}</Badge></TableCell>
                    <TableCell>{dollars(c.total_revenue_cents)}</TableCell>
                    <TableCell>{c.split_count}</TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => unassignMut.mutate(c.content_id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Split History */}
      <Card>
        <CardHeader>
          <CardTitle>Split History</CardTitle>
          <CardDescription>Audit trail of automatic revenue splits</CardDescription>
        </CardHeader>
        <CardContent>
          {splits.length === 0 ? (
            <p className="text-sm text-muted-foreground">No splits yet</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Date</TableHead>
                  <TableHead>Content</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Gross</TableHead>
                  <TableHead>Distribution</TableHead>
                  <TableHead>Dispute</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {splits.map((s) => (
                  <TableRow key={s.split_id} data-testid="collab-split-row">
                    <TableCell>
                      {new Date(s.created_at * 1000).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{s.content_id}</TableCell>
                    <TableCell><Badge variant="outline">{s.source}</Badge></TableCell>
                    <TableCell>{dollars(s.gross_amount_cents)}</TableCell>
                    <TableCell className="text-xs">
                      {s.distributions.map((d) => (
                        <div key={d.user_id}>
                          {d.user_id}: {dollars(d.amount_cents)} ({d.percentage}%)
                        </div>
                      ))}
                    </TableCell>
                    <TableCell>
                      {s.dispute_status ? (
                        <Badge variant="destructive">{s.dispute_status}</Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={!!s.dispute_status}
                        onClick={() => setDisputeSplit(s)}
                      >
                        Dispute
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Disputes */}
      {disputes.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Disputes</CardTitle>
            <CardDescription>Open and resolved split disputes</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Filed By</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {disputes.map((d) => (
                  <TableRow key={d.dispute_id} data-testid="collab-dispute-row">
                    <TableCell>{d.filed_by}</TableCell>
                    <TableCell className="max-w-xs truncate">{d.reason}</TableCell>
                    <TableCell><Badge>{d.status}</Badge></TableCell>
                    <TableCell>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={d.status === "resolved" || resolveMut.isPending}
                        onClick={() => resolveMut.mutate(d.dispute_id)}
                      >
                        Resolve
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Assign Content Dialog */}
      <Dialog open={assignOpen} onOpenChange={setAssignOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Assign Content</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="content-id">Content ID</Label>
              <Input
                id="content-id"
                value={assignForm.content_id}
                onChange={(e) => setAssignForm({ ...assignForm, content_id: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="content-type">Content Type</Label>
              <select
                id="content-type"
                className="w-full border rounded-md h-9 px-2 bg-background"
                value={assignForm.content_type}
                onChange={(e) =>
                  setAssignForm({ ...assignForm, content_type: e.target.value as CollabContentAssignIn["content_type"] })
                }
              >
                <option value="post">post</option>
                <option value="vod">vod</option>
                <option value="broadcast">broadcast</option>
              </select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="content-title">Title</Label>
              <Input
                id="content-title"
                value={assignForm.title}
                onChange={(e) => setAssignForm({ ...assignForm, title: e.target.value })}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAssignOpen(false)}>Cancel</Button>
            <Button
              disabled={!assignForm.content_id || assignMut.isPending}
              onClick={() => assignMut.mutate()}
            >
              Assign
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <CollaborationSplitDisputeDialog
        collabId={collabId}
        split={disputeSplit}
        open={!!disputeSplit}
        onOpenChange={(o) => !o && setDisputeSplit(null)}
      />
    </div>
  );
}
