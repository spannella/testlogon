import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Scale, RefreshCw, Search } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useAuthStore } from "@/stores/authStore";
import { canAccessModerationBoard } from "@/lib/adminCapabilities";
import {
  listDmcaClaims,
  resolveDmcaClaim,
  getInfringerStatus,
  type DmcaClaimOut,
  type DmcaResolveIn,
  type RepeatInfringerStatus,
} from "@/api/endpoints/dmca";

function fmt(ts?: number) {
  if (!ts) return "--";
  return new Date(ts * 1000).toLocaleString();
}

function statusBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "pending":
    case "content_removed":
      return "default";
    case "counter_notice_filed":
    case "waiting_period":
      return "secondary";
    case "resolved":
      return "outline";
    default:
      return "default";
  }
}

export default function DmcaDashboardPage() {
  const token = useAuthStore((s) => s.accessToken);
  const canAccess = canAccessModerationBoard(token);
  const queryClient = useQueryClient();

  const [statusFilter, setStatusFilter] = useState("all");
  const [userIdFilter, setUserIdFilter] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [selectedClaim, setSelectedClaim] = useState<DmcaClaimOut | null>(null);
  const [resolveDialogOpen, setResolveDialogOpen] = useState(false);
  const [resolution, setResolution] = useState<DmcaResolveIn["resolution"]>("upheld");
  const [resolutionNotes, setResolutionNotes] = useState("");
  const [infringerUserId, setInfringerUserId] = useState<string | null>(null);

  const buildParams = () => {
    const params: Record<string, string> = {};
    if (statusFilter && statusFilter !== "all") params.status = statusFilter;
    if (userIdFilter.trim()) params.target_user_id = userIdFilter.trim();
    if (cursor) params.cursor = cursor;
    return params;
  };

  const claimsQuery = useQuery({
    queryKey: ["dmca-claims", statusFilter, userIdFilter, cursor],
    queryFn: () => listDmcaClaims(buildParams()),
    enabled: canAccess,
  });

  const infringerQuery = useQuery({
    queryKey: ["dmca-infringer", infringerUserId],
    queryFn: () => getInfringerStatus(infringerUserId!),
    enabled: canAccess && !!infringerUserId,
  });

  const resolveMutation = useMutation({
    mutationFn: ({ claimId, data }: { claimId: string; data: DmcaResolveIn }) =>
      resolveDmcaClaim(claimId, data),
    onSuccess: (data) => {
      toast.success(`Claim resolved: ${data.resolution}`);
      setResolveDialogOpen(false);
      setSelectedClaim(null);
      setResolutionNotes("");
      void queryClient.invalidateQueries({ queryKey: ["dmca-claims"] });
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof Error ? err.message : "Failed to resolve claim",
      ),
  });

  if (!canAccess) {
    return (
      <div className="p-6">
        <PageHeader title="DMCA Claims Dashboard" />
        <p className="text-muted-foreground">
          You do not have permission to access the DMCA claims dashboard.
        </p>
      </div>
    );
  }

  const items = claimsQuery.data?.items ?? [];
  const nextCursor = claimsQuery.data?.next_cursor;
  const infringerStatus: RepeatInfringerStatus | undefined = infringerQuery.data;

  const handleRowClick = (claim: DmcaClaimOut) => {
    setSelectedClaim(claim);
    if (claim.target_user_id) {
      setInfringerUserId(claim.target_user_id);
    }
  };

  const handleOpenResolve = () => {
    setResolution("upheld");
    setResolutionNotes("");
    setResolveDialogOpen(true);
  };

  const handleResolve = () => {
    if (!selectedClaim) return;
    resolveMutation.mutate({
      claimId: selectedClaim.claim_id,
      data: {
        resolution,
        resolution_notes: resolutionNotes || undefined,
      },
    });
  };

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="DMCA Claims Dashboard"
        description="Review and manage DMCA takedown claims"
      />

      {/* Filters */}
      <div className="flex items-end gap-4 flex-wrap">
        <div>
          <Label htmlFor="status-filter">Status</Label>
          <Select value={statusFilter} onValueChange={(val) => { setStatusFilter(val); setCursor(undefined); }}>
            <SelectTrigger id="status-filter" className="w-48">
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Statuses</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="content_removed">Content Removed</SelectItem>
              <SelectItem value="counter_notice_filed">Counter Notice Filed</SelectItem>
              <SelectItem value="waiting_period">Waiting Period</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-end gap-2">
          <div>
            <Label htmlFor="user-id-filter">Target User ID</Label>
            <Input
              id="user-id-filter"
              placeholder="Filter by user ID"
              value={userIdFilter}
              onChange={(e) => setUserIdFilter(e.target.value)}
              className="w-64"
            />
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => { setCursor(undefined); void claimsQuery.refetch(); }}
          >
            <Search className="h-4 w-4 mr-1" />
            Search
          </Button>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => claimsQuery.refetch()}
          disabled={claimsQuery.isFetching}
        >
          <RefreshCw className="h-4 w-4 mr-1" />
          Refresh
        </Button>
      </div>

      {/* Claims Table */}
      {claimsQuery.isLoading ? (
        <p className="text-muted-foreground">Loading...</p>
      ) : items.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            <Scale className="h-12 w-12 mx-auto mb-3 opacity-50" />
            <p>No DMCA claims found</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Claim ID</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Content Type</TableHead>
                  <TableHead>Target User</TableHead>
                  <TableHead>Strike #</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((claim) => (
                  <TableRow
                    key={claim.claim_id}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => handleRowClick(claim)}
                    data-testid={`claim-row-${claim.claim_id}`}
                  >
                    <TableCell className="font-mono text-xs">
                      {claim.claim_id.slice(0, 12)}...
                    </TableCell>
                    <TableCell>
                      <Badge variant={statusBadgeVariant(claim.status)}>
                        {claim.status.replace(/_/g, " ")}
                      </Badge>
                    </TableCell>
                    <TableCell>{claim.content_type.replace(/_/g, " ")}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {claim.target_user_id ? `${claim.target_user_id.slice(0, 12)}...` : "--"}
                    </TableCell>
                    <TableCell>{claim.strike_number}</TableCell>
                    <TableCell className="text-sm">{fmt(claim.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Pagination */}
      {nextCursor && (
        <div className="flex justify-center">
          <Button
            variant="outline"
            onClick={() => setCursor(nextCursor)}
            disabled={claimsQuery.isFetching}
          >
            Load More
          </Button>
        </div>
      )}

      {/* Detail Panel (Dialog) */}
      <Dialog
        open={!!selectedClaim}
        onOpenChange={(open) => {
          if (!open) {
            setSelectedClaim(null);
            setInfringerUserId(null);
          }
        }}
      >
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>DMCA Claim Detail</DialogTitle>
            <DialogDescription>
              Claim ID: {selectedClaim?.claim_id}
            </DialogDescription>
          </DialogHeader>

          {selectedClaim && (
            <div className="space-y-4">
              {/* Claim Info */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="font-medium text-muted-foreground">Status</span>
                  <div className="mt-1">
                    <Badge variant={statusBadgeVariant(selectedClaim.status)}>
                      {selectedClaim.status.replace(/_/g, " ")}
                    </Badge>
                  </div>
                </div>
                <div>
                  <span className="font-medium text-muted-foreground">Strike Number</span>
                  <p className="mt-1">{selectedClaim.strike_number}</p>
                </div>
                <div>
                  <span className="font-medium text-muted-foreground">Claimant</span>
                  <p className="mt-1">{selectedClaim.claimant_name}</p>
                  <p className="text-xs text-muted-foreground">{selectedClaim.claimant_email}</p>
                </div>
                <div>
                  <span className="font-medium text-muted-foreground">Content Type</span>
                  <p className="mt-1">{selectedClaim.content_type.replace(/_/g, " ")}</p>
                </div>
                <div className="col-span-2">
                  <span className="font-medium text-muted-foreground">Content URL</span>
                  <p className="mt-1 break-all text-xs">{selectedClaim.content_url}</p>
                </div>
                <div className="col-span-2">
                  <span className="font-medium text-muted-foreground">Original Work Description</span>
                  <p className="mt-1 text-xs">{selectedClaim.original_work_description}</p>
                </div>
                <div>
                  <span className="font-medium text-muted-foreground">Created</span>
                  <p className="mt-1">{fmt(selectedClaim.created_at)}</p>
                </div>
                <div>
                  <span className="font-medium text-muted-foreground">Updated</span>
                  <p className="mt-1">{fmt(selectedClaim.updated_at)}</p>
                </div>
                {selectedClaim.content_removed_at && (
                  <div>
                    <span className="font-medium text-muted-foreground">Content Removed</span>
                    <p className="mt-1">{fmt(selectedClaim.content_removed_at)}</p>
                  </div>
                )}
                {selectedClaim.counter_notice_filed_at && (
                  <div>
                    <span className="font-medium text-muted-foreground">Counter Notice Filed</span>
                    <p className="mt-1">{fmt(selectedClaim.counter_notice_filed_at)}</p>
                  </div>
                )}
                {selectedClaim.waiting_period_expires_at && (
                  <div>
                    <span className="font-medium text-muted-foreground">Waiting Period Expires</span>
                    <p className="mt-1">{fmt(selectedClaim.waiting_period_expires_at)}</p>
                  </div>
                )}
                {selectedClaim.resolved_at && (
                  <div>
                    <span className="font-medium text-muted-foreground">Resolved</span>
                    <p className="mt-1">{fmt(selectedClaim.resolved_at)}</p>
                  </div>
                )}
                {selectedClaim.resolution && (
                  <div>
                    <span className="font-medium text-muted-foreground">Resolution</span>
                    <p className="mt-1">{selectedClaim.resolution.replace(/_/g, " ")}</p>
                  </div>
                )}
              </div>

              {/* Infringer Status */}
              {infringerStatus && (
                <Card>
                  <CardContent className="p-4">
                    <h4 className="text-sm font-semibold mb-2">Repeat Infringer Status</h4>
                    <div className="grid grid-cols-3 gap-3 text-sm">
                      <div>
                        <span className="text-muted-foreground">Total Claims</span>
                        <p className="font-medium">{infringerStatus.total_claims}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Upheld Claims</span>
                        <p className="font-medium">{infringerStatus.upheld_claims}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Strikes</span>
                        <p className="font-medium">
                          {infringerStatus.strike_count} / {infringerStatus.threshold}
                        </p>
                      </div>
                      <div className="col-span-3">
                        <span className="text-muted-foreground">Account Status</span>
                        <div className="mt-1">
                          <Badge
                            variant={
                              infringerStatus.status === "active"
                                ? "default"
                                : "destructive"
                            }
                          >
                            {infringerStatus.status}
                          </Badge>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Resolve Action */}
              {selectedClaim.status !== "resolved" && (
                <div className="flex justify-end">
                  <Button onClick={handleOpenResolve}>Resolve Claim</Button>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Resolve Dialog */}
      <Dialog open={resolveDialogOpen} onOpenChange={setResolveDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Resolve DMCA Claim</DialogTitle>
            <DialogDescription>
              Choose a resolution for claim {selectedClaim?.claim_id?.slice(0, 12)}...
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="resolution-type">Resolution</Label>
              <Select value={resolution} onValueChange={(val) => setResolution(val as DmcaResolveIn["resolution"])}>
                <SelectTrigger id="resolution-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="restored">Restored (content put back)</SelectItem>
                  <SelectItem value="upheld">Upheld (content stays removed)</SelectItem>
                  <SelectItem value="court_order">Court Order</SelectItem>
                  <SelectItem value="withdrawn">Withdrawn by claimant</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="resolution-notes">Notes (optional)</Label>
              <Textarea
                id="resolution-notes"
                value={resolutionNotes}
                onChange={(e) => setResolutionNotes(e.target.value)}
                placeholder="Additional notes about this resolution"
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setResolveDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleResolve}
              disabled={resolveMutation.isPending}
            >
              {resolveMutation.isPending ? "Resolving..." : "Confirm Resolution"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
